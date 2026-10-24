//! Device sync for one encrypted vault file shared through a folder (iCloud Drive).
//!
//! Each install keeps its device id in a local config file. The vault file stores a
//! revision, the last writer, per-item version vectors, tombstones, and conflict copies.
//! A save re-reads the file and merges when the nonce, revision, or ciphertext hash changed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::{
    self, now_rfc3339, parse_encrypted, ItemBody, ItemConflict, Tombstone, UnlockedVault, VaultData,
    VaultError, VaultItem, VaultSettings,
};

pub const SYNC_POLL_SECS: u64 = 3;
pub const LEGACY_DEVICE: &str = "legacy";
pub const LEGACY_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

#[derive(Clone, Debug)]
pub struct FileStamp {
    pub revision: u64,
    pub nonce: String,
    pub hash: [u8; 32],
    pub modified: Option<SystemTime>,
    pub len: u64,
}

impl Default for FileStamp {
    fn default() -> Self {
        Self {
            revision: 0,
            nonce: String::new(),
            hash: [0u8; 32],
            modified: None,
            len: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub state: String,
    pub vault_path: String,
    pub device_id: String,
    pub revision: u64,
    pub generation: u64,
    pub conflict_count: usize,
    pub pending_files: Vec<String>,
    pub message: String,
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConflictView {
    pub item_id: String,
    pub conflict_id: String,
    pub current_deleted: bool,
    pub current_title: String,
    pub current_updated_at: String,
    pub current_item_type: String,
    pub current_username: String,
    pub conflict_deleted: bool,
    pub conflict_title: String,
    pub conflict_updated_at: String,
    pub conflict_item_type: String,
    pub conflict_username: String,
    pub conflict_updated_by: String,
}

#[derive(Clone, Debug)]
pub struct LocalConfig {
    pub device_id: String,
    pub vault_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalConfigFile {
    #[serde(default)]
    device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault_path: Option<String>,
}

#[derive(Clone, Debug)]
struct Record {
    id: String,
    deleted: bool,
    updated_at: String,
    updated_by: String,
    versions: BTreeMap<String, u64>,
    conflicts: Vec<ItemConflict>,
    resolved: Vec<String>,
    content: ItemBody,
}

pub fn local_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("keyhaven-config.json")
}

pub fn default_vault_file(data_dir: &Path) -> PathBuf {
    data_dir.join("vault.khv")
}

pub fn load_or_create_local_config(data_dir: &Path) -> Result<LocalConfig, VaultError> {
    fs::create_dir_all(data_dir)?;
    let path = local_config_path(data_dir);
    let mut file = if path.exists() {
        let bytes = fs::read(&path)?;
        serde_json::from_slice::<LocalConfigFile>(&bytes).unwrap_or(LocalConfigFile {
            device_id: String::new(),
            vault_path: None,
        })
    } else {
        LocalConfigFile {
            device_id: String::new(),
            vault_path: None,
        }
    };
    let mut changed = !path.exists();
    if file.device_id.trim().is_empty() {
        file.device_id = uuid::Uuid::new_v4().to_string();
        changed = true;
    }
    let config = LocalConfig {
        device_id: file.device_id.clone(),
        vault_path: file.vault_path.as_ref().map(PathBuf::from),
    };
    if changed {
        write_local_config_file(&path, &file)?;
    }
    Ok(config)
}

pub fn save_local_config(data_dir: &Path, config: &LocalConfig) -> Result<(), VaultError> {
    fs::create_dir_all(data_dir)?;
    let file = LocalConfigFile {
        device_id: config.device_id.clone(),
        vault_path: config.vault_path.as_ref().map(|path| path.to_string_lossy().into_owned()),
    };
    write_local_config_file(&local_config_path(data_dir), &file)
}

fn write_local_config_file(path: &Path, file: &LocalConfigFile) -> Result<(), VaultError> {
    let bytes = serde_json::to_vec_pretty(file)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut handle = File::create(&tmp)?;
        handle.write_all(&bytes)?;
        handle.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn require_absolute(path: &Path) -> Result<(), VaultError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(VaultError::AbsolutePathRequired)
    }
}

/// Expand a leading `~` so a pasted iCloud path such as `~/Library/...` is absolute.
pub fn user_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    if let Some(home) = home {
        if trimmed == "~" {
            return PathBuf::from(home);
        }
        if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix("~\\")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(trimmed)
}

pub fn normalize_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    if let Some(parent) = path.parent() {
        if let Ok(parent) = parent.canonicalize() {
            if let Some(name) = path.file_name() {
                return parent.join(name);
            }
        }
    }
    path.to_path_buf()
}

pub fn relocate_vault_file(from: &Path, to: &Path) -> Result<(), VaultError> {
    if normalize_path(from) == normalize_path(to) {
        return Ok(());
    }
    if to.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(from, to)?;
            fs::remove_file(from)?;
            Ok(())
        }
    }
}

pub fn icloud_placeholder(vault_path: &Path) -> Option<PathBuf> {
    let name = vault_path.file_name()?;
    let mut placeholder = std::ffi::OsString::from(".");
    placeholder.push(name);
    placeholder.push(".icloud");
    Some(vault_path.with_file_name(placeholder))
}

pub fn prompt_icloud_download(vault_path: &Path) {
    if let Some(placeholder) = icloud_placeholder(vault_path) {
        if placeholder.exists() {
            request_icloud_download(&placeholder);
        }
    }
    request_icloud_download(vault_path);
}

#[cfg(target_os = "macos")]
fn request_icloud_download(path: &Path) {
    let _ = std::process::Command::new("brctl")
        .arg("download")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(target_os = "macos"))]
fn request_icloud_download(path: &Path) {
    let _ = path;
}

pub fn conflict_siblings(vault_path: &Path) -> Vec<PathBuf> {
    let Some(parent) = vault_path.parent() else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && is_conflict_sibling(vault_path, &path) {
            found.push(path);
        }
    }
    found.sort();
    found
}

pub fn is_conflict_sibling(vault_path: &Path, candidate: &Path) -> bool {
    let Some(vault_name) = vault_path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(name) = candidate.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name == vault_name || name.ends_with(".merged-bak") || name.ends_with(".tmp") {
        return false;
    }
    let Some(stem) = vault_path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };
    let ext = vault_path.extension().and_then(|ext| ext.to_str()).unwrap_or("khv");
    let suffix = format!(".{ext}");
    if !name.ends_with(&suffix) {
        return false;
    }
    let without_ext = &name[..name.len() - suffix.len()];
    let Some(rest) = without_ext.strip_prefix(&format!("{stem} ")) else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    if rest.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    rest.to_ascii_lowercase().contains("conflict")
}

pub fn capture_stamp(path: &Path, revision: u64) -> Result<FileStamp, VaultError> {
    let bytes = fs::read(path)?;
    let meta = fs::metadata(path)?;
    let enc = parse_encrypted(&bytes)?;
    Ok(FileStamp {
        revision,
        nonce: enc.nonce,
        hash: sha256(&bytes),
        modified: meta.modified().ok(),
        len: bytes.len() as u64,
    })
}

pub fn save_vault(path: &Path, unlocked: &mut UnlockedVault) -> Result<(), VaultError> {
    with_vault_lock(path, || sync_locked(path, unlocked, true))
}

pub fn pull_vault(path: &Path, unlocked: &mut UnlockedVault) -> Result<(), VaultError> {
    with_vault_lock(path, || sync_locked(path, unlocked, false))
}

pub fn merge_with_password(
    main: &Path,
    foreign: &Path,
    password: &SecretString,
    unlocked: &mut UnlockedVault,
) -> Result<(), VaultError> {
    let foreign_path = normalize_path(foreign);
    let main_path = normalize_path(main);
    let bytes = fs::read(&foreign_path)?;
    let enc = parse_encrypted(&bytes)?;
    let (_key, _salt, mut data) = vault::unlock_with_password(&enc, password)?;
    migrate_data(&mut data);
    let file_revision = data.revision;
    merge_vault(&mut unlocked.data, &data);
    let foreign_text = foreign_path.to_string_lossy().into_owned();
    unlocked.pending_password_files.retain(|pending| {
        pending != &foreign_text && normalize_path(Path::new(pending)) != foreign_path
    });
    if foreign_path == main_path {
        unlocked.stamp = capture_stamp(&foreign_path, file_revision)?;
    } else if is_conflict_sibling(&main_path, &foreign_path) {
        archive_merged(&foreign_path)?;
    }
    unlocked.dirty = true;
    unlocked.sync_error = None;
    unlocked.waiting_icloud = false;
    Ok(())
}

fn sync_locked(path: &Path, unlocked: &mut UnlockedVault, force_write: bool) -> Result<(), VaultError> {
    if unlocked.device_id.is_empty() {
        unlocked.device_id = "device".to_string();
    }
    migrate_data(&mut unlocked.data);

    if !path.exists() {
        if icloud_placeholder(path).is_some_and(|placeholder| placeholder.exists()) {
            unlocked.waiting_icloud = true;
            unlocked.sync_error = None;
            prompt_icloud_download(path);
            if force_write {
                return Err(VaultError::WaitingForIcloud);
            }
            return Ok(());
        }
        unlocked.waiting_icloud = false;
        if force_write || unlocked.dirty {
            write_current(path, unlocked)?;
        }
        return Ok(());
    }

    for _attempt in 0..4 {
        let bytes = fs::read(path)?;
        let meta = fs::metadata(path)?;
        let enc = match parse_encrypted(&bytes) {
            Ok(enc) => enc,
            Err(err) => {
                unlocked.sync_error = Some(err.to_string());
                return Err(err);
            }
        };
        let hash = sha256(&bytes);
        let disk_matches = hash == unlocked.stamp.hash && enc.nonce == unlocked.stamp.nonce;
        let mut pending = Vec::new();
        let mut diverged_from_disk = false;
        let mut incorporated_revision = unlocked.data.revision;

        if !disk_matches {
            match vault::decrypt_data(&enc, &unlocked.key) {
                Ok(mut remote) => {
                    migrate_data(&mut remote);
                    incorporated_revision = remote.revision;
                    let remote_fp = content_fingerprint(&remote);
                    merge_vault(&mut unlocked.data, &remote);
                    if content_fingerprint(&unlocked.data) != remote_fp {
                        diverged_from_disk = true;
                    }
                    unlocked.stamp = FileStamp {
                        revision: incorporated_revision,
                        nonce: enc.nonce.clone(),
                        hash,
                        modified: meta.modified().ok(),
                        len: bytes.len() as u64,
                    };
                    unlocked.waiting_icloud = false;
                }
                Err(VaultError::Tampered) | Err(VaultError::WrongPassword) => {
                    pending.push(path.to_string_lossy().into_owned());
                    collect_locked_siblings(path, &mut pending);
                    unlocked.pending_password_files = pending;
                    unlocked.waiting_icloud = false;
                    unlocked.sync_error = None;
                    if force_write {
                        return Err(VaultError::SyncPasswordRequired);
                    }
                    return Ok(());
                }
                Err(err) => {
                    unlocked.sync_error = Some(err.to_string());
                    return Err(err);
                }
            }
        } else if unlocked.stamp.modified != meta.modified().ok() || unlocked.stamp.len != bytes.len() as u64 {
            unlocked.stamp.modified = meta.modified().ok();
            unlocked.stamp.len = bytes.len() as u64;
            let _ = incorporated_revision;
        }

        let mut archived = Vec::new();
        let mut sibling_merged = false;
        for sibling in conflict_siblings(path) {
            let sibling_bytes = fs::read(&sibling)?;
            let sibling_enc = match parse_encrypted(&sibling_bytes) {
                Ok(enc) => enc,
                Err(_) => {
                    pending.push(sibling.to_string_lossy().into_owned());
                    continue;
                }
            };
            match vault::decrypt_data(&sibling_enc, &unlocked.key) {
                Ok(mut remote) => {
                    migrate_data(&mut remote);
                    merge_vault(&mut unlocked.data, &remote);
                    sibling_merged = true;
                    archived.push(sibling);
                }
                Err(VaultError::Tampered) | Err(VaultError::WrongPassword) => {
                    pending.push(sibling.to_string_lossy().into_owned());
                }
                Err(err) => {
                    unlocked.sync_error = Some(err.to_string());
                    return Err(err);
                }
            }
        }
        unlocked.pending_password_files = pending;
        unlocked.sync_error = None;
        unlocked.waiting_icloud = false;

        let should_write = force_write || unlocked.dirty || sibling_merged || diverged_from_disk;
        if !should_write {
            unlocked.dirty = false;
            return Ok(());
        }

        let again = fs::read(path)?;
        if sha256(&again) != hash {
            continue;
        }
        write_current(path, unlocked)?;
        for sibling in archived {
            archive_merged(&sibling)?;
        }
        return Ok(());
    }
    Err(VaultError::Io(std::io::Error::new(
        ErrorKind::WouldBlock,
        "vault changed while saving",
    )))
}

fn collect_locked_siblings(vault_path: &Path, pending: &mut Vec<String>) {
    for sibling in conflict_siblings(vault_path) {
        let text = sibling.to_string_lossy().into_owned();
        if !pending.iter().any(|path| path == &text) {
            pending.push(text);
        }
    }
}

fn write_current(path: &Path, unlocked: &mut UnlockedVault) -> Result<(), VaultError> {
    migrate_data(&mut unlocked.data);
    unlocked.data.revision = unlocked.data.revision.saturating_add(1);
    unlocked.data.device_id = unlocked.device_id.clone();
    let enc = vault::encrypt_data(&unlocked.data, &unlocked.key, &unlocked.params, &unlocked.salt)?;
    let bytes = vault::serialize_encrypted(&enc)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    vault::atomic_write(path, &bytes)?;
    unlocked.stamp = capture_stamp(path, unlocked.data.revision)?;
    unlocked.dirty = false;
    unlocked.waiting_icloud = false;
    unlocked.sync_error = None;
    Ok(())
}

fn with_vault_lock<T>(vault_path: &Path, body: impl FnOnce() -> Result<T, VaultError>) -> Result<T, VaultError> {
    let lock_path = temp_lock_path(vault_path);
    let started = std::time::Instant::now();
    loop {
        match File::options().write(true).create_new(true).open(&lock_path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                let result = body();
                drop(file);
                let _ = fs::remove_file(&lock_path);
                return result;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                if lock_is_stale(&lock_path) {
                    let _ = fs::remove_file(&lock_path);
                    continue;
                }
                if started.elapsed() > Duration::from_secs(10) {
                    return Err(VaultError::Io(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "vault file is busy",
                    )));
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn temp_lock_path(vault_path: &Path) -> PathBuf {
    let digest = sha256(normalize_path(vault_path).to_string_lossy().as_bytes());
    std::env::temp_dir().join(format!("keyhaven-vault-{}.lock", hex_encode(&digest[..8])))
}

fn lock_is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .map(|age| age > Duration::from_secs(30))
        .unwrap_or(false)
}

fn archive_merged(path: &Path) -> Result<(), VaultError> {
    let mut name = path.as_os_str().to_os_string();
    name.push(".merged-bak");
    let mut dest = PathBuf::from(&name);
    if dest.exists() {
        let millis = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        let mut numbered = name;
        numbered.push(format!(".{millis}"));
        dest = PathBuf::from(numbered);
    }
    fs::rename(path, dest)?;
    Ok(())
}

pub fn migrate_data(data: &mut VaultData) {
    data.settings = data.settings.clone().normalized();
    for item in &mut data.items {
        migrate_item(item);
    }
    for tombstone in &mut data.tombstones {
        if tombstone.updated_at.is_empty() {
            tombstone.updated_at = LEGACY_TIMESTAMP.to_string();
        }
        if tombstone.versions.is_empty() {
            tombstone.versions.insert(LEGACY_DEVICE.to_string(), 1);
        }
        for conflict in &mut tombstone.conflicts {
            if conflict.id.is_empty() {
                conflict.id = conflict_fingerprint(conflict);
            }
        }
    }
}

fn migrate_item(item: &mut VaultItem) {
    if item.created_at.is_empty() {
        item.created_at = LEGACY_TIMESTAMP.to_string();
    }
    if item.updated_at.is_empty() {
        item.updated_at = item.created_at.clone();
    }
    if item.item_type.is_empty() {
        item.item_type = "login".to_string();
    }
    if item.id.is_empty() {
        item.id = legacy_id(item);
    }
    if item.versions.is_empty() {
        item.versions.insert(LEGACY_DEVICE.to_string(), 1);
    }
    for conflict in &mut item.conflicts {
        if conflict.id.is_empty() {
            conflict.id = conflict_fingerprint(conflict);
        }
    }
}

fn legacy_id(item: &VaultItem) -> String {
    let body = item.body();
    let material = serde_json::json!({
        "itemType": body.item_type,
        "title": body.title,
        "username": body.username,
        "password": body.password,
        "url": body.url,
        "notes": body.notes,
        "cardholder": body.cardholder,
        "number": body.number,
        "expiry": body.expiry,
        "cvv": body.cvv,
        "tags": body.tags,
        "createdAt": item.created_at,
    });
    let digest = sha256(material.to_string().as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4],
        digest[5],
        digest[6] & 0x0f,
        digest[7],
        (digest[8] & 0x3f) | 0x80,
        digest[9],
        digest[10],
        digest[11],
        digest[12],
        digest[13],
        digest[14],
        digest[15],
    )
}

pub fn insert_new(data: &mut VaultData, mut item: VaultItem, device_id: &str) -> VaultItem {
    let device = device_or_default(device_id);
    if item.id.is_empty() {
        item.id = vault::new_id();
    }
    let now = now_rfc3339();
    if item.created_at.is_empty() {
        item.created_at = now.clone();
    }
    item.updated_at = now;
    item.updated_by = Some(device.clone());
    item.versions.clear();
    item.versions.insert(device, 1);
    item.conflicts.clear();
    item.resolved_conflicts.clear();
    if data.tombstones.iter().any(|tombstone| tombstone.id == item.id) {
        let mut remote = VaultData::default();
        remote.items.push(item.clone());
        merge_vault(data, &remote);
        return data
            .items
            .iter()
            .find(|existing| existing.id == item.id)
            .cloned()
            .unwrap_or(item);
    }
    data.items.push(item.clone());
    item
}

pub fn update_existing(data: &mut VaultData, incoming: VaultItem, device_id: &str) -> Result<VaultItem, VaultError> {
    vault::validate_item_type(&incoming.item_type)?;
    let device = device_or_default(device_id);
    let Some(index) = data.items.iter().position(|item| item.id == incoming.id) else {
        return Err(VaultError::ItemNotFound);
    };
    let existing = data.items[index].clone();
    let mut updated = incoming;
    if !existing.created_at.is_empty() {
        updated.created_at = existing.created_at;
    }
    updated.versions = existing.versions;
    updated.conflicts = existing.conflicts;
    updated.resolved_conflicts = existing.resolved_conflicts;
    if updated.versions.is_empty() {
        updated.versions.insert(LEGACY_DEVICE.to_string(), 1);
    }
    let next = updated.versions.get(&device).copied().unwrap_or(0).saturating_add(1);
    updated.versions.insert(device.clone(), next);
    updated.updated_at = now_rfc3339();
    updated.updated_by = Some(device);
    data.items[index] = updated.clone();
    Ok(updated)
}

pub fn delete_item(data: &mut VaultData, id: &str, device_id: &str) -> Result<(), VaultError> {
    let device = device_or_default(device_id);
    let Some(index) = data.items.iter().position(|item| item.id == id) else {
        return Err(VaultError::ItemNotFound);
    };
    let item = data.items.remove(index);
    let mut versions = item.versions.clone();
    if versions.is_empty() {
        versions.insert(LEGACY_DEVICE.to_string(), 1);
    }
    let next = versions.get(&device).copied().unwrap_or(0).saturating_add(1);
    versions.insert(device.clone(), next);
    let tombstone = Tombstone {
        id: item.id.clone(),
        updated_at: now_rfc3339(),
        updated_by: Some(device),
        versions,
        conflicts: item.conflicts.clone(),
        resolved_conflicts: item.resolved_conflicts.clone(),
        body: item.body(),
    };
    upsert_tombstone(data, tombstone);
    Ok(())
}

fn upsert_tombstone(data: &mut VaultData, tombstone: Tombstone) {
    if let Some(existing) = data.tombstones.iter_mut().find(|current| current.id == tombstone.id) {
        let merged = merge_records(record_from_tombstone(existing), record_from_tombstone(&tombstone));
        *existing = tombstone_from_record(&merged);
    } else {
        data.tombstones.push(tombstone);
    }
}

pub fn resolve_conflict(
    data: &mut VaultData,
    item_id: &str,
    conflict_id: &str,
    action: &str,
    device_id: &str,
) -> Result<(), VaultError> {
    if action != "keep" && action != "restore" {
        return Err(VaultError::InvalidItemType);
    }
    let device = device_or_default(device_id);
    if let Some(index) = data.items.iter().position(|item| item.id == item_id) {
        let Some(conflict_index) = data.items[index].conflicts.iter().position(|conflict| conflict.id == conflict_id) else {
            return Err(VaultError::ItemNotFound);
        };
        let conflict = data.items[index].conflicts.remove(conflict_index);
        remember_resolved(&mut data.items[index].resolved_conflicts, &conflict.id);
        if action == "restore" {
            let current_fp = item_fingerprint(&data.items[index]);
            remember_resolved(&mut data.items[index].resolved_conflicts, &current_fp);
            let resolved = data.items[index].resolved_conflicts.clone();
            let mut versions = vv_max(&data.items[index].versions, &conflict.versions);
            let next = versions.get(&device).copied().unwrap_or(0).saturating_add(1);
            versions.insert(device.clone(), next);
            data.items[index].apply_body(&conflict.body);
            data.items[index].updated_at = now_rfc3339();
            data.items[index].updated_by = Some(device);
            data.items[index].versions = versions;
            data.items[index].resolved_conflicts = resolved;
            let resolved_now = data.items[index].resolved_conflicts.clone();
            data.items[index].conflicts.retain(|entry| !resolved_now.iter().any(|id| id == &entry.id));
        }
        return Ok(());
    }
    let Some(index) = data.tombstones.iter().position(|tombstone| tombstone.id == item_id) else {
        return Err(VaultError::ItemNotFound);
    };
    let Some(conflict_index) = data.tombstones[index].conflicts.iter().position(|conflict| conflict.id == conflict_id) else {
        return Err(VaultError::ItemNotFound);
    };
    let mut tombstone = data.tombstones.remove(index);
    let conflict = tombstone.conflicts.remove(conflict_index);
    remember_resolved(&mut tombstone.resolved_conflicts, &conflict.id);
    if action == "keep" {
        data.tombstones.push(tombstone);
        return Ok(());
    }
    let mut item = VaultItem::skeleton();
    item.id = tombstone.id.clone();
    if conflict.deleted {
        item.apply_body(&tombstone.body);
    } else {
        item.apply_body(&conflict.body);
    }
    let tombstone_fp = tombstone_fingerprint(&tombstone);
    remember_resolved(&mut tombstone.resolved_conflicts, &tombstone_fp);
    let mut versions = vv_max(&tombstone.versions, &conflict.versions);
    let next = versions.get(&device).copied().unwrap_or(0).saturating_add(1);
    versions.insert(device.clone(), next);
    item.versions = versions;
    item.updated_at = now_rfc3339();
    item.updated_by = Some(device);
    item.resolved_conflicts = tombstone.resolved_conflicts;
    item.conflicts = tombstone.conflicts;
    let resolved = item.resolved_conflicts.clone();
    item.conflicts.retain(|entry| !resolved.iter().any(|id| id == &entry.id));
    data.items.push(item);
    Ok(())
}

pub fn list_conflicts(data: &VaultData) -> Vec<ConflictView> {
    let mut views = Vec::new();
    for item in &data.items {
        for conflict in &item.conflicts {
            views.push(ConflictView {
                item_id: item.id.clone(),
                conflict_id: conflict.id.clone(),
                current_deleted: false,
                current_title: item.title.clone(),
                current_updated_at: item.updated_at.clone(),
                current_item_type: item.item_type.clone(),
                current_username: item.username.clone().unwrap_or_default(),
                conflict_deleted: conflict.deleted,
                conflict_title: conflict.body.title.clone(),
                conflict_updated_at: conflict.updated_at.clone(),
                conflict_item_type: conflict.body.item_type.clone(),
                conflict_username: conflict.body.username.clone().unwrap_or_default(),
                conflict_updated_by: conflict.updated_by.clone().unwrap_or_default(),
            });
        }
    }
    for tombstone in &data.tombstones {
        for conflict in &tombstone.conflicts {
            views.push(ConflictView {
                item_id: tombstone.id.clone(),
                conflict_id: conflict.id.clone(),
                current_deleted: true,
                current_title: tombstone.body.title.clone(),
                current_updated_at: tombstone.updated_at.clone(),
                current_item_type: tombstone.body.item_type.clone(),
                current_username: tombstone.body.username.clone().unwrap_or_default(),
                conflict_deleted: conflict.deleted,
                conflict_title: conflict.body.title.clone(),
                conflict_updated_at: conflict.updated_at.clone(),
                conflict_item_type: conflict.body.item_type.clone(),
                conflict_username: conflict.body.username.clone().unwrap_or_default(),
                conflict_updated_by: conflict.updated_by.clone().unwrap_or_default(),
            });
        }
    }
    views
}

pub fn count_conflicts(data: &VaultData) -> usize {
    data.items.iter().map(|item| item.conflicts.len()).sum::<usize>()
        + data.tombstones.iter().map(|tombstone| tombstone.conflicts.len()).sum::<usize>()
}

pub fn content_fingerprint(data: &VaultData) -> [u8; 32] {
    let mut lines = Vec::new();
    for item in &data.items {
        lines.push(format!(
            "i\t{}\t{}\t{}\t{}\t{}",
            item.id,
            item.updated_at,
            item.title,
            item.item_type,
            item.versions.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",")
        ));
        for conflict in &item.conflicts {
            lines.push(format!("c\t{}\t{}\t{}", item.id, conflict.id, conflict.updated_at));
        }
    }
    for tombstone in &data.tombstones {
        lines.push(format!("t\t{}\t{}\t{}", tombstone.id, tombstone.updated_at, tombstone.body.title));
        for conflict in &tombstone.conflicts {
            lines.push(format!("tc\t{}\t{}\t{}", tombstone.id, conflict.id, conflict.updated_at));
        }
    }
    lines.push(format!(
        "s\t{}\t{}\t{}\t{}\t{}",
        data.settings.auto_lock_minutes,
        data.settings.lock_on_screen_lock,
        data.settings.biometrics_enabled,
        data.settings.password_interval_days,
        data.settings.settings_updated_at.clone().unwrap_or_default()
    ));
    lines.sort();
    sha256(lines.join("\n").as_bytes())
}

pub fn status_of(
    vault_path: &Path,
    device_id: &str,
    unlocked: Option<&UnlockedVault>,
    generation: u64,
    locked: bool,
) -> SyncStatus {
    let placeholder = icloud_placeholder(vault_path).is_some_and(|path| path.exists());
    let waiting = unlocked.map(|vault| vault.waiting_icloud).unwrap_or(false) || (!vault_path.exists() && placeholder);
    let pending = unlocked.map(|vault| vault.pending_password_files.clone()).unwrap_or_default();
    let sync_error = unlocked.and_then(|vault| vault.sync_error.clone());
    let state = if waiting {
        "waiting_icloud"
    } else if !pending.is_empty() {
        "password_required"
    } else if sync_error.is_some() {
        "error"
    } else {
        "ok"
    };
    let message = match state {
        "waiting_icloud" => "waiting for iCloud download".to_string(),
        "password_required" => "vault file needs a different password".to_string(),
        "error" => sync_error.unwrap_or_else(|| "sync error".to_string()),
        _ => "ok".to_string(),
    };
    SyncStatus {
        state: state.to_string(),
        vault_path: vault_path.to_string_lossy().into_owned(),
        device_id: device_id.to_string(),
        revision: unlocked.map(|vault| vault.data.revision).unwrap_or(0),
        generation,
        conflict_count: unlocked.map(|vault| count_conflicts(&vault.data)).unwrap_or(0),
        pending_files: pending,
        message,
        locked,
    }
}

pub fn merge_vault(local: &mut VaultData, remote: &VaultData) {
    migrate_data(local);
    let mut remote = remote.clone();
    migrate_data(&mut remote);
    let settings = merge_settings(&local.settings, &remote.settings);
    let revision = local.revision.max(remote.revision);
    let device_id = if local.device_id.is_empty() {
        remote.device_id.clone()
    } else {
        local.device_id.clone()
    };
    let mut ids = BTreeSet::new();
    for item in local.items.iter().chain(remote.items.iter()) {
        ids.insert(item.id.clone());
    }
    for tombstone in local.tombstones.iter().chain(remote.tombstones.iter()) {
        ids.insert(tombstone.id.clone());
    }
    let mut items = Vec::new();
    let mut tombstones = Vec::new();
    for id in ids {
        let merged = match (record_for(local, &id), record_for(&remote, &id)) {
            (Some(left), Some(right)) => merge_records(left, right),
            (Some(left), None) => left,
            (None, Some(right)) => right,
            (None, None) => continue,
        };
        if merged.deleted {
            tombstones.push(tombstone_from_record(&merged));
        } else {
            items.push(item_from_record(&merged));
        }
    }
    local.items = items;
    local.tombstones = tombstones;
    local.settings = settings;
    local.revision = revision;
    local.device_id = device_id;
}

fn record_for(data: &VaultData, id: &str) -> Option<Record> {
    if let Some(item) = data.items.iter().find(|item| item.id == id) {
        let live = record_from_item(item);
        if let Some(tombstone) = data.tombstones.iter().find(|tombstone| tombstone.id == id) {
            return Some(merge_records(live, record_from_tombstone(tombstone)));
        }
        return Some(live);
    }
    data.tombstones.iter().find(|tombstone| tombstone.id == id).map(record_from_tombstone)
}

fn merge_records(left: Record, right: Record) -> Record {
    if vv_dominates(&left.versions, &right.versions) {
        return absorb(left, right);
    }
    if vv_dominates(&right.versions, &left.versions) {
        return absorb(right, left);
    }
    if left.versions == right.versions && left.deleted == right.deleted && left.content == right.content {
        return absorb(left, right);
    }
    let left_wins = prefer_left(&left, &right);
    let (mut winner, loser) = if left_wins { (left, right) } else { (right, left) };
    let loser_conflict = record_to_conflict(&loser);
    winner.conflicts.push(loser_conflict);
    winner.conflicts.extend(loser.conflicts);
    winner.resolved = union_strings(winner.resolved, loser.resolved);
    winner.versions = vv_max(&winner.versions, &loser.versions);
    cleanup(&mut winner);
    winner
}

fn absorb(mut winner: Record, loser: Record) -> Record {
    winner.conflicts.extend(loser.conflicts);
    winner.resolved = union_strings(winner.resolved, loser.resolved);
    cleanup(&mut winner);
    winner
}

fn cleanup(record: &mut Record) {
    record.resolved.sort();
    record.resolved.dedup();
    let mut seen = BTreeSet::new();
    let resolved = record.resolved.clone();
    let current = record.content.clone();
    let deleted = record.deleted;
    record.conflicts.retain(|conflict| {
        if resolved.iter().any(|id| id == &conflict.id) {
            return false;
        }
        if !seen.insert(conflict.id.clone()) {
            return false;
        }
        if !conflict.deleted && !deleted && conflict.body == current {
            return false;
        }
        true
    });
}

fn prefer_left(left: &Record, right: &Record) -> bool {
    match stamp_cmp(&left.updated_at, &right.updated_at) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => left.updated_by >= right.updated_by,
    }
}

fn stamp_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    let parsed_left = chrono::DateTime::parse_from_rfc3339(left).ok();
    let parsed_right = chrono::DateTime::parse_from_rfc3339(right).ok();
    match (parsed_left, parsed_right) {
        (Some(left_time), Some(right_time)) => left_time.cmp(&right_time),
        _ => left.cmp(right),
    }
}

fn merge_settings(local: &VaultSettings, remote: &VaultSettings) -> VaultSettings {
    let local_stamp = local.settings_updated_at.clone().unwrap_or_default();
    let remote_stamp = remote.settings_updated_at.clone().unwrap_or_default();
    let mut chosen = if stamp_cmp(&remote_stamp, &local_stamp) == std::cmp::Ordering::Greater {
        remote.clone()
    } else {
        local.clone()
    };
    chosen.last_password_unlock_at = later_stamp(&local.last_password_unlock_at, &remote.last_password_unlock_at);
    chosen.normalized()
}

fn later_stamp(left: &Option<String>, right: &Option<String>) -> Option<String> {
    match (left.clone(), right.clone()) {
        (Some(left), Some(right)) => {
            if stamp_cmp(&right, &left) == std::cmp::Ordering::Greater {
                Some(right)
            } else {
                Some(left)
            }
        }
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn record_from_item(item: &VaultItem) -> Record {
    Record {
        id: item.id.clone(),
        deleted: false,
        updated_at: item.updated_at.clone(),
        updated_by: item.updated_by.clone().unwrap_or_default(),
        versions: item.versions.clone(),
        conflicts: item.conflicts.clone(),
        resolved: item.resolved_conflicts.clone(),
        content: item.body(),
    }
}

fn record_from_tombstone(tombstone: &Tombstone) -> Record {
    Record {
        id: tombstone.id.clone(),
        deleted: true,
        updated_at: tombstone.updated_at.clone(),
        updated_by: tombstone.updated_by.clone().unwrap_or_default(),
        versions: tombstone.versions.clone(),
        conflicts: tombstone.conflicts.clone(),
        resolved: tombstone.resolved_conflicts.clone(),
        content: tombstone.body.clone(),
    }
}

fn item_from_record(record: &Record) -> VaultItem {
    let mut item = VaultItem::skeleton();
    item.id = record.id.clone();
    item.apply_body(&record.content);
    item.updated_at = record.updated_at.clone();
    item.updated_by = if record.updated_by.is_empty() {
        None
    } else {
        Some(record.updated_by.clone())
    };
    item.versions = record.versions.clone();
    item.conflicts = record.conflicts.clone();
    item.resolved_conflicts = record.resolved.clone();
    item
}

fn tombstone_from_record(record: &Record) -> Tombstone {
    Tombstone {
        id: record.id.clone(),
        updated_at: record.updated_at.clone(),
        updated_by: if record.updated_by.is_empty() {
            None
        } else {
            Some(record.updated_by.clone())
        },
        versions: record.versions.clone(),
        conflicts: record.conflicts.clone(),
        resolved_conflicts: record.resolved.clone(),
        body: record.content.clone(),
    }
}

fn record_to_conflict(record: &Record) -> ItemConflict {
    let mut conflict = ItemConflict {
        id: String::new(),
        updated_at: record.updated_at.clone(),
        updated_by: if record.updated_by.is_empty() {
            None
        } else {
            Some(record.updated_by.clone())
        },
        versions: record.versions.clone(),
        deleted: record.deleted,
        body: record.content.clone(),
    };
    conflict.id = conflict_fingerprint(&conflict);
    conflict
}

fn item_fingerprint(item: &VaultItem) -> String {
    conflict_fingerprint(&ItemConflict {
        id: String::new(),
        updated_at: item.updated_at.clone(),
        updated_by: item.updated_by.clone(),
        versions: item.versions.clone(),
        deleted: false,
        body: item.body(),
    })
}

fn tombstone_fingerprint(tombstone: &Tombstone) -> String {
    conflict_fingerprint(&ItemConflict {
        id: String::new(),
        updated_at: tombstone.updated_at.clone(),
        updated_by: tombstone.updated_by.clone(),
        versions: tombstone.versions.clone(),
        deleted: true,
        body: tombstone.body.clone(),
    })
}

fn conflict_fingerprint(conflict: &ItemConflict) -> String {
    let value = serde_json::json!({
        "deleted": conflict.deleted,
        "updatedAt": conflict.updated_at,
        "updatedBy": conflict.updated_by,
        "versions": conflict.versions,
        "itemType": conflict.body.item_type,
        "title": conflict.body.title,
        "favorite": conflict.body.favorite,
        "createdAt": conflict.body.created_at,
        "username": conflict.body.username,
        "password": conflict.body.password,
        "url": conflict.body.url,
        "notes": conflict.body.notes,
        "cardholder": conflict.body.cardholder,
        "number": conflict.body.number,
        "expiry": conflict.body.expiry,
        "cvv": conflict.body.cvv,
        "tags": conflict.body.tags,
    });
    hex_encode(&sha256(value.to_string().as_bytes()))
}

fn remember_resolved(resolved: &mut Vec<String>, id: &str) {
    if !id.is_empty() && !resolved.iter().any(|existing| existing == id) {
        resolved.push(id.to_string());
    }
}

fn union_strings(mut left: Vec<String>, right: Vec<String>) -> Vec<String> {
    for value in right {
        remember_resolved(&mut left, &value);
    }
    left
}

fn vv_max(left: &BTreeMap<String, u64>, right: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {
    let mut merged = left.clone();
    for (key, value) in right {
        let entry = merged.entry(key.clone()).or_insert(0);
        if *value > *entry {
            *entry = *value;
        }
    }
    merged
}

fn vv_dominates(left: &BTreeMap<String, u64>, right: &BTreeMap<String, u64>) -> bool {
    if left == right {
        return false;
    }
    let mut strict = false;
    let mut keys = BTreeSet::new();
    keys.extend(left.keys().cloned());
    keys.extend(right.keys().cloned());
    for key in keys {
        let left_value = left.get(&key).copied().unwrap_or(0);
        let right_value = right.get(&key).copied().unwrap_or(0);
        if left_value < right_value {
            return false;
        }
        if left_value > right_value {
            strict = true;
        }
    }
    strict
}

fn device_or_default(device_id: &str) -> String {
    if device_id.is_empty() {
        "device".to_string()
    } else {
        device_id.to_string()
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn secret(value: &str) -> SecretString {
        SecretString::new(value.to_string())
    }

    fn versions(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(key, value)| ((*key).to_string(), *value)).collect()
    }

    fn live_item(id: &str, title: &str, updated_at: &str, device: &str, version_pairs: &[(&str, u64)]) -> VaultItem {
        let mut item = VaultItem::skeleton();
        item.id = id.to_string();
        item.item_type = "login".to_string();
        item.title = title.to_string();
        item.username = Some(format!("{title}-user"));
        item.password = Some(format!("{title}-secret"));
        item.created_at = "2026-01-01T00:00:00Z".to_string();
        item.updated_at = updated_at.to_string();
        item.updated_by = Some(device.to_string());
        item.versions = versions(version_pairs);
        item
    }

    fn unlocked_pair(dir: &Path, password: &str) -> (PathBuf, UnlockedVault, UnlockedVault) {
        let path = dir.join("vault.khv");
        let created = vault::create_vault_at(&path, &secret(password)).unwrap();
        drop(created);
        let mut first = vault::unlock_file(&path, &secret(password)).unwrap();
        first.device_id = "device-a".to_string();
        let mut second = vault::unlock_file(&path, &secret(password)).unwrap();
        second.device_id = "device-b".to_string();
        (path, first, second)
    }

    #[test]
    fn both_devices_add_then_merge() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut first, mut second) = unlocked_pair(dir.path(), "both-add");
        let item_a = live_item("item-a", "Alpha", "2026-04-01T00:00:00Z", "device-a", &[("device-a", 1)]);
        let item_b = live_item("item-b", "Beta", "2026-04-01T00:00:01Z", "device-b", &[("device-b", 1)]);
        first.data.items.push(item_a);
        second.data.items.push(item_b);
        first.dirty = true;
        second.dirty = true;
        save_vault(&path, &mut first).unwrap();
        save_vault(&path, &mut second).unwrap();
        let loaded = vault::unlock_file(&path, &secret("both-add")).unwrap();
        let titles: BTreeSet<_> = loaded.data.items.iter().map(|item| item.title.clone()).collect();
        assert_eq!(titles, BTreeSet::from(["Alpha".to_string(), "Beta".to_string()]));
    }

    #[test]
    fn concurrent_edits_keep_conflict_copy() {
        let mut base = VaultData::default();
        base.items.push(live_item(
            "same",
            "Base",
            "2026-04-01T00:00:00Z",
            "legacy",
            &[("legacy", 1)],
        ));
        let mut left = base.clone();
        let mut right = base.clone();
        left.items[0].title = "Alpha".to_string();
        left.items[0].password = Some("alpha-secret".to_string());
        left.items[0].updated_at = "2026-04-02T00:00:00Z".to_string();
        left.items[0].updated_by = Some("device-a".to_string());
        left.items[0].versions = versions(&[("legacy", 1), ("device-a", 1)]);
        right.items[0].title = "Beta".to_string();
        right.items[0].password = Some("beta-secret".to_string());
        right.items[0].updated_at = "2026-04-03T00:00:00Z".to_string();
        right.items[0].updated_by = Some("device-b".to_string());
        right.items[0].versions = versions(&[("legacy", 1), ("device-b", 1)]);
        merge_vault(&mut left, &right);
        assert_eq!(left.items.len(), 1);
        assert_eq!(left.items[0].title, "Beta");
        assert_eq!(left.items[0].password.as_deref(), Some("beta-secret"));
        assert_eq!(left.items[0].conflicts.len(), 1);
        assert_eq!(left.items[0].conflicts[0].body.title, "Alpha");
        assert_eq!(left.items[0].conflicts[0].body.password.as_deref(), Some("alpha-secret"));
        assert!(!left.items[0].conflicts[0].deleted);

        let mut tied_left = base.clone();
        let mut tied_right = base;
        let stamp = "2026-05-01T00:00:00Z";
        tied_left.items[0].title = "FromA".to_string();
        tied_left.items[0].updated_at = stamp.to_string();
        tied_left.items[0].updated_by = Some("device-a".to_string());
        tied_left.items[0].versions = versions(&[("legacy", 1), ("device-a", 1)]);
        tied_right.items[0].title = "FromB".to_string();
        tied_right.items[0].updated_at = stamp.to_string();
        tied_right.items[0].updated_by = Some("device-b".to_string());
        tied_right.items[0].versions = versions(&[("legacy", 1), ("device-b", 1)]);
        merge_vault(&mut tied_left, &tied_right);
        assert_eq!(tied_left.items[0].title, "FromB");
        assert_eq!(tied_left.items[0].conflicts[0].body.title, "FromA");
    }

    #[test]
    fn delete_versus_edit() {
        let item = live_item("same", "Original", "2026-04-01T00:00:00Z", "device-a", &[("device-a", 1)]);
        let mut deleted = VaultData::default();
        deleted.tombstones.push(Tombstone {
            id: "same".to_string(),
            updated_at: "2026-04-02T00:00:00Z".to_string(),
            updated_by: Some("device-a".to_string()),
            versions: versions(&[("device-a", 2)]),
            conflicts: Vec::new(),
            resolved_conflicts: Vec::new(),
            body: item.body(),
        });
        let mut older = VaultData::default();
        older.items.push(item.clone());
        merge_vault(&mut older, &deleted);
        assert!(older.items.is_empty(), "an older copy must not resurrect a deleted item");
        assert!(older.tombstones[0].conflicts.is_empty());

        let mut edit = VaultData::default();
        let mut edited = item.clone();
        edited.title = "Edited".to_string();
        edited.password = Some("edited-secret".to_string());
        edited.updated_at = "2026-04-02T00:00:00Z".to_string();
        edited.updated_by = Some("device-b".to_string());
        edited.versions = versions(&[("device-a", 1), ("device-b", 1)]);
        edit.items.push(edited);
        let mut deletion = VaultData::default();
        deletion.tombstones.push(Tombstone {
            id: "same".to_string(),
            updated_at: "2026-04-03T00:00:00Z".to_string(),
            updated_by: Some("device-a".to_string()),
            versions: versions(&[("device-a", 2)]),
            conflicts: Vec::new(),
            resolved_conflicts: Vec::new(),
            body: item.body(),
        });
        merge_vault(&mut edit, &deletion);
        assert!(edit.items.is_empty(), "the newer delete stays deleted");
        assert_eq!(edit.tombstones.len(), 1);
        assert_eq!(edit.tombstones[0].conflicts.len(), 1);
        assert_eq!(edit.tombstones[0].conflicts[0].body.title, "Edited");
        assert_eq!(edit.tombstones[0].conflicts[0].body.password.as_deref(), Some("edited-secret"));
        assert!(!edit.tombstones[0].conflicts[0].deleted);
    }

    #[test]
    fn concurrent_save_two_handles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        vault::create_vault_at(&path, &secret("concurrent")).unwrap();
        let mut first = vault::unlock_file(&path, &secret("concurrent")).unwrap();
        let mut second = vault::unlock_file(&path, &secret("concurrent")).unwrap();
        first.device_id = "device-a".to_string();
        second.device_id = "device-b".to_string();
        first.data.items.push(live_item(
            "from-a",
            "HandleA",
            "2026-06-01T00:00:00Z",
            "device-a",
            &[("device-a", 1)],
        ));
        second.data.items.push(live_item(
            "from-b",
            "HandleB",
            "2026-06-01T00:00:01Z",
            "device-b",
            &[("device-b", 1)],
        ));
        first.dirty = true;
        second.dirty = true;
        let path_a = path.clone();
        let path_b = path.clone();
        let left = std::thread::spawn(move || save_vault(&path_a, &mut first));
        let right = std::thread::spawn(move || save_vault(&path_b, &mut second));
        left.join().unwrap().unwrap();
        right.join().unwrap().unwrap();
        let loaded = vault::unlock_file(&path, &secret("concurrent")).unwrap();
        let titles: BTreeSet<_> = loaded.data.items.iter().map(|item| item.title.clone()).collect();
        assert_eq!(titles, BTreeSet::from(["HandleA".to_string(), "HandleB".to_string()]));
    }

    #[test]
    fn old_format_migrates_ids_timestamps_and_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("legacy-sync");
        let params = vault::default_kdf_params();
        let salt = vault::random_salt();
        let key = vault::derive_key(&password, &salt, &params).unwrap();
        let legacy = br#"{"items":[{"itemType":"note","title":"Old note","favorite":false,"notes":"kept"},{"id":"fixed-id","itemType":"login","title":"Has id","favorite":false,"createdAt":"2024-05-01T00:00:00Z","updatedAt":"2024-05-02T00:00:00Z","username":"ada"}]}"#;
        let enc = vault::encrypt_vault(legacy, &key, &params, &salt).unwrap();
        let bytes = vault::serialize_encrypted(&enc).unwrap();
        vault::atomic_write(&path, &bytes).unwrap();
        let loaded = vault::unlock_file(&path, &password).unwrap();
        assert_eq!(loaded.data.items.len(), 2);
        let old = loaded.data.items.iter().find(|item| item.title == "Old note").unwrap();
        assert!(!old.id.is_empty());
        assert_eq!(old.created_at, LEGACY_TIMESTAMP);
        assert_eq!(old.updated_at, LEGACY_TIMESTAMP);
        assert_eq!(old.versions.get(LEGACY_DEVICE), Some(&1));
        assert_eq!(old.notes.as_deref(), Some("kept"));
        let fixed = loaded.data.items.iter().find(|item| item.id == "fixed-id").unwrap();
        assert_eq!(fixed.created_at, "2024-05-01T00:00:00Z");
        assert_eq!(fixed.updated_at, "2024-05-02T00:00:00Z");
        assert_eq!(fixed.versions.get(LEGACY_DEVICE), Some(&1));
        let again = vault::unlock_file(&path, &password).unwrap();
        let again_old = again.data.items.iter().find(|item| item.title == "Old note").unwrap();
        assert_eq!(again_old.id, old.id);
    }

    #[test]
    fn different_password_is_detected_and_not_merged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let mut main = vault::create_vault_at(&path, &secret("password-a")).unwrap();
        main.device_id = "device-a".to_string();
        main.data.items.push(live_item(
            "local",
            "Local",
            "2026-07-01T00:00:00Z",
            "device-a",
            &[("device-a", 1)],
        ));
        main.dirty = true;
        save_vault(&path, &mut main).unwrap();

        let sibling = dir.path().join("vault 2.khv");
        let mut other = vault::create_vault_at(&sibling, &secret("password-b")).unwrap();
        other.device_id = "device-b".to_string();
        other.data.items.push(live_item(
            "foreign",
            "Foreign",
            "2026-07-02T00:00:00Z",
            "device-b",
            &[("device-b", 1)],
        ));
        other.dirty = true;
        save_vault(&sibling, &mut other).unwrap();

        let mut handle = vault::unlock_file(&path, &secret("password-a")).unwrap();
        handle.device_id = "device-a".to_string();
        save_vault(&path, &mut handle).unwrap();
        assert!(handle.data.items.iter().all(|item| item.id != "foreign"));
        assert!(sibling.exists(), "a different password must not be archived");
        assert!(handle.pending_password_files.iter().any(|pending| pending.contains("vault 2.khv")));
        let status = status_of(&path, "device-a", Some(&handle), 1, false);
        assert_eq!(status.state, "password_required");

        merge_with_password(&path, &sibling, &secret("password-b"), &mut handle).unwrap();
        save_vault(&path, &mut handle).unwrap();
        assert!(handle.data.items.iter().any(|item| item.title == "Foreign"));
        assert!(!sibling.exists());
        assert!(sibling.with_extension("khv.merged-bak").exists() || dir.path().read_dir().unwrap().any(|entry| {
            entry.unwrap().file_name().to_string_lossy().contains("merged-bak")
        }));

        let mut replaced = vault::unlock_file(&path, &secret("password-a")).unwrap();
        replaced.device_id = "device-a".to_string();
        let params = vault::default_kdf_params();
        let salt = vault::random_salt();
        let key = vault::derive_key(&secret("other-master"), &salt, &params).unwrap();
        let foreign = VaultData {
            items: vec![live_item(
                "other-only",
                "OtherOnly",
                "2026-08-01T00:00:00Z",
                "device-z",
                &[("device-z", 1)],
            )],
            ..VaultData::default()
        };
        let enc = vault::encrypt_data(&foreign, &key, &params, &salt).unwrap();
        let bytes = vault::serialize_encrypted(&enc).unwrap();
        vault::atomic_write(&path, &bytes).unwrap();
        replaced.data.items.push(live_item(
            "new-local",
            "NewLocal",
            "2026-08-02T00:00:00Z",
            "device-a",
            &[("device-a", 1)],
        ));
        replaced.dirty = true;
        let err = save_vault(&path, &mut replaced).unwrap_err();
        assert!(matches!(err, VaultError::SyncPasswordRequired));
        let still = vault::unlock_file(&path, &secret("other-master")).unwrap();
        assert!(still.data.items.iter().all(|item| item.title != "NewLocal"));
        assert!(still.data.items.iter().any(|item| item.title == "OtherOnly"));
    }

    #[test]
    fn conflict_names_placeholder_and_waiting_state() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.khv");
        assert!(is_conflict_sibling(&vault_path, &dir.path().join("vault 2.khv")));
        assert!(is_conflict_sibling(&vault_path, &dir.path().join("vault (conflict).khv")));
        assert!(is_conflict_sibling(&vault_path, &dir.path().join("vault (Conflicted Copy).khv")));
        assert!(!is_conflict_sibling(&vault_path, &vault_path));
        assert!(!is_conflict_sibling(&vault_path, &dir.path().join("vault 2.khv.merged-bak")));
        assert!(!is_conflict_sibling(&vault_path, &dir.path().join("notes.khv")));
        let placeholder = icloud_placeholder(&vault_path).unwrap();
        assert_eq!(placeholder.file_name().unwrap(), ".vault.khv.icloud");
        fs::write(&placeholder, b"not-downloaded").unwrap();
        let err = vault::unlock_file(&vault_path, &secret("anything")).unwrap_err();
        assert!(matches!(err, VaultError::WaitingForIcloud));
        let status = status_of(&vault_path, "device", None, 0, true);
        assert_eq!(status.state, "waiting_icloud");
    }
}
