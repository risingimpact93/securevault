//! Device sync for one encrypted vault file shared through a folder (iCloud Drive).
//!
//! Each install keeps its device id in a local config file. The vault file stores a
//! revision, the last writer, per-item version vectors, tombstones, and conflict copies.
//! A save re-reads the file and merges when the nonce, revision, or ciphertext hash changed.
//! After that save, merged conflict files move to the local `sync-backups` directory.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
pub const SYNC_BACKUP_KEEP: usize = 10;
pub const SYNC_BACKUP_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Directory depth under the scan root. `0` is the root itself.
pub const DISCOVERY_MAX_DEPTH: usize = 4;
/// Directory entries visited before a scan stops.
pub const DISCOVERY_MAX_ENTRIES: usize = 4_000;

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
    order: String,
    order_updated_at: String,
    order_updated_by: String,
    order_versions: BTreeMap<String, u64>,
}

pub fn local_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("keyhaven-config.json")
}

pub fn default_vault_file(data_dir: &Path) -> PathBuf {
    data_dir.join("vault.khv")
}

pub fn sync_backup_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("sync-backups")
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

/// Store `vault_path` without minting a new device id.
/// An empty `device_id` is filled from the config file already on disk.
pub fn save_vault_path(data_dir: &Path, device_id: &str, vault_path: &Path) -> Result<LocalConfig, VaultError> {
    require_absolute(vault_path)?;
    let device_id = if device_id.trim().is_empty() {
        load_or_create_local_config(data_dir)?.device_id
    } else {
        device_id.to_string()
    };
    let config = LocalConfig {
        device_id,
        vault_path: Some(normalize_path(vault_path)),
    };
    save_local_config(data_dir, &config)?;
    Ok(config)
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredVault {
    pub path: String,
    pub name: String,
    pub placeholder: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenVaultStatus {
    /// `ready` or `waiting_icloud`.
    pub state: String,
    pub path: String,
    pub message: String,
    pub placeholder: bool,
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

pub fn icloud_drive_dir() -> Option<PathBuf> {
    Some(
        home_dir()?
            .join("Library")
            .join("Mobile Documents")
            .join("com~apple~CloudDocs"),
    )
}

/// `.vault.khv.icloud` → `vault.khv`. Other iCloud placeholders are ignored.
pub fn vault_file_name_from_placeholder(name: &str) -> Option<&str> {
    let rest = name.strip_prefix('.')?.strip_suffix(".icloud")?;
    if rest.is_empty() || rest.contains('/') || rest.contains('\\') {
        return None;
    }
    if !is_khv_name(rest) {
        return None;
    }
    Some(rest)
}

pub fn is_icloud_placeholder_name(name: &str) -> bool {
    vault_file_name_from_placeholder(name).is_some()
}

/// Map a picked placeholder (`.name.khv.icloud`) back to the real vault path.
pub fn canonical_vault_choice(path: &Path) -> PathBuf {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.to_path_buf();
    };
    match vault_file_name_from_placeholder(name) {
        Some(real) => path.with_file_name(real),
        None => path.to_path_buf(),
    }
}

pub fn discover_icloud_vaults() -> Vec<DiscoveredVault> {
    let Some(root) = icloud_drive_dir() else {
        return Vec::new();
    };
    if !root.is_dir() {
        return Vec::new();
    }
    discover_vaults(&root, DISCOVERY_MAX_DEPTH, DISCOVERY_MAX_ENTRIES)
}

/// Vaults under `home`, including iCloud Drive.
///
/// `Library` is not walked from the home root. That tree is large, and the
/// iCloud folder under it is scanned on its own so the entry limit still
/// reaches `vault.khv`.
pub fn discover_home_vaults_at(home: &Path) -> Vec<DiscoveredVault> {
    if !home.is_dir() {
        return Vec::new();
    }
    let mut merged = BTreeMap::new();
    let icloud = home
        .join("Library")
        .join("Mobile Documents")
        .join("com~apple~CloudDocs");
    if icloud.is_dir() {
        for vault in discover_vaults(&icloud, DISCOVERY_MAX_DEPTH, DISCOVERY_MAX_ENTRIES) {
            insert_discovered(&mut merged, vault);
        }
    }
    for vault in discover_vaults_filtered(home, DISCOVERY_MAX_DEPTH, DISCOVERY_MAX_ENTRIES, skip_home_dir) {
        insert_discovered(&mut merged, vault);
    }
    merged.into_values().collect()
}

pub fn discover_home_vaults() -> Vec<DiscoveredVault> {
    home_dir()
        .map(|home| discover_home_vaults_at(&home))
        .unwrap_or_default()
}

pub fn discover_vaults(root: &Path, max_depth: usize, max_entries: usize) -> Vec<DiscoveredVault> {
    discover_vaults_filtered(root, max_depth, max_entries, |_| false)
}

fn discover_vaults_filtered(
    root: &Path,
    max_depth: usize,
    max_entries: usize,
    skip_dir: impl Fn(&str) -> bool,
) -> Vec<DiscoveredVault> {
    if max_entries == 0 || !root.is_dir() {
        return Vec::new();
    }
    let mut found = BTreeMap::new();
    let mut entries_seen = 0usize;
    let mut queue = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0usize));
    while let Some((dir, depth)) = queue.pop_front() {
        if entries_seen >= max_entries {
            break;
        }
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read {
            if entries_seen >= max_entries {
                break;
            }
            entries_seen += 1;
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if depth < max_depth {
                    if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                        if !skip_dir(name) {
                            queue.push_back((path, depth + 1));
                        }
                    }
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Some(real_name) = vault_file_name_from_placeholder(name) {
                let real = path.with_file_name(real_name);
                insert_discovered(
                    &mut found,
                    DiscoveredVault {
                        name: real_name.to_string(),
                        path: real.to_string_lossy().into_owned(),
                        placeholder: true,
                    },
                );
                continue;
            }
            if is_khv_name(name) {
                insert_discovered(
                    &mut found,
                    DiscoveredVault {
                        name: name.to_string(),
                        path: path.to_string_lossy().into_owned(),
                        placeholder: false,
                    },
                );
            }
        }
    }
    found.into_values().collect()
}

fn skip_home_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(name, "Library" | "node_modules" | "target" | "dist" | "Applications")
}

fn insert_discovered(found: &mut BTreeMap<String, DiscoveredVault>, vault: DiscoveredVault) {
    match found.get_mut(&vault.path) {
        Some(existing) => {
            if !vault.placeholder {
                existing.placeholder = false;
            }
        }
        None => {
            found.insert(vault.path.clone(), vault);
        }
    }
}

fn is_khv_name(name: &str) -> bool {
    if name.starts_with('.') || name.ends_with(".tmp") || is_merged_backup_name(name) {
        return false;
    }
    name.to_ascii_lowercase().ends_with(".khv")
}

/// Check a chosen path. A real `.khv` must have a valid header. A missing file
/// whose sibling is `.<name>.icloud` asks macOS to download and reports waiting.
pub fn classify_vault_candidate(path: &Path) -> Result<OpenVaultStatus, VaultError> {
    let real = canonical_vault_choice(path);
    require_absolute(&real)?;
    let placeholder_path = icloud_placeholder(&real);
    let placeholder_exists = placeholder_path.as_ref().is_some_and(|candidate| candidate.exists());
    let chosen_placeholder = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_icloud_placeholder_name)
        && path.exists();
    if real.is_file() {
        let bytes = fs::read(&real)?;
        match vault::validate_vault_header(&bytes) {
            Ok(_) => {
                let stored = normalize_path(&real);
                return Ok(OpenVaultStatus {
                    state: "ready".to_string(),
                    path: stored.to_string_lossy().into_owned(),
                    message: String::new(),
                    placeholder: false,
                });
            }
            // A sibling `.icloud` file means the bytes on disk are not the vault yet.
            Err(_) if placeholder_exists || chosen_placeholder => {
                return Ok(waiting_status(&real));
            }
            Err(err) => return Err(err),
        }
    }
    if real.exists() {
        return Err(VaultError::NotAVault);
    }
    if placeholder_exists || chosen_placeholder {
        return Ok(waiting_status(&real));
    }
    Err(VaultError::NotFound)
}

fn waiting_status(real: &Path) -> OpenVaultStatus {
    prompt_icloud_download(real);
    let stored = normalize_path(real);
    OpenVaultStatus {
        state: "waiting_icloud".to_string(),
        path: stored.to_string_lossy().into_owned(),
        message: VaultError::WaitingForIcloud.to_string(),
        placeholder: true,
    }
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
    if name == vault_name || name.ends_with(".tmp") || is_merged_backup_name(name) {
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
        // Archive only after the merged vault is saved. A different-password sibling
        // never reaches this branch because decrypt failed before merge_vault.
        remember_pending_archive(unlocked, foreign_path);
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
            if is_pending_archive(unlocked, &sibling) {
                continue;
            }
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
        let mut freshly = archived;
        freshly.append(&mut unlocked.pending_archive);
        if let Err(err) = finalize_merged_backups(path, &unlocked.backup_dir, &freshly) {
            unlocked.dirty = true;
            unlocked.pending_archive = freshly.into_iter().filter(|pending| pending.exists()).collect();
            return Err(err);
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

fn remember_pending_archive(unlocked: &mut UnlockedVault, path: PathBuf) {
    if !is_pending_archive(unlocked, &path) {
        unlocked.pending_archive.push(path);
    }
}

fn is_pending_archive(unlocked: &UnlockedVault, path: &Path) -> bool {
    unlocked.pending_archive.iter().any(|pending| same_path(pending, path))
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right || normalize_path(left) == normalize_path(right)
}

/// `name.merged-bak` or `name.merged-bak.<digits>` (optional extra numeric suffixes).
fn is_merged_backup_name(name: &str) -> bool {
    let Some(index) = name.rfind(".merged-bak") else {
        return false;
    };
    let rest = &name[index + ".merged-bak".len()..];
    if rest.is_empty() {
        return true;
    }
    rest.starts_with('.')
        && rest[1..]
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn archive_merged_inplace(path: &Path) -> Result<(), VaultError> {
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

/// Move merged siblings and leftover `*.merged-bak` files out of the sync folder.
/// Files that were not merged (still a conflict sibling) stay where they are.
fn finalize_merged_backups(
    vault_path: &Path,
    backup_dir: &Path,
    freshly_merged: &[PathBuf],
) -> Result<(), VaultError> {
    let freshly = dedup_paths(freshly_merged);
    if backup_dir.as_os_str().is_empty() {
        for path in &freshly {
            if path.exists() && !same_path(path, vault_path) {
                archive_merged_inplace(path)?;
            }
        }
        return Ok(());
    }
    fs::create_dir_all(backup_dir)?;
    for path in &freshly {
        if path.exists() && !same_path(path, vault_path) {
            move_into_backup(path, backup_dir, &backup_name_for(path))?;
        }
    }
    if let Some(folder) = vault_path.parent() {
        if !same_path(folder, backup_dir) {
            for path in merged_backup_files(folder) {
                if path.exists() && !same_path(&path, vault_path) {
                    move_into_backup(&path, backup_dir, &backup_name_for(&path))?;
                }
            }
        }
    }
    prune_sync_backups(backup_dir, SystemTime::now())
}

fn backup_name_for(path: &Path) -> String {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("vault.khv");
    if is_merged_backup_name(name) {
        name.to_string()
    } else {
        format!("{name}.merged-bak")
    }
}

fn merged_backup_files(folder: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_merged_backup_name(name) {
            found.push(path);
        }
    }
    found.sort();
    found
}

fn dedup_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for path in paths {
        if !out.iter().any(|existing| same_path(existing, path)) {
            out.push(path.clone());
        }
    }
    out
}

fn move_into_backup(src: &Path, backup_dir: &Path, file_name: &str) -> Result<(), VaultError> {
    let mtime = fs::metadata(src).and_then(|meta| meta.modified()).ok();
    let dest = unique_backup_path(backup_dir, file_name);
    if same_path(src, &dest) {
        return Ok(());
    }
    if fs::rename(src, &dest).is_err() {
        fs::copy(src, &dest)?;
        fs::remove_file(src)?;
    }
    if let Some(mtime) = mtime {
        if let Ok(file) = File::options().write(true).open(&dest) {
            let _ = file.set_modified(mtime);
        }
    }
    Ok(())
}

fn unique_backup_path(dir: &Path, file_name: &str) -> PathBuf {
    let direct = dir.join(file_name);
    if !direct.exists() {
        return direct;
    }
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    for extra in 0..10_000 {
        let candidate = if extra == 0 {
            dir.join(format!("{file_name}.{millis}"))
        } else {
            dir.join(format!("{file_name}.{millis}.{extra}"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{file_name}.{millis}.10001"))
}

fn prune_sync_backups(dir: &Path, now: SystemTime) -> Result<(), VaultError> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut keep = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !is_merged_backup_name(name) {
            continue;
        }
        let modified = entry.metadata().and_then(|meta| meta.modified()).unwrap_or(now);
        let old = now
            .duration_since(modified)
            .ok()
            .map(|age| age > SYNC_BACKUP_MAX_AGE)
            .unwrap_or(false);
        if old {
            fs::remove_file(&path)?;
        } else {
            keep.push((path, modified));
        }
    }
    // Newest mtime first. Equal mtimes (copied iCloud files) rank the longer
    // timestamped name ahead of the bare `name.merged-bak` prefix.
    keep.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| right.0.cmp(&left.0)));
    for (path, _) in keep.into_iter().skip(SYNC_BACKUP_KEEP) {
        fs::remove_file(path)?;
    }
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
    migrate_orders(data);
}

fn order_device(data: &VaultData) -> String {
    if data.device_id.trim().is_empty() {
        LEGACY_DEVICE.to_string()
    } else {
        data.device_id.clone()
    }
}

fn fill_order_meta(
    order_updated_at: &mut String,
    order_updated_by: &mut Option<String>,
    order_versions: &mut BTreeMap<String, u64>,
    device: &str,
) {
    if order_updated_at.is_empty() {
        *order_updated_at = LEGACY_TIMESTAMP.to_string();
    }
    if order_updated_by.as_ref().map(|value| value.is_empty()).unwrap_or(true) {
        *order_updated_by = Some(device.to_string());
    }
    if order_versions.is_empty() {
        let owner = order_updated_by.clone().unwrap_or_else(|| device.to_string());
        order_versions.insert(owner, 1);
    }
}

/// Assign missing fractional keys in the current vector order.
/// A second call does not reshuffle keys that are already set.
fn migrate_item_orders(items: &mut [VaultItem], device: &str) {
    let count = items.len();
    for index in 0..count {
        if items[index].order.is_empty() {
            let before = if index == 0 {
                None
            } else {
                let value = items[index - 1].order.clone();
                if value.is_empty() { None } else { Some(value) }
            };
            let after = items[index + 1..]
                .iter()
                .find(|item| !item.order.is_empty())
                .map(|item| item.order.clone());
            items[index].order = crate::order::key_between(before.as_deref(), after.as_deref());
        }
        fill_order_meta(
            &mut items[index].order_updated_at,
            &mut items[index].order_updated_by,
            &mut items[index].order_versions,
            device,
        );
    }
}

fn migrate_orders(data: &mut VaultData) {
    let device = order_device(data);
    migrate_item_orders(&mut data.items, &device);
    for tombstone in &mut data.tombstones {
        if tombstone.order.is_empty() {
            if let Some(item) = data.items.iter().find(|item| item.id == tombstone.id) {
                tombstone.order = item.order.clone();
                tombstone.order_updated_at = item.order_updated_at.clone();
                tombstone.order_updated_by = item.order_updated_by.clone();
                tombstone.order_versions = item.order_versions.clone();
            }
            continue;
        }
        fill_order_meta(
            &mut tombstone.order_updated_at,
            &mut tombstone.order_updated_by,
            &mut tombstone.order_versions,
            &device,
        );
    }
}

pub fn sort_items(items: &mut [VaultItem]) {
    items.sort_by(|left, right| left.order.cmp(&right.order).then_with(|| left.id.cmp(&right.id)));
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
    migrate_data(data);
    let device = device_or_default(device_id);
    if item.id.is_empty() {
        item.id = vault::new_id();
    }
    let now = now_rfc3339();
    if item.created_at.is_empty() {
        item.created_at = now.clone();
    }
    item.updated_at = now.clone();
    item.updated_by = Some(device.clone());
    item.versions.clear();
    item.versions.insert(device.clone(), 1);
    item.conflicts.clear();
    item.resolved_conflicts.clear();
    if item.order.is_empty() {
        let max_order = data
            .items
            .iter()
            .map(|existing| existing.order.as_str())
            .filter(|order| !order.is_empty())
            .max()
            .map(str::to_string);
        item.order = crate::order::key_between(max_order.as_deref(), None);
        item.order_updated_at = now;
        item.order_updated_by = Some(device.clone());
        item.order_versions.clear();
        item.order_versions.insert(device.clone(), 1);
    }
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
    migrate_data(data);
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
    updated.order = existing.order;
    updated.order_updated_at = existing.order_updated_at;
    updated.order_updated_by = existing.order_updated_by;
    updated.order_versions = existing.order_versions;
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
    migrate_data(data);
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
        order: item.order,
        order_updated_at: item.order_updated_at,
        order_updated_by: item.order_updated_by,
        order_versions: item.order_versions,
    };
    upsert_tombstone(data, tombstone);
    Ok(())
}

/// Place `id` immediately before `before_id` in the sorted list.
/// `before_id` of `None` or `""` moves the item to the end.
/// Order metadata changes; content versions and `updated_at` do not.
pub fn move_item(
    data: &mut VaultData,
    id: &str,
    before_id: Option<&str>,
    device_id: &str,
) -> Result<VaultItem, VaultError> {
    migrate_data(data);
    sort_items(&mut data.items);
    let device = device_or_default(device_id);
    let before_id = before_id.filter(|value| !value.is_empty());
    let Some(from) = data.items.iter().position(|item| item.id == id) else {
        return Err(VaultError::ItemNotFound);
    };
    if before_id == Some(id) {
        return Ok(data.items[from].clone());
    }
    if let Some(before) = before_id {
        if data.items.iter().all(|item| item.id != before) {
            return Err(VaultError::ItemNotFound);
        }
    }
    let dest = match before_id {
        Some(before) => data.items.iter().position(|item| item.id == before).unwrap(),
        None => data.items.len(),
    };
    if dest == from + 1 || (before_id.is_none() && from + 1 == data.items.len()) {
        return Ok(data.items[from].clone());
    }
    let mut item = data.items.remove(from);
    let dest = match before_id {
        Some(before) => data.items.iter().position(|entry| entry.id == before).unwrap(),
        None => data.items.len(),
    };
    let prev = if dest == 0 {
        None
    } else {
        let value = data.items[dest - 1].order.clone();
        if value.is_empty() { None } else { Some(value) }
    };
    let next = if dest >= data.items.len() {
        None
    } else {
        let value = data.items[dest].order.clone();
        if value.is_empty() { None } else { Some(value) }
    };
    item.order = crate::order::key_between(prev.as_deref(), next.as_deref());
    item.order_updated_at = now_rfc3339();
    item.order_updated_by = Some(device.clone());
    let next_version = item.order_versions.get(&device).copied().unwrap_or(0).saturating_add(1);
    item.order_versions.insert(device, next_version);
    data.items.insert(dest, item.clone());
    Ok(item)
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
    // The new counter must strictly dominate the tombstone, or the next merge deletes again.
    let versions = bump_device(&vv_max(&tombstone.versions, &conflict.versions), &device);
    debug_assert!(vv_dominates(&versions, &tombstone.versions));
    item.versions = versions;
    item.updated_at = now_rfc3339();
    item.updated_by = Some(device);
    item.order = tombstone.order.clone();
    item.order_updated_at = tombstone.order_updated_at.clone();
    item.order_updated_by = tombstone.order_updated_by.clone();
    item.order_versions = tombstone.order_versions.clone();
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
            "i\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            item.id,
            item.updated_at,
            item.title,
            item.item_type,
            item.versions.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","),
            item.order,
            item.order_updated_at,
        ));
        for conflict in &item.conflicts {
            lines.push(format!("c\t{}\t{}\t{}", item.id, conflict.id, conflict.updated_at));
        }
    }
    for tombstone in &data.tombstones {
        lines.push(format!(
            "t\t{}\t{}\t{}\t{}\t{}",
            tombstone.id, tombstone.updated_at, tombstone.body.title, tombstone.order, tombstone.order_updated_at
        ));
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
    let pick = pick_order(&left, &right);
    let mut merged = merge_content_records(left, right);
    apply_order(&mut merged, pick);
    merged
}

fn merge_content_records(left: Record, right: Record) -> Record {
    if vv_dominates(&left.versions, &right.versions) {
        return absorb(left, right);
    }
    if vv_dominates(&right.versions, &left.versions) {
        return absorb(right, left);
    }
    if left.versions == right.versions && left.deleted == right.deleted && left.content == right.content {
        return absorb(left, right);
    }
    // A delete beats a concurrent edit (the edit's vector is not causally after the delete).
    // The edit is kept as a conflict so the user can restore it.
    let (winner, loser) = if left.deleted != right.deleted {
        if left.deleted { (left, right) } else { (right, left) }
    } else if prefer_left(&left, &right) {
        (left, right)
    } else {
        (right, left)
    };
    keep_conflict(winner, loser)
}

struct OrderPick {
    order: String,
    order_updated_at: String,
    order_updated_by: String,
    order_versions: BTreeMap<String, u64>,
}

fn pick_order(left: &Record, right: &Record) -> OrderPick {
    let chosen = if order_prefers_left(left, right) { left } else { right };
    OrderPick {
        order: chosen.order.clone(),
        order_updated_at: chosen.order_updated_at.clone(),
        order_updated_by: chosen.order_updated_by.clone(),
        order_versions: vv_max(&left.order_versions, &right.order_versions),
    }
}

/// Newer order stamp wins. Ties break by device id, then item id, then order key.
/// The comparison is a total order, so `merge(A, B)` and `merge(B, A)` agree.
fn order_prefers_left(left: &Record, right: &Record) -> bool {
    match stamp_cmp(&left.order_updated_at, &right.order_updated_at) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => match left.order_updated_by.cmp(&right.order_updated_by) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => match left.id.cmp(&right.id) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => left.order >= right.order,
            },
        },
    }
}

fn apply_order(record: &mut Record, pick: OrderPick) {
    record.order = pick.order;
    record.order_updated_at = pick.order_updated_at;
    record.order_updated_by = pick.order_updated_by;
    record.order_versions = pick.order_versions;
}

fn keep_conflict(mut winner: Record, loser: Record) -> Record {
    winner.conflicts.push(record_to_conflict(&loser));
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
        order: item.order.clone(),
        order_updated_at: item.order_updated_at.clone(),
        order_updated_by: item.order_updated_by.clone().unwrap_or_default(),
        order_versions: item.order_versions.clone(),
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
        order: tombstone.order.clone(),
        order_updated_at: tombstone.order_updated_at.clone(),
        order_updated_by: tombstone.order_updated_by.clone().unwrap_or_default(),
        order_versions: tombstone.order_versions.clone(),
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
    item.order = record.order.clone();
    item.order_updated_at = record.order_updated_at.clone();
    item.order_updated_by = if record.order_updated_by.is_empty() {
        None
    } else {
        Some(record.order_updated_by.clone())
    };
    item.order_versions = record.order_versions.clone();
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
        order: record.order.clone(),
        order_updated_at: record.order_updated_at.clone(),
        order_updated_by: if record.order_updated_by.is_empty() {
            None
        } else {
            Some(record.order_updated_by.clone())
        },
        order_versions: record.order_versions.clone(),
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

fn bump_device(versions: &BTreeMap<String, u64>, device: &str) -> BTreeMap<String, u64> {
    let mut next = versions.clone();
    let value = next.get(device).copied().unwrap_or(0).saturating_add(1);
    next.insert(device.to_string(), value);
    next
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
            ..Tombstone::default()
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
        // Newer wall clock than the delete, but the vector is not causally after it.
        edited.updated_at = "2026-04-10T00:00:00Z".to_string();
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
            ..Tombstone::default()
        });
        merge_vault(&mut edit, &deletion);
        assert!(edit.items.is_empty(), "a concurrent edit must not revive a delete");
        assert_eq!(edit.tombstones.len(), 1);
        assert_eq!(edit.tombstones[0].conflicts.len(), 1);
        assert_eq!(edit.tombstones[0].conflicts[0].body.title, "Edited");
        assert_eq!(edit.tombstones[0].conflicts[0].body.password.as_deref(), Some("edited-secret"));
        assert!(!edit.tombstones[0].conflicts[0].deleted);

        let mut from_delete = deletion.clone();
        let mut live = VaultData::default();
        let mut edited_again = item.clone();
        edited_again.title = "Edited".to_string();
        edited_again.password = Some("edited-secret".to_string());
        edited_again.updated_at = "2026-04-10T00:00:00Z".to_string();
        edited_again.updated_by = Some("device-b".to_string());
        edited_again.versions = versions(&[("device-a", 1), ("device-b", 1)]);
        live.items.push(edited_again);
        merge_vault(&mut from_delete, &live);
        assert!(from_delete.items.is_empty());
        assert_eq!(from_delete.tombstones[0].conflicts.len(), 1);
        assert_eq!(from_delete.tombstones[0].conflicts[0].body.title, "Edited");

        let mut revived = VaultData::default();
        let mut after = item.clone();
        after.title = "Revived".to_string();
        after.password = Some("revived-secret".to_string());
        after.updated_at = "2026-03-01T00:00:00Z".to_string();
        after.updated_by = Some("device-b".to_string());
        after.versions = versions(&[("device-a", 2), ("device-b", 1)]);
        revived.items.push(after);
        merge_vault(&mut revived, &deletion);
        assert_eq!(revived.items.len(), 1, "an edit causally after the delete revives the item");
        assert_eq!(revived.items[0].title, "Revived");
        assert!(revived.tombstones.is_empty());
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
        assert!(!is_conflict_sibling(&vault_path, &dir.path().join("vault 2.khv.merged-bak.171000")));
        assert!(!is_conflict_sibling(&vault_path, &dir.path().join("notes.khv")));
        let placeholder = icloud_placeholder(&vault_path).unwrap();
        assert_eq!(placeholder.file_name().unwrap(), ".vault.khv.icloud");
        fs::write(&placeholder, b"not-downloaded").unwrap();
        let err = vault::unlock_file(&vault_path, &secret("anything")).unwrap_err();
        assert!(matches!(err, VaultError::WaitingForIcloud));
        let status = status_of(&vault_path, "device", None, 0, true);
        assert_eq!(status.state, "waiting_icloud");
    }

    fn tombstone_of(item: &VaultItem, updated_at: &str, device: &str, version_pairs: &[(&str, u64)]) -> Tombstone {
        Tombstone {
            id: item.id.clone(),
            updated_at: updated_at.to_string(),
            updated_by: Some(device.to_string()),
            versions: versions(version_pairs),
            conflicts: Vec::new(),
            resolved_conflicts: Vec::new(),
            body: item.body(),
            order: item.order.clone(),
            order_updated_at: item.order_updated_at.clone(),
            order_updated_by: item.order_updated_by.clone(),
            order_versions: item.order_versions.clone(),
        }
    }

    fn assert_restored_alive(data: &VaultData) {
        assert_eq!(data.items.len(), 1, "restored item must stay alive");
        assert_eq!(data.items[0].title, "Edited");
        assert_eq!(data.items[0].password.as_deref(), Some("edited-secret"));
        assert!(data.tombstones.is_empty(), "the tombstone must not win again");
    }

    #[test]
    fn restore_of_concurrent_edit_survives_later_merges() {
        let item = live_item("same", "Original", "2026-04-01T00:00:00Z", "device-a", &[("device-a", 1)]);
        let mut edited = item.clone();
        edited.title = "Edited".to_string();
        edited.password = Some("edited-secret".to_string());
        edited.updated_at = "2026-05-01T00:00:00Z".to_string();
        edited.updated_by = Some("device-b".to_string());
        edited.versions = versions(&[("device-a", 1), ("device-b", 1)]);
        let tombstone = tombstone_of(&item, "2026-04-02T00:00:00Z", "device-a", &[("device-a", 2)]);

        let mut edit = VaultData::default();
        edit.items.push(edited);
        let mut deletion = VaultData::default();
        deletion.tombstones.push(tombstone.clone());
        merge_vault(&mut edit, &deletion);
        assert!(edit.items.is_empty());
        let views = list_conflicts(&edit);
        assert_eq!(views.len(), 1);
        assert!(views[0].current_deleted);
        assert!(!views[0].conflict_deleted);
        assert_eq!(views[0].conflict_title, "Edited");
        assert_eq!(views[0].item_id, "same");

        let mut restored = edit.clone();
        resolve_conflict(&mut restored, "same", &views[0].conflict_id, "restore", "device-b").unwrap();
        assert_restored_alive(&restored);
        assert!(list_conflicts(&restored).is_empty());
        assert!(vv_dominates(&restored.items[0].versions, &edit.tombstones[0].versions));
        assert!(vv_dominates(&restored.items[0].versions, &tombstone.versions));

        let mut from_merged_tombstone = edit.clone();
        merge_vault(&mut from_merged_tombstone, &restored);
        assert_restored_alive(&from_merged_tombstone);
        let mut into_merged_tombstone = restored.clone();
        merge_vault(&mut into_merged_tombstone, &edit);
        assert_restored_alive(&into_merged_tombstone);

        let mut from_original = deletion.clone();
        merge_vault(&mut from_original, &restored);
        assert_restored_alive(&from_original);
        let mut into_original = restored.clone();
        merge_vault(&mut into_original, &deletion);
        assert_restored_alive(&into_original);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let mut saved = vault::create_vault_at(&path, &secret("restore-persists")).unwrap();
        saved.device_id = "device-b".to_string();
        saved.data.items = restored.items.clone();
        saved.data.tombstones = restored.tombstones.clone();
        saved.dirty = true;
        save_vault(&path, &mut saved).unwrap();
        let loaded = vault::unlock_file(&path, &secret("restore-persists")).unwrap();
        let mut round = loaded.data.clone();
        merge_vault(&mut round, &edit);
        assert_restored_alive(&round);
        let mut back = edit.clone();
        merge_vault(&mut back, &loaded.data);
        assert_restored_alive(&back);
    }

    fn set_mtime(path: &Path, when: SystemTime) {
        let file = File::options().write(true).open(path).unwrap();
        file.set_modified(when).unwrap();
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).unwrap().flatten() {
            if entry.path().is_file() {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        names
    }

    #[test]
    fn backup_prune_by_age_and_count() {
        let now = SystemTime::now();
        let age_dir = tempfile::tempdir().unwrap();
        let recent = age_dir.path().join("recent.khv.merged-bak");
        let week = age_dir.path().join("week.khv.merged-bak");
        let old = age_dir.path().join("old.khv.merged-bak.1000");
        fs::write(&recent, b"recent").unwrap();
        fs::write(&week, b"week").unwrap();
        fs::write(&old, b"old").unwrap();
        set_mtime(&recent, now.checked_sub(Duration::from_secs(60)).unwrap());
        set_mtime(&week, now.checked_sub(SYNC_BACKUP_MAX_AGE).unwrap());
        set_mtime(&old, now.checked_sub(SYNC_BACKUP_MAX_AGE + Duration::from_secs(60)).unwrap());
        prune_sync_backups(age_dir.path(), now).unwrap();
        let aged = file_names(age_dir.path());
        assert!(aged.iter().any(|name| name.starts_with("recent")));
        assert!(aged.iter().any(|name| name.starts_with("week")), "exactly 7 days is kept");
        assert!(aged.iter().all(|name| !name.starts_with("old")));

        let count_dir = tempfile::tempdir().unwrap();
        for index in 0..12 {
            let path = count_dir.path().join(format!("keep-{index:02}.khv.merged-bak"));
            fs::write(&path, b"bak").unwrap();
            let age = Duration::from_secs((index as u64 + 1) * 60);
            set_mtime(&path, now.checked_sub(age).unwrap());
        }
        prune_sync_backups(count_dir.path(), now).unwrap();
        let kept = file_names(count_dir.path());
        assert_eq!(kept.len(), SYNC_BACKUP_KEEP);
        assert!(kept.iter().any(|name| name.starts_with("keep-00")));
        assert!(kept.iter().any(|name| name.starts_with("keep-09")));
        assert!(kept.iter().all(|name| !name.starts_with("keep-10")));
        assert!(kept.iter().all(|name| !name.starts_with("keep-11")));
    }

    #[test]
    fn finalize_moves_merged_bak_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let sync_dir = dir.path().join("sync");
        let backup = dir.path().join("app").join("sync-backups");
        fs::create_dir_all(&sync_dir).unwrap();
        let vault = sync_dir.join("vault.khv");
        fs::write(&vault, b"vault").unwrap();
        let bak = sync_dir.join("vault 2.khv.merged-bak");
        fs::write(&bak, b"bak").unwrap();
        let stamped = sync_dir.join("vault 2.khv.merged-bak.55");
        fs::write(&stamped, b"stamped").unwrap();
        let pending = sync_dir.join("vault (conflict).khv");
        fs::write(&pending, b"pending").unwrap();
        let fresh = sync_dir.join("vault 3.khv");
        fs::write(&fresh, b"fresh").unwrap();
        fs::write(sync_dir.join("notes.txt"), b"leave-me").unwrap();
        finalize_merged_backups(&vault, &backup, &[fresh.clone()]).unwrap();
        assert!(!fresh.exists());
        assert!(!bak.exists());
        assert!(!stamped.exists());
        assert_eq!(fs::read(&pending).unwrap(), b"pending");
        assert_eq!(fs::read(sync_dir.join("notes.txt")).unwrap(), b"leave-me");
        assert_eq!(fs::read(&vault).unwrap(), b"vault");
        let names = file_names(&backup);
        assert!(names.iter().any(|name| name.starts_with("vault 3.khv.merged-bak")));
        assert!(names.iter().any(|name| name.starts_with("vault 2.khv.merged-bak") && !name.contains(".55")));
        assert!(names.iter().any(|name| name.contains("merged-bak.55")));
        assert!(names.iter().all(|name| !name.contains("conflict")));
        assert!(names.iter().all(|name| !name.contains("notes")));
        assert!(file_names(&sync_dir).iter().all(|name| !name.contains("merged-bak")));
    }

    #[test]
    fn merged_backups_move_prune_and_leave_unmerged_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let sync_dir = dir.path().join("icloud");
        fs::create_dir_all(&sync_dir).unwrap();
        let path = sync_dir.join("vault.khv");
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

        // A real iCloud sibling is a divergent copy of the same ciphertext key.
        let sibling = sync_dir.join("vault 2.khv");
        fs::copy(&path, &sibling).unwrap();
        let mut other = vault::unlock_file(&sibling, &secret("password-a")).unwrap();
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

        let pending = sync_dir.join("vault (conflict).khv");
        let mut foreign = vault::create_vault_at(&pending, &secret("password-b")).unwrap();
        foreign.device_id = "device-c".to_string();
        foreign.data.items.push(live_item(
            "secret-item",
            "Secret",
            "2026-07-03T00:00:00Z",
            "device-c",
            &[("device-c", 1)],
        ));
        foreign.dirty = true;
        save_vault(&pending, &mut foreign).unwrap();
        let pending_bytes = fs::read(&pending).unwrap();

        let now = SystemTime::now();
        for index in 1..=12 {
            let file = sync_dir.join(format!("aged-{index:02}.khv.merged-bak"));
            fs::write(&file, format!("aged-{index}")).unwrap();
            set_mtime(&file, now.checked_sub(Duration::from_secs(index * 3600)).unwrap());
        }
        let stamped = sync_dir.join("extra.khv.merged-bak.424242");
        fs::write(&stamped, b"stamped").unwrap();
        set_mtime(&stamped, now.checked_sub(Duration::from_secs(30 * 60)).unwrap());
        let old = sync_dir.join("old-8d.khv.merged-bak");
        fs::write(&old, b"old").unwrap();
        set_mtime(&old, now.checked_sub(Duration::from_secs(8 * 24 * 60 * 60)).unwrap());
        let older = sync_dir.join("old-10d.khv.merged-bak.999");
        fs::write(&older, b"older").unwrap();
        set_mtime(&older, now.checked_sub(Duration::from_secs(10 * 24 * 60 * 60)).unwrap());
        fs::write(sync_dir.join("notes.txt"), b"leave-me").unwrap();

        let mut handle = vault::unlock_file(&path, &secret("password-a")).unwrap();
        handle.device_id = "device-a".to_string();
        handle.backup_dir = dir.path().join("appdata").join("sync-backups");
        pull_vault(&path, &mut handle).unwrap();

        assert!(handle.data.items.iter().any(|item| item.title == "Foreign"));
        assert!(handle.data.items.iter().all(|item| item.title != "Secret"));
        assert!(pending.exists());
        assert_eq!(fs::read(&pending).unwrap(), pending_bytes);
        assert!(!sibling.exists());
        assert!(handle
            .pending_password_files
            .iter()
            .any(|pending_path| pending_path.contains("vault (conflict).khv")));
        assert_eq!(fs::read(sync_dir.join("notes.txt")).unwrap(), b"leave-me");
        assert!(file_names(&sync_dir).iter().all(|name| !name.contains("merged-bak")));

        let backup_names = file_names(&handle.backup_dir);
        assert_eq!(backup_names.len(), SYNC_BACKUP_KEEP);
        assert!(backup_names.iter().any(|name| name.starts_with("vault 2.khv.merged-bak")));
        assert!(backup_names.iter().any(|name| name.contains("424242")));
        assert!(backup_names.iter().any(|name| name.starts_with("aged-01")));
        assert!(backup_names.iter().any(|name| name.starts_with("aged-08")));
        assert!(backup_names.iter().all(|name| !name.starts_with("aged-09")));
        assert!(backup_names.iter().all(|name| !name.starts_with("aged-12")));
        assert!(backup_names.iter().all(|name| !name.starts_with("old-")));
        assert!(backup_names.iter().all(|name| !name.contains("conflict")));
        assert!(backup_names.iter().all(|name| name.contains("merged-bak")));
    }

    #[test]
    fn backup_prune_ranks_by_mtime_not_name() {
        let now = SystemTime::now();
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("vault 2.khv.merged-bak");
        fs::write(&bare, b"bare").unwrap();
        set_mtime(&bare, now.checked_sub(Duration::from_secs(24 * 3600)).unwrap());
        for index in 0..5 {
            let path = dir.path().join(format!("aaa-{index:02}.khv.merged-bak"));
            fs::write(&path, b"old-name").unwrap();
            set_mtime(
                &path,
                now.checked_sub(Duration::from_secs(20 * 3600 + index as u64 * 60)).unwrap(),
            );
        }
        for index in 0..10 {
            let path = dir.path().join(format!("zzz-{index:02}.khv.merged-bak.{index}"));
            fs::write(&path, b"new").unwrap();
            set_mtime(&path, now.checked_sub(Duration::from_secs(120 + index as u64 * 60)).unwrap());
        }
        prune_sync_backups(dir.path(), now).unwrap();
        let kept = file_names(dir.path());
        assert_eq!(kept.len(), SYNC_BACKUP_KEEP, "{kept:?}");
        assert!(kept.iter().all(|name| name.starts_with("zzz-")), "{kept:?}");
        assert!(kept.iter().all(|name| !name.contains("vault 2")));
        assert!(kept.iter().all(|name| !name.starts_with("aaa-")));
    }

    #[test]
    fn backup_prune_equal_mtime_drops_untimestamped_prefix() {
        let now = SystemTime::now();
        let when = now.checked_sub(Duration::from_secs(3600)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("vault 2.khv.merged-bak");
        fs::write(&bare, b"bare").unwrap();
        set_mtime(&bare, when);
        for index in 0..10 {
            let path = dir.path().join(format!("vault 2.khv.merged-bak.{index:04}"));
            fs::write(&path, b"stamped").unwrap();
            set_mtime(&path, when);
        }
        prune_sync_backups(dir.path(), now).unwrap();
        let kept = file_names(dir.path());
        assert_eq!(kept.len(), SYNC_BACKUP_KEEP, "{kept:?}");
        assert!(kept.iter().all(|name| name != "vault 2.khv.merged-bak"), "{kept:?}");
        assert!(kept.iter().all(|name| name.contains("merged-bak.")));
    }

    fn set_order(item: &mut VaultItem, order: &str, at: &str, device: &str, version: u64) {
        item.order = order.to_string();
        item.order_updated_at = at.to_string();
        item.order_updated_by = Some(device.to_string());
        item.order_versions = versions(&[(device, version)]);
    }

    fn ordered_pair() -> VaultData {
        let mut data = VaultData::default();
        data.items.push(live_item(
            "a",
            "A",
            "2026-01-01T00:00:00Z",
            "device-a",
            &[("device-a", 1)],
        ));
        data.items.push(live_item(
            "b",
            "B",
            "2026-01-01T00:00:00Z",
            "device-a",
            &[("device-a", 1)],
        ));
        set_order(&mut data.items[0], "a0", "2026-03-01T00:00:00Z", "device-a", 1);
        set_order(&mut data.items[1], "a1", "2026-03-01T00:00:00Z", "device-a", 1);
        data
    }

    #[test]
    fn order_merge_concurrent_reorders_and_content_edit() {
        let base = ordered_pair();
        let mut left = base.clone();
        let mut right = base.clone();
        set_order(&mut left.items[0], "a2", "2026-04-02T00:00:00Z", "device-a", 2);
        set_order(&mut left.items[1], "a0", "2026-04-01T00:00:00Z", "device-a", 2);
        set_order(&mut right.items[0], "a0", "2026-04-01T00:00:00Z", "device-b", 1);
        set_order(&mut right.items[1], "a3", "2026-05-01T00:00:00Z", "device-b", 3);

        let mut merged = left.clone();
        merge_vault(&mut merged, &right);
        let mut flipped = right.clone();
        merge_vault(&mut flipped, &left);
        for result in [&merged, &flipped] {
            let a = result.items.iter().find(|item| item.id == "a").unwrap();
            let b = result.items.iter().find(|item| item.id == "b").unwrap();
            assert_eq!(a.order, "a2", "newer order on a wins");
            assert_eq!(b.order, "a3", "newer order on b wins");
            assert_eq!(a.title, "A");
            assert_eq!(b.title, "B");
            assert!(a.conflicts.is_empty());
            assert_eq!(a.order_versions.get("device-a"), Some(&2));
            assert_eq!(a.order_versions.get("device-b"), Some(&1));
            assert_eq!(b.order_versions.get("device-b"), Some(&3));
            assert_eq!(a.order_updated_by.as_deref(), Some("device-a"));
            assert_eq!(b.order_updated_by.as_deref(), Some("device-b"));
        }

        let mut edited = base.clone();
        edited.items[0].title = "Edited".to_string();
        edited.items[0].password = Some("edited-secret".to_string());
        edited.items[0].updated_at = "2026-06-01T00:00:00Z".to_string();
        edited.items[0].updated_by = Some("device-a".to_string());
        edited.items[0].versions = versions(&[("device-a", 2)]);
        let mut reordered = base.clone();
        set_order(&mut reordered.items[0], "a2", "2026-07-01T00:00:00Z", "device-b", 1);
        set_order(&mut reordered.items[1], "a0", "2026-07-01T00:00:00Z", "device-b", 1);
        let mut both = edited.clone();
        merge_vault(&mut both, &reordered);
        let mut back = reordered.clone();
        merge_vault(&mut back, &edited);
        for result in [&both, &back] {
            let a = result.items.iter().find(|item| item.id == "a").unwrap();
            assert_eq!(a.title, "Edited");
            assert_eq!(a.password.as_deref(), Some("edited-secret"));
            assert_eq!(a.order, "a2");
            assert!(a.conflicts.is_empty(), "an order-only change is not a content conflict");
            assert_eq!(a.versions.get("device-a"), Some(&2));
            assert_eq!(a.order_updated_by.as_deref(), Some("device-b"));
        }
    }

    #[test]
    fn order_tie_break_is_symmetric() {
        let mut left = VaultData::default();
        left.items.push(live_item(
            "item",
            "Same",
            "2026-01-01T00:00:00Z",
            "device-a",
            &[("device-a", 1)],
        ));
        set_order(&mut left.items[0], "a0", "2026-08-01T00:00:00Z", "device-a", 1);
        let mut right = left.clone();
        right.items[0].updated_by = Some("device-b".to_string());
        right.items[0].versions = versions(&[("device-b", 1)]);
        set_order(&mut right.items[0], "a1", "2026-08-01T00:00:00Z", "device-b", 1);

        let mut forward = left.clone();
        merge_vault(&mut forward, &right);
        let mut backward = right.clone();
        merge_vault(&mut backward, &left);
        assert_eq!(forward.items[0].order, "a1");
        assert_eq!(backward.items[0].order, "a1");
        assert_eq!(forward.items[0].order_updated_by.as_deref(), Some("device-b"));
        assert_eq!(backward.items[0].order_updated_by.as_deref(), Some("device-b"));
        assert_eq!(forward.items[0].title, "Same");
        assert!(forward.items[0].conflicts.is_empty());

        let mut low = left.clone();
        set_order(&mut low.items[0], "a0", "2026-08-01T00:00:00Z", "device-a", 1);
        let mut high = left.clone();
        set_order(&mut high.items[0], "a2", "2026-08-01T00:00:00Z", "device-a", 4);
        let mut one = low.clone();
        merge_vault(&mut one, &high);
        let mut two = high.clone();
        merge_vault(&mut two, &low);
        assert_eq!(one.items[0].order, "a2");
        assert_eq!(two.items[0].order, "a2");
        assert_eq!(one.items[0].order_versions.get("device-a"), Some(&4));

        let mut first = record_from_item(&low.items[0]);
        let mut second = first.clone();
        first.id = "aaa".to_string();
        first.order = "a0".to_string();
        second.id = "zzz".to_string();
        second.order = "a9".to_string();
        let ab = merge_records(first.clone(), second.clone());
        let ba = merge_records(second, first);
        assert_eq!(ab.order, "a9");
        assert_eq!(ba.order, "a9");
    }

    #[test]
    fn order_migration_preserves_current_order() {
        let raw = r#"{"items":[{"id":"b","itemType":"note","title":"B","favorite":false},{"id":"a","itemType":"note","title":"A","favorite":false}]}"#;
        let mut data: VaultData = serde_json::from_str(raw).unwrap();
        assert!(data.items.iter().all(|item| item.order.is_empty()));
        migrate_data(&mut data);
        assert_eq!(data.items[0].id, "b");
        assert_eq!(data.items[1].id, "a");
        assert!(data.items[0].order < data.items[1].order);
        assert_eq!(data.items[0].order_updated_at, LEGACY_TIMESTAMP);
        assert_eq!(data.items[0].order_updated_by.as_deref(), Some(LEGACY_DEVICE));
        assert_eq!(data.items[0].order_versions.get(LEGACY_DEVICE), Some(&1));
        let keys: Vec<_> = data.items.iter().map(|item| item.order.clone()).collect();
        migrate_data(&mut data);
        let again: Vec<_> = data.items.iter().map(|item| item.order.clone()).collect();
        assert_eq!(keys, again);
        let mut sorted = data.items.clone();
        sort_items(&mut sorted);
        assert_eq!(sorted.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["b", "a"]);

        data.items.insert(
            1,
            live_item("m", "M", "2026-01-01T00:00:00Z", "device-a", &[("device-a", 1)]),
        );
        data.items[1].order.clear();
        data.items[1].order_updated_at.clear();
        data.items[1].order_updated_by = None;
        data.items[1].order_versions.clear();
        let low = data.items[0].order.clone();
        let high = data.items[2].order.clone();
        migrate_data(&mut data);
        assert!(data.items[1].order.as_str() > low.as_str(), "{}", data.items[1].order);
        assert!(data.items[1].order.as_str() < high.as_str(), "{}", data.items[1].order);
        let middle = data.items[1].order.clone();
        migrate_data(&mut data);
        assert_eq!(data.items[1].order, middle);
    }

    #[test]
    fn move_item_reorders_without_touching_content() {
        let mut data = VaultData::default();
        data.device_id = "device-a".to_string();
        data.items.push(live_item("a", "A", "2026-01-01T00:00:00Z", "device-a", &[("device-a", 1)]));
        data.items.push(live_item("b", "B", "2026-01-01T00:00:00Z", "device-a", &[("device-a", 1)]));
        data.items.push(live_item("c", "C", "2026-01-01T00:00:00Z", "device-a", &[("device-a", 1)]));
        migrate_data(&mut data);
        let key_a = data.items[0].order.clone();
        let versions = data.items[0].versions.clone();
        let updated_at = data.items[0].updated_at.clone();

        let stayed = move_item(&mut data, "a", Some("b"), "device-a").unwrap();
        assert_eq!(stayed.order, key_a);
        assert_eq!(stayed.versions, versions);
        assert_eq!(stayed.updated_at, updated_at);
        assert_eq!(stayed.title, "A");
        assert_eq!(move_item(&mut data, "a", Some("a"), "device-a").unwrap().order, key_a);

        let moved = move_item(&mut data, "c", Some("a"), "device-a").unwrap();
        assert!(moved.order.as_str() < key_a.as_str(), "{}", moved.order);
        assert_eq!(moved.title, "C");
        assert_eq!(moved.versions.get("device-a"), Some(&1));
        assert_eq!(moved.updated_at, "2026-01-01T00:00:00Z");
        assert!(moved.order_versions.get("device-a").copied().unwrap() >= 1);
        sort_items(&mut data.items);
        assert_eq!(data.items[0].id, "c");

        let ended = move_item(&mut data, "c", None, "device-a").unwrap();
        sort_items(&mut data.items);
        assert_eq!(data.items.last().unwrap().id, "c");
        assert!(ended.order.as_str() > data.items[data.items.len() - 2].order.as_str());
        let again = move_item(&mut data, "c", Some(""), "device-a").unwrap();
        assert_eq!(again.order, ended.order);
        assert!(matches!(
            move_item(&mut data, "missing", Some("a"), "device-a"),
            Err(VaultError::ItemNotFound)
        ));
    }

    #[test]
    fn update_existing_ignores_client_order() {
        let mut data = VaultData::default();
        data.items.push(live_item("a", "A", "2026-01-01T00:00:00Z", "device-a", &[("device-a", 1)]));
        migrate_data(&mut data);
        set_order(&mut data.items[0], "a0", "2026-02-01T00:00:00Z", "device-a", 3);
        let mut incoming = data.items[0].clone();
        incoming.title = "Changed".to_string();
        incoming.order = "zzz".to_string();
        incoming.order_updated_at = "2026-09-01T00:00:00Z".to_string();
        incoming.order_updated_by = Some("device-b".to_string());
        let updated = update_existing(&mut data, incoming, "device-b").unwrap();
        assert_eq!(updated.title, "Changed");
        assert_eq!(updated.order, "a0");
        assert_eq!(updated.order_updated_at, "2026-02-01T00:00:00Z");
        assert_eq!(updated.order_updated_by.as_deref(), Some("device-a"));
        assert_eq!(updated.order_versions.get("device-a"), Some(&3));
        assert!(updated.order_versions.get("device-b").is_none());
        assert_eq!(updated.versions.get("device-b"), Some(&1));
        assert_eq!(updated.versions.get(LEGACY_DEVICE), None);
    }

    fn sample_header() -> Vec<u8> {
        let mut bytes = vault::VAULT_MAGIC.to_vec();
        bytes.extend_from_slice(
            br#"{"version":1,"kdf":{"algorithm":"argon2id","m":32,"t":1,"p":1},"salt":"s","nonce":"n","ciphertext":"c"}"#,
        );
        bytes
    }

    #[test]
    fn placeholder_name_maps_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.khv");
        let placeholder = icloud_placeholder(&vault).unwrap();
        assert_eq!(placeholder.file_name().unwrap(), ".vault.khv.icloud");
        assert_eq!(canonical_vault_choice(&placeholder), vault);
        assert_eq!(canonical_vault_choice(&vault), vault);
        let spaced = dir.path().join("My Vault.khv");
        assert_eq!(
            icloud_placeholder(&spaced).unwrap().file_name().unwrap(),
            ".My Vault.khv.icloud"
        );
        assert_eq!(
            vault_file_name_from_placeholder(".My Vault.khv.icloud"),
            Some("My Vault.khv")
        );
        assert_eq!(vault_file_name_from_placeholder("vault.khv"), None);
        assert_eq!(vault_file_name_from_placeholder(".notes.txt.icloud"), None);
        assert!(is_icloud_placeholder_name(".vault.khv.icloud"));
        assert!(!is_icloud_placeholder_name("vault.khv"));

        fs::write(&placeholder, b"not-yet").unwrap();
        let waiting = classify_vault_candidate(&vault).unwrap();
        assert_eq!(waiting.state, "waiting_icloud");
        assert!(waiting.placeholder);
        assert!(waiting.path.ends_with("vault.khv"));
        let from_placeholder = classify_vault_candidate(&placeholder).unwrap();
        assert_eq!(from_placeholder.state, "waiting_icloud");
        assert_eq!(from_placeholder.path, waiting.path);
    }

    #[test]
    fn saving_vault_path_keeps_device_id() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir_all(&data).unwrap();
        fs::write(local_config_path(&data), br#"{"deviceId":"device-fixed"}"#).unwrap();
        let loaded = load_or_create_local_config(&data).unwrap();
        assert_eq!(loaded.device_id, "device-fixed");
        assert!(loaded.vault_path.is_none());

        let vault = dir.path().join("Cloud").join("vault.khv");
        fs::create_dir_all(vault.parent().unwrap()).unwrap();
        fs::write(&vault, sample_header()).unwrap();
        let status = classify_vault_candidate(&vault).unwrap();
        assert_eq!(status.state, "ready");
        assert!(!status.placeholder);
        let saved = save_vault_path(&data, &loaded.device_id, Path::new(&status.path)).unwrap();
        assert_eq!(saved.device_id, "device-fixed");
        let again = load_or_create_local_config(&data).unwrap();
        assert_eq!(again.device_id, "device-fixed");
        assert_eq!(again.vault_path.as_deref(), Some(Path::new(&status.path)));
        let raw = fs::read_to_string(local_config_path(&data)).unwrap();
        assert!(raw.contains("device-fixed"));
        assert!(raw.contains("vault.khv"));
    }

    #[test]
    fn discovery_respects_depth_and_entry_limit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("here.khv"), b"x").unwrap();
        let mid = root.join("a").join("b").join("c").join("d");
        fs::create_dir_all(&mid).unwrap();
        fs::write(mid.join("at-limit.khv"), b"x").unwrap();
        let deep = mid.join("e");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("too-deep.khv"), b"x").unwrap();
        fs::write(root.join("skip.txt"), b"no").unwrap();
        fs::write(root.join(".secret.khv.icloud"), b"ph").unwrap();
        fs::write(root.join("notes.khv.tmp"), b"tmp").unwrap();

        let found = discover_vaults(root, 4, 100);
        let names: BTreeSet<_> = found.iter().map(|vault| vault.name.clone()).collect();
        assert!(names.contains("here.khv"), "{names:?}");
        assert!(names.contains("at-limit.khv"), "{names:?}");
        assert!(names.contains("secret.khv"), "{names:?}");
        assert!(!names.contains("too-deep.khv"), "{names:?}");
        assert!(!names.contains("notes.khv.tmp"), "{names:?}");
        let placeholder = found.iter().find(|vault| vault.name == "secret.khv").unwrap();
        assert!(placeholder.placeholder);
        assert!(placeholder.path.ends_with("secret.khv"));

        let shallower = discover_vaults(root, 3, 100);
        assert!(shallower.iter().all(|vault| vault.name != "at-limit.khv"));
        assert!(shallower.iter().all(|vault| vault.name != "too-deep.khv"));
        assert!(shallower.iter().any(|vault| vault.name == "here.khv"));

        fs::write(root.join("secret.khv"), b"real").unwrap();
        let both = discover_vaults(root, 4, 100);
        let secret = both.iter().find(|vault| vault.name == "secret.khv").unwrap();
        assert!(!secret.placeholder);

        let many = root.join("many");
        fs::create_dir_all(&many).unwrap();
        for index in 0..10 {
            fs::write(many.join(format!("v{index}.khv")), b"x").unwrap();
        }
        let limited = discover_vaults(&many, 4, 3);
        assert_eq!(limited.len(), 3, "{limited:?}");
    }

    #[test]
    fn home_discovery_finds_icloud_and_skips_library_noise() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let icloud = home
            .join("Library")
            .join("Mobile Documents")
            .join("com~apple~CloudDocs")
            .join("SecureVault");
        fs::create_dir_all(&icloud).unwrap();
        fs::write(icloud.join("vault.khv"), b"vault").unwrap();
        fs::write(icloud.join(".other.khv.icloud"), b"ph").unwrap();
        let cache = home.join("Library").join("Caches");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("noise.khv"), b"no").unwrap();
        fs::create_dir_all(home.join("Documents")).unwrap();
        fs::write(home.join("Documents").join("mine.khv"), b"mine").unwrap();
        let modules = home.join("node_modules").join("pkg");
        fs::create_dir_all(&modules).unwrap();
        fs::write(modules.join("skip.khv"), b"skip").unwrap();

        let found = discover_home_vaults_at(home);
        let names: BTreeSet<_> = found.iter().map(|vault| vault.name.clone()).collect();
        assert!(names.contains("vault.khv"), "{names:?}");
        assert!(names.contains("other.khv"), "{names:?}");
        assert!(names.contains("mine.khv"), "{names:?}");
        assert!(!names.contains("noise.khv"), "{names:?}");
        assert!(!names.contains("skip.khv"), "{names:?}");
        assert!(found.iter().find(|vault| vault.name == "other.khv").unwrap().placeholder);
    }
}
