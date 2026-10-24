//! Pure vault crypto and item storage. Independent of Tauri.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::{Rng, RngCore, seq::SliceRandom};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VAULT_VERSION: u32 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
/// Idle choices shown in the settings menu. Stored inside the encrypted vault.
pub const AUTO_LOCK_MINUTES: [u32; 6] = [1, 2, 5, 10, 30, 60];
pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 1;
pub const DEFAULT_PASSWORD_INTERVAL_DAYS: u32 = 14;
const PRF_WRAP_AAD: &[u8] = b"keyhaven-vault-key-prf-v1";

#[cfg(not(any(test, feature = "fast-kdf")))]
const KDF_M: u32 = 65536; // 64 MiB
#[cfg(not(any(test, feature = "fast-kdf")))]
const KDF_T: u32 = 3;
#[cfg(not(any(test, feature = "fast-kdf")))]
const KDF_P: u32 = 1;

#[cfg(any(test, feature = "fast-kdf"))]
const KDF_M: u32 = 32;
#[cfg(any(test, feature = "fast-kdf"))]
const KDF_T: u32 = 1;
#[cfg(any(test, feature = "fast-kdf"))]
const KDF_P: u32 = 1;

const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("wrong password")]
    WrongPassword,
    #[error("vault is locked")]
    Locked,
    #[error("vault already exists")]
    AlreadyExists,
    #[error("vault not found")]
    NotFound,
    #[error("item not found")]
    ItemNotFound,
    #[error("ciphertext or header was tampered with")]
    Tampered,
    #[error("invalid item type")]
    InvalidItemType,
    #[error("password generator requires a length between 4 and 128")]
    GeneratorLength,
    #[error("password generator requires at least one character set")]
    GeneratorCharset,
    #[error("invalid auto-lock choice")]
    InvalidAutoLock,
    #[error("invalid password interval")]
    InvalidPasswordInterval,
    #[error("master password required")]
    MasterPasswordRequired,
    #[error("biometrics unavailable")]
    BiometricsUnavailable,
    #[error("biometrics invalidated")]
    BiometricsInvalidated,
    #[error("passkey session only")]
    PasskeySessionOnly,
    #[error("cancelled")]
    Cancelled,
    #[error("kdf error: {0}")]
    Kdf(String),
    #[error("crypto error")]
    Crypto,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Another copy of the vault could not be decrypted with the current key.
    #[error("vault file needs a different password")]
    SyncPasswordRequired,
    /// The vault file is an iCloud placeholder and the ciphertext is not local yet.
    #[error("waiting for iCloud download")]
    WaitingForIcloud,
    #[error("path must be absolute")]
    AbsolutePathRequired,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey([REDACTED])")
    }
}

impl VaultKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != KEY_LEN {
            return Err(VaultError::Crypto);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub algorithm: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub fn production() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            m: KDF_M,
            t: KDF_T,
            p: KDF_P,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedVault {
    pub version: u32,
    pub kdf: KdfParams,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Non-secret structural fields shared by conflict copies and delete snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ItemBody {
    #[serde(default)]
    pub item_type: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvv: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// A concurrent version that lost the newest-`updated_at` comparison.
/// Stored on the winning item (or its tombstone) so nothing is dropped silently.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ItemConflict {
    pub id: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub versions: BTreeMap<String, u64>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(flatten)]
    pub body: ItemBody,
}

/// A deleted item. Kept so an older copy cannot bring the item back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Tombstone {
    pub id: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub versions: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<ItemConflict>,
    /// Fingerprints of conflicts the user already resolved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_conflicts: Vec<String>,
    /// Body at delete time, so a concurrent edit does not erase it.
    #[serde(default)]
    pub body: ItemBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultItem {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub item_type: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvv: Option<String>,
    /// Free-form labels. Missing on older vault files; never a secret channel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Device id → counter. Empty on files written before sync existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub versions: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<ItemConflict>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_conflicts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

impl VaultItem {
    pub fn skeleton() -> Self {
        Self {
            id: String::new(),
            item_type: String::new(),
            title: String::new(),
            favorite: false,
            created_at: String::new(),
            updated_at: String::new(),
            username: None,
            password: None,
            url: None,
            notes: None,
            cardholder: None,
            number: None,
            expiry: None,
            cvv: None,
            tags: Vec::new(),
            versions: BTreeMap::new(),
            conflicts: Vec::new(),
            resolved_conflicts: Vec::new(),
            updated_by: None,
        }
    }

    pub fn body(&self) -> ItemBody {
        ItemBody {
            item_type: self.item_type.clone(),
            title: self.title.clone(),
            favorite: self.favorite,
            created_at: self.created_at.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            url: self.url.clone(),
            notes: self.notes.clone(),
            cardholder: self.cardholder.clone(),
            number: self.number.clone(),
            expiry: self.expiry.clone(),
            cvv: self.cvv.clone(),
            tags: self.tags.clone(),
        }
    }

    pub fn apply_body(&mut self, body: &ItemBody) {
        self.item_type = body.item_type.clone();
        self.title = body.title.clone();
        self.favorite = body.favorite;
        self.created_at = body.created_at.clone();
        self.username = body.username.clone();
        self.password = body.password.clone();
        self.url = body.url.clone();
        self.notes = body.notes.clone();
        self.cardholder = body.cardholder.clone();
        self.number = body.number.clone();
        self.expiry = body.expiry.clone();
        self.cvv = body.cvv.clone();
        self.tags = body.tags.clone();
    }
}

fn default_auto_lock_minutes() -> u32 {
    DEFAULT_AUTO_LOCK_MINUTES
}

fn default_password_interval_days() -> u32 {
    DEFAULT_PASSWORD_INTERVAL_DAYS
}

/// Preferences stored inside the encrypted payload so desktop and web share them.
/// Every field defaults, so vault files written before this struct still open.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettings {
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u32,
    #[serde(default)]
    pub lock_on_screen_lock: bool,
    #[serde(default)]
    pub biometrics_enabled: bool,
    #[serde(default = "default_password_interval_days")]
    pub password_interval_days: u32,
    /// Last successful master-password unlock. Biometric unlock does not refresh it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_password_unlock_at: Option<String>,
    /// When the preference fields above were last changed. Password-unlock stamps do not move this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings_updated_at: Option<String>,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            lock_on_screen_lock: false,
            biometrics_enabled: false,
            password_interval_days: DEFAULT_PASSWORD_INTERVAL_DAYS,
            last_password_unlock_at: None,
            settings_updated_at: None,
        }
    }
}

/// Partial update from the settings screen. Absent fields stay as they are.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPatch {
    pub auto_lock_minutes: Option<u32>,
    pub lock_on_screen_lock: Option<bool>,
    pub password_interval_days: Option<u32>,
}

impl VaultSettings {
    pub fn normalized(mut self) -> Self {
        self.auto_lock_minutes = normalize_auto_lock_minutes(self.auto_lock_minutes);
        if self.password_interval_days == 0 {
            self.password_interval_days = DEFAULT_PASSWORD_INTERVAL_DAYS;
        } else {
            self.password_interval_days = self.password_interval_days.clamp(1, 365);
        }
        self
    }

    pub fn apply_patch(&mut self, patch: &SettingsPatch) -> Result<(), VaultError> {
        if let Some(minutes) = patch.auto_lock_minutes {
            if !AUTO_LOCK_MINUTES.contains(&minutes) {
                return Err(VaultError::InvalidAutoLock);
            }
            self.auto_lock_minutes = minutes;
        }
        if let Some(flag) = patch.lock_on_screen_lock {
            self.lock_on_screen_lock = flag;
        }
        if let Some(days) = patch.password_interval_days {
            if !(1..=365).contains(&days) {
                return Err(VaultError::InvalidPasswordInterval);
            }
            self.password_interval_days = days;
        }
        if patch.auto_lock_minutes.is_some()
            || patch.lock_on_screen_lock.is_some()
            || patch.password_interval_days.is_some()
        {
            self.touch();
        }
        Ok(())
    }

    pub fn touch(&mut self) {
        self.settings_updated_at = Some(now_rfc3339());
    }
}

pub fn normalize_auto_lock_minutes(minutes: u32) -> u32 {
    if AUTO_LOCK_MINUTES.contains(&minutes) {
        return minutes;
    }
    AUTO_LOCK_MINUTES
        .into_iter()
        .min_by_key(|choice| (choice.abs_diff(minutes), *choice))
        .unwrap_or(DEFAULT_AUTO_LOCK_MINUTES)
}

pub fn mark_password_unlock(data: &mut VaultData) {
    data.settings.last_password_unlock_at = Some(now_rfc3339());
}

/// `true` when a master password is required again (missing stamp or interval elapsed).
pub fn password_unlock_expired_now(settings: &VaultSettings) -> bool {
    password_unlock_expired(settings, chrono::Utc::now())
}

pub fn backdate_password_unlock(settings: &mut VaultSettings, days: i64) {
    let then = chrono::Utc::now() - chrono::Duration::days(days);
    settings.last_password_unlock_at =
        Some(then.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
}

pub fn password_unlock_expired(settings: &VaultSettings, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Some(stamp) = settings.last_password_unlock_at.as_deref() else {
        return true;
    };
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(stamp) else {
        return true;
    };
    let then = then.with_timezone(&chrono::Utc);
    let limit = chrono::Duration::days(i64::from(settings.password_interval_days.max(1)));
    now.signed_duration_since(then) >= limit
}

/// Vault key wrapped by a WebAuthn PRF output. Stored outside the vault ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WrappedVaultKey {
    pub nonce: String,
    pub ciphertext: String,
}

pub fn wrap_vault_key(key: &VaultKey, prf_output: &[u8]) -> Result<WrappedVaultKey, VaultError> {
    let prf_key = prf_key(prf_output)?;
    let nonce = random_nonce();
    let cipher = XChaCha20Poly1305::new_from_slice(&prf_key).map_err(|_| VaultError::Crypto)?;
    let xnonce = XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            xnonce,
            Payload {
                msg: key.as_bytes(),
                aad: PRF_WRAP_AAD,
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    Ok(WrappedVaultKey {
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn unwrap_vault_key(wrapped: &WrappedVaultKey, prf_output: &[u8]) -> Result<VaultKey, VaultError> {
    let prf_key = prf_key(prf_output)?;
    let nonce = B64.decode(&wrapped.nonce)?;
    if nonce.len() != NONCE_LEN {
        return Err(VaultError::Tampered);
    }
    let ciphertext = B64.decode(&wrapped.ciphertext)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&prf_key).map_err(|_| VaultError::Crypto)?;
    let xnonce = XNonce::from_slice(&nonce);
    let plain = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: &ciphertext,
                aad: PRF_WRAP_AAD,
            },
        )
        .map_err(|_| VaultError::Tampered)?;
    VaultKey::try_from_slice(&plain)
}

fn prf_key(prf_output: &[u8]) -> Result<[u8; KEY_LEN], VaultError> {
    if prf_output.len() != KEY_LEN {
        return Err(VaultError::Crypto);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(prf_output);
    Ok(key)
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VaultData {
    pub items: Vec<VaultItem>,
    /// Missing on vaults created before settings lived in the payload.
    #[serde(default)]
    pub settings: VaultSettings,
    /// Increments on every successful save. Old files deserialize as 0.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub revision: u64,
    /// Device that last wrote this file. Each install keeps its own id in local config.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<Tombstone>,
}

impl VaultData {
    pub fn upsert(&mut self, item: VaultItem) {
        if let Some(existing) = self.items.iter_mut().find(|i| i.id == item.id) {
            *existing = item;
        } else {
            self.items.push(item);
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        crate::sync::delete_item(self, id, "legacy").is_ok()
    }

    pub fn merge(&mut self, other: VaultData) {
        crate::sync::merge_vault(self, &other);
    }
}

/// In-memory unlocked vault. Desktop (Tauri) and web persist this identically.
#[derive(Debug)]
pub struct UnlockedVault {
    pub key: VaultKey,
    pub salt: Vec<u8>,
    pub params: KdfParams,
    pub data: VaultData,
    /// Stable id for this install, from the local config file. Not written as a secret.
    pub device_id: String,
    /// Identity of the ciphertext this memory was last read from or written to.
    pub stamp: crate::sync::FileStamp,
    pub dirty: bool,
    /// Sibling or main files that need a different master password before merge.
    pub pending_password_files: Vec<String>,
    pub waiting_icloud: bool,
    pub sync_error: Option<String>,
    /// Vault path this memory belongs to. Poll skips a tick when the configured path differs,
    /// so a location switch cannot write the new vault back onto the previous file.
    pub bound_path: PathBuf,
}

fn fresh_unlocked(key: VaultKey, salt: Vec<u8>, params: KdfParams, data: VaultData) -> UnlockedVault {
    UnlockedVault {
        key,
        salt,
        params,
        data,
        device_id: String::new(),
        stamp: crate::sync::FileStamp::default(),
        dirty: false,
        pending_password_files: Vec::new(),
        waiting_icloud: false,
        sync_error: None,
        bound_path: PathBuf::new(),
    }
}

impl UnlockedVault {
    pub fn items(&self) -> Vec<VaultItem> {
        self.data.items.clone()
    }

    pub fn change_master_password(
        &mut self,
        current: &SecretString,
        new: &SecretString,
    ) -> Result<(), VaultError> {
        let check_key = derive_key(current, &self.salt, &self.params)?;
        if check_key.as_bytes() != self.key.as_bytes() {
            return Err(VaultError::WrongPassword);
        }
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(new, &salt, &params)?;
        self.key = key;
        self.salt = salt.to_vec();
        self.params = params;
        Ok(())
    }
}

/// Encrypt the in-memory vault. If the file changed since the last read, merge first.
pub fn persist_unlocked(path: &Path, unlocked: &mut UnlockedVault) -> Result<(), VaultError> {
    crate::sync::save_vault(path, unlocked)
}

/// Desktop unlock path: read the file and decrypt with the master password.
pub fn unlock_file(path: &Path, password: &SecretString) -> Result<UnlockedVault, VaultError> {
    if !path.exists() {
        if crate::sync::icloud_placeholder(path).is_some_and(|placeholder| placeholder.exists()) {
            crate::sync::prompt_icloud_download(path);
            return Err(VaultError::WaitingForIcloud);
        }
        return Err(VaultError::NotFound);
    }
    let bytes = fs::read(path)?;
    let enc: EncryptedVault = parse_encrypted(&bytes)?;
    let (key, salt, mut data) = unlock_with_password(&enc, password)?;
    crate::sync::migrate_data(&mut data);
    let mut unlocked = fresh_unlocked(key, salt, enc.kdf, data);
    unlocked.stamp = crate::sync::capture_stamp(path, unlocked.data.revision)?;
    Ok(unlocked)
}

/// Desktop create path: write a new empty vault file and return it unlocked.
pub fn create_vault_at(path: &Path, password: &SecretString) -> Result<UnlockedVault, VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if crate::sync::icloud_placeholder(path).is_some_and(|placeholder| placeholder.exists()) {
        crate::sync::prompt_icloud_download(path);
        return Err(VaultError::WaitingForIcloud);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let (key, salt, params, enc, data) = create_empty_vault(password)?;
    let bytes = serialize_encrypted(&enc)?;
    atomic_write(path, &bytes)?;
    let mut unlocked = fresh_unlocked(key, salt, params, data);
    unlocked.stamp = crate::sync::capture_stamp(path, unlocked.data.revision)?;
    Ok(unlocked)
}

pub fn default_kdf_params() -> KdfParams {
    KdfParams::production()
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn validate_item_type(item_type: &str) -> Result<(), VaultError> {
    match item_type {
        "login" | "note" | "card" => Ok(()),
        _ => Err(VaultError::InvalidItemType),
    }
}

fn aad_bytes(version: u32, kdf: &KdfParams, salt_b64: &str, nonce_b64: &str) -> Vec<u8> {
    format!(
        "v{}|alg={}|m={}|t={}|p={}|salt={}|nonce={}",
        version, kdf.algorithm, kdf.m, kdf.t, kdf.p, salt_b64, nonce_b64
    )
    .into_bytes()
}

pub fn derive_key(
    password: &SecretString,
    salt: &[u8],
    params: &KdfParams,
) -> Result<VaultKey, VaultError> {
    if params.algorithm != "argon2id" {
        return Err(VaultError::Kdf("unsupported kdf".into()));
    }
    let argon_params = Params::new(params.m, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(VaultKey(key))
}

pub fn encrypt_vault(
    plaintext: &[u8],
    key: &VaultKey,
    params: &KdfParams,
    salt: &[u8],
) -> Result<EncryptedVault, VaultError> {
    let nonce = random_nonce();
    let salt_b64 = B64.encode(salt);
    let nonce_b64 = B64.encode(nonce);
    let aad = aad_bytes(VAULT_VERSION, params, &salt_b64, &nonce_b64);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| VaultError::Crypto)?;
    let xnonce = XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    Ok(EncryptedVault {
        version: VAULT_VERSION,
        kdf: params.clone(),
        salt: salt_b64,
        nonce: nonce_b64,
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn decrypt_vault(file: &EncryptedVault, key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    let nonce = B64.decode(&file.nonce)?;
    if nonce.len() != NONCE_LEN {
        return Err(VaultError::Tampered);
    }
    let ciphertext = B64.decode(&file.ciphertext)?;
    let aad = aad_bytes(file.version, &file.kdf, &file.salt, &file.nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| VaultError::Crypto)?;
    let xnonce = XNonce::from_slice(&nonce);
    cipher
        .decrypt(
            xnonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Tampered)
}

pub fn encrypt_data(
    data: &VaultData,
    key: &VaultKey,
    params: &KdfParams,
    salt: &[u8],
) -> Result<EncryptedVault, VaultError> {
    let plaintext = serde_json::to_vec(data)?;
    encrypt_vault(&plaintext, key, params, salt)
}

pub fn decrypt_data(file: &EncryptedVault, key: &VaultKey) -> Result<VaultData, VaultError> {
    let plain = decrypt_vault(file, key)?;
    let mut data: VaultData = serde_json::from_slice(&plain)?;
    data.settings = data.settings.normalized();
    Ok(data)
}

/// Decrypt a vault file with a key already recovered from the keychain or a PRF wrap.
pub fn unlock_file_with_key(path: &Path, key: &VaultKey) -> Result<UnlockedVault, VaultError> {
    if !path.exists() {
        return Err(VaultError::NotFound);
    }
    let bytes = fs::read(path)?;
    let enc: EncryptedVault = parse_encrypted(&bytes)?;
    let mut data = decrypt_data(&enc, key)?;
    crate::sync::migrate_data(&mut data);
    let salt = B64.decode(&enc.salt)?;
    if salt.len() != SALT_LEN {
        return Err(VaultError::Tampered);
    }
    let mut unlocked = fresh_unlocked(key.clone(), salt, enc.kdf, data);
    unlocked.stamp = crate::sync::capture_stamp(path, unlocked.data.revision)?;
    Ok(unlocked)
}

pub fn unlock_with_password(
    file: &EncryptedVault,
    password: &SecretString,
) -> Result<(VaultKey, Vec<u8>, VaultData), VaultError> {
    let salt = B64.decode(&file.salt)?;
    if salt.len() != SALT_LEN {
        return Err(VaultError::Tampered);
    }
    let key = derive_key(password, &salt, &file.kdf)?;
    match decrypt_data(file, &key) {
        Ok(data) => Ok((key, salt, data)),
        Err(VaultError::Tampered) => Err(VaultError::WrongPassword),
        Err(e) => Err(e),
    }
}

/// Unlock that distinguishes a wrong password from a tampered file when the
/// password is known to be correct (used by tests). Decrypt errors stay Tampered.
pub fn decrypt_with_password(
    file: &EncryptedVault,
    password: &SecretString,
) -> Result<VaultData, VaultError> {
    let salt = B64.decode(&file.salt)?;
    let key = derive_key(password, &salt, &file.kdf)?;
    decrypt_data(file, &key)
}

pub fn create_empty_vault(
    password: &SecretString,
) -> Result<(VaultKey, Vec<u8>, KdfParams, EncryptedVault, VaultData), VaultError> {
    let params = default_kdf_params();
    let salt = random_salt();
    let key = derive_key(password, &salt, &params)?;
    let data = VaultData::default();
    let enc = encrypt_data(&data, &key, &params, &salt)?;
    Ok((key, salt.to_vec(), params, enc, data))
}

pub fn serialize_encrypted(file: &EncryptedVault) -> Result<Vec<u8>, VaultError> {
    Ok(serde_json::to_vec(file)?)
}

pub fn parse_encrypted(bytes: &[u8]) -> Result<EncryptedVault, VaultError> {
    Ok(serde_json::from_slice(bytes)?)
}

pub fn export_bytes(data: &VaultData, export_password: &SecretString) -> Result<Vec<u8>, VaultError> {
    let params = default_kdf_params();
    let salt = random_salt();
    let key = derive_key(export_password, &salt, &params)?;
    let enc = encrypt_data(data, &key, &params, &salt)?;
    serialize_encrypted(&enc)
}

pub fn import_bytes(bytes: &[u8], export_password: &SecretString) -> Result<VaultData, VaultError> {
    let enc = parse_encrypted(bytes)?;
    match decrypt_with_password(&enc, export_password) {
        Ok(data) => Ok(data),
        Err(VaultError::Tampered) => Err(VaultError::WrongPassword),
        Err(e) => Err(e),
    }
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.khv");
    let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if path.exists() {
        #[cfg(windows)]
        fs::remove_file(path)?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

pub fn generate_password(
    length: usize,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, VaultError> {
    if !(4..=128).contains(&length) {
        return Err(VaultError::GeneratorLength);
    }
    let mut pools: Vec<&str> = Vec::new();
    if upper {
        pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if lower {
        pools.push("abcdefghijklmnopqrstuvwxyz");
    }
    if digits {
        pools.push("0123456789");
    }
    if symbols {
        pools.push(SYMBOLS);
    }
    if pools.is_empty() {
        return Err(VaultError::GeneratorCharset);
    }

    let mut charset = String::new();
    for p in &pools {
        charset.push_str(p);
    }
    let charset_chars: Vec<char> = charset.chars().collect();
    let mut rng = OsRng;
    let mut chars: Vec<char> = Vec::with_capacity(length);

    // Guarantee at least one character from each selected set.
    for pool in &pools {
        let pool_chars: Vec<char> = pool.chars().collect();
        chars.push(pool_chars[rng.gen_range(0..pool_chars.len())]);
    }
    while chars.len() < length {
        chars.push(charset_chars[rng.gen_range(0..charset_chars.len())]);
    }
    chars.shuffle(&mut rng);
    Ok(chars.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_string())
    }

    fn sample_item() -> VaultItem {
        VaultItem {
            id: "11111111-1111-1111-1111-111111111111".into(),
            item_type: "login".into(),
            title: "Example".into(),
            favorite: true,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-02T00:00:00Z".into(),
            username: Some("user".into()),
            password: Some("secret-pass".into()),
            url: Some("https://example.com".into()),
            notes: Some("note".into()),
            cardholder: None,
            number: None,
            expiry: None,
            cvv: None,
            tags: vec!["example".into()],
            ..VaultItem::skeleton()
        }
    }

    #[test]
    fn item_without_tags_deserializes() {
        let json = r#"{"id":"1","itemType":"login","title":"t","favorite":false,"createdAt":"c","updatedAt":"u","password":"p"}"#;
        let item: VaultItem = serde_json::from_str(json).unwrap();
        assert!(item.tags.is_empty());
        assert_eq!(item.password.as_deref(), Some("p"));
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let password = secret("correct horse battery staple");
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&password, &salt, &params).unwrap();
        let data = VaultData {
            items: vec![sample_item()],
            ..VaultData::default()
        };
        let enc = encrypt_data(&data, &key, &params, &salt).unwrap();
        let out = decrypt_data(&enc, &key).unwrap();
        assert_eq!(data, out);
    }

    #[test]
    fn wrong_password_fails() {
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&secret("right-password"), &salt, &params).unwrap();
        let data = VaultData {
            items: vec![sample_item()],
            ..VaultData::default()
        };
        let enc = encrypt_data(&data, &key, &params, &salt).unwrap();
        let err = decrypt_with_password(&enc, &secret("wrong-password")).unwrap_err();
        assert!(matches!(err, VaultError::Tampered | VaultError::WrongPassword));
        let err = unlock_with_password(&enc, &secret("wrong-password")).unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let password = secret("pw-tamper-ct");
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&password, &salt, &params).unwrap();
        let data = VaultData {
            items: vec![sample_item()],
            ..VaultData::default()
        };
        let mut enc = encrypt_data(&data, &key, &params, &salt).unwrap();
        let mut ct = B64.decode(&enc.ciphertext).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        enc.ciphertext = B64.encode(ct);
        let err = decrypt_data(&enc, &key).unwrap_err();
        assert!(matches!(err, VaultError::Tampered));
    }

    #[test]
    fn tampered_header_fails() {
        let password = secret("pw-tamper-hdr");
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&password, &salt, &params).unwrap();
        let data = VaultData {
            items: vec![sample_item()],
            ..VaultData::default()
        };
        let mut enc = encrypt_data(&data, &key, &params, &salt).unwrap();
        // Flip a byte of the stored salt (AAD + key derivation input).
        let mut salt_bytes = B64.decode(&enc.salt).unwrap();
        salt_bytes[0] ^= 0x5a;
        enc.salt = B64.encode(salt_bytes);
        let err = decrypt_data(&enc, &key).unwrap_err();
        assert!(matches!(err, VaultError::Tampered));

        let mut enc2 = encrypt_data(&data, &key, &params, &salt).unwrap();
        enc2.kdf.t = enc2.kdf.t.saturating_add(1);
        let err = decrypt_data(&enc2, &key).unwrap_err();
        assert!(matches!(err, VaultError::Tampered));

        let mut enc3 = encrypt_data(&data, &key, &params, &salt).unwrap();
        enc3.version = 99;
        let err = decrypt_data(&enc3, &key).unwrap_err();
        assert!(matches!(err, VaultError::Tampered));
    }

    #[test]
    fn export_import_roundtrip() {
        let data = VaultData {
            items: vec![sample_item()],
            ..VaultData::default()
        };
        let export_pw = secret("export-pass-123");
        let bytes = export_bytes(&data, &export_pw).unwrap();
        let imported = import_bytes(&bytes, &export_pw).unwrap();
        assert_eq!(data, imported);
        let err = import_bytes(&bytes, &secret("nope")).unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword | VaultError::Tampered));
    }

    #[test]
    fn password_generator_respects_length_and_charsets() {
        let pw = generate_password(24, true, true, true, false).unwrap();
        assert_eq!(pw.chars().count(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

        let only_lower = generate_password(12, false, true, false, false).unwrap();
        assert_eq!(only_lower.chars().count(), 12);
        assert!(only_lower.chars().all(|c| c.is_ascii_lowercase()));

        let only_digits = generate_password(8, false, false, true, false).unwrap();
        assert!(only_digits.chars().all(|c| c.is_ascii_digit()));

        let with_symbols = generate_password(16, false, false, false, true).unwrap();
        assert!(with_symbols.chars().all(|c| SYMBOLS.contains(c)));

        assert!(generate_password(3, true, true, true, true).is_err());
        assert!(generate_password(16, false, false, false, false).is_err());
    }

    #[test]
    fn atomic_write_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        atomic_write(&path, b"one").unwrap();
        atomic_write(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert!(!path.with_extension("khv.tmp").exists());
    }

    #[test]
    fn create_persist_unlock_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("desktop-path-master");
        let mut unlocked = create_vault_at(&path, &password).unwrap();
        unlocked.data.items.push(sample_item());
        persist_unlocked(&path, &mut unlocked).unwrap();
        let loaded = unlock_file(&path, &password).unwrap();
        assert_eq!(loaded.data.items, unlocked.data.items);
        let err = unlock_file(&path, &secret("nope")).unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
    }

    #[test]
    fn legacy_vault_without_settings_defaults() {
        let json = r#"{"items":[]}"#;
        let parsed: VaultData = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.settings, VaultSettings::default());
        assert_eq!(parsed.settings.auto_lock_minutes, 1);
        assert!(!parsed.settings.lock_on_screen_lock);
        assert!(!parsed.settings.biometrics_enabled);
        assert_eq!(parsed.settings.password_interval_days, 14);
        assert!(parsed.settings.last_password_unlock_at.is_none());

        let partial = r#"{"items":[],"settings":{"lockOnScreenLock":true}}"#;
        let partial: VaultData = serde_json::from_str(partial).unwrap();
        assert!(partial.settings.lock_on_screen_lock);
        assert_eq!(partial.settings.auto_lock_minutes, DEFAULT_AUTO_LOCK_MINUTES);
        assert_eq!(
            partial.settings.password_interval_days,
            DEFAULT_PASSWORD_INTERVAL_DAYS
        );

        let password = secret("legacy-vault");
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&password, &salt, &params).unwrap();
        let legacy = br#"{"items":[],"settings":{"autoLockMinutes":7,"passwordIntervalDays":0}}"#;
        let enc = encrypt_vault(legacy, &key, &params, &salt).unwrap();
        let out = decrypt_data(&enc, &key).unwrap();
        assert_eq!(out.settings.auto_lock_minutes, 5);
        assert_eq!(out.settings.password_interval_days, DEFAULT_PASSWORD_INTERVAL_DAYS);
        assert!(out.items.is_empty());

        let loaded = unlock_with_password(&enc, &password).unwrap();
        assert_eq!(loaded.2.settings.auto_lock_minutes, 5);
    }

    #[test]
    fn settings_patch_and_password_interval() {
        let mut settings = VaultSettings::default();
        settings
            .apply_patch(&SettingsPatch {
                auto_lock_minutes: Some(60),
                lock_on_screen_lock: Some(true),
                password_interval_days: Some(14),
            })
            .unwrap();
        assert_eq!(settings.auto_lock_minutes, 60);
        assert!(settings.lock_on_screen_lock);
        assert!(settings
            .apply_patch(&SettingsPatch {
                auto_lock_minutes: Some(3),
                ..SettingsPatch::default()
            })
            .is_err());
        assert!(settings
            .apply_patch(&SettingsPatch {
                password_interval_days: Some(0),
                ..SettingsPatch::default()
            })
            .is_err());

        let now = chrono::Utc::now();
        assert!(password_unlock_expired(&settings, now));
        let mut data = VaultData::default();
        data.settings = settings;
        mark_password_unlock(&mut data);
        assert!(!password_unlock_expired(&data.settings, now));
        data.settings.last_password_unlock_at = Some(
            (now - chrono::Duration::days(15))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        assert!(password_unlock_expired(&data.settings, chrono::Utc::now()));
    }

    #[test]
    fn prf_wrap_roundtrip_and_rejects_wrong_output() {
        let password = secret("wrap-me");
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&password, &salt, &params).unwrap();
        let prf = [7u8; KEY_LEN];
        let wrapped = wrap_vault_key(&key, &prf).unwrap();
        let opened = unwrap_vault_key(&wrapped, &prf).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
        let mut wrong = prf;
        wrong[0] ^= 0xff;
        assert!(matches!(
            unwrap_vault_key(&wrapped, &wrong).unwrap_err(),
            VaultError::Tampered
        ));
        assert!(wrap_vault_key(&key, &[1, 2, 3]).is_err());
    }
}
