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

/// On-disk format for vaults without a Secret Key. 0.2.x files use this.
pub const VAULT_VERSION: u32 = 1;
/// On-disk format for Secret Key (2SKD) vaults. Non-SK vaults keep writing [`VAULT_VERSION`].
pub const VAULT_VERSION_SK: u32 = 2;
/// Accepted when reading a file that starts with this prefix.
/// New files do not write it. They are the historical JSON envelope, which
/// SecureVault 0.2.0 can open.
pub const VAULT_MAGIC: &[u8] = b"KHV1";
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
/// Idle choices shown in the settings menu. Stored inside the encrypted vault.
pub const AUTO_LOCK_MINUTES: [u32; 6] = [1, 2, 5, 10, 30, 60];
pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 1;
pub const DEFAULT_PASSWORD_INTERVAL_DAYS: u32 = 14;
/// AAD for PRF-wrapped vault keys. This bytestring is part of the on-disk wrap
/// and stays `keyhaven-vault-key-prf-v1` so existing wraps still open.
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
    /// The bytes are not a SecureVault file (wrong magic, or not a vault header).
    #[error("not a vault")]
    NotAVault,
    /// The magic or header started, but the file is too short or incomplete.
    #[error("corrupt")]
    Corrupt,
    /// Magic matched, but the header version or KDF is not one this build can open.
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("secret key required")]
    SecretKeyRequired,
    #[error("Secret Key가 이 금고와 맞지 않습니다")]
    SecretKeyMismatch,
    #[error("Secret Key 형식이 올바르지 않습니다")]
    InvalidSecretKey,
    #[error("Secret Key 접두사가 올바르지 않습니다")]
    InvalidSecretKeyPrefix,
    #[error("Secret Key 체크섬이 올바르지 않습니다")]
    InvalidSecretKeyChecksum,
    #[error("secret key store unavailable")]
    SecretKeyStoreUnavailable,
    /// This device is not the Secret Key manager. The string is the manager's display name.
    #[error("관리 기기({0})에서만 변경할 수 있어요")]
    NotSecretKeyManager(String),
    #[error("관리 기기가 없습니다")]
    NoSecretKeyManager,
    #[error("등록되지 않은 기기입니다")]
    UnknownDevice,
    #[error("기기 ID가 없습니다")]
    DeviceIdRequired,
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

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedVault {
    pub version: u32,
    pub kdf: KdfParams,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    /// Set only on SK-enabled (v2) vaults. Omitted from 0.2.x / non-SK files.
    #[serde(default, skip_serializing_if = "is_false", rename = "skEnabled")]
    pub sk_enabled: bool,
    /// First 8 bytes of SHA-256(domain || SK), standard Base64. Public.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "skFingerprint")]
    pub sk_fingerprint: Option<String>,
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
    /// Fields this build does not know. Kept so a newer payload can be re-saved.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// A version that lost the merge.
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

/// A deleted item. An older copy cannot bring it back. A concurrent edit is kept in `conflicts`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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
    /// Fractional index. Merged separately from the item body.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub order: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub order_updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub order_versions: BTreeMap<String, u64>,
    /// Fields this build does not know. Kept so a newer tombstone can be re-saved.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
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
    /// Fractional index. Empty on vaults saved before reordering existed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub order: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub order_updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub order_versions: BTreeMap<String, u64>,
    /// Fields this build does not know. Kept so a newer item can be re-saved.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
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
            order: String::new(),
            order_updated_at: String::new(),
            order_updated_by: None,
            order_versions: BTreeMap::new(),
            extra: BTreeMap::new(),
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
            extra: BTreeMap::new(),
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
    /// Fields this build does not know. Kept so a newer settings object can be re-saved.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
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
            extra: BTreeMap::new(),
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

/// One install that has opened this vault. Synced inside the encrypted payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_seen: String,
}

/// What the settings screen shows about this install and the Secret Key manager.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceManagerStatus {
    pub device_id: String,
    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_device_name: Option<String>,
    /// False only when a manager is set and it is a different device.
    pub can_change_secret_key: bool,
    /// No `managerDeviceId` in the payload. Older apps, and 0.3.1 re-saves, look like this.
    pub manager_missing: bool,
    pub is_manager: bool,
    /// Set when this device must not enable, rotate, or disable the Secret Key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
    pub devices: Vec<DeviceRecord>,
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
    /// Device allowed to enable, rotate, or disable the Secret Key.
    /// Empty means no manager: any device may change it (0.2.x / 0.3.0 / 0.3.1 vaults).
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "managerDeviceId")]
    pub manager_device_id: String,
    /// When `manager_device_id` was last assigned. Merge is last-writer-wins on this stamp.
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "managerUpdatedAt")]
    pub manager_updated_at: String,
    /// Devices that have unlocked this vault. Merged per id by `lastSeen`.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "deviceRegistry")]
    pub device_registry: Vec<DeviceRecord>,
    /// Fields this build does not know. Kept so a newer payload can be re-saved.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl VaultData {
    pub fn manager_id(&self) -> Option<&str> {
        let id = self.manager_device_id.trim();
        if id.is_empty() {
            None
        } else {
            Some(id)
        }
    }

    pub fn device_record(&self, id: &str) -> Option<&DeviceRecord> {
        self.device_registry.iter().find(|device| device.id == id)
    }

    pub fn device_display_name(&self, id: &str) -> String {
        self.device_record(id)
            .map(|device| device.name.trim())
            .filter(|name| !name.is_empty())
            .unwrap_or(id)
            .to_string()
    }

    /// Absent manager keeps the pre-0.3.2 rule: every device may change the Secret Key.
    pub fn allows_secret_key_change(&self, device_id: &str) -> bool {
        match self.manager_id() {
            None => true,
            Some(manager) => {
                let device_id = device_id.trim();
                !device_id.is_empty() && manager == device_id
            }
        }
    }
}

/// Keep keys only the loser has. Conflicting keys stay with `winner`.
pub fn merge_unknown_fields(
    winner: &mut BTreeMap<String, serde_json::Value>,
    loser: &BTreeMap<String, serde_json::Value>,
) {
    for (key, value) in loser {
        winner.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

/// macOS ComputerName, then `hostname`. Empty results are skipped.
pub fn local_device_name() -> String {
    if let Some(name) = command_stdout("scutil", &["--get", "ComputerName"]) {
        return name;
    }
    if let Some(name) = command_stdout("hostname", &[]) {
        return name;
    }
    "이 기기".to_string()
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8(output.stdout).ok()?;
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Insert or refresh this install in the synced registry.
pub fn register_device(data: &mut VaultData, device_id: &str, name: &str) {
    let device_id = device_id.trim();
    if device_id.is_empty() {
        return;
    }
    let name = {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            device_id.to_string()
        } else {
            trimmed.to_string()
        }
    };
    let now = now_rfc3339();
    if let Some(existing) = data.device_registry.iter_mut().find(|device| device.id == device_id) {
        existing.name = name;
        existing.last_seen = now;
    } else {
        data.device_registry.push(DeviceRecord {
            id: device_id.to_string(),
            name,
            last_seen: now,
        });
    }
    data.device_registry.sort_by(|left, right| left.id.cmp(&right.id));
}

pub fn note_local_device(unlocked: &mut UnlockedVault) {
    register_device(&mut unlocked.data, &unlocked.device_id, &local_device_name());
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
    /// Local `sync-backups` directory. Empty leaves a `.merged-bak` beside the vault.
    pub backup_dir: PathBuf,
    /// Conflict siblings already merged in memory. Moved only after a successful save.
    pub pending_archive: Vec<PathBuf>,
    /// Secret Key bytes when this process has them. Never serialized into the vault file.
    pub secret_key: Option<crate::secret_key::SecretKey>,
    /// Public SK fingerprint copied from the header so v2 files stay v2 after Touch ID unlock.
    pub sk_fingerprint: Option<[u8; crate::secret_key::SECRET_KEY_FINGERPRINT_LEN]>,
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
        backup_dir: PathBuf::new(),
        pending_archive: Vec::new(),
        secret_key: None,
        sk_fingerprint: None,
    }
}

impl UnlockedVault {
    pub fn items(&self) -> Vec<VaultItem> {
        self.data.items.clone()
    }

    pub fn sk_enabled(&self) -> bool {
        self.secret_key.is_some() || self.sk_fingerprint.is_some()
    }

    pub fn fingerprint_b64(&self) -> Option<String> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        if let Some(sk) = &self.secret_key {
            return Some(sk.fingerprint_b64());
        }
        self.sk_fingerprint.map(|fp| B64.encode(fp))
    }

    pub fn verify_master_password(&self, password: &SecretString) -> Result<(), VaultError> {
        let argon = derive_key(password, &self.salt, &self.params)?;
        let expected = match &self.secret_key {
            Some(sk) => crate::secret_key::apply_2skd(&argon, sk)?,
            None if self.sk_fingerprint.is_some() => return Err(VaultError::SecretKeyRequired),
            None => argon,
        };
        if expected.as_bytes() != self.key.as_bytes() {
            return Err(VaultError::WrongPassword);
        }
        Ok(())
    }

    pub fn device_manager_status(&self) -> DeviceManagerStatus {
        let device_id = self.device_id.trim().to_string();
        let registered = self.data.device_display_name(&device_id);
        let device_name = if device_id.is_empty() {
            local_device_name()
        } else if registered == device_id {
            local_device_name()
        } else {
            registered
        };
        let manager_device_id = self.data.manager_id().map(str::to_string);
        let manager_device_name = manager_device_id
            .as_deref()
            .map(|id| self.data.device_display_name(id));
        let manager_missing = manager_device_id.is_none();
        let is_manager = manager_device_id.as_deref() == Some(device_id.as_str()) && !device_id.is_empty();
        let can_change_secret_key = self.data.allows_secret_key_change(&device_id);
        let notice = if can_change_secret_key {
            None
        } else {
            manager_device_name
                .clone()
                .map(|name| format!("관리 기기({name})에서만 변경할 수 있어요"))
        };
        DeviceManagerStatus {
            device_id,
            device_name,
            manager_device_id,
            manager_device_name,
            can_change_secret_key,
            manager_missing,
            is_manager,
            notice,
            devices: self.data.device_registry.clone(),
        }
    }

    pub fn ensure_secret_key_change(&self) -> Result<(), VaultError> {
        if self.data.allows_secret_key_change(&self.device_id) {
            return Ok(());
        }
        let manager = self.data.manager_id().unwrap_or("");
        let name = self.data.device_display_name(manager);
        Err(VaultError::NotSecretKeyManager(name))
    }

    fn assign_manager(&mut self, device_id: &str) {
        self.data.manager_device_id = device_id.to_string();
        self.data.manager_updated_at = now_rfc3339();
    }

    fn ensure_known_device(&self) -> Result<String, VaultError> {
        let device_id = self.device_id.trim();
        if device_id.is_empty() {
            Err(VaultError::DeviceIdRequired)
        } else {
            Ok(device_id.to_string())
        }
    }

    fn verify_password_and_secret_key(
        &self,
        password: &SecretString,
        secret_key: &crate::secret_key::SecretKey,
    ) -> Result<(), VaultError> {
        if !self.sk_enabled() {
            return Err(VaultError::SecretKeyRequired);
        }
        if let Some(fp) = self.sk_fingerprint {
            if secret_key.fingerprint() != fp {
                return Err(VaultError::SecretKeyMismatch);
            }
        } else if let Some(current) = &self.secret_key {
            if secret_key.fingerprint() != current.fingerprint() {
                return Err(VaultError::SecretKeyMismatch);
            }
        }
        let argon = derive_key(password, &self.salt, &self.params)?;
        let derived = crate::secret_key::apply_2skd(&argon, secret_key)?;
        if derived.as_bytes() != self.key.as_bytes() {
            return Err(VaultError::WrongPassword);
        }
        Ok(())
    }

    pub fn enable_secret_key(
        &mut self,
        password: &SecretString,
    ) -> Result<crate::secret_key::SecretKey, VaultError> {
        self.ensure_secret_key_change()?;
        if self.sk_enabled() {
            return Err(VaultError::AlreadyExists);
        }
        self.verify_master_password(password)?;
        let argon = derive_key(password, &self.salt, &self.params)?;
        let sk = crate::secret_key::SecretKey::generate();
        self.key = crate::secret_key::apply_2skd(&argon, &sk)?;
        self.sk_fingerprint = Some(sk.fingerprint());
        self.secret_key = Some(sk.clone());
        if let Ok(device_id) = self.ensure_known_device() {
            if self.data.device_record(&device_id).is_none() {
                register_device(&mut self.data, &device_id, &local_device_name());
            }
            self.assign_manager(&device_id);
        }
        Ok(sk)
    }

    pub fn disable_secret_key(
        &mut self,
        password: &SecretString,
        secret_key: &crate::secret_key::SecretKey,
    ) -> Result<(), VaultError> {
        self.ensure_secret_key_change()?;
        if !self.sk_enabled() {
            return Ok(());
        }
        self.verify_password_and_secret_key(password, secret_key)?;
        let argon = derive_key(password, &self.salt, &self.params)?;
        self.key = argon;
        self.secret_key = None;
        self.sk_fingerprint = None;
        Ok(())
    }

    /// Claim the manager role when the vault has a Secret Key and no manager yet.
    pub fn designate_manager(
        &mut self,
        password: &SecretString,
        secret_key: &crate::secret_key::SecretKey,
    ) -> Result<(), VaultError> {
        if self.data.manager_id().is_some() {
            return self.ensure_secret_key_change().and_then(|_| {
                if self.data.allows_secret_key_change(&self.device_id) {
                    Ok(())
                } else {
                    Err(VaultError::NoSecretKeyManager)
                }
            });
        }
        let device_id = self.ensure_known_device()?;
        self.verify_password_and_secret_key(password, secret_key)?;
        if self.data.device_record(&device_id).is_none() {
            register_device(&mut self.data, &device_id, &local_device_name());
        }
        self.assign_manager(&device_id);
        Ok(())
    }

    /// Become the manager from another device by proving the master password and current Secret Key.
    pub fn takeover_manager(
        &mut self,
        password: &SecretString,
        secret_key: &crate::secret_key::SecretKey,
    ) -> Result<(), VaultError> {
        let device_id = self.ensure_known_device()?;
        self.verify_password_and_secret_key(password, secret_key)?;
        if self.data.device_record(&device_id).is_none() {
            register_device(&mut self.data, &device_id, &local_device_name());
        }
        self.assign_manager(&device_id);
        Ok(())
    }

    /// The current manager assigns the role to another device already in the registry.
    pub fn handover_manager(&mut self, target_device_id: &str) -> Result<(), VaultError> {
        let target = target_device_id.trim();
        if target.is_empty() || self.data.device_record(target).is_none() {
            return Err(VaultError::UnknownDevice);
        }
        if self.data.manager_id().is_none() {
            return Err(VaultError::NoSecretKeyManager);
        }
        self.ensure_secret_key_change()?;
        self.assign_manager(target);
        Ok(())
    }

    /// Replace the Secret Key and re-wrap the vault key in memory.
    ///
    /// Callers persist once. This never clears the SK flag first: a disable
    /// followed by enable would write a version-1 file in between.
    pub fn rotate_secret_key(
        &mut self,
        password: &SecretString,
        current: &crate::secret_key::SecretKey,
    ) -> Result<crate::secret_key::SecretKey, VaultError> {
        self.ensure_secret_key_change()?;
        if !self.sk_enabled() {
            return Err(VaultError::SecretKeyRequired);
        }
        let expected_fp = if let Some(fp) = self.sk_fingerprint {
            fp
        } else if let Some(sk) = &self.secret_key {
            sk.fingerprint()
        } else {
            return Err(VaultError::SecretKeyRequired);
        };
        if current.fingerprint() != expected_fp {
            return Err(VaultError::SecretKeyMismatch);
        }
        let argon = derive_key(password, &self.salt, &self.params)?;
        let derived = crate::secret_key::apply_2skd(&argon, current)?;
        if derived.as_bytes() != self.key.as_bytes() {
            return Err(VaultError::WrongPassword);
        }
        let new_sk = crate::secret_key::SecretKey::generate();
        self.key = crate::secret_key::apply_2skd(&argon, &new_sk)?;
        self.sk_fingerprint = Some(new_sk.fingerprint());
        self.secret_key = Some(new_sk.clone());
        Ok(new_sk)
    }

    pub fn change_master_password(
        &mut self,
        current: &SecretString,
        new: &SecretString,
    ) -> Result<(), VaultError> {
        self.verify_master_password(current)?;
        let params = default_kdf_params();
        let salt = random_salt();
        let argon = derive_key(new, &salt, &params)?;
        let key = match &self.secret_key {
            Some(sk) => crate::secret_key::apply_2skd(&argon, sk)?,
            None => argon,
        };
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
    unlock_file_with_secret_key(path, password, None, None)
}

/// Unlock, applying 2SKD when the header says the vault has a Secret Key.
pub fn unlock_file_with_secret_key(
    path: &Path,
    password: &SecretString,
    secret_key: Option<&str>,
    store: Option<&dyn crate::secret_key_store::SecretKeyStore>,
) -> Result<UnlockedVault, VaultError> {
    if !path.exists() {
        if crate::sync::icloud_placeholder(path).is_some_and(|placeholder| placeholder.exists()) {
            crate::sync::prompt_icloud_download(path);
            return Err(VaultError::WaitingForIcloud);
        }
        return Err(VaultError::NotFound);
    }
    let bytes = fs::read(path)?;
    let enc: EncryptedVault = parse_encrypted(&bytes)?;
    let sk = resolve_secret_key(&enc, secret_key, store)?;
    let (key, salt, mut data) = unlock_with_secret(&enc, password, sk.as_ref())?;
    crate::sync::migrate_data(&mut data);
    let mut unlocked = fresh_unlocked(key, salt, enc.kdf.clone(), data);
    attach_secret_key(&mut unlocked, &enc, sk);
    unlocked.stamp = crate::sync::capture_stamp(path, unlocked.data.revision)?;
    Ok(unlocked)
}

pub fn peek_secret_key_header(path: &Path) -> Result<(bool, Option<String>), VaultError> {
    if !path.exists() {
        return Err(VaultError::NotFound);
    }
    let bytes = fs::read(path)?;
    let enc = parse_encrypted(&bytes)?;
    Ok((enc.sk_enabled, enc.sk_fingerprint))
}

pub fn resolve_secret_key(
    header: &EncryptedVault,
    typed: Option<&str>,
    store: Option<&dyn crate::secret_key_store::SecretKeyStore>,
) -> Result<Option<crate::secret_key::SecretKey>, VaultError> {
    if !header.sk_enabled {
        return Ok(None);
    }
    let expected = header
        .sk_fingerprint
        .as_deref()
        .ok_or(VaultError::Corrupt)?;
    let check = |sk: crate::secret_key::SecretKey| -> Result<crate::secret_key::SecretKey, VaultError> {
        if sk.fingerprint_b64() != expected {
            return Err(VaultError::SecretKeyMismatch);
        }
        Ok(sk)
    };
    if let Some(typed) = typed.map(str::trim).filter(|value| !value.is_empty()) {
        return check(crate::secret_key::SecretKey::parse(typed)?).map(Some);
    }
    if let Some(store) = store {
        let vault_id = crate::secret_key::vault_id_from_fingerprint_b64(expected)?;
        match store.load(&vault_id) {
            Ok(Some(sk)) => return check(sk).map(Some),
            Ok(None) => {}
            Err(VaultError::SecretKeyStoreUnavailable) => {}
            Err(err) => return Err(err),
        }
    }
    Err(VaultError::SecretKeyRequired)
}

pub fn load_stored_secret_key(
    unlocked: &mut UnlockedVault,
    store: &dyn crate::secret_key_store::SecretKeyStore,
) {
    if unlocked.secret_key.is_some() {
        return;
    }
    let Some(fp) = unlocked.fingerprint_b64() else {
        return;
    };
    let Ok(id) = crate::secret_key::vault_id_from_fingerprint_b64(&fp) else {
        return;
    };
    if let Ok(Some(sk)) = store.load(&id) {
        if sk.fingerprint_b64() == fp {
            unlocked.secret_key = Some(sk);
        }
    }
}

fn attach_secret_key(
    unlocked: &mut UnlockedVault,
    enc: &EncryptedVault,
    sk: Option<crate::secret_key::SecretKey>,
) {
    if let Some(sk) = sk {
        unlocked.sk_fingerprint = Some(sk.fingerprint());
        unlocked.secret_key = Some(sk);
        return;
    }
    if enc.sk_enabled {
        if let Some(fp) = enc.sk_fingerprint.as_deref() {
            if let Ok(bytes) = crate::secret_key::decode_fingerprint_b64(fp) {
                unlocked.sk_fingerprint = Some(bytes);
            }
        }
    }
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

fn aad_bytes(
    version: u32,
    kdf: &KdfParams,
    salt_b64: &str,
    nonce_b64: &str,
    sk_fingerprint: Option<&str>,
) -> Vec<u8> {
    match sk_fingerprint {
        Some(fp) => format!(
            "v{}|alg={}|m={}|t={}|p={}|salt={}|nonce={}|skfp={}",
            version, kdf.algorithm, kdf.m, kdf.t, kdf.p, salt_b64, nonce_b64, fp
        )
        .into_bytes(),
        None => format!(
            "v{}|alg={}|m={}|t={}|p={}|salt={}|nonce={}",
            version, kdf.algorithm, kdf.m, kdf.t, kdf.p, salt_b64, nonce_b64
        )
        .into_bytes(),
    }
}

fn aad_for(file: &EncryptedVault) -> Vec<u8> {
    let fp = if file.sk_enabled {
        file.sk_fingerprint.as_deref()
    } else {
        None
    };
    aad_bytes(file.version, &file.kdf, &file.salt, &file.nonce, fp)
}

pub fn derive_vault_key(
    password: &SecretString,
    salt: &[u8],
    params: &KdfParams,
    secret_key: Option<&crate::secret_key::SecretKey>,
) -> Result<VaultKey, VaultError> {
    let argon = derive_key(password, salt, params)?;
    match secret_key {
        Some(sk) => crate::secret_key::apply_2skd(&argon, sk),
        None => Ok(argon),
    }
}

pub fn secret_key_headers_match(enc: &EncryptedVault, unlocked: &UnlockedVault) -> bool {
    match (enc.sk_enabled, unlocked.sk_enabled()) {
        (false, false) => true,
        (true, true) => enc.sk_fingerprint.as_deref() == unlocked.fingerprint_b64().as_deref(),
        _ => false,
    }
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
    encrypt_vault_ex(plaintext, key, params, salt, None)
}

pub fn encrypt_vault_ex(
    plaintext: &[u8],
    key: &VaultKey,
    params: &KdfParams,
    salt: &[u8],
    sk_fingerprint: Option<&[u8]>,
) -> Result<EncryptedVault, VaultError> {
    let nonce = random_nonce();
    let salt_b64 = B64.encode(salt);
    let nonce_b64 = B64.encode(nonce);
    let (version, sk_enabled, sk_fp) = match sk_fingerprint {
        Some(fp) if fp.len() == crate::secret_key::SECRET_KEY_FINGERPRINT_LEN => {
            (VAULT_VERSION_SK, true, Some(B64.encode(fp)))
        }
        _ => (VAULT_VERSION, false, None),
    };
    let aad = aad_bytes(version, params, &salt_b64, &nonce_b64, sk_fp.as_deref());
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
        version,
        kdf: params.clone(),
        salt: salt_b64,
        nonce: nonce_b64,
        ciphertext: B64.encode(ciphertext),
        sk_enabled,
        sk_fingerprint: sk_fp,
    })
}

pub fn decrypt_vault(file: &EncryptedVault, key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    let nonce = B64.decode(&file.nonce)?;
    if nonce.len() != NONCE_LEN {
        return Err(VaultError::Tampered);
    }
    let ciphertext = B64.decode(&file.ciphertext)?;
    let aad = aad_for(file);
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

pub fn encrypt_unlocked(unlocked: &UnlockedVault) -> Result<EncryptedVault, VaultError> {
    let plaintext = serde_json::to_vec(&unlocked.data)?;
    let fp = unlocked
        .secret_key
        .as_ref()
        .map(|sk| sk.fingerprint())
        .or(unlocked.sk_fingerprint);
    encrypt_vault_ex(
        &plaintext,
        &unlocked.key,
        &unlocked.params,
        &unlocked.salt,
        fp.as_ref().map(|value| value.as_slice()),
    )
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
    let mut unlocked = fresh_unlocked(key.clone(), salt, enc.kdf.clone(), data);
    attach_secret_key(&mut unlocked, &enc, None);
    unlocked.stamp = crate::sync::capture_stamp(path, unlocked.data.revision)?;
    Ok(unlocked)
}

pub fn unlock_with_password(
    file: &EncryptedVault,
    password: &SecretString,
) -> Result<(VaultKey, Vec<u8>, VaultData), VaultError> {
    unlock_with_secret(file, password, None)
}

pub fn unlock_with_secret(
    file: &EncryptedVault,
    password: &SecretString,
    secret_key: Option<&crate::secret_key::SecretKey>,
) -> Result<(VaultKey, Vec<u8>, VaultData), VaultError> {
    if file.sk_enabled {
        let expected = file.sk_fingerprint.as_deref().ok_or(VaultError::Corrupt)?;
        let Some(sk) = secret_key else {
            return Err(VaultError::SecretKeyRequired);
        };
        if sk.fingerprint_b64() != expected {
            return Err(VaultError::SecretKeyMismatch);
        }
    }
    let salt = B64.decode(&file.salt)?;
    if salt.len() != SALT_LEN {
        return Err(VaultError::Tampered);
    }
    let key = derive_vault_key(password, &salt, &file.kdf, secret_key)?;
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

/// Write the historical JSON envelope (`serde_json` of the header).
/// A `KHV1` prefix is not written. Readers still accept that prefix.
pub fn serialize_encrypted(file: &EncryptedVault) -> Result<Vec<u8>, VaultError> {
    Ok(serde_json::to_vec(file)?)
}

/// Read the vault header. Does not decrypt.
///
/// The historical file is a JSON object with `version`, an argon2id `kdf`,
/// `salt`, `nonce`, and `ciphertext`. A file that starts with `KHV1` and then
/// that JSON is valid too. Anything else with a different prefix is not a vault.
/// A short or cut-off header is corrupt. A newer `version` is unsupported.
pub fn validate_vault_header(bytes: &[u8]) -> Result<u32, VaultError> {
    let json = vault_json_slice(bytes)?;
    header_version(json)
}

pub fn parse_encrypted(bytes: &[u8]) -> Result<EncryptedVault, VaultError> {
    let json = vault_json_slice(bytes)?;
    let version = header_version(json)?;
    let enc: EncryptedVault = serde_json::from_slice(json).map_err(|_| VaultError::Corrupt)?;
    if enc.version != version {
        return Err(VaultError::Corrupt);
    }
    Ok(enc)
}

fn vault_json_slice(bytes: &[u8]) -> Result<&[u8], VaultError> {
    let bytes = strip_bom(bytes);
    let bytes = trim_ascii_start(bytes);
    if bytes.is_empty() {
        return Err(VaultError::Corrupt);
    }
    if bytes.starts_with(VAULT_MAGIC) {
        let rest = trim_ascii_start(&bytes[VAULT_MAGIC.len()..]);
        if rest.is_empty() {
            return Err(VaultError::Corrupt);
        }
        return Ok(rest);
    }
    if bytes.starts_with(b"{") {
        return Ok(bytes);
    }
    // `KHV` is the start of the magic with the rest of the header missing.
    if bytes.len() < VAULT_MAGIC.len() && VAULT_MAGIC.starts_with(bytes) {
        return Err(VaultError::Corrupt);
    }
    Err(VaultError::NotAVault)
}

fn header_version(json: &[u8]) -> Result<u32, VaultError> {
    if json.is_empty() {
        return Err(VaultError::Corrupt);
    }
    let value: serde_json::Value = serde_json::from_slice(json).map_err(|_| VaultError::Corrupt)?;
    let obj = value.as_object().ok_or(VaultError::NotAVault)?;
    let version = obj
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or(VaultError::Corrupt)?;
    if version == 0 || version > u64::from(VAULT_VERSION_SK) {
        return Err(VaultError::UnsupportedVersion);
    }
    if version == u64::from(VAULT_VERSION_SK) {
        let enabled = obj
            .get("skEnabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return Err(VaultError::Corrupt);
        }
        let fingerprint = obj
            .get("skFingerprint")
            .and_then(|v| v.as_str())
            .ok_or(VaultError::Corrupt)?;
        let fp = B64.decode(fingerprint).map_err(|_| VaultError::Corrupt)?;
        if fp.len() != crate::secret_key::SECRET_KEY_FINGERPRINT_LEN {
            return Err(VaultError::Corrupt);
        }
    }
    let kdf = obj.get("kdf").and_then(|v| v.as_object()).ok_or(VaultError::Corrupt)?;
    let algorithm = kdf
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or(VaultError::Corrupt)?;
    if algorithm != "argon2id" {
        return Err(VaultError::UnsupportedVersion);
    }
    for key in ["m", "t", "p"] {
        let number = kdf.get(key).and_then(|v| v.as_u64()).ok_or(VaultError::Corrupt)?;
        if number == 0 || number > u64::from(u32::MAX) {
            return Err(VaultError::Corrupt);
        }
    }
    for key in ["salt", "nonce", "ciphertext"] {
        let text = obj.get(key).and_then(|v| v.as_str()).ok_or(VaultError::Corrupt)?;
        if text.is_empty() {
            return Err(VaultError::Corrupt);
        }
    }
    Ok(version as u32)
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
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

#[cfg(test)]
thread_local! {
    static ATOMIC_WRITES: std::cell::RefCell<Option<Vec<Vec<u8>>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn record_atomic_write(data: &[u8]) {
    ATOMIC_WRITES.with(|slot| {
        if let Some(log) = slot.borrow_mut().as_mut() {
            log.push(data.to_vec());
        }
    });
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    #[cfg(test)]
    record_atomic_write(data);
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

    fn sample_header_json(version: u32) -> Vec<u8> {
        format!(
            r#"{{"version":{version},"kdf":{{"algorithm":"argon2id","m":32,"t":1,"p":1}},"salt":"s","nonce":"n","ciphertext":"c"}}"#
        )
        .into_bytes()
    }

    #[test]
    fn header_validation_accepts_magic_and_legacy_json() {
        let mut magic = VAULT_MAGIC.to_vec();
        magic.extend_from_slice(&sample_header_json(1));
        assert_eq!(validate_vault_header(&magic).unwrap(), 1);
        assert!(matches!(parse_encrypted(&magic).unwrap().version, 1));

        let legacy = sample_header_json(1);
        assert!(!legacy.starts_with(VAULT_MAGIC));
        assert_eq!(validate_vault_header(&legacy).unwrap(), 1);
        assert_eq!(parse_encrypted(&legacy).unwrap().version, 1);

        let password = secret("header-roundtrip");
        let (_key, _salt, _params, enc, _data) = create_empty_vault(&password).unwrap();
        let bytes = serialize_encrypted(&enc).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&enc).unwrap());
        assert!(!bytes.starts_with(VAULT_MAGIC));
        assert_eq!(validate_vault_header(&bytes).unwrap(), VAULT_VERSION);
        assert_eq!(parse_encrypted(&bytes).unwrap(), enc);

        let mut unsupported = VAULT_MAGIC.to_vec();
        unsupported.extend_from_slice(&sample_header_json(99));
        assert!(matches!(
            validate_vault_header(&unsupported).unwrap_err(),
            VaultError::UnsupportedVersion
        ));
    }

    #[test]
    fn header_validation_rejects_wrong_magic() {
        let err = validate_vault_header(b"NOPE{\"version\":1}").unwrap_err();
        assert!(matches!(err, VaultError::NotAVault));
        assert_eq!(err.to_string(), "not a vault");
        assert!(matches!(
            validate_vault_header(b"ABCD").unwrap_err(),
            VaultError::NotAVault
        ));
        assert!(matches!(
            parse_encrypted(b"this is not a vault").unwrap_err(),
            VaultError::NotAVault
        ));
    }

    #[test]
    fn header_validation_rejects_truncated() {
        assert!(matches!(
            validate_vault_header(b"KHV").unwrap_err(),
            VaultError::Corrupt
        ));
        assert_eq!(validate_vault_header(b"KHV").unwrap_err().to_string(), "corrupt");
        assert!(matches!(
            validate_vault_header(b"KHV1").unwrap_err(),
            VaultError::Corrupt
        ));
        let mut cut = VAULT_MAGIC.to_vec();
        cut.extend_from_slice(br#"{"version":1,"kdf":"#);
        assert!(matches!(
            validate_vault_header(&cut).unwrap_err(),
            VaultError::Corrupt
        ));
        assert!(matches!(
            validate_vault_header(b"").unwrap_err(),
            VaultError::Corrupt
        ));
        assert!(matches!(parse_encrypted(b"KHV").unwrap_err(), VaultError::Corrupt));
    }

    #[test]
    fn written_vault_has_no_khv1_prefix_and_matches_old_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("format-stable");
        let unlocked = create_vault_at(&path, &password).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.starts_with(b"KHV1"));
        assert!(bytes.starts_with(b"{"));
        let enc: EncryptedVault = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&enc).unwrap());
        assert_eq!(parse_encrypted(&bytes).unwrap(), enc);
        assert_eq!(validate_vault_header(&bytes).unwrap(), VAULT_VERSION);
        let again = unlock_file(&path, &password).unwrap();
        assert_eq!(again.data.revision, unlocked.data.revision);

        let mut prefixed = b"KHV1".to_vec();
        prefixed.extend_from_slice(&bytes);
        assert_eq!(validate_vault_header(&prefixed).unwrap(), VAULT_VERSION);
        assert_eq!(parse_encrypted(&prefixed).unwrap(), enc);
    }

    #[test]
    fn secret_key_roundtrip_wrong_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("sk-master-pass");
        let mut unlocked = create_vault_at(&path, &password).unwrap();
        unlocked.data.items.push(sample_item());
        let sk = unlocked.enable_secret_key(&password).unwrap();
        persist_unlocked(&path, &mut unlocked).unwrap();

        let bytes = fs::read(&path).unwrap();
        let enc = parse_encrypted(&bytes).unwrap();
        assert_eq!(enc.version, VAULT_VERSION_SK);
        assert!(enc.sk_enabled);
        assert_eq!(enc.sk_fingerprint.as_deref(), Some(sk.fingerprint_b64().as_str()));
        let json = String::from_utf8(bytes.clone()).unwrap();
        assert!(!json.contains(&sk.format_display()));
        assert!(!json.contains(&data_encoding::BASE32_NOPAD.encode(sk.as_bytes())));

        let loaded = unlock_file_with_secret_key(&path, &password, Some(&sk.format_display()), None).unwrap();
        assert_eq!(loaded.data.items, unlocked.data.items);
        assert!(loaded.sk_enabled());

        let missing = unlock_file(&path, &password).unwrap_err();
        assert!(matches!(missing, VaultError::SecretKeyRequired));

        let other = crate::secret_key::SecretKey::generate();
        let mismatch = unlock_file_with_secret_key(&path, &password, Some(&other.format_display()), None)
            .unwrap_err();
        assert!(matches!(mismatch, VaultError::SecretKeyMismatch));
        assert_eq!(mismatch.to_string(), "Secret Key가 이 금고와 맞지 않습니다");

        let wrong_pw = unlock_file_with_secret_key(&path, &secret("nope"), Some(&sk.format_display()), None)
            .unwrap_err();
        assert!(matches!(wrong_pw, VaultError::WrongPassword));
    }

    #[test]
    fn open_0_2_x_vault_from_old_code_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("legacy-0.2.x-master");
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&password, &salt, &params).unwrap();
        let data = VaultData {
            items: vec![sample_item()],
            ..VaultData::default()
        };
        let enc = encrypt_data(&data, &key, &params, &salt).unwrap();
        assert_eq!(enc.version, VAULT_VERSION);
        assert!(!enc.sk_enabled);
        assert!(enc.sk_fingerprint.is_none());
        let bytes = serialize_encrypted(&enc).unwrap();
        assert!(!bytes.starts_with(b"KHV1"));
        atomic_write(&path, &bytes).unwrap();

        let loaded = unlock_file(&path, &password).unwrap();
        assert_eq!(loaded.data.items[0].title, "Example");
        assert_eq!(loaded.data.items[0].password.as_deref(), Some("secret-pass"));
        assert!(!loaded.sk_enabled());
        let json = String::from_utf8(fs::read(&path).unwrap()).unwrap();
        assert!(!json.contains("skEnabled"));
        assert!(!json.contains("skFingerprint"));
    }

    #[test]
    fn enable_disable_secret_key_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("migrate-sk-master");
        let mut unlocked = create_vault_at(&path, &password).unwrap();
        unlocked.data.items.push(sample_item());
        persist_unlocked(&path, &mut unlocked).unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(parse_encrypted(&before).unwrap().version, VAULT_VERSION);

        let sk = unlocked.enable_secret_key(&password).unwrap();
        persist_unlocked(&path, &mut unlocked).unwrap();
        let enabled = parse_encrypted(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(enabled.version, VAULT_VERSION_SK);
        assert!(enabled.sk_enabled);

        let mut loaded =
            unlock_file_with_secret_key(&path, &password, Some(&sk.format_display()), None).unwrap();
        loaded.device_id = unlocked.device_id.clone();
        loaded.disable_secret_key(&password, &sk).unwrap();
        persist_unlocked(&path, &mut loaded).unwrap();
        let disabled = parse_encrypted(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(disabled.version, VAULT_VERSION);
        assert!(!disabled.sk_enabled);
        assert!(disabled.sk_fingerprint.is_none());
        let again = unlock_file(&path, &password).unwrap();
        assert_eq!(again.data.items[0].title, "Example");
        assert!(!again.sk_enabled());
    }

    #[test]
    fn secret_key_store_used_on_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("store-unlock");
        let mut unlocked = create_vault_at(&path, &password).unwrap();
        let sk = unlocked.enable_secret_key(&password).unwrap();
        persist_unlocked(&path, &mut unlocked).unwrap();
        use crate::secret_key_store::SecretKeyStore;
        let store = crate::secret_key_store::MemorySecretKeyStore::new();
        store.store(&sk.vault_id(), &sk).unwrap();
        let loaded = unlock_file_with_secret_key(&path, &password, None, Some(&store)).unwrap();
        assert!(loaded.sk_enabled());
        assert_eq!(loaded.secret_key.as_ref().unwrap().as_bytes(), sk.as_bytes());
    }

    struct WriteCapture;

    impl WriteCapture {
        fn start() -> Self {
            super::ATOMIC_WRITES.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
            Self
        }

        fn finish(self) -> Vec<Vec<u8>> {
            super::ATOMIC_WRITES.with(|slot| slot.borrow_mut().take().unwrap_or_default())
        }
    }

    impl Drop for WriteCapture {
        fn drop(&mut self) {
            super::ATOMIC_WRITES.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn assert_sk_payload(bytes: &[u8]) {
        let enc = parse_encrypted(bytes).expect("written bytes must stay a vault header");
        assert!(enc.sk_enabled, "SK flag missing from written vault");
        assert!(enc.sk_fingerprint.is_some(), "SK fingerprint missing");
        assert_eq!(enc.version, VAULT_VERSION_SK);
        let text = std::str::from_utf8(bytes).expect("vault json is utf-8");
        assert!(
            text.contains("\"skEnabled\":true"),
            "serialized header dropped the SK flag: {text}"
        );
    }

    fn assert_dir_vaults_keep_secret_key(dir: &Path) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            if let Ok(enc) = parse_encrypted(&bytes) {
                assert!(
                    enc.sk_enabled && enc.version == VAULT_VERSION_SK && enc.sk_fingerprint.is_some(),
                    "{} was written without a Secret Key",
                    path.display()
                );
            }
        }
        let leftovers: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().to_string_lossy().into_owned();
                if name.contains(".tmp") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        assert!(leftovers.is_empty(), "temp vault left behind: {leftovers:?}");
    }

    #[test]
    fn rotate_secret_key_rejects_wrong_secret_or_password_without_touching_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("rotate-reject-master");
        let mut unlocked = create_vault_at(&path, &password).unwrap();
        let before_plain = fs::read(&path).unwrap();
        let bogus = crate::secret_key::SecretKey::generate();
        let not_enabled = unlocked.rotate_secret_key(&password, &bogus).unwrap_err();
        assert!(matches!(not_enabled, VaultError::SecretKeyRequired));
        assert_eq!(fs::read(&path).unwrap(), before_plain);
        assert_eq!(parse_encrypted(&before_plain).unwrap().version, VAULT_VERSION);

        unlocked.data.items.push(sample_item());
        let current = unlocked.enable_secret_key(&password).unwrap();
        persist_unlocked(&path, &mut unlocked).unwrap();
        let before = fs::read(&path).unwrap();
        let fp = unlocked.fingerprint_b64();
        let key = unlocked.key.as_bytes().to_vec();
        let sk_bytes = unlocked.secret_key.as_ref().unwrap().as_bytes().to_vec();

        let wrong_password = unlocked
            .rotate_secret_key(&secret("not-the-master"), &current)
            .unwrap_err();
        assert!(matches!(wrong_password, VaultError::WrongPassword));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(unlocked.fingerprint_b64(), fp);
        assert_eq!(unlocked.key.as_bytes().as_slice(), key.as_slice());
        assert_eq!(
            unlocked.secret_key.as_ref().unwrap().as_bytes().as_slice(),
            sk_bytes.as_slice()
        );

        let other = crate::secret_key::SecretKey::generate();
        let wrong_sk = unlocked.rotate_secret_key(&password, &other).unwrap_err();
        assert!(matches!(wrong_sk, VaultError::SecretKeyMismatch));
        assert_eq!(wrong_sk.to_string(), "Secret Key가 이 금고와 맞지 않습니다");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(unlocked.fingerprint_b64(), fp);
        assert_eq!(unlocked.key.as_bytes().as_slice(), key.as_slice());
        assert_sk_payload(&before);
    }

    #[test]
    fn rotate_secret_key_roundtrip_old_key_fails_and_write_stays_sk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = secret("rotate-roundtrip-master");
        let mut created = create_vault_at(&path, &password).unwrap();
        created.data.items.push(sample_item());
        let old = created.enable_secret_key(&password).unwrap();
        persist_unlocked(&path, &mut created).unwrap();

        let mut unlocked =
            unlock_file_with_secret_key(&path, &password, Some(&old.format_display()), None).unwrap();
        // Touch ID unlock keeps the fingerprint but not the Secret Key bytes.
        unlocked.secret_key = None;
        assert!(unlocked.sk_fingerprint.is_some());

        let capture = WriteCapture::start();
        let new_sk = unlocked.rotate_secret_key(&password, &old).unwrap();
        assert_ne!(new_sk.as_bytes(), old.as_bytes());
        assert!(unlocked.sk_enabled());
        assert!(unlocked.secret_key.is_some());
        unlocked.dirty = true;
        persist_unlocked(&path, &mut unlocked).unwrap();
        let writes = capture.finish();

        assert_eq!(
            writes.len(),
            1,
            "rotation must atomically rewrite the vault once, got {} writes",
            writes.len()
        );
        for bytes in &writes {
            assert_sk_payload(bytes);
        }
        let final_bytes = fs::read(&path).unwrap();
        assert_sk_payload(&final_bytes);
        assert_eq!(final_bytes, writes[0]);
        assert_dir_vaults_keep_secret_key(dir.path());

        let loaded =
            unlock_file_with_secret_key(&path, &password, Some(&new_sk.format_display()), None)
                .unwrap();
        assert_eq!(loaded.data.items[0].title, "Example");
        assert_eq!(loaded.data.items[0].password.as_deref(), Some("secret-pass"));
        assert_eq!(loaded.secret_key.as_ref().unwrap().as_bytes(), new_sk.as_bytes());
        assert_eq!(
            loaded.fingerprint_b64().as_deref(),
            Some(new_sk.fingerprint_b64().as_str())
        );

        let old_fails =
            unlock_file_with_secret_key(&path, &password, Some(&old.format_display()), None)
                .unwrap_err();
        assert!(matches!(old_fails, VaultError::SecretKeyMismatch));
        let missing = unlock_file(&path, &password).unwrap_err();
        assert!(matches!(missing, VaultError::SecretKeyRequired));
        let wrong_pw =
            unlock_file_with_secret_key(&path, &secret("nope"), Some(&new_sk.format_display()), None)
                .unwrap_err();
        assert!(matches!(wrong_pw, VaultError::WrongPassword));
    }

    fn memory_vault(password: &str, device: &str) -> UnlockedVault {
        let params = default_kdf_params();
        let salt = random_salt().to_vec();
        let key = derive_key(&secret(password), &salt, &params).unwrap();
        let mut unlocked = fresh_unlocked(key, salt, params, VaultData::default());
        unlocked.device_id = device.to_string();
        unlocked
    }

    fn device(id: &str, name: &str, last_seen: &str) -> DeviceRecord {
        DeviceRecord {
            id: id.to_string(),
            name: name.to_string(),
            last_seen: last_seen.to_string(),
        }
    }

    #[test]
    fn non_manager_cannot_enable_rotate_or_disable() {
        let password = secret("manager-gate");
        let mut manager = memory_vault("manager-gate", "device-a");
        register_device(&mut manager.data, "device-a", "작업실");
        let sk = manager.enable_secret_key(&password).unwrap();
        assert_eq!(manager.data.manager_id(), Some("device-a"));
        let display = sk.format_display();

        let mut other = manager;
        other.device_id = "device-b".to_string();
        let enable_err = other.enable_secret_key(&password).unwrap_err();
        assert_eq!(enable_err.to_string(), "관리 기기(작업실)에서만 변경할 수 있어요");
        let rotate_err = other.rotate_secret_key(&password, &sk).unwrap_err();
        assert!(matches!(rotate_err, VaultError::NotSecretKeyManager(_)));
        let disable_err = other.disable_secret_key(&secret("wrong"), &sk).unwrap_err();
        assert!(matches!(disable_err, VaultError::NotSecretKeyManager(_)));
        assert!(other.sk_enabled());
        assert_eq!(
            other.secret_key.as_ref().map(|key| key.format_display()).as_deref(),
            Some(display.as_str())
        );
        assert_eq!(other.data.manager_id(), Some("device-a"));
    }

    #[test]
    fn vault_without_manager_lets_any_device_change_secret_key() {
        let json = r#"{"items":[],"revision":3,"device_id":"legacy"}"#;
        let data: VaultData = serde_json::from_str(json).unwrap();
        assert!(data.manager_id().is_none());
        assert!(data.allows_secret_key_change("device-a"));
        assert!(data.allows_secret_key_change("device-b"));

        let password = secret("legacy-open");
        let mut first = memory_vault("legacy-open", "");
        let sk = first.enable_secret_key(&password).unwrap();
        assert!(first.data.manager_id().is_none(), "an unnamed install does not lock the role");
        first.device_id = "device-b".to_string();
        let rotated = first.rotate_secret_key(&password, &sk).unwrap();
        first.disable_secret_key(&password, &rotated).unwrap();
        assert!(!first.sk_enabled());
        first.device_id = "device-c".to_string();
        let again = first.enable_secret_key(&password).unwrap();
        assert_eq!(first.data.manager_id(), Some("device-c"));
        assert!(again.format_display().starts_with("SV1-"));
    }

    #[test]
    fn designate_manager_when_none_requires_password_and_secret_key() {
        let password = secret("designate-pw");
        let mut vault = memory_vault("designate-pw", "device-a");
        let sk = vault.enable_secret_key(&password).unwrap();
        vault.data.manager_device_id.clear();
        vault.data.manager_updated_at.clear();
        assert!(vault.data.manager_id().is_none());
        vault.device_id = "device-b".to_string();

        let wrong = vault.designate_manager(&secret("nope"), &sk).unwrap_err();
        assert!(matches!(wrong, VaultError::WrongPassword));
        assert!(vault.data.manager_id().is_none());

        vault.designate_manager(&password, &sk).unwrap();
        assert_eq!(vault.data.manager_id(), Some("device-b"));
        assert!(!vault.data.manager_updated_at.is_empty());

        vault.device_id = "device-a".to_string();
        let blocked = vault.designate_manager(&password, &sk).unwrap_err();
        assert!(matches!(blocked, VaultError::NotSecretKeyManager(_)));
        let blocked_change = vault.rotate_secret_key(&password, &sk).unwrap_err();
        assert!(matches!(blocked_change, VaultError::NotSecretKeyManager(_)));
    }

    #[test]
    fn takeover_and_handover_move_the_manager() {
        let password = secret("hand-pw");
        let mut vault = memory_vault("hand-pw", "device-a");
        register_device(&mut vault.data, "device-a", "작업실");
        register_device(&mut vault.data, "device-b", "여행용");
        let sk = vault.enable_secret_key(&password).unwrap();
        assert_eq!(vault.data.manager_id(), Some("device-a"));

        let unknown = vault.handover_manager("missing").unwrap_err();
        assert!(matches!(unknown, VaultError::UnknownDevice));

        vault.handover_manager("device-b").unwrap();
        assert_eq!(vault.data.manager_id(), Some("device-b"));
        let cannot_hand_back = vault.handover_manager("device-a").unwrap_err();
        assert!(matches!(cannot_hand_back, VaultError::NotSecretKeyManager(_)));

        let wrong = vault.takeover_manager(&password, &crate::secret_key::SecretKey::generate()).unwrap_err();
        assert!(matches!(wrong, VaultError::SecretKeyMismatch));
        assert_eq!(vault.data.manager_id(), Some("device-b"));

        vault.takeover_manager(&password, &sk).unwrap();
        assert_eq!(vault.data.manager_id(), Some("device-a"));
        vault.rotate_secret_key(&password, &sk).unwrap();
        assert_eq!(vault.data.manager_id(), Some("device-a"));
    }

    #[test]
    fn disable_keeps_manager_so_only_that_device_can_enable_again() {
        let password = secret("keep-manager");
        let mut vault = memory_vault("keep-manager", "device-a");
        register_device(&mut vault.data, "device-a", "작업실");
        let sk = vault.enable_secret_key(&password).unwrap();
        vault.disable_secret_key(&password, &sk).unwrap();
        assert!(!vault.sk_enabled());
        assert_eq!(vault.data.manager_id(), Some("device-a"));
        vault.device_id = "device-b".to_string();
        let err = vault.enable_secret_key(&password).unwrap_err();
        assert!(matches!(err, VaultError::NotSecretKeyManager(_)));
        vault.device_id = "device-a".to_string();
        vault.enable_secret_key(&password).unwrap();
        assert_eq!(vault.data.manager_id(), Some("device-a"));
    }

    #[test]
    fn unknown_payload_item_and_settings_fields_roundtrip() {
        let mut value = serde_json::to_value(VaultData {
            items: vec![sample_item()],
            ..VaultData::default()
        })
        .unwrap();
        value["futurePayload"] = serde_json::json!("keep");
        value["settings"]["futureSetting"] = serde_json::json!(9);
        value["items"][0]["futureItem"] = serde_json::json!(true);
        value["items"][0]["conflicts"] = serde_json::json!([{
            "id": "c1",
            "updatedAt": "2026-01-01T00:00:00Z",
            "deleted": false,
            "itemType": "login",
            "title": "t",
            "futureConflict": "c"
        }]);
        value["tombstones"] = serde_json::json!([{
            "id": "tomb",
            "updatedAt": "2026-01-02T00:00:00Z",
            "futureTomb": 1,
            "body": {"itemType": "note", "title": "gone", "futureBody": "b"}
        }]);
        let parsed: VaultData = serde_json::from_value(value).unwrap();
        let again = serde_json::to_value(&parsed).unwrap();
        assert_eq!(again["futurePayload"], "keep");
        assert_eq!(again["settings"]["futureSetting"], 9);
        assert_eq!(again["items"][0]["futureItem"], true);
        assert_eq!(again["items"][0]["conflicts"][0]["futureConflict"], "c");
        assert_eq!(again["tombstones"][0]["futureTomb"], 1);
        assert_eq!(again["tombstones"][0]["body"]["futureBody"], "b");

        let password = secret("extra-roundtrip");
        let params = default_kdf_params();
        let salt = random_salt();
        let key = derive_key(&password, &salt, &params).unwrap();
        let enc = encrypt_data(&parsed, &key, &params, &salt).unwrap();
        let out = decrypt_data(&enc, &key).unwrap();
        assert_eq!(out.extra.get("futurePayload").and_then(|v| v.as_str()), Some("keep"));
        assert_eq!(out.settings.extra.get("futureSetting").and_then(|v| v.as_i64()), Some(9));
        assert_eq!(out.items[0].extra.get("futureItem").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            out.items[0].conflicts[0].body.extra.get("futureConflict").and_then(|v| v.as_str()),
            Some("c")
        );
    }

    #[test]
    fn manager_fields_are_inside_the_ciphertext_not_the_header() {
        let password = secret("inside-payload");
        let mut vault = memory_vault("inside-payload", "device-a");
        register_device(&mut vault.data, "device-a", "작업실");
        let _sk = vault.enable_secret_key(&password).unwrap();
        vault.data.extra.insert("futurePayload".into(), serde_json::json!("hidden"));
        let enc = encrypt_unlocked(&vault).unwrap();
        let bytes = serialize_encrypted(&enc).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(header.get("managerDeviceId").is_none());
        assert!(header.get("deviceRegistry").is_none());
        assert!(header.get("managerUpdatedAt").is_none());
        let data = decrypt_data(&enc, &vault.key).unwrap();
        assert_eq!(data.manager_id(), Some("device-a"));
        assert_eq!(data.device_registry[0].name, "작업실");
        assert_eq!(data.extra.get("futurePayload").and_then(|v| v.as_str()), Some("hidden"));
    }

    #[test]
    fn merge_manager_is_last_writer_wins_and_registry_merges_by_last_seen() {
        let mut local = VaultData::default();
        local.manager_device_id = "aaa".into();
        local.manager_updated_at = "2026-01-01T00:00:00Z".into();
        local.device_registry = vec![
            device("aaa", "Old", "2026-01-01T00:00:00Z"),
            device("bbb", "B", "2026-02-01T00:00:00Z"),
        ];
        local.extra.insert("onlyLocal".into(), serde_json::json!(1));
        local.extra.insert("both".into(), serde_json::json!("local"));
        local.revision = 1;
        local.device_id = "writer-a".into();

        let mut remote = VaultData::default();
        remote.manager_device_id = "bbb".into();
        remote.manager_updated_at = "2026-03-01T00:00:00Z".into();
        remote.device_registry = vec![
            device("bbb", "B2", "2026-04-01T00:00:00Z"),
            device("ccc", "C", "2026-01-01T00:00:00Z"),
        ];
        remote.extra.insert("onlyRemote".into(), serde_json::json!(2));
        remote.extra.insert("both".into(), serde_json::json!("remote"));
        remote.revision = 4;
        remote.device_id = "writer-b".into();

        let mut flipped = remote.clone();
        local.merge(remote);
        assert_eq!(local.manager_device_id, "bbb");
        assert_eq!(local.manager_updated_at, "2026-03-01T00:00:00Z");
        assert_eq!(local.device_registry.iter().find(|d| d.id == "bbb").unwrap().name, "B2");
        assert!(local.device_registry.iter().any(|d| d.id == "aaa" && d.name == "Old"));
        assert!(local.device_registry.iter().any(|d| d.id == "ccc"));
        assert_eq!(local.extra.get("onlyLocal").and_then(|v| v.as_i64()), Some(1));
        assert_eq!(local.extra.get("onlyRemote").and_then(|v| v.as_i64()), Some(2));
        assert_eq!(local.extra.get("both").and_then(|v| v.as_str()), Some("remote"));

        let mut tied_left = VaultData::default();
        tied_left.manager_device_id = "device-a".into();
        tied_left.manager_updated_at = "2026-05-01T00:00:00Z".into();
        let mut tied_right = VaultData::default();
        tied_right.manager_device_id = "device-m".into();
        tied_right.manager_updated_at = "2026-05-01T00:00:00Z".into();
        let mut right_first = tied_right.clone();
        let left_copy = tied_left.clone();
        tied_left.merge(tied_right);
        right_first.merge(left_copy);
        assert_eq!(tied_left.manager_device_id, "device-m");
        assert_eq!(right_first.manager_device_id, "device-m");

        let mut bare = VaultData::default();
        flipped.manager_updated_at = "2026-06-01T00:00:00Z".into();
        bare.merge(flipped);
        assert_eq!(bare.manager_device_id, "bbb");
    }
}
