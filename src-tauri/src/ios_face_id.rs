//! iOS Face ID unlock. Desktop commands return "unsupported".
//!
//! The secret in the keychain is the 2SKD-derived vault key, not the master
//! password. Policy metadata (boot time, last password unlock) is a JSON file
//! in app data so the vault.khv format stays unchanged.

use serde::Serialize;
use tauri::AppHandle;
use securevault_core::vault::{VaultError, VaultKey};

use super::{err, require_unlocked, AppState};

#[cfg(target_os = "ios")]
use std::path::Path;
#[cfg(target_os = "ios")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "ios")]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(target_os = "ios")]
use base64::Engine as _;
#[cfg(target_os = "ios")]
use securevault_core::biometric_policy::{
    self, after_password_unlock, can_use_biometric, disable, enroll, should_disable_toggle,
    BiometricDecision, BiometricMeta, PasswordReason,
};
#[cfg(target_os = "ios")]
use securevault_core::vault::unlock_file_with_key;
#[cfg(target_os = "ios")]
use tauri::Manager;
#[cfg(target_os = "ios")]
use zeroize::Zeroize;

#[cfg(target_os = "ios")]
use super::{
    bind_device, device_id, ensure_local, persist, prepare_sync, remember_settings, sk_store,
    vault_path,
};

#[cfg(target_os = "ios")]
const META_FILE: &str = "face-id.json";
#[cfg(target_os = "ios")]
const LOAD_REASON: &str = "SecureVault 금고를 Face ID로 잠금 해제합니다.";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaceIdStatus {
    pub supported: bool,
    pub available: bool,
    pub enrolled: bool,
    pub biometry_type: String,
    pub enabled: bool,
    pub can_unlock: bool,
    pub item_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub disabled_toggle: bool,
}

impl FaceIdStatus {
    fn unsupported() -> Self {
        Self {
            supported: false,
            available: false,
            enrolled: false,
            biometry_type: "none".into(),
            enabled: false,
            can_unlock: false,
            item_present: false,
            reason: Some("notEnabled"),
            disabled_toggle: false,
        }
    }
}

#[cfg(target_os = "ios")]
fn reason_name(reason: PasswordReason) -> &'static str {
    match reason {
        PasswordReason::NotEnabled => "notEnabled",
        PasswordReason::FirstSetup => "firstSetup",
        PasswordReason::Rebooted => "rebooted",
        PasswordReason::Expired => "expired",
        PasswordReason::ItemMissing => "itemMissing",
        PasswordReason::Invalidated => "invalidated",
    }
}

#[cfg(target_os = "ios")]
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(target_os = "ios")]
fn boot_time() -> i64 {
    biometric_policy::current_boot_time().unwrap_or(0)
}

#[cfg(target_os = "ios")]
fn meta_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(META_FILE)
}

#[cfg(target_os = "ios")]
fn load_meta(data_dir: &Path) -> BiometricMeta {
    let path = meta_path(data_dir);
    let Ok(bytes) = std::fs::read(&path) else {
        return BiometricMeta::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

#[cfg(target_os = "ios")]
fn save_meta(data_dir: &Path, meta: &BiometricMeta) -> Result<(), String> {
    let path = meta_path(data_dir);
    let bytes = serde_json::to_vec_pretty(meta).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

#[cfg(target_os = "ios")]
fn demo_face_id() -> bool {
    matches!(
        securevault_core::env_var("DEMO").as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

#[cfg(target_os = "ios")]
fn map_plugin_err(err: securevault_ios::BiometricLoadError) -> String {
    match err {
        securevault_ios::BiometricLoadError::NotFound => "notFound".into(),
        securevault_ios::BiometricLoadError::Invalidated => "invalidated".into(),
        securevault_ios::BiometricLoadError::Cancelled => "cancelled".into(),
        securevault_ios::BiometricLoadError::Failed => "failed".into(),
        securevault_ios::BiometricLoadError::Unsupported => "unsupported".into(),
    }
}

#[tauri::command]
pub async fn ios_face_id_status(app: AppHandle) -> Result<FaceIdStatus, String> {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = app;
        return Ok(FaceIdStatus::unsupported());
    }
    #[cfg(target_os = "ios")]
    {
        status_ios(&app).await
    }
}

#[cfg(target_os = "ios")]
async fn status_ios(app: &AppHandle) -> Result<FaceIdStatus, String> {
    let local = ensure_local(app)?;
    let mut meta = load_meta(&local.data_dir);
    let hw = securevault_ios::biometric_status(app)
        .await
        .unwrap_or_default();
    let mut item_present = hw.item_present;
    let mut item_invalidated = false;
    if demo_face_id() && !hw.available {
        // Simulator has no Face ID. Screenshots still show the toggle and button.
        return Ok(FaceIdStatus {
            supported: true,
            available: true,
            enrolled: true,
            biometry_type: "faceId".into(),
            enabled: meta.enabled,
            can_unlock: meta.enabled,
            item_present: meta.enabled,
            reason: if meta.enabled {
                None
            } else {
                Some("notEnabled")
            },
            disabled_toggle: false,
        });
    }
    let decision = can_use_biometric(
        now_unix(),
        boot_time(),
        Some(&meta),
        item_present,
        item_invalidated,
    );
    if let BiometricDecision::RequirePassword(reason) = decision {
        if should_disable_toggle(reason) && meta.enabled {
            disable(&mut meta);
            save_meta(&local.data_dir, &meta)?;
            let _ = securevault_ios::biometric_delete(app).await;
            item_present = false;
            item_invalidated = matches!(reason, PasswordReason::Invalidated);
            return Ok(FaceIdStatus {
                supported: true,
                available: hw.available,
                enrolled: hw.enrolled,
                biometry_type: hw.biometry_type,
                enabled: false,
                can_unlock: false,
                item_present: false,
                reason: Some(reason_name(reason)),
                disabled_toggle: true,
            });
        }
        return Ok(FaceIdStatus {
            supported: true,
            available: hw.available,
            enrolled: hw.enrolled,
            biometry_type: hw.biometry_type,
            enabled: meta.enabled,
            can_unlock: false,
            item_present,
            reason: Some(reason_name(reason)),
            disabled_toggle: false,
        });
    }
    let _ = item_invalidated;
    Ok(FaceIdStatus {
        supported: true,
        available: hw.available,
        enrolled: hw.enrolled,
        biometry_type: hw.biometry_type,
        enabled: meta.enabled,
        can_unlock: hw.available && meta.enabled && item_present,
        item_present,
        reason: None,
        disabled_toggle: false,
    })
}

#[tauri::command]
pub async fn ios_face_id_enable(app: AppHandle, password: String) -> Result<FaceIdStatus, String> {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = (app, password);
        return Err("unsupported".into());
    }
    #[cfg(target_os = "ios")]
    {
        enable_ios(&app, password).await
    }
}

#[cfg(target_os = "ios")]
async fn enable_ios(app: &AppHandle, password: String) -> Result<FaceIdStatus, String> {
    let local = ensure_local(app)?;
    let hw = securevault_ios::biometric_status(app).await.unwrap_or_default();
    if !hw.available && !demo_face_id() {
        return Err("biometrics unavailable".into());
    }
    let mut key_bytes = {
        let state = app.state::<AppState>();
        let guard = require_unlocked(&state)?;
        let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
        let secret = secrecy::SecretString::new(password);
        unlocked.verify_master_password(&secret).map_err(err)?;
        unlocked.export_unlock_key().as_bytes().to_vec()
    };
    if !demo_face_id() || hw.available {
        let b64 = B64.encode(&key_bytes);
        key_bytes.zeroize();
        securevault_ios::biometric_store(app, &b64)
            .await
            .map_err(map_plugin_err)?;
    } else {
        key_bytes.zeroize();
    }
    let meta = enroll(now_unix(), boot_time());
    save_meta(&local.data_dir, &meta)?;
    status_ios(app).await
}

#[tauri::command]
pub async fn ios_face_id_disable(app: AppHandle) -> Result<FaceIdStatus, String> {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = app;
        return Err("unsupported".into());
    }
    #[cfg(target_os = "ios")]
    {
        disable_ios(&app).await
    }
}

#[cfg(target_os = "ios")]
async fn disable_ios(app: &AppHandle) -> Result<FaceIdStatus, String> {
    let local = ensure_local(app)?;
    let mut meta = load_meta(&local.data_dir);
    disable(&mut meta);
    save_meta(&local.data_dir, &meta)?;
    let _ = securevault_ios::biometric_delete(app).await;
    status_ios(app).await
}

#[tauri::command]
pub async fn ios_face_id_unlock(app: AppHandle) -> Result<(), String> {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = app;
        return Err("unsupported".into());
    }
    #[cfg(target_os = "ios")]
    {
        unlock_ios(&app).await
    }
}

#[cfg(target_os = "ios")]
async fn unlock_ios(app: &AppHandle) -> Result<(), String> {
    let local = ensure_local(app)?;
    let mut meta = load_meta(&local.data_dir);
    let hw = securevault_ios::biometric_status(app)
        .await
        .unwrap_or_default();
    let decision = can_use_biometric(
        now_unix(),
        boot_time(),
        Some(&meta),
        hw.item_present,
        false,
    );
    if let BiometricDecision::RequirePassword(reason) = decision {
        if should_disable_toggle(reason) {
            disable(&mut meta);
            save_meta(&local.data_dir, &meta)?;
            let _ = securevault_ios::biometric_delete(app).await;
        }
        return Err(reason_name(reason).into());
    }
    let b64 = securevault_ios::biometric_load(app, LOAD_REASON)
        .await
        .map_err(|load_err| {
            if matches!(
                load_err,
                securevault_ios::BiometricLoadError::NotFound
                    | securevault_ios::BiometricLoadError::Invalidated
            ) {
                disable(&mut meta);
                let _ = save_meta(&local.data_dir, &meta);
            }
            map_plugin_err(load_err)
        })?;
    let mut bytes = B64.decode(&b64).map_err(|e| e.to_string())?;
    let key = VaultKey::try_from_slice(&bytes).map_err(err);
    bytes.zeroize();
    let key = key?;
    let path = vault_path(app)?;
    let device = device_id(app)?;
    let mut unlocked = unlock_file_with_key(&path, &key).map_err(err)?;
    if let Ok(store) = sk_store(app) {
        securevault_core::vault::load_stored_secret_key(&mut unlocked, store.as_ref());
    }
    bind_device(&mut unlocked, &device);
    unlocked.bound_path = path.clone();
    prepare_sync(app, &mut unlocked)?;
    securevault_core::sync::pull_vault(&path, &mut unlocked).map_err(err)?;
    securevault_core::vault::note_local_device(&mut unlocked);
    unlocked.dirty = true;
    persist(app, &path, &mut unlocked)?;
    let state = app.state::<AppState>();
    remember_settings(&state, &unlocked.data.settings);
    let mut guard = require_unlocked(&state)?;
    *guard = Some(unlocked);
    Ok(())
}

/// After a successful master-password unlock: restamp policy metadata.
/// The keychain item survives reboot; matching boot time is what re-enables Face ID.
pub fn on_password_unlock(app: &AppHandle, key: &VaultKey) {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = (app, key);
    }
    #[cfg(target_os = "ios")]
    {
        let Ok(local) = ensure_local(app) else {
            return;
        };
        let mut meta = load_meta(&local.data_dir);
        after_password_unlock(&mut meta, now_unix(), boot_time());
        let _ = save_meta(&local.data_dir, &meta);
        let _ = key;
    }
}

/// Rewrite the Face ID keychain item after the derived key changes (password or Secret Key).
pub fn refresh_stored_key(app: &AppHandle, key: &VaultKey) {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = (app, key);
    }
    #[cfg(target_os = "ios")]
    {
        let Ok(local) = ensure_local(app) else {
            return;
        };
        let mut meta = load_meta(&local.data_dir);
        after_password_unlock(&mut meta, now_unix(), boot_time());
        let _ = save_meta(&local.data_dir, &meta);
        if !meta.enabled {
            return;
        }
        let mut bytes = key.as_bytes().to_vec();
        let b64 = B64.encode(&bytes);
        bytes.zeroize();
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = securevault_ios::biometric_store(&app, &b64).await;
        });
    }
}

#[tauri::command]
pub fn verify_master_password(state: tauri::State<'_, AppState>, password: String) -> Result<(), String> {
    let guard = require_unlocked(&state)?;
    let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
    let secret = secrecy::SecretString::new(password);
    unlocked.verify_master_password(&secret).map_err(err)
}
