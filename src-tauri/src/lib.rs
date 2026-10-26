mod ios_access;
#[cfg(target_os = "ios")]
mod ios_bookmark;
#[cfg(target_os = "ios")]
mod ios_vault_io;
mod mcp_host;
mod platform;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use securevault_core::emergency_kit::{self, EmergencyKitDoc};
use securevault_core::secret_key::SecretKey;
use securevault_core::secret_key_store::{local_secret_key_store, SecretKeyStore};
use securevault_core::sync::{self, ConflictView, SyncStatus};
use securevault_core::vault::{
    self, generate_password as vault_generate_password, import_bytes, mark_password_unlock, new_id,
    now_rfc3339, password_unlock_expired_now, unlock_file_with_key, validate_item_type,
    SettingsPatch, UnlockedVault, VaultError, VaultItem, VaultKey, VaultSettings,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroize;

#[derive(Clone)]
struct LocalState {
    device_id: String,
    vault_path: PathBuf,
    data_dir: PathBuf,
}

pub struct AppState {
    pub(crate) unlocked: Arc<Mutex<Option<UnlockedVault>>>,
    pub(crate) mcp: Mutex<Option<Arc<mcp_host::McpHost>>>,
    password_verified: AtomicBool,
    pub(crate) settings: Mutex<VaultSettings>,
    biometrics_invalidated: AtomicBool,
    local: Mutex<Option<LocalState>>,
    generation: AtomicU64,
}

fn remember_settings(state: &AppState, settings: &VaultSettings) {
    if let Ok(mut guard) = state.settings.lock() {
        *guard = settings.clone();
    }
}

fn bind_device(unlocked: &mut UnlockedVault, device_id: &str) {
    if unlocked.device_id.is_empty() {
        unlocked.device_id = device_id.to_string();
    }
}

fn prepare_sync(app: &AppHandle, unlocked: &mut UnlockedVault) -> Result<(), String> {
    let local = ensure_local(app)?;
    if unlocked.device_id.is_empty() {
        unlocked.device_id = local.device_id;
    }
    if unlocked.backup_dir.as_os_str().is_empty() {
        unlocked.backup_dir = sync::sync_backup_dir(&local.data_dir);
    }
    Ok(())
}

fn accept_password_unlock(app: &AppHandle, state: &AppState, mut unlocked: UnlockedVault) -> Result<(), String> {
    let path = vault_path(app)?;
    let device = device_id(app)?;
    if state.biometrics_invalidated.load(Ordering::Relaxed) {
        platform::delete_vault_key();
        unlocked.data.settings.biometrics_enabled = false;
        unlocked.data.settings.touch();
        state.biometrics_invalidated.store(false, Ordering::Relaxed);
    }
    bind_device(&mut unlocked, &device);
    vault::note_local_device(&mut unlocked);
    mark_password_unlock(&mut unlocked.data);
    unlocked.bound_path = path.clone();
    persist(app, &path, &mut unlocked)?;
    state.password_verified.store(true, Ordering::Relaxed);
    remember_settings(state, &unlocked.data.settings);
    let mut guard = require_unlocked(state)?;
    *guard = Some(unlocked);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsView {
    auto_lock_minutes: u32,
    lock_on_screen_lock: bool,
    biometrics_enabled: bool,
    password_interval_days: u32,
    screen_lock_supported: bool,
}

fn settings_view(settings: &VaultSettings) -> SettingsView {
    SettingsView {
        auto_lock_minutes: settings.auto_lock_minutes,
        lock_on_screen_lock: settings.lock_on_screen_lock,
        biometrics_enabled: settings.biometrics_enabled,
        password_interval_days: settings.password_interval_days,
        screen_lock_supported: platform::screen_lock_supported(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BiometricStatus {
    available: bool,
    configured: bool,
    prf: bool,
    can_unlock: bool,
    password_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    platform: &'static str,
    touch_id_reregister: bool,
}

fn biometric_view(state: &AppState, touch_id_reregister: bool) -> BiometricStatus {
    let settings = state
        .settings
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let invalidated = state.biometrics_invalidated.load(Ordering::Relaxed);
    let password_verified = state.password_verified.load(Ordering::Relaxed);
    let (password_required, reason) = if !password_verified {
        (true, Some("restart".to_string()))
    } else if password_unlock_expired_now(&settings) {
        (true, Some("interval".to_string()))
    } else {
        (false, None)
    };
    let available = platform::biometrics_available();
    let configured = settings.biometrics_enabled && !invalidated;
    BiometricStatus {
        available,
        configured,
        prf: false,
        can_unlock: available && configured && !password_required,
        password_required,
        reason,
        platform: client_platform(),
        touch_id_reregister,
    }
}

fn err(e: VaultError) -> String {
    e.to_string()
}

fn ensure_local(app: &AppHandle) -> Result<LocalState, String> {
    let state = app.state::<AppState>();
    if let Ok(guard) = state.local.lock() {
        if let Some(local) = guard.clone() {
            return Ok(local);
        }
    }
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    securevault_core::migrate::migrate_sibling_data_dir(&dir).map_err(err)?;
    let config = sync::load_or_create_local_config(&dir).map_err(err)?;
    let local = LocalState {
        device_id: config.device_id,
        vault_path: config.vault_path.unwrap_or_else(|| dir.join("vault.khv")),
        data_dir: dir,
    };
    if let Ok(mut guard) = state.local.lock() {
        if let Some(existing) = guard.clone() {
            return Ok(existing);
        }
        *guard = Some(local.clone());
    }
    Ok(local)
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(ensure_local(app)?.vault_path)
}

fn device_id(app: &AppHandle) -> Result<String, String> {
    Ok(ensure_local(app)?.device_id)
}

fn remember_vault_path(app: &AppHandle, path: PathBuf) -> Result<(), String> {
    let mut local = ensure_local(app)?;
    let saved = sync::save_vault_path(&local.data_dir, &local.device_id, &path).map_err(err)?;
    local.device_id = saved.device_id;
    local.vault_path = saved.vault_path.unwrap_or(path);
    let state = app.state::<AppState>();
    if let Ok(mut guard) = state.local.lock() {
        *guard = Some(local);
    }
    Ok(())
}

fn persist(app: &AppHandle, path: &Path, unlocked: &mut UnlockedVault) -> Result<(), String> {
    prepare_sync(app, unlocked)?;
    // iOS and desktop share persist_unlocked. The iOS name is what the compat test calls.
    #[cfg(target_os = "ios")]
    {
        securevault_core::ios_path::resave_ios_vault(path, unlocked).map_err(err)?;
    }
    #[cfg(not(target_os = "ios"))]
    {
        vault::persist_unlocked(path, unlocked).map_err(err)?;
    }
    app.state::<AppState>().generation.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn sk_store(app: &AppHandle) -> Result<Box<dyn SecretKeyStore>, String> {
    let local = ensure_local(app)?;
    Ok(local_secret_key_store(&local.data_dir))
}

fn env_secret_key() -> Option<String> {
    securevault_core::env_var("SECRET_KEY")
}

fn vault_display_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("SecureVault")
        .to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretKeyStatusView {
    enabled: bool,
    stored: bool,
    required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EmergencyKitView {
    secret_key: String,
    vault_name: String,
    date: String,
    stored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    store_error: Option<String>,
}

fn emergency_kit(
    path: &Path,
    sk: &SecretKey,
    stored: bool,
    store_error: Option<String>,
) -> EmergencyKitView {
    EmergencyKitView {
        secret_key: sk.format_display(),
        vault_name: vault_display_name(path),
        date: chrono_date(),
        stored,
        store_error,
    }
}

fn chrono_date() -> String {
    now_rfc3339().chars().take(10).collect()
}

fn remember_secret_key(store: &dyn SecretKeyStore, sk: &SecretKey) -> (bool, Option<String>) {
    match store.store(&sk.vault_id(), sk) {
        Ok(()) => (true, None),
        Err(error) => (false, Some(error.to_string())),
    }
}

async fn refresh_touch_id_if_enabled(app: &AppHandle, path: &Path) -> Result<(), String> {
    let state = app.state::<AppState>();
    let (mut key_bytes, enabled) = {
        let guard = require_unlocked(&state)?;
        let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
        (
            unlocked.key.as_bytes().to_vec(),
            unlocked.data.settings.biometrics_enabled,
        )
    };
    if !enabled {
        key_bytes.zeroize();
        return Ok(());
    }
    let refresh = tokio::task::spawn_blocking(move || {
        let result = platform::store_vault_key(&key_bytes);
        key_bytes.zeroize();
        result
    })
    .await
    .map_err(|e| e.to_string())?;
    if refresh.is_err() {
        platform::delete_vault_key();
        let mut guard = require_unlocked(&state)?;
        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
        unlocked.data.settings.biometrics_enabled = false;
        unlocked.data.settings.touch();
        persist(app, path, unlocked)?;
        remember_settings(&state, &unlocked.data.settings);
    }
    Ok(())
}

fn foreign_password(error: &VaultError) -> bool {
    matches!(
        error,
        VaultError::Tampered
            | VaultError::WrongPassword
            | VaultError::Crypto
            | VaultError::Base64(_)
            | VaultError::Json(_)
            | VaultError::SyncPasswordRequired
    )
}

fn poll_desktop(app: &AppHandle) {
    let Ok(local) = ensure_local(app) else {
        return;
    };
    let state = app.state::<AppState>();
    let Ok(mut guard) = state.unlocked.lock() else {
        return;
    };
    let Some(unlocked) = guard.as_mut() else {
        return;
    };
    if unlocked.device_id.is_empty() {
        unlocked.device_id = local.device_id.clone();
    }
    if unlocked.backup_dir.as_os_str().is_empty() {
        unlocked.backup_dir = sync::sync_backup_dir(&local.data_dir);
    }
    if !unlocked.bound_path.as_os_str().is_empty() && unlocked.bound_path != local.vault_path {
        return;
    }
    let before = sync::content_fingerprint(&unlocked.data);
    if sync::pull_vault(&local.vault_path, unlocked).is_ok() {
        let after = sync::content_fingerprint(&unlocked.data);
        if before != after {
            state.generation.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn require_unlocked(state: &AppState) -> Result<std::sync::MutexGuard<'_, Option<UnlockedVault>>, String> {
    state
        .unlocked
        .lock()
        .map_err(|_| "lock poisoned".to_string())
}

#[tauri::command]
fn vault_exists(app: AppHandle) -> Result<bool, String> {
    let path = vault_path(&app)?;
    let placeholder = sync::icloud_placeholder(&path).is_some_and(|candidate| candidate.exists());
    Ok(securevault_core::vault_io::exists(&path) || placeholder)
}

#[tauri::command]
fn discover_vaults() -> Result<Vec<sync::DiscoveredVault>, String> {
    Ok(sync::discover_icloud_vaults())
}

#[tauri::command]
fn open_existing_vault(app: AppHandle, state: State<AppState>, path: String) -> Result<sync::OpenVaultStatus, String> {
    if state
        .unlocked
        .lock()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
    {
        return Err(err(VaultError::AlreadyExists));
    }
    let chosen = sync::user_path(&path);
    let status = sync::classify_vault_candidate(&chosen).map_err(err)?;
    if status.state == "ready" {
        remember_vault_path(&app, PathBuf::from(&status.path))?;
    }
    Ok(status)
}

#[tauri::command]
fn create_vault(app: AppHandle, state: State<AppState>, password: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    let secret = SecretString::new(password);
    let unlocked = vault::create_vault_at(&path, &secret).map_err(err)?;
    accept_password_unlock(&app, &state, unlocked)
}

#[tauri::command]
fn unlock(
    app: AppHandle,
    state: State<AppState>,
    password: String,
    secret_key: Option<String>,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let store = sk_store(&app)?;
    let typed = secret_key
        .filter(|value| !value.trim().is_empty())
        .or_else(env_secret_key);
    let secret = SecretString::new(password);
    #[cfg(target_os = "ios")]
    let unlocked = {
        let device = device_id(&app)?;
        let name = vault::local_device_name();
        securevault_core::ios_path::open_ios_vault(
            &path,
            &secret,
            typed.as_deref(),
            Some(store.as_ref()),
            &device,
            &name,
        )
        .map_err(err)?
    };
    #[cfg(not(target_os = "ios"))]
    let unlocked = vault::unlock_file_with_secret_key(
        &path,
        &secret,
        typed.as_deref(),
        Some(store.as_ref()),
    )
    .map_err(err)?;
    if let Some(sk) = unlocked.secret_key.as_ref() {
        let _ = store.store(&sk.vault_id(), sk);
    }
    accept_password_unlock(&app, &state, unlocked)
}

#[tauri::command]
fn secret_key_status(app: AppHandle) -> Result<SecretKeyStatusView, String> {
    let path = vault_path(&app)?;
    let store = sk_store(&app)?;
    if !securevault_core::vault_io::exists(&path) {
        return Ok(SecretKeyStatusView {
            enabled: false,
            stored: false,
            required: false,
        });
    }
    let (enabled, fingerprint) = vault::peek_secret_key_header(&path).map_err(err)?;
    let stored = if enabled {
        if env_secret_key().is_some() {
            true
        } else if let Some(fp) = fingerprint.as_deref() {
            match securevault_core::secret_key::vault_id_from_fingerprint_b64(fp) {
                Ok(id) => store.load(&id).ok().flatten().is_some(),
                Err(_) => false,
            }
        } else {
            false
        }
    } else {
        false
    };
    Ok(SecretKeyStatusView {
        enabled,
        stored,
        required: enabled && !stored,
    })
}

#[tauri::command]
fn import_secret_key(app: AppHandle, secret_key: String) -> Result<SecretKeyStatusView, String> {
    let path = vault_path(&app)?;
    let store = sk_store(&app)?;
    let (enabled, fingerprint) = vault::peek_secret_key_header(&path).map_err(err)?;
    if !enabled {
        return Err("이 금고는 Secret Key를 쓰지 않습니다.".into());
    }
    let sk = SecretKey::parse(&secret_key).map_err(err)?;
    if Some(sk.fingerprint_b64()) != fingerprint {
        return Err(err(VaultError::SecretKeyMismatch));
    }
    let _ = store.store(&sk.vault_id(), &sk);
    secret_key_status(app)
}

#[tauri::command]
async fn enable_secret_key(app: AppHandle, password: String) -> Result<EmergencyKitView, String> {
    let path = vault_path(&app)?;
    let store = sk_store(&app)?;
    let secret = SecretString::new(password);
    let sk = {
        let state = app.state::<AppState>();
        let device = device_id(&app)?;
        let mut guard = require_unlocked(&state)?;
        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
        bind_device(unlocked, &device);
        // iPhone must not become the manager just by turning the Secret Key on.
        #[cfg(target_os = "ios")]
        let sk = unlocked.enable_secret_key_claiming(&secret, false).map_err(err)?;
        #[cfg(not(target_os = "ios"))]
        let sk = unlocked.enable_secret_key(&secret).map_err(err)?;
        unlocked.dirty = true;
        persist(&app, &path, unlocked)?;
        sk
    };
    let (stored, store_error) = remember_secret_key(store.as_ref(), &sk);
    refresh_touch_id_if_enabled(&app, &path).await?;
    Ok(emergency_kit(&path, &sk, stored, store_error))
}

#[tauri::command]
async fn disable_secret_key(
    app: AppHandle,
    password: String,
    secret_key: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let store = sk_store(&app)?;
    let secret = SecretString::new(password);
    let sk = SecretKey::parse(&secret_key).map_err(err)?;
    let vault_id = sk.vault_id();
    {
        let state = app.state::<AppState>();
        let device = device_id(&app)?;
        let mut guard = require_unlocked(&state)?;
        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
        bind_device(unlocked, &device);
        unlocked.disable_secret_key(&secret, &sk).map_err(err)?;
        unlocked.dirty = true;
        persist(&app, &path, unlocked)?;
    }
    let _ = store.delete(&vault_id);
    refresh_touch_id_if_enabled(&app, &path).await?;
    Ok(())
}

#[tauri::command]
async fn rotate_secret_key(
    app: AppHandle,
    password: String,
    secret_key: String,
) -> Result<EmergencyKitView, String> {
    let path = vault_path(&app)?;
    let store = sk_store(&app)?;
    let secret = SecretString::new(password);
    let current = SecretKey::parse(&secret_key).map_err(err)?;
    let old_id = current.vault_id();
    let sk = {
        let state = app.state::<AppState>();
        let device = device_id(&app)?;
        let mut guard = require_unlocked(&state)?;
        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
        bind_device(unlocked, &device);
        let sk = unlocked.rotate_secret_key(&secret, &current).map_err(err)?;
        unlocked.dirty = true;
        persist(&app, &path, unlocked)?;
        sk
    };
    let _ = store.delete(&old_id);
    let (stored, store_error) = remember_secret_key(store.as_ref(), &sk);
    refresh_touch_id_if_enabled(&app, &path).await?;
    Ok(emergency_kit(&path, &sk, stored, store_error))
}

#[tauri::command]
fn device_manager_status(app: AppHandle) -> Result<vault::DeviceManagerStatus, String> {
    let state = app.state::<AppState>();
    let device = device_id(&app)?;
    let guard = require_unlocked(&state)?;
    let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
    let mut view = unlocked.device_manager_status();
    if view.device_id.is_empty() {
        view.device_id = device;
    }
    Ok(view)
}

#[tauri::command]
fn designate_manager(app: AppHandle, password: String, secret_key: String) -> Result<vault::DeviceManagerStatus, String> {
    let path = vault_path(&app)?;
    let secret = SecretString::new(password);
    let sk = SecretKey::parse(&secret_key).map_err(err)?;
    let state = app.state::<AppState>();
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    unlocked.designate_manager(&secret, &sk).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    Ok(unlocked.device_manager_status())
}

#[tauri::command]
fn takeover_manager(app: AppHandle, password: String, secret_key: String) -> Result<vault::DeviceManagerStatus, String> {
    let path = vault_path(&app)?;
    let secret = SecretString::new(password);
    let sk = SecretKey::parse(&secret_key).map_err(err)?;
    let state = app.state::<AppState>();
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    unlocked.takeover_manager(&secret, &sk).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    Ok(unlocked.device_manager_status())
}

#[tauri::command]
fn handover_manager(app: AppHandle, device_id: String) -> Result<vault::DeviceManagerStatus, String> {
    let path = vault_path(&app)?;
    let state = app.state::<AppState>();
    let local_device = ensure_local(&app)?.device_id;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &local_device);
    unlocked.handover_manager(&device_id).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    Ok(unlocked.device_manager_status())
}

#[tauri::command]
fn reveal_secret_key(app: AppHandle, password: String) -> Result<EmergencyKitView, String> {
    let path = vault_path(&app)?;
    let store = sk_store(&app)?;
    let secret = SecretString::new(password);
    let state = app.state::<AppState>();
    let guard = require_unlocked(&state)?;
    let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
    unlocked.verify_master_password(&secret).map_err(err)?;
    let sk = if let Some(sk) = unlocked.secret_key.clone() {
        sk
    } else if let Some(fp) = unlocked.fingerprint_b64() {
        let id = securevault_core::secret_key::vault_id_from_fingerprint_b64(&fp).map_err(err)?;
        store
            .load(&id)
            .map_err(err)?
            .ok_or_else(|| err(VaultError::SecretKeyRequired))?
    } else {
        return Err(err(VaultError::SecretKeyRequired));
    };
    if let Some(expected) = unlocked.fingerprint_b64() {
        if sk.fingerprint_b64() != expected {
            return Err(err(VaultError::SecretKeyMismatch));
        }
    }
    Ok(emergency_kit(&path, &sk, true, None))
}

#[tauri::command]
fn lock(state: State<AppState>) -> Result<(), String> {
    let mut guard = require_unlocked(&state)?;
    *guard = None;
    Ok(())
}

#[tauri::command]
fn is_unlocked(state: State<AppState>) -> Result<bool, String> {
    let guard = require_unlocked(&state)?;
    Ok(guard.is_some())
}

#[tauri::command]
fn list_items(state: State<AppState>) -> Result<Vec<VaultItem>, String> {
    let guard = require_unlocked(&state)?;
    let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
    let mut items = unlocked.data.items.clone();
    sync::sort_items(&mut items);
    Ok(items)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppBuild {
    version: String,
    commit: String,
}

#[tauri::command]
fn client_platform() -> &'static str {
    #[cfg(target_os = "ios")]
    {
        "ios"
    }
    #[cfg(not(target_os = "ios"))]
    {
        if platform::biometrics_available() {
            "macos"
        } else {
            "unsupported"
        }
    }
}

fn store_picked_vault(app: &AppHandle, path: &Path, bookmark: &str) -> Result<String, String> {
    let local = ensure_local(app)?;
    let record_path;
    let record_bookmark;
    if !bookmark.trim().is_empty() {
        record_path = path.display().to_string();
        record_bookmark = bookmark.to_string();
        remember_vault_path(app, path.to_path_buf())?;
        #[cfg(target_os = "ios")]
        ios_vault_io::install(app, &vault_path(app)?, bookmark, &local.data_dir)?;
    } else {
        let copied = ios_access::copy_into_app_dir(&local.data_dir, path)?;
        record_path = copied.display().to_string();
        record_bookmark = String::new();
        remember_vault_path(app, copied)?;
    }
    ios_access::save_record(
        &local.data_dir,
        &ios_access::VaultAccessRecord {
            path: record_path.clone(),
            bookmark: record_bookmark,
        },
    )?;
    Ok(record_path)
}

#[tauri::command]
async fn ios_plugin_status(app: AppHandle) -> Result<String, String> {
    #[cfg(target_os = "ios")]
    {
        let result = match securevault_ios::ping(&app).await {
            Ok(ping) if ping.ok => {
                let app2 = app.clone();
                match tauri::async_runtime::spawn_blocking(move || ios_vault_io::self_test(&app2)).await {
                    Ok(Ok(io)) => Ok(format!("{} {io}", ping.plugin)),
                    Ok(Err(e)) => Err(format!("파일 입출력 자체 점검 실패: {e}")),
                    Err(e) => Err(e.to_string()),
                }
            }
            Ok(_) => Err("vault-access 플러그인이 ok를 돌려주지 않았습니다.".to_string()),
            Err(err) => Err(err),
        };
        // CI reads this marker from the simulator app container.
        if let Ok(local) = ensure_local(&app) {
            let line = match &result {
                Ok(name) => format!("ok {name}\n"),
                Err(err) => format!("error {err}\n"),
            };
            let _ = std::fs::create_dir_all(&local.data_dir);
            let _ = std::fs::write(local.data_dir.join("plugin-status.txt"), line);
        }
        return result;
    }
    #[cfg(not(target_os = "ios"))]
    {
        let _ = app;
        Ok("desktop".into())
    }
}

#[tauri::command]
async fn pick_ios_vault(app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = app;
        return Err("iOS에서만 문서를 고를 수 있습니다.".into());
    }
    #[cfg(target_os = "ios")]
    {
        let picked = securevault_ios::pick(&app).await?;
        if picked.cancelled || picked.path.trim().is_empty() {
            return Ok(None);
        }
        let path = PathBuf::from(&picked.path);
        if picked.copied {
            let local = ensure_local(&app)?;
            ios_access::save_record(
                &local.data_dir,
                &ios_access::VaultAccessRecord {
                    path: picked.path.clone(),
                    bookmark: String::new(),
                },
            )?;
            remember_vault_path(&app, path)?;
            return Ok(Some(picked.path));
        }
        Ok(Some(store_picked_vault(&app, &path, &picked.bookmark)?))
    }
}

#[tauri::command]
fn adopt_ios_vault_path(app: AppHandle, path: String) -> Result<String, String> {
    let source = PathBuf::from(&path);
    if path.trim().is_empty() || !source.is_file() {
        return Err("금고 파일을 찾지 못했습니다.".into());
    }
    #[cfg(target_os = "ios")]
    if let Some(bookmark) = ios_bookmark::create_bookmark(&source) {
        return store_picked_vault(&app, &source, &bookmark);
    }
    store_picked_vault(&app, &source, "")
}

#[tauri::command]
fn app_build() -> AppBuild {
    AppBuild {
        version: securevault_core::VERSION.to_string(),
        commit: securevault_core::GIT_COMMIT.to_string(),
    }
}

#[tauri::command]
fn move_item(
    app: AppHandle,
    state: State<AppState>,
    id: String,
    before_id: Option<String>,
) -> Result<VaultItem, String> {
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    let before = before_id.as_deref().filter(|value| !value.is_empty());
    let moved = sync::move_item(&mut unlocked.data, &id, before, &unlocked.device_id).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    Ok(moved)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItemDraft {
    item_type: String,
    title: String,
    #[serde(default)]
    favorite: bool,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    cardholder: Option<String>,
    number: Option<String>,
    expiry: Option<String>,
    cvv: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

fn draft_to_item(draft: ItemDraft, id: String, created_at: String, updated_at: String) -> Result<VaultItem, String> {
    validate_item_type(&draft.item_type).map_err(err)?;
    Ok(VaultItem {
        id,
        item_type: draft.item_type,
        title: draft.title,
        favorite: draft.favorite,
        created_at,
        updated_at,
        username: draft.username,
        password: draft.password,
        url: draft.url,
        notes: draft.notes,
        cardholder: draft.cardholder,
        number: draft.number,
        expiry: draft.expiry,
        cvv: draft.cvv,
        tags: draft.tags,
        ..VaultItem::skeleton()
    })
}

#[tauri::command]
fn add_item(app: AppHandle, state: State<AppState>, item: ItemDraft) -> Result<VaultItem, String> {
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let now = now_rfc3339();
    let new_item = draft_to_item(item, new_id(), now.clone(), now)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    let stored = sync::insert_new(&mut unlocked.data, new_item, &unlocked.device_id);
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    Ok(stored)
}

#[tauri::command]
fn update_item(app: AppHandle, state: State<AppState>, item: VaultItem) -> Result<VaultItem, String> {
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    let updated = sync::update_existing(&mut unlocked.data, item, &unlocked.device_id).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    Ok(updated)
}

#[tauri::command]
fn delete_item(app: AppHandle, state: State<AppState>, id: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    sync::delete_item(&mut unlocked.data, &id, &unlocked.device_id).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)
}

#[tauri::command]
async fn change_master_password(
    app: AppHandle,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let (mut key_bytes, enabled) = {
        let mut guard = require_unlocked(&state)?;
        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
        bind_device(unlocked, &device);
        let current = SecretString::new(current_password);
        let new_secret = SecretString::new(new_password);
        unlocked
            .change_master_password(&current, &new_secret)
            .map_err(err)?;
        persist(&app, &path, unlocked)?;
        (
            unlocked.key.as_bytes().to_vec(),
            unlocked.data.settings.biometrics_enabled,
        )
    };
    if !enabled {
        key_bytes.zeroize();
        return Ok(());
    }
    let refresh = tokio::task::spawn_blocking(move || {
        let result = platform::store_vault_key(&key_bytes);
        key_bytes.zeroize();
        result
    })
    .await
    .map_err(|e| e.to_string())?;
    if refresh.is_err() {
        platform::delete_vault_key();
        let state = app.state::<AppState>();
        let mut guard = require_unlocked(&state)?;
        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
        unlocked.data.settings.biometrics_enabled = false;
        unlocked.data.settings.touch();
        persist(&app, &path, unlocked)?;
        remember_settings(&state, &unlocked.data.settings);
    }
    Ok(())
}

#[tauri::command]
fn get_vault_settings(state: State<AppState>) -> Result<SettingsView, String> {
    let guard = require_unlocked(&state)?;
    let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
    Ok(settings_view(&unlocked.data.settings))
}

#[tauri::command]
fn update_vault_settings(app: AppHandle, state: State<AppState>, patch: SettingsPatch) -> Result<SettingsView, String> {
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    unlocked.data.settings.apply_patch(&patch).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    let settings = unlocked.data.settings.clone();
    drop(guard);
    remember_settings(&state, &settings);
    Ok(settings_view(&settings))
}

#[tauri::command]
fn screen_lock_supported() -> bool {
    platform::screen_lock_supported()
}

#[tauri::command]
async fn biometric_status(app: AppHandle) -> Result<BiometricStatus, String> {
    let local = ensure_local(&app)?;
    let dir = local.data_dir.clone();
    tokio::task::spawn_blocking(move || platform::migrate_touch_id_keychain(&dir))
        .await
        .map_err(|err| err.to_string())?;
    let flag = securevault_core::migrate::touch_id_reregister_pending(&local.data_dir);
    let state = app.state::<AppState>();
    Ok(biometric_view(&state, flag))
}

#[tauri::command]
async fn biometric_enable(app: AppHandle) -> Result<BiometricStatus, String> {
    let state = app.state::<AppState>();
    let path = vault_path(&app)?;
    let mut key_bytes = {
        let guard = require_unlocked(&state)?;
        let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
        unlocked.key.as_bytes().to_vec()
    };
    tokio::task::spawn_blocking(move || {
        let result = platform::store_vault_key(&key_bytes);
        key_bytes.zeroize();
        result
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(err)?;
    let state = app.state::<AppState>();
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    unlocked.data.settings.biometrics_enabled = true;
    unlocked.data.settings.touch();
    state.biometrics_invalidated.store(false, Ordering::Relaxed);
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    remember_settings(&state, &unlocked.data.settings);
    if let Ok(local) = ensure_local(&app) {
        securevault_core::migrate::clear_touch_id_reregister(&local.data_dir);
    }
    Ok(biometric_view(&state, false))
}

#[tauri::command]
fn biometric_disable(app: AppHandle, state: State<AppState>) -> Result<BiometricStatus, String> {
    platform::delete_vault_key();
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    unlocked.data.settings.biometrics_enabled = false;
    unlocked.data.settings.touch();
    state.biometrics_invalidated.store(false, Ordering::Relaxed);
    unlocked.dirty = true;
    persist(&app, &path, unlocked)?;
    remember_settings(&state, &unlocked.data.settings);
    let flag = ensure_local(&app)
        .map(|local| securevault_core::migrate::touch_id_reregister_pending(&local.data_dir))
        .unwrap_or(false);
    Ok(biometric_view(&state, flag))
}

#[tauri::command]
async fn biometric_unlock(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    if !state.password_verified.load(Ordering::Relaxed) {
        return Err(err(VaultError::MasterPasswordRequired));
    }
    let cached = state
        .settings
        .lock()
        .map_err(|_| "lock poisoned".to_string())?
        .clone();
    if password_unlock_expired_now(&cached) {
        return Err(err(VaultError::MasterPasswordRequired));
    }
    if !cached.biometrics_enabled || state.biometrics_invalidated.load(Ordering::Relaxed) {
        return Err(err(VaultError::BiometricsUnavailable));
    }
    let loaded = tokio::task::spawn_blocking(platform::load_vault_key)
        .await
        .map_err(|e| e.to_string())?;
    let mut bytes = match loaded {
        Ok(bytes) => bytes,
        Err(VaultError::BiometricsInvalidated) => {
            state.biometrics_invalidated.store(true, Ordering::Relaxed);
            return Err(err(VaultError::BiometricsInvalidated));
        }
        Err(err) => return Err(err.to_string()),
    };
    let key = VaultKey::try_from_slice(&bytes).map_err(err);
    bytes.zeroize();
    let key = key?;
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let mut unlocked = unlock_file_with_key(&path, &key).map_err(err)?;
    if let Ok(store) = sk_store(&app) {
        vault::load_stored_secret_key(&mut unlocked, store.as_ref());
    }
    if password_unlock_expired_now(&unlocked.data.settings) {
        return Err(err(VaultError::MasterPasswordRequired));
    }
    if !unlocked.data.settings.biometrics_enabled {
        return Err(err(VaultError::BiometricsUnavailable));
    }
    bind_device(&mut unlocked, &device);
    unlocked.bound_path = path.clone();
    prepare_sync(&app, &mut unlocked)?;
    sync::pull_vault(&path, &mut unlocked).map_err(err)?;
    vault::note_local_device(&mut unlocked);
    unlocked.dirty = true;
    persist(&app, &path, &mut unlocked)?;
    remember_settings(&state, &unlocked.data.settings);
    let mut guard = require_unlocked(&state)?;
    *guard = Some(unlocked);
    Ok(())
}

#[tauri::command]
fn generate_password(
    length: u32,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, String> {
    vault_generate_password(length as usize, upper, lower, digits, symbols).map_err(err)
}

#[tauri::command]
fn export_vault(
    state: State<AppState>,
    path: String,
    export_password: String,
) -> Result<(), String> {
    let guard = require_unlocked(&state)?;
    let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
    let secret = SecretString::new(export_password);
    let bytes = vault::export_bytes(&unlocked.data, &secret).map_err(err)?;
    vault::atomic_write(&PathBuf::from(path), &bytes).map_err(err)
}

#[tauri::command]
fn import_vault(
    app: AppHandle,
    state: State<AppState>,
    path: String,
    export_password: String,
    mode: String,
) -> Result<(), String> {
    let vault_file = vault_path(&app)?;
    let device = device_id(&app)?;
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let secret = SecretString::new(export_password);
    let imported = import_bytes(&bytes, &secret).map_err(err)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    match mode.as_str() {
        "replace" => unlocked.data = imported,
        "merge" => unlocked.data.merge(imported),
        _ => return Err("mode must be merge or replace".into()),
    }
    let settings = unlocked.data.settings.clone();
    unlocked.dirty = true;
    persist(&app, &vault_file, unlocked)?;
    remember_settings(&state, &settings);
    Ok(())
}

#[tauri::command]
fn sync_status(app: AppHandle) -> Result<SyncStatus, String> {
    poll_desktop(&app);
    let state = app.state::<AppState>();
    let local = ensure_local(&app)?;
    let guard = state.unlocked.lock().map_err(|_| "lock poisoned".to_string())?;
    let unlocked = guard.as_ref();
    Ok(sync::status_of(
        &local.vault_path,
        &local.device_id,
        unlocked,
        state.generation.load(Ordering::Relaxed),
        unlocked.is_none(),
    ))
}

#[tauri::command]
fn sync_conflicts(state: State<AppState>) -> Result<Vec<ConflictView>, String> {
    let guard = require_unlocked(&state)?;
    let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
    Ok(sync::list_conflicts(&unlocked.data))
}

#[tauri::command]
fn resolve_sync_conflict(
    app: AppHandle,
    item_id: String,
    conflict_id: String,
    action: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let device = device_id(&app)?;
    let state = app.state::<AppState>();
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    sync::resolve_conflict(&mut unlocked.data, &item_id, &conflict_id, &action, &unlocked.device_id)
        .map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &path, unlocked)
}

#[tauri::command]
fn set_vault_location(app: AppHandle, path: String, mode: String) -> Result<SyncStatus, String> {
    let dest = sync::normalize_path(&sync::user_path(&path));
    sync::require_absolute(&dest).map_err(err)?;
    let state = app.state::<AppState>();
    match mode.as_str() {
        "move" => {
            let src = vault_path(&app)?;
            let device = device_id(&app)?;
            {
                let mut guard = require_unlocked(&state)?;
                let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
                bind_device(unlocked, &device);
                unlocked.dirty = true;
                persist(&app, &src, unlocked)?;
                unlocked.bound_path = dest.clone();
            }
            if let Err(error) = sync::relocate_vault_file(&src, &dest) {
                if let Ok(mut guard) = state.unlocked.lock() {
                    if let Some(unlocked) = guard.as_mut() {
                        unlocked.bound_path = src;
                    }
                }
                return Err(err(error));
            }
            remember_vault_path(&app, dest)?;
        }
        "open" => {
            let exists = dest.exists();
            let placeholder = sync::icloud_placeholder(&dest).is_some_and(|candidate| candidate.exists());
            if !exists && placeholder {
                sync::prompt_icloud_download(&dest);
                {
                    let mut guard = require_unlocked(&state)?;
                    *guard = None;
                }
                remember_vault_path(&app, dest)?;
                return sync_status(app);
            }
            if !exists {
                return Err(err(VaultError::NotFound));
            }
            let key = {
                let guard = require_unlocked(&state)?;
                let unlocked = guard.as_ref().ok_or_else(|| err(VaultError::Locked))?;
                unlocked.key.clone()
            };
            match vault::unlock_file_with_key(&dest, &key) {
                Ok(opened) => {
                    let device = device_id(&app)?;
                    {
                        let mut guard = require_unlocked(&state)?;
                        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
                        unlocked.data = opened.data;
                        unlocked.stamp = opened.stamp;
                        unlocked.dirty = false;
                        unlocked.pending_password_files.clear();
                        unlocked.waiting_icloud = false;
                        unlocked.sync_error = None;
                        bind_device(unlocked, &device);
                        unlocked.bound_path = dest.clone();
                    }
                    remember_vault_path(&app, dest)?;
                    state.generation.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) if foreign_password(&error) => {
                    {
                        let mut guard = require_unlocked(&state)?;
                        *guard = None;
                    }
                    remember_vault_path(&app, dest)?;
                    return Err(err(VaultError::SyncPasswordRequired));
                }
                Err(error) => return Err(err(error)),
            }
        }
        _ => return Err("mode must be move or open".into()),
    }
    sync_status(app)
}

#[tauri::command]
fn merge_sync_password(app: AppHandle, path: String, password: String) -> Result<(), String> {
    let foreign = sync::normalize_path(&sync::user_path(&path));
    sync::require_absolute(&foreign).map_err(err)?;
    let main = vault_path(&app)?;
    let device = device_id(&app)?;
    let state = app.state::<AppState>();
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    bind_device(unlocked, &device);
    let secret = SecretString::new(password);
    sync::merge_with_password(&main, &foreign, &secret, unlocked).map_err(err)?;
    unlocked.dirty = true;
    persist(&app, &main, unlocked)
}

fn documents_dir(app: &AppHandle) -> Option<PathBuf> {
    app.path().document_dir().ok()
}

fn save_bytes_with_dialog(
    app: &AppHandle,
    title: &str,
    file_name: &str,
    filter_name: &str,
    extensions: &[&str],
    bytes: &[u8],
) -> Result<Option<String>, String> {
    let mut builder = app
        .dialog()
        .file()
        .set_title(title)
        .set_file_name(file_name)
        .add_filter(filter_name, extensions);
    if let Some(dir) = documents_dir(app) {
        builder = builder.set_directory(dir);
    }
    #[cfg(desktop)]
    if let Some(window) = app.get_webview_window("main") {
        builder = builder.set_parent(&window);
    }
    let Some(file) = builder.blocking_save_file() else {
        return Ok(None);
    };
    let path = file
        .into_path()
        .map_err(|_| "파일을 저장하지 못했습니다.".to_string())?;
    std::fs::write(&path, bytes).map_err(|_| "파일을 저장하지 못했습니다.".to_string())?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[tauri::command]
async fn save_emergency_kit_pdf(
    app: AppHandle,
    secret_key: String,
    vault_name: String,
    date: String,
) -> Result<Option<String>, String> {
    let bytes = tokio::task::spawn_blocking(move || {
        emergency_kit::render_pdf(&EmergencyKitDoc {
            secret_key: &secret_key,
            vault_name: &vault_name,
            date: &date,
        })
    })
    .await
    .map_err(|_| "PDF를 만들지 못했습니다.".to_string())?
    .map_err(|_| "PDF를 만들지 못했습니다.".to_string())?;
    save_bytes_with_dialog(
        &app,
        "비상 키트 PDF 저장",
        "SecureVault Emergency Kit.pdf",
        "PDF",
        &["pdf"],
        &bytes,
    )
}

#[tauri::command]
async fn print_emergency_kit(
    app: AppHandle,
    secret_key: String,
    vault_name: String,
    date: String,
) -> Result<(), String> {
    let bytes = tokio::task::spawn_blocking(move || {
        emergency_kit::render_pdf(&EmergencyKitDoc {
            secret_key: &secret_key,
            vault_name: &vault_name,
            date: &date,
        })
    })
    .await
    .map_err(|_| "PDF를 만들지 못했습니다.".to_string())?
    .map_err(|_| "PDF를 만들지 못했습니다.".to_string())?;
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    std::fs::create_dir_all(&dir)
        .map_err(|_| "인쇄용 PDF를 저장할 폴더를 만들지 못했습니다.".to_string())?;
    let path = dir.join("emergency-kit-print.pdf");
    std::fs::write(&path, bytes).map_err(|_| "인쇄용 PDF를 저장하지 못했습니다.".to_string())?;
    open_saved_file_preview(path.to_string_lossy().into_owned())
}

#[tauri::command]
async fn save_secret_key_qr(app: AppHandle, secret_key: String) -> Result<Option<String>, String> {
    let bytes = tokio::task::spawn_blocking(move || emergency_kit::render_qr_png(&secret_key))
        .await
        .map_err(|_| "QR 이미지를 만들지 못했습니다.".to_string())?
        .map_err(|_| "QR 이미지를 만들지 못했습니다.".to_string())?;
    save_bytes_with_dialog(
        &app,
        "Secret Key QR 저장",
        "SecureVault Secret Key QR.png",
        "PNG",
        &["png"],
        &bytes,
    )
}

fn spawn_checked(program: &str, args: &[&str], fail: &str) -> Result<(), String> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|_| fail.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(fail.to_string())
    }
}

#[tauri::command]
fn reveal_saved_file(path: String) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("파일 경로가 없습니다.".into());
    }
    #[cfg(target_os = "macos")]
    {
        return spawn_checked("open", &["-R", &path], "Finder에서 파일을 보여주지 못했습니다.");
    }
    #[cfg(target_os = "windows")]
    {
        return spawn_checked(
            "explorer",
            &["/select,", &path],
            "파일 위치에서 보여주지 못했습니다.",
        );
    }
    #[cfg(target_os = "ios")]
    {
        let _ = path;
        return Err("iOS에서는 파일 앱에서 직접 여세요.".into());
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows"), not(target_os = "ios")))]
    {
        let parent = Path::new(&path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        spawn_checked(
            "xdg-open",
            &[parent.to_str().unwrap_or(".")],
            "파일 위치에서 보여주지 못했습니다.",
        )
    }
}

#[tauri::command]
fn open_saved_file_preview(path: String) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("파일 경로가 없습니다.".into());
    }
    #[cfg(target_os = "macos")]
    {
        return spawn_checked(
            "open",
            &["-a", "Preview", &path],
            "Preview에서 파일을 열지 못했습니다.",
        );
    }
    #[cfg(target_os = "windows")]
    {
        return spawn_checked("cmd", &["/C", "start", "", &path], "파일을 열지 못했습니다.");
    }
    #[cfg(target_os = "ios")]
    {
        let _ = path;
        return Err("iOS에서는 미리보기를 열 수 없습니다. PDF로 저장한 뒤 파일 앱에서 여세요.".into());
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows"), not(target_os = "ios")))]
    {
        spawn_checked("xdg-open", &[&path], "파일을 열지 못했습니다.")
    }
}

#[tauri::command]
fn copy_to_clipboard(app: AppHandle, text: String, clear_after_secs: u64) -> Result<(), String> {
    app.clipboard()
        .write_text(text.clone())
        .map_err(|e| e.to_string())?;
    if clear_after_secs == 0 {
        return Ok(());
    }
    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(clear_after_secs));
        let current = handle.clipboard().read_text().ok();
        let matches = match current {
            Some(value) => value == text,
            None => false,
        };
        if matches {
            if handle.clipboard().clear().is_err() {
                let mut empty = String::new();
                let _ = handle.clipboard().write_text(empty.clone());
                empty.zeroize();
            }
        }
    });
    Ok(())
}

fn restore_bookmarked_vault(app: &AppHandle) {
    let Ok(local) = ensure_local(app) else {
        return;
    };
    if let Some(path) = ios_access::restore(&local.data_dir) {
        let _ = remember_vault_path(app, path);
        #[cfg(target_os = "ios")]
        if let Some(record) = ios_access::load_record(&local.data_dir) {
            if !record.bookmark.trim().is_empty() {
                if let Ok(path) = vault_path(app) {
                    let _ = ios_vault_io::install(app, &path, &record.bookmark, &local.data_dir);
                }
            }
        }
    }
}

fn demo_requested() -> bool {
    matches!(
        securevault_core::env_var("DEMO").as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn prepare_demo(app: &AppHandle) {
    if !demo_requested() {
        return;
    }
    if let Err(err) = prepare_demo_inner(app) {
        eprintln!("securevault demo: {err}");
    }
}

fn prepare_demo_inner(app: &AppHandle) -> Result<(), String> {
    let local = ensure_local(app)?;
    let path = local.data_dir.join("demo-vault.khv");
    remember_vault_path(app, path.clone())?;
    let password = SecretString::new("demo-password".to_string());
    let mut unlocked = if path.is_file() {
        vault::unlock_file(&path, &password).map_err(err)?
    } else {
        vault::create_vault_at(&path, &password).map_err(err)?
    };
    if unlocked.data.items.is_empty() {
        let mut login = VaultItem::skeleton();
        login.item_type = "login".to_string();
        login.title = "예시 메일".to_string();
        login.username = Some("ada@example.invalid".to_string());
        login.password = Some("dummy-not-secret".to_string());
        login.url = Some("https://example.invalid".to_string());
        login.notes = Some("더미 데이터".to_string());
        let mut card = VaultItem::skeleton();
        card.item_type = "card".to_string();
        card.title = "예시 카드".to_string();
        card.cardholder = Some("DUMMY USER".to_string());
        card.number = Some("0000 0000 0000 0000".to_string());
        card.expiry = Some("01/30".to_string());
        card.cvv = Some("000".to_string());
        card.notes = Some("더미 데이터".to_string());
        let mut note = VaultItem::skeleton();
        note.item_type = "note".to_string();
        note.title = "예시 메모".to_string();
        note.notes = Some("더미 데이터. 실제 비밀이 아닙니다.".to_string());
        for item in [login, card, note] {
            sync::insert_new(&mut unlocked.data, item, &local.device_id);
        }
    }
    unlocked.data.settings.auto_lock_minutes = 60;
    unlocked.dirty = true;
    let state = app.state::<AppState>();
    accept_password_unlock(app, &state, unlocked)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(securevault_ios::init());
    #[cfg(target_os = "ios")]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    builder
        .manage(AppState {
            unlocked: Arc::new(Mutex::new(None)),
            mcp: Mutex::new(None),
            password_verified: AtomicBool::new(false),
            settings: Mutex::new(VaultSettings::default()),
            biometrics_invalidated: AtomicBool::new(false),
            local: Mutex::new(None),
            generation: AtomicU64::new(0),
        })
        .invoke_handler(tauri::generate_handler![
            ios_plugin_status,
            vault_exists,
            discover_vaults,
            open_existing_vault,
            create_vault,
            unlock,
            secret_key_status,
            import_secret_key,
            enable_secret_key,
            disable_secret_key,
            rotate_secret_key,
            reveal_secret_key,
            device_manager_status,
            designate_manager,
            takeover_manager,
            handover_manager,
            lock,
            is_unlocked,
            list_items,
            add_item,
            update_item,
            delete_item,
            move_item,
            app_build,
            change_master_password,
            generate_password,
            export_vault,
            import_vault,
            copy_to_clipboard,
            save_emergency_kit_pdf,
            print_emergency_kit,
            save_secret_key_qr,
            reveal_saved_file,
            open_saved_file_preview,
            client_platform,
            pick_ios_vault,
            adopt_ios_vault_path,
            get_vault_settings,
            update_vault_settings,
            screen_lock_supported,
            biometric_status,
            biometric_enable,
            biometric_disable,
            biometric_unlock,
            sync_status,
            sync_conflicts,
            resolve_sync_conflict,
            set_vault_location,
            merge_sync_password,
            mcp_host::mcp_get_settings,
            mcp_host::mcp_set_settings,
            mcp_host::mcp_issue_token,
            mcp_host::mcp_revoke_token,
            mcp_host::mcp_access_log,
            mcp_host::respond_mcp_approval,
        ])
        .setup(|app| {
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&dir);
                if let Err(err) = securevault_core::migrate::migrate_sibling_data_dir(&dir) {
                    eprintln!("securevault migration: {err}");
                }
            }
            restore_bookmarked_vault(app.handle());
            prepare_demo(app.handle());
            platform::start_screen_lock_watcher(app.handle().clone());
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(sync::SYNC_POLL_SECS));
                poll_desktop(&handle);
            });
            // The loopback MCP host is a desktop feature. iOS has no local server.
            #[cfg(not(target_os = "ios"))]
            if let Err(err) = mcp_host::install(app.handle()) {
                eprintln!("securevault mcp: {err}");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
