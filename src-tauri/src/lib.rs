mod mcp_host;
mod platform;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keyhaven_core::vault::{
    self, generate_password as vault_generate_password, import_bytes, mark_password_unlock, new_id,
    now_rfc3339, password_unlock_expired_now, persist_unlocked, unlock_file_with_key, validate_item_type,
    SettingsPatch, UnlockedVault, VaultError, VaultItem, VaultKey, VaultSettings,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroize;

pub struct AppState {
    pub(crate) unlocked: Arc<Mutex<Option<UnlockedVault>>>,
    pub(crate) mcp: Mutex<Option<Arc<mcp_host::McpHost>>>,
    password_verified: AtomicBool,
    pub(crate) settings: Mutex<VaultSettings>,
    biometrics_invalidated: AtomicBool,
}

fn remember_settings(state: &AppState, settings: &VaultSettings) {
    if let Ok(mut guard) = state.settings.lock() {
        *guard = settings.clone();
    }
}

fn accept_password_unlock(app: &AppHandle, state: &AppState, mut unlocked: UnlockedVault) -> Result<(), String> {
    let path = vault_path(app)?;
    if state.biometrics_invalidated.load(Ordering::Relaxed) {
        platform::delete_vault_key();
        unlocked.data.settings.biometrics_enabled = false;
        state.biometrics_invalidated.store(false, Ordering::Relaxed);
    }
    mark_password_unlock(&mut unlocked.data);
    persist(&path, &unlocked)?;
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
}

fn biometric_view(state: &AppState) -> BiometricStatus {
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
        platform: if available { "macos" } else { "unsupported" },
    }
}

fn err(e: VaultError) -> String {
    e.to_string()
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("vault.khv"))
}

fn persist(path: &PathBuf, unlocked: &UnlockedVault) -> Result<(), String> {
    persist_unlocked(path, unlocked).map_err(err)
}

fn require_unlocked(state: &AppState) -> Result<std::sync::MutexGuard<'_, Option<UnlockedVault>>, String> {
    state
        .unlocked
        .lock()
        .map_err(|_| "lock poisoned".to_string())
}

#[tauri::command]
fn vault_exists(app: AppHandle) -> Result<bool, String> {
    Ok(vault_path(&app)?.exists())
}

#[tauri::command]
fn create_vault(app: AppHandle, state: State<AppState>, password: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    let secret = SecretString::new(password);
    let unlocked = vault::create_vault_at(&path, &secret).map_err(err)?;
    accept_password_unlock(&app, &state, unlocked)
}

#[tauri::command]
fn unlock(app: AppHandle, state: State<AppState>, password: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    let secret = SecretString::new(password);
    let unlocked = vault::unlock_file(&path, &secret).map_err(err)?;
    accept_password_unlock(&app, &state, unlocked)
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
    Ok(unlocked.data.items.clone())
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
    })
}

#[tauri::command]
fn add_item(app: AppHandle, state: State<AppState>, item: ItemDraft) -> Result<VaultItem, String> {
    let path = vault_path(&app)?;
    let now = now_rfc3339();
    let new_item = draft_to_item(item, new_id(), now.clone(), now)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    unlocked.data.items.push(new_item.clone());
    persist(&path, unlocked)?;
    Ok(new_item)
}

#[tauri::command]
fn update_item(app: AppHandle, state: State<AppState>, item: VaultItem) -> Result<VaultItem, String> {
    validate_item_type(&item.item_type).map_err(err)?;
    let path = vault_path(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    let mut updated = item;
    updated.updated_at = now_rfc3339();
    if !unlocked.data.items.iter().any(|i| i.id == updated.id) {
        return Err("item not found".into());
    }
    unlocked.data.upsert(updated.clone());
    persist(&path, unlocked)?;
    Ok(updated)
}

#[tauri::command]
fn delete_item(app: AppHandle, state: State<AppState>, id: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    if !unlocked.data.remove(&id) {
        return Err("item not found".into());
    }
    persist(&path, unlocked)
}

#[tauri::command]
async fn change_master_password(
    app: AppHandle,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let path = vault_path(&app)?;
    let (mut key_bytes, enabled) = {
        let mut guard = require_unlocked(&state)?;
        let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
        let current = SecretString::new(current_password);
        let new_secret = SecretString::new(new_password);
        unlocked
            .change_master_password(&current, &new_secret)
            .map_err(err)?;
        persist(&path, unlocked)?;
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
        persist(&path, unlocked)?;
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
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    unlocked.data.settings.apply_patch(&patch).map_err(err)?;
    persist(&path, unlocked)?;
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
fn biometric_status(state: State<AppState>) -> BiometricStatus {
    biometric_view(&state)
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
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    unlocked.data.settings.biometrics_enabled = true;
    state.biometrics_invalidated.store(false, Ordering::Relaxed);
    persist(&path, unlocked)?;
    remember_settings(&state, &unlocked.data.settings);
    Ok(biometric_view(&state))
}

#[tauri::command]
fn biometric_disable(app: AppHandle, state: State<AppState>) -> Result<BiometricStatus, String> {
    platform::delete_vault_key();
    let path = vault_path(&app)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    unlocked.data.settings.biometrics_enabled = false;
    state.biometrics_invalidated.store(false, Ordering::Relaxed);
    persist(&path, unlocked)?;
    remember_settings(&state, &unlocked.data.settings);
    Ok(biometric_view(&state))
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
    let unlocked = unlock_file_with_key(&path, &key).map_err(err)?;
    if password_unlock_expired_now(&unlocked.data.settings) {
        return Err(err(VaultError::MasterPasswordRequired));
    }
    if !unlocked.data.settings.biometrics_enabled {
        return Err(err(VaultError::BiometricsUnavailable));
    }
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
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let secret = SecretString::new(export_password);
    let imported = import_bytes(&bytes, &secret).map_err(err)?;
    let mut guard = require_unlocked(&state)?;
    let unlocked = guard.as_mut().ok_or_else(|| err(VaultError::Locked))?;
    match mode.as_str() {
        "replace" => unlocked.data = imported,
        "merge" => unlocked.data.merge(imported),
        _ => return Err("mode must be merge or replace".into()),
    }
    let settings = unlocked.data.settings.clone();
    persist(&vault_file, unlocked)?;
    remember_settings(&state, &settings);
    Ok(())
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            unlocked: Arc::new(Mutex::new(None)),
            mcp: Mutex::new(None),
            password_verified: AtomicBool::new(false),
            settings: Mutex::new(VaultSettings::default()),
            biometrics_invalidated: AtomicBool::new(false),
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            create_vault,
            unlock,
            lock,
            is_unlocked,
            list_items,
            add_item,
            update_item,
            delete_item,
            change_master_password,
            generate_password,
            export_vault,
            import_vault,
            copy_to_clipboard,
            get_vault_settings,
            update_vault_settings,
            screen_lock_supported,
            biometric_status,
            biometric_enable,
            biometric_disable,
            biometric_unlock,
            mcp_host::mcp_get_settings,
            mcp_host::mcp_set_settings,
            mcp_host::mcp_issue_token,
            mcp_host::mcp_revoke_token,
            mcp_host::mcp_access_log,
            mcp_host::respond_mcp_approval,
        ])
        .setup(|app| {
            platform::start_screen_lock_watcher(app.handle().clone());
            if let Err(err) = mcp_host::install(app.handle()) {
                eprintln!("keyhaven mcp: {err}");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
