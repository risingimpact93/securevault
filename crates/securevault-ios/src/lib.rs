//! iOS document access. On other targets `init` is a no-op so Linux and macOS
//! still link the crate. The Swift picker is compiled only by Xcode.

use serde::Deserialize;
use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};
#[cfg(target_os = "ios")]
use tauri::Manager;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_vault_access);

#[cfg(target_os = "ios")]
struct VaultAccess<R: Runtime> {
    handle: tauri::plugin::PluginHandle<R>,
}

/// What the document picker returned. `cancelled` is a user dismiss, not an error.
#[derive(Debug, Clone, Deserialize)]
pub struct PickedVault {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub bookmark: String,
    #[serde(default)]
    pub cancelled: bool,
    #[serde(default)]
    pub copied: bool,
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("vault-access")
        .setup(|app, api| {
            #[cfg(target_os = "ios")]
            {
                let handle = api.register_ios_plugin(init_plugin_vault_access)?;
                app.manage(VaultAccess { handle });
            }
            #[cfg(not(target_os = "ios"))]
            {
                let _ = (app, api);
            }
            Ok(())
        })
        .build()
}

/// Answer from the Swift `ping` command; proves the plugin is registered.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct PluginPing {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub plugin: String,
}

/// Present the open-mode document picker. iOS only.
///
/// Must be awaited from an async command. The Swift side presents on the main
/// thread; the blocking `run_mobile_plugin` from a sync command (which Tauri
/// runs on the main thread) deadlocks and the picker never appears.
#[cfg(target_os = "ios")]
pub async fn pick<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<PickedVault, String> {
    let handle = app.state::<VaultAccess<R>>().handle.clone();
    handle
        .run_mobile_plugin_async("pickVault", ())
        .await
        .map_err(|err| format!("문서 선택기를 열지 못했습니다: {err}"))
}

#[cfg(target_os = "ios")]
pub async fn ping<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<PluginPing, String> {
    let handle = app
        .try_state::<VaultAccess<R>>()
        .ok_or_else(|| "vault-access 플러그인이 등록되지 않았습니다.".to_string())?
        .handle
        .clone();
    handle
        .run_mobile_plugin_async("ping", ())
        .await
        .map_err(|err| format!("vault-access 플러그인이 응답하지 않습니다: {err}"))
}
