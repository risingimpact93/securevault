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

/// Present the open-mode document picker. iOS only.
#[cfg(target_os = "ios")]
pub fn pick<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<PickedVault, String> {
    let state = app.state::<VaultAccess<R>>();
    state
        .handle
        .run_mobile_plugin("pickVault", ())
        .map_err(|err| err.to_string())
}
