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

/// Opens an http(s) URL with UIApplication.open (async: the plugin hops to main).
#[cfg(target_os = "ios")]
pub async fn open_url<R: Runtime>(app: &tauri::AppHandle<R>, url: &str) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct Args<'a> {
        url: &'a str,
    }
    let handle = app.state::<VaultAccess<R>>().handle.clone();
    handle
        .run_mobile_plugin_async::<serde::de::IgnoredAny>("openUrl", Args { url })
        .await
        .map(|_| ())
        .map_err(|err| err.to_string())
}

/// Result of a scoped read/write/stat. `bookmark` is set when iOS reported the
/// stored bookmark as stale and a fresh one was made.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedFileReply {
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub exists: Option<bool>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub mtime_ms: i64,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub bookmark: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopedFileArgs<'a> {
    bookmark: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    timeout_secs: f64,
}

/// Blocking calls into the Swift plugin for the bookmarked vault file. Safe on
/// any thread: Tauri runs Swift plugin commands on its own ipc queue, and these
/// commands never touch the main thread.
#[cfg(target_os = "ios")]
#[derive(Clone)]
pub struct ScopedFile<R: Runtime> {
    handle: tauri::plugin::PluginHandle<R>,
}

#[cfg(target_os = "ios")]
pub fn scoped_file<R: Runtime>(app: &tauri::AppHandle<R>) -> Option<ScopedFile<R>> {
    app.try_state::<VaultAccess<R>>().map(|state| ScopedFile {
        handle: state.handle.clone(),
    })
}

#[cfg(target_os = "ios")]
impl<R: Runtime> ScopedFile<R> {
    fn call(&self, command: &str, bookmark: &str, data: Option<String>) -> Result<ScopedFileReply, String> {
        self.handle
            .run_mobile_plugin(
                command,
                ScopedFileArgs {
                    bookmark,
                    data,
                    timeout_secs: 60.0,
                },
            )
            .map_err(|err| err.to_string())
    }

    pub fn read(&self, bookmark: &str) -> Result<ScopedFileReply, String> {
        self.call("vaultRead", bookmark, None)
    }

    pub fn write(&self, bookmark: &str, data_b64: String) -> Result<ScopedFileReply, String> {
        self.call("vaultWrite", bookmark, Some(data_b64))
    }

    pub fn stat(&self, bookmark: &str) -> Result<ScopedFileReply, String> {
        self.call("vaultStat", bookmark, None)
    }

    pub fn make_bookmark(&self, path: &str) -> Result<String, String> {
        #[derive(Deserialize)]
        struct Reply {
            bookmark: String,
        }
        #[derive(serde::Serialize)]
        struct Args<'a> {
            path: &'a str,
        }
        self.handle
            .run_mobile_plugin::<Reply>("makeBookmark", Args { path })
            .map(|reply| reply.bookmark)
            .map_err(|err| err.to_string())
    }
}

/// Hardware + keychain existence. No Face ID prompt.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricHwStatus {
    #[serde(default)]
    pub available: bool,
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default)]
    pub biometry_type: String,
    #[serde(default)]
    pub item_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricLoadError {
    NotFound,
    Invalidated,
    Cancelled,
    Failed,
    Unsupported,
}

impl BiometricLoadError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "notFound",
            Self::Invalidated => "invalidated",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
        }
    }

    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    fn from_plugin(err: &str) -> Self {
        let lower = err.to_ascii_lowercase();
        if lower.contains("notfound") {
            Self::NotFound
        } else if lower.contains("invalidated") {
            Self::Invalidated
        } else if lower.contains("cancelled") || lower.contains("canceled") {
            Self::Cancelled
        } else if lower.contains("unsupported") {
            Self::Unsupported
        } else {
            Self::Failed
        }
    }
}

impl std::fmt::Display for BiometricLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(target_os = "ios")]
fn plugin_handle<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<tauri::plugin::PluginHandle<R>, String> {
    app.try_state::<VaultAccess<R>>()
        .ok_or_else(|| "vault-access 플러그인이 등록되지 않았습니다.".to_string())
        .map(|state| state.handle.clone())
}

#[cfg(target_os = "ios")]
pub async fn biometric_status<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<BiometricHwStatus, String> {
    let handle = plugin_handle(app)?;
    handle
        .run_mobile_plugin_async("biometricStatus", ())
        .await
        .map_err(|err| err.to_string())
}

#[cfg(target_os = "ios")]
pub async fn biometric_store<R: Runtime>(app: &tauri::AppHandle<R>, data_b64: &str) -> Result<(), BiometricLoadError> {
    #[derive(serde::Serialize)]
    struct Args<'a> {
        data: &'a str,
    }
    let handle = plugin_handle(app).map_err(|_| BiometricLoadError::Failed)?;
    handle
        .run_mobile_plugin_async::<serde::de::IgnoredAny>("biometricStore", Args { data: data_b64 })
        .await
        .map(|_| ())
        .map_err(|err| BiometricLoadError::from_plugin(&err.to_string()))
}

#[cfg(target_os = "ios")]
pub async fn biometric_load<R: Runtime>(
    app: &tauri::AppHandle<R>,
    reason: &str,
) -> Result<String, BiometricLoadError> {
    #[derive(serde::Serialize)]
    struct Args<'a> {
        reason: &'a str,
    }
    #[derive(Deserialize)]
    struct Reply {
        data: String,
    }
    let handle = plugin_handle(app).map_err(|_| BiometricLoadError::Failed)?;
    handle
        .run_mobile_plugin_async::<Reply>("biometricLoad", Args { reason })
        .await
        .map(|reply| reply.data)
        .map_err(|err| BiometricLoadError::from_plugin(&err.to_string()))
}

#[cfg(target_os = "ios")]
pub async fn biometric_delete<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<(), String> {
    let handle = plugin_handle(app)?;
    handle
        .run_mobile_plugin_async::<serde::de::IgnoredAny>("biometricDelete", ())
        .await
        .map(|_| ())
        .map_err(|err| err.to_string())
}

#[cfg(not(target_os = "ios"))]
pub async fn biometric_status<R: Runtime>(_app: &tauri::AppHandle<R>) -> Result<BiometricHwStatus, String> {
    Err("unsupported".into())
}

#[cfg(not(target_os = "ios"))]
pub async fn biometric_store<R: Runtime>(
    _app: &tauri::AppHandle<R>,
    _data_b64: &str,
) -> Result<(), BiometricLoadError> {
    Err(BiometricLoadError::Unsupported)
}

#[cfg(not(target_os = "ios"))]
pub async fn biometric_load<R: Runtime>(
    _app: &tauri::AppHandle<R>,
    _reason: &str,
) -> Result<String, BiometricLoadError> {
    Err(BiometricLoadError::Unsupported)
}

#[cfg(not(target_os = "ios"))]
pub async fn biometric_delete<R: Runtime>(_app: &tauri::AppHandle<R>) -> Result<(), String> {
    Err("unsupported".into())
}
