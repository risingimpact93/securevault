//! App side of the Chrome autofill bridge (desktop Unix only).
//!
//! The listener exists only while the user has turned on
//! '브라우저 확장 연결' (default OFF). The setting lives in
//! `<app data>/autofill/config.json`, outside the vault file.

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillStatus {
    pub supported: bool,
    pub enabled: bool,
    pub listening: bool,
    pub host_installed: bool,
    pub extension_id: String,
    pub manifest_path: Option<String>,
}

#[cfg(all(unix, not(any(target_os = "ios", target_os = "android"))))]
mod imp {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use securevault_core::autofill::AutofillGate;
    use securevault_core::autofill_ipc::{self as ipc, AutofillPaths, ItemsAccess};
    use securevault_core::vault::{UnlockedVault, VaultItem};
    use tokio::sync::watch;

    use crate::AppState;

    pub struct AutofillHost {
        paths: AutofillPaths,
        unlocked: Arc<Mutex<Option<UnlockedVault>>>,
        running: Mutex<Option<watch::Sender<bool>>>,
    }

    fn config_path(paths: &AutofillPaths) -> PathBuf {
        paths.dir.join("config.json")
    }

    fn load_enabled(paths: &AutofillPaths) -> bool {
        std::fs::read(config_path(paths))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("enabled").and_then(|e| e.as_bool()))
            .unwrap_or(false)
    }

    fn save_enabled(paths: &AutofillPaths, enabled: bool) -> Result<(), String> {
        ipc::ensure_private_dir(&paths.dir).map_err(|e| e.to_string())?;
        let body = serde_json::json!({ "enabled": enabled }).to_string();
        std::fs::write(config_path(paths), body).map_err(|e| e.to_string())
    }

    impl AutofillHost {
        fn start(&self) -> Result<(), String> {
            let mut running = self.running.lock().map_err(|_| "lock poisoned".to_string())?;
            if running.is_some() {
                return Ok(());
            }
            // A fresh token per listener start: an old token copy is useless.
            ipc::rotate_token(&self.paths).map_err(|e| format!("토큰을 만들 수 없습니다: {e}"))?;
            let token = ipc::read_token(&self.paths).map_err(|e| e.to_string())?;
            let gate = Arc::new(AutofillGate::new(&token, ipc::allowed_origins()));
            drop(token);
            let unlocked = self.unlocked.clone();
            let items: Arc<ItemsAccess> = Arc::new(move |f: &mut dyn FnMut(Option<&[VaultItem]>)| {
                let guard = match unlocked.lock() {
                    Ok(g) => g,
                    Err(_) => return f(None),
                };
                match guard.as_ref() {
                    Some(v) => {
                        let items = v.items();
                        f(Some(&items));
                    }
                    None => f(None),
                }
            });
            let paths = self.paths.clone();
            let (tx, rx) = watch::channel(false);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            tauri::async_runtime::spawn(async move {
                match ipc::bind_socket(&paths) {
                    Ok(listener) => {
                        let _ = ready_tx.send(Ok(()));
                        ipc::serve(listener, gate, items, ipc::current_uid(), rx).await;
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                    }
                }
                let _ = std::fs::remove_file(&paths.socket);
            });
            ready_rx
                .recv()
                .map_err(|e| e.to_string())?
                .map_err(|e| format!("소켓을 열 수 없습니다: {e}"))?;
            *running = Some(tx);
            Ok(())
        }

        fn stop(&self) {
            if let Ok(mut running) = self.running.lock() {
                if let Some(tx) = running.take() {
                    let _ = tx.send(true);
                }
            }
            let _ = std::fs::remove_file(&self.paths.socket);
            let _ = std::fs::remove_file(&self.paths.token);
        }

        fn listening(&self) -> bool {
            self.running.lock().map(|r| r.is_some()).unwrap_or(false)
        }
    }

    pub fn install(app: &AppHandle) -> Result<(), String> {
        let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
        let state = app.state::<AppState>();
        let host = AutofillHost {
            paths: AutofillPaths::new(&dir),
            unlocked: state.unlocked.clone(),
            running: Mutex::new(None),
        };
        let enabled = load_enabled(&host.paths);
        if enabled {
            if let Err(err) = host.start() {
                eprintln!("securevault autofill: {err}");
            }
        } else {
            host.stop(); // clean stale socket/token from a previous run
        }
        app.manage(host);
        Ok(())
    }

    pub fn chrome_manifest_dir() -> Option<PathBuf> {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        if cfg!(target_os = "macos") {
            Some(home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts"))
        } else {
            Some(home.join(".config/google-chrome/NativeMessagingHosts"))
        }
    }

    fn manifest_path() -> Option<PathBuf> {
        chrome_manifest_dir().map(|d| d.join(format!("{}.json", ipc::HOST_NAME)))
    }

    fn host_installed(exe: &Path) -> bool {
        let Some(p) = manifest_path() else { return false };
        let Ok(bytes) = std::fs::read(p) else { return false };
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .map(|v| v == ipc::host_manifest(exe))
            .unwrap_or(false)
    }

    pub fn status(host: &AutofillHost) -> AutofillStatus {
        let exe = std::env::current_exe().ok();
        AutofillStatus {
            supported: true,
            enabled: load_enabled(&host.paths),
            listening: host.listening(),
            host_installed: exe.as_deref().map(host_installed).unwrap_or(false),
            extension_id: ipc::EXTENSION_ID.to_string(),
            manifest_path: manifest_path().map(|p| p.to_string_lossy().into_owned()),
        }
    }

    pub fn set_enabled(host: &AutofillHost, enabled: bool) -> Result<(), String> {
        save_enabled(&host.paths, enabled)?;
        if enabled {
            host.start()
        } else {
            host.stop();
            Ok(())
        }
    }

    pub fn install_host() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe = exe.canonicalize().unwrap_or(exe);
        let s = exe.to_string_lossy();
        if s.starts_with("/Volumes/") || s.contains("/AppTranslocation/") {
            return Err("앱을 응용 프로그램 폴더로 옮긴 뒤 다시 눌러 주세요.".into());
        }
        let dir = chrome_manifest_dir().ok_or("홈 폴더를 찾을 수 없습니다.")?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("{}.json", ipc::HOST_NAME));
        let body = serde_json::to_string_pretty(&ipc::host_manifest(&exe)).map_err(|e| e.to_string())?;
        std::fs::write(&path, body).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())
    }

    pub type Host<'a> = State<'a, AutofillHost>;
}

#[cfg(all(unix, not(any(target_os = "ios", target_os = "android"))))]
pub use imp::install;

#[cfg(all(unix, not(any(target_os = "ios", target_os = "android"))))]
#[tauri::command]
pub fn autofill_get_status(host: imp::Host<'_>) -> AutofillStatus {
    imp::status(&host)
}

#[cfg(all(unix, not(any(target_os = "ios", target_os = "android"))))]
#[tauri::command]
pub fn autofill_set_enabled(host: imp::Host<'_>, enabled: bool) -> Result<AutofillStatus, String> {
    imp::set_enabled(&host, enabled)?;
    Ok(imp::status(&host))
}

#[cfg(all(unix, not(any(target_os = "ios", target_os = "android"))))]
#[tauri::command]
pub fn autofill_install_host(host: imp::Host<'_>) -> Result<AutofillStatus, String> {
    imp::install_host()?;
    Ok(imp::status(&host))
}

#[cfg(not(all(unix, not(any(target_os = "ios", target_os = "android")))))]
fn unsupported() -> AutofillStatus {
    AutofillStatus {
        supported: false,
        enabled: false,
        listening: false,
        host_installed: false,
        extension_id: String::new(),
        manifest_path: None,
    }
}

#[cfg(not(all(unix, not(any(target_os = "ios", target_os = "android")))))]
#[tauri::command]
pub fn autofill_get_status(_app: AppHandle) -> AutofillStatus {
    unsupported()
}

#[cfg(not(all(unix, not(any(target_os = "ios", target_os = "android")))))]
#[tauri::command]
pub fn autofill_set_enabled(_app: AppHandle, _enabled: bool) -> Result<AutofillStatus, String> {
    Err("이 기기에서는 지원하지 않습니다.".into())
}

#[cfg(not(all(unix, not(any(target_os = "ios", target_os = "android")))))]
#[tauri::command]
pub fn autofill_install_host(_app: AppHandle) -> Result<AutofillStatus, String> {
    Err("이 기기에서는 지원하지 않습니다.".into())
}

/// Entry for `securevault chrome-extension://…/` (Chrome starting the native host).
pub fn run_native_host(caller_origin: &str) -> i32 {
    #[cfg(unix)]
    {
        use securevault_core::autofill_ipc as ipc;
        let Some(dir) = ipc::default_app_data_dir("com.securevault.app") else { return 1 };
        match ipc::run_native_host(&ipc::AutofillPaths::new(&dir), caller_origin) {
            Ok(()) => 0,
            Err(_) => 1,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = caller_origin;
        1
    }
}
