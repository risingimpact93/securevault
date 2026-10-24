//! Tauri glue for the MCP server: loopback listener lifecycle and approval events.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{oneshot, watch};

use keyhaven_core::mcp::{
    self, ApprovalDecision, ApprovalRequest, McpService, SecretApprover, VaultView, APPROVAL_TIMEOUT_SECS,
};
use keyhaven_core::vault::{self, UnlockedVault, VaultItem};
use crate::AppState;

pub struct TauriApprover {
    app: AppHandle,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
}

impl TauriApprover {
    fn new(app: AppHandle) -> Self {
        Self {
            app,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn respond(&self, request_id: &str, approved: bool) -> Result<(), String> {
        let sender = self
            .pending
            .lock()
            .map_err(|_| "lock poisoned".to_string())?
            .remove(request_id)
            .ok_or_else(|| "승인 요청을 찾을 수 없습니다.".to_string())?;
        let _ = sender.send(approved);
        Ok(())
    }
}

impl SecretApprover for TauriApprover {
    fn decide<'a>(
        &'a self,
        request: &'a ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + 'a>> {
        let app = self.app.clone();
        let pending = self.pending.clone();
        let request = request.clone();
        Box::pin(async move {
            let id = vault::new_id();
            let (tx, rx) = oneshot::channel();
            {
                let mut map = match pending.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                map.insert(id.clone(), tx);
            }
            let event = ApprovalEvent {
                request_id: id.clone(),
                token_name: request.token_name,
                item_title: request.item_title,
                field: request.field,
                timeout_secs: APPROVAL_TIMEOUT_SECS,
            };
            if app.emit("mcp-approval-request", event).is_err() {
                pending.lock().ok().map(|mut map| map.remove(&id));
                return ApprovalDecision::Denied;
            }
            match tokio::time::timeout(Duration::from_secs(APPROVAL_TIMEOUT_SECS), rx).await {
                Ok(Ok(true)) => ApprovalDecision::Approved,
                Ok(Ok(false)) | Ok(Err(_)) => ApprovalDecision::Denied,
                Err(_) => {
                    pending.lock().ok().map(|mut map| map.remove(&id));
                    ApprovalDecision::TimedOut
                }
            }
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalEvent {
    request_id: String,
    token_name: String,
    item_title: String,
    field: String,
    timeout_secs: u64,
}

struct AppVault {
    unlocked: Arc<Mutex<Option<UnlockedVault>>>,
}

impl VaultView for AppVault {
    fn is_unlocked(&self) -> bool {
        self.unlocked
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn items(&self) -> Vec<VaultItem> {
        let Ok(guard) = self.unlocked.lock() else {
            return Vec::new();
        };
        guard.as_ref().map(|vault| vault.items()).unwrap_or_default()
    }
}

struct Running {
    addr: std::net::SocketAddr,
    tx: watch::Sender<bool>,
    handle: tauri::async_runtime::JoinHandle<()>,
}

pub struct McpHost {
    service: Arc<McpService>,
    approver: Arc<TauriApprover>,
    running: Mutex<Option<Running>>,
    apply_lock: tokio::sync::Mutex<()>,
}

impl McpHost {
    pub async fn apply_settings(&self, enabled: bool, port: u16) -> Result<(), String> {
        if port == 0 {
            return Err("포트는 1에서 65535 사이여야 합니다.".into());
        }
        let _guard = self.apply_lock.lock().await;
        if !enabled {
            self.stop().await;
            return self.service.set_listen(false, port);
        }
        let current_port = self
            .running
            .lock()
            .map_err(|_| "lock poisoned".to_string())?
            .as_ref()
            .map(|running| running.addr.port());
        if current_port == Some(port) {
            return self.service.set_listen(true, port);
        }
        let started = spawn_on(self.service.clone(), port)?;
        self.stop().await;
        *self.running.lock().map_err(|_| "lock poisoned".to_string())? = Some(started);
        self.service.set_listen(true, port)
    }

    async fn stop(&self) {
        let running = self.running.lock().ok().and_then(|mut guard| guard.take());
        if let Some(running) = running {
            let _ = running.tx.send(true);
            let _ = running.handle.await;
        }
    }
}

fn spawn_on(service: Arc<McpService>, port: u16) -> Result<Running, String> {
    let (listener, addr) =
        mcp::bind_loopback(port).map_err(|e| format!("포트를 열 수 없습니다: {e}"))?;
    let (tx, rx) = watch::channel(false);
    let handle = tauri::async_runtime::spawn(async move {
        mcp::run_server(listener, service, rx).await;
    });
    Ok(Running { addr, tx, handle })
}

pub fn install(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let approver = Arc::new(TauriApprover::new(app.clone()));
    let vault = Arc::new(AppVault {
        unlocked: state.unlocked.clone(),
    });
    let service = Arc::new(McpService::open(
        dir,
        vault,
        approver.clone() as Arc<dyn SecretApprover>,
    )?);
    if service.enabled() {
        match spawn_on(service.clone(), service.port()) {
            Ok(running) => {
                // Stored after the host exists. See below.
                let host = Arc::new(McpHost {
                    service,
                    approver,
                    running: Mutex::new(Some(running)),
                    apply_lock: tokio::sync::Mutex::new(()),
                });
                *state.mcp.lock().map_err(|_| "lock poisoned".to_string())? = Some(host);
                return Ok(());
            }
            Err(err) => {
                eprintln!("keyhaven mcp: {err}");
                let port = service.port();
                let _ = service.set_listen(false, port);
            }
        }
    }
    let host = Arc::new(McpHost {
        service,
        approver,
        running: Mutex::new(None),
        apply_lock: tokio::sync::Mutex::new(()),
    });
    *state.mcp.lock().map_err(|_| "lock poisoned".to_string())? = Some(host);
    Ok(())
}

fn host(state: &AppState) -> Result<Arc<McpHost>, String> {
    state
        .mcp
        .lock()
        .map_err(|_| "lock poisoned".to_string())?
        .clone()
        .ok_or_else(|| "MCP를 사용할 수 없습니다.".to_string())
}

#[tauri::command]
pub fn mcp_get_settings(state: State<'_, AppState>) -> Result<keyhaven_core::mcp::PublicSettings, String> {
    host(&state)?.service.public_settings()
}

#[tauri::command]
pub async fn mcp_set_settings(
    state: State<'_, AppState>,
    enabled: bool,
    port: u16,
) -> Result<(), String> {
    let host = host(&state)?;
    host.apply_settings(enabled, port).await
}

#[tauri::command]
pub fn mcp_issue_token(state: State<'_, AppState>, name: String) -> Result<mcp::IssuedToken, String> {
    host(&state)?.service.issue_token(&name)
}

#[tauri::command]
pub fn mcp_revoke_token(state: State<'_, AppState>, id: String) -> Result<(), String> {
    host(&state)?.service.revoke_token(&id)
}

#[tauri::command]
pub fn mcp_access_log(state: State<'_, AppState>) -> Result<Vec<mcp::AccessLogEntry>, String> {
    Ok(host(&state)?.service.access_log())
}

#[tauri::command]
pub fn respond_mcp_approval(
    state: State<'_, AppState>,
    request_id: String,
    approved: bool,
) -> Result<(), String> {
    host(&state)?.approver.respond(&request_id, approved)
}
