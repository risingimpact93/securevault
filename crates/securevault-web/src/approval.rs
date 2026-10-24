//! In-browser approval for MCP `get_secret`, with SSE fan-out and 60s timeout.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use securevault_core::mcp::{ApprovalDecision, ApprovalRequest, SecretApprover};
use securevault_core::vault;
use serde::Serialize;
use tokio::sync::{broadcast, oneshot};

pub const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 60;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalEvent {
    pub request_id: String,
    pub token_name: String,
    pub item_title: String,
    pub field: String,
    pub timeout_secs: u64,
}

struct Pending {
    event: ApprovalEvent,
    tx: oneshot::Sender<bool>,
}

pub struct WebApprover {
    pending: Mutex<HashMap<String, Pending>>,
    tx: broadcast::Sender<ApprovalEvent>,
    timeout: Duration,
}

impl WebApprover {
    pub fn new(timeout: Duration) -> Arc<Self> {
        let (tx, _) = broadcast::channel(32);
        Arc::new(Self {
            pending: Mutex::new(HashMap::new()),
            tx,
            timeout,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalEvent> {
        self.tx.subscribe()
    }

    pub fn pending(&self) -> Vec<ApprovalEvent> {
        self.pending
            .lock()
            .map(|map| map.values().map(|p| p.event.clone()).collect())
            .unwrap_or_default()
    }

    pub fn respond(&self, request_id: &str, approved: bool) -> Result<(), String> {
        let sender = self
            .pending
            .lock()
            .map_err(|_| "lock poisoned".to_string())?
            .remove(request_id)
            .ok_or_else(|| "승인 요청을 찾을 수 없습니다.".to_string())?;
        let _ = sender.tx.send(approved);
        Ok(())
    }

    fn timeout_secs(&self) -> u64 {
        self.timeout.as_secs().max(1)
    }
}

impl SecretApprover for WebApprover {
    fn decide<'a>(
        &'a self,
        request: &'a ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + 'a>> {
        let timeout = self.timeout;
        Box::pin(async move {
            let id = vault::new_id();
            let (tx, rx) = oneshot::channel();
            let event = ApprovalEvent {
                request_id: id.clone(),
                token_name: request.token_name.clone(),
                item_title: request.item_title.clone(),
                field: request.field.clone(),
                timeout_secs: self.timeout_secs(),
            };
            {
                let mut map = match self.pending.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                map.insert(
                    id.clone(),
                    Pending {
                        event: event.clone(),
                        tx,
                    },
                );
            }
            let _ = self.tx.send(event);
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(true)) => ApprovalDecision::Approved,
                Ok(Ok(false)) | Ok(Err(_)) => ApprovalDecision::Denied,
                Err(_) => {
                    self.pending.lock().ok().map(|mut map| map.remove(&id));
                    ApprovalDecision::TimedOut
                }
            }
        })
    }
}
