//! Local MCP server, bearer-token auth, and access log.
//!
//! This module does not depend on Tauri. The app injects a [`VaultView`] and a
//! [`SecretApprover`]; tests inject an in-memory vault and auto approve/deny.

use std::fs;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::vault::{self, VaultItem};

pub const DEFAULT_PORT: u16 = 47821;
pub const APPROVAL_TIMEOUT_SECS: u64 = 60;
const MAX_LOG: usize = 1000;
const MAX_BODY: usize = 1024 * 1024;
const CONFIG_FILE: &str = "mcp-config.json";
const LOG_FILE: &str = "mcp-access.json";

const SECRET_FIELDS: &[&str] = &[
    "password",
    "notes",
    "number",
    "cvv",
    "cardholder",
    "expiry",
    "username",
    "url",
];

const KNOWN_TOOLS: &[&str] = &[
    "search_items",
    "list_items",
    "get_item_metadata",
    "get_secret",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Denied,
    TimedOut,
}

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub token_name: String,
    /// Vault id of the item being read. Available to approvers; the UI shows the title.
    #[allow(dead_code)]
    pub item_id: String,
    pub item_title: String,
    pub field: String,
}

/// In-app approval for `get_secret`. Production waits on a Tauri event.
/// Tests inject [`AutoApprove`] or [`AutoDeny`].
pub trait SecretApprover: Send + Sync {
    fn decide<'a>(
        &'a self,
        request: &'a ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + 'a>>;
}

pub struct AutoApprove;

impl SecretApprover for AutoApprove {
    fn decide<'a>(
        &'a self,
        _request: &'a ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + 'a>> {
        Box::pin(async { ApprovalDecision::Approved })
    }
}

pub struct AutoDeny;

impl SecretApprover for AutoDeny {
    fn decide<'a>(
        &'a self,
        _request: &'a ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + 'a>> {
        Box::pin(async { ApprovalDecision::Denied })
    }
}

/// Read-only view of the unlocked vault. Implementations must not block.
pub trait VaultView: Send + Sync {
    fn is_unlocked(&self) -> bool;
    fn items(&self) -> Vec<VaultItem>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredToken {
    id: String,
    name: String,
    token_hash: String,
    created_at: String,
    #[serde(default)]
    last_used_at: Option<String>,
    #[serde(default)]
    revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McpConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    tokens: Vec<StoredToken>,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_PORT,
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedToken {
    pub token: String,
    pub info: TokenInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicSettings {
    pub enabled: bool,
    pub port: u16,
    pub tokens: Vec<TokenInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub token_name: String,
    pub tool: String,
    pub item_id: Option<String>,
    pub allowed: bool,
    pub reason: String,
}

pub struct HttpReply {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub body: Vec<u8>,
}

impl HttpReply {
    fn json(status: u16, value: Value) -> Self {
        let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
        Self {
            status,
            content_type: Some("application/json"),
            body,
        }
    }

    fn accepted() -> Self {
        Self {
            status: 202,
            content_type: None,
            body: Vec::new(),
        }
    }

    fn unauthorized() -> Self {
        Self::json(401, json!({"error": "unauthorized"}))
    }
}

struct AuthToken {
    name: String,
}

pub struct McpService {
    config_path: PathBuf,
    log_path: PathBuf,
    config: Mutex<McpConfig>,
    log: Mutex<Vec<AccessLogEntry>>,
    vault: Arc<dyn VaultView>,
    approver: Arc<dyn SecretApprover>,
}

impl McpService {
    pub fn open(
        dir: impl AsRef<Path>,
        vault: Arc<dyn VaultView>,
        approver: Arc<dyn SecretApprover>,
    ) -> Result<Self, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let config_path = dir.join(CONFIG_FILE);
        let log_path = dir.join(LOG_FILE);
        let config = load_json(&config_path).unwrap_or_default();
        let mut log: Vec<AccessLogEntry> = load_json(&log_path).unwrap_or_default();
        trim_log(&mut log);
        Ok(Self {
            config_path,
            log_path,
            config: Mutex::new(config),
            log: Mutex::new(log),
            vault,
            approver,
        })
    }

    pub fn enabled(&self) -> bool {
        self.config.lock().expect("mcp config").enabled
    }

    pub fn port(&self) -> u16 {
        let port = self.config.lock().expect("mcp config").port;
        if port == 0 {
            DEFAULT_PORT
        } else {
            port
        }
    }

    pub fn set_listen(&self, enabled: bool, port: u16) -> Result<(), String> {
        if port == 0 {
            return Err("포트는 1에서 65535 사이여야 합니다.".into());
        }
        let mut cfg = self.config.lock().map_err(|_| "lock poisoned".to_string())?;
        cfg.enabled = enabled;
        cfg.port = port;
        save_json(&self.config_path, &*cfg)
    }

    pub fn public_settings(&self) -> Result<PublicSettings, String> {
        let cfg = self.config.lock().map_err(|_| "lock poisoned".to_string())?;
        Ok(PublicSettings {
            enabled: cfg.enabled,
            port: if cfg.port == 0 { DEFAULT_PORT } else { cfg.port },
            tokens: cfg
                .tokens
                .iter()
                .filter(|t| !t.revoked)
                .map(token_info)
                .collect(),
        })
    }

    pub fn issue_token(&self, name: &str) -> Result<IssuedToken, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("토큰 이름이 필요합니다.".into());
        }
        if name.chars().count() > 80 {
            return Err("토큰 이름은 80자 이하여야 합니다.".into());
        }
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let token = format!("khv_{}", URL_SAFE_NO_PAD.encode(raw));
        let stored = StoredToken {
            id: vault::new_id(),
            name: name.to_string(),
            token_hash: hash_token(&token),
            created_at: vault::now_rfc3339(),
            last_used_at: None,
            revoked: false,
        };
        let info = token_info(&stored);
        let mut cfg = self.config.lock().map_err(|_| "lock poisoned".to_string())?;
        cfg.tokens.push(stored);
        save_json(&self.config_path, &*cfg)?;
        Ok(IssuedToken { token, info })
    }

    pub fn revoke_token(&self, id: &str) -> Result<(), String> {
        let mut cfg = self.config.lock().map_err(|_| "lock poisoned".to_string())?;
        let token = cfg
            .tokens
            .iter_mut()
            .find(|t| t.id == id && !t.revoked)
            .ok_or_else(|| "토큰을 찾을 수 없습니다.".to_string())?;
        token.revoked = true;
        save_json(&self.config_path, &*cfg)
    }

    pub fn access_log(&self) -> Vec<AccessLogEntry> {
        self.log.lock().expect("mcp log").clone()
    }

    #[cfg(test)]
    fn log_path(&self) -> &Path {
        &self.log_path
    }

    #[cfg(test)]
    fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub async fn handle_http(
        &self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> HttpReply {
        if path != "/mcp" {
            return HttpReply::json(404, json!({"error": "not found"}));
        }
        if method.eq_ignore_ascii_case("GET") {
            return HttpReply {
                status: 405,
                content_type: Some("application/json"),
                body: serde_json::to_vec(&json!({"error": "method not allowed"})).unwrap_or_default(),
            };
        }
        if !method.eq_ignore_ascii_case("POST") {
            return HttpReply {
                status: 405,
                content_type: Some("application/json"),
                body: serde_json::to_vec(&json!({"error": "method not allowed"})).unwrap_or_default(),
            };
        }
        if body.len() > MAX_BODY {
            return HttpReply::json(413, json!({"error": "payload too large"}));
        }
        let auth = match self.authenticate(authorization) {
            Ok(token) => token,
            Err(()) => return HttpReply::unauthorized(),
        };
        let parsed: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => {
                return HttpReply::json(
                    200,
                    rpc_error(&Value::Null, -32700, "parse error"),
                );
            }
        };
        if let Value::Array(items) = parsed {
            return self.handle_batch(&auth, items).await;
        }
        self.handle_message(&auth, parsed).await
    }

    async fn handle_batch(&self, auth: &AuthToken, items: Vec<Value>) -> HttpReply {
        let mut responses = Vec::new();
        for item in items {
            if is_notification(&item) {
                continue;
            }
            let reply = self.handle_message(auth, item).await;
            if reply.status == 202 {
                continue;
            }
            if let Ok(value) = serde_json::from_slice::<Value>(&reply.body) {
                responses.push(value);
            }
        }
        if responses.is_empty() {
            HttpReply::accepted()
        } else {
            HttpReply::json(200, Value::Array(responses))
        }
    }

    async fn handle_message(&self, auth: &AuthToken, message: Value) -> HttpReply {
        if is_notification(&message) {
            return HttpReply::accepted();
        }
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        if message.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return HttpReply::json(200, rpc_error(&id, -32600, "invalid request"));
        }
        let method = message.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = message.get("params").cloned();
        let result = match method {
            "initialize" => initialize_result(params.as_ref()),
            "ping" => json!({}),
            "tools/list" => tools_list(),
            "tools/call" => return self.tools_call(auth, &id, params.as_ref()).await,
            "" => return HttpReply::json(200, rpc_error(&id, -32600, "invalid request")),
            _ => return HttpReply::json(200, rpc_error(&id, -32601, "method not found")),
        };
        HttpReply::json(200, json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    async fn tools_call(&self, auth: &AuthToken, id: &Value, params: Option<&Value>) -> HttpReply {
        let params = params.cloned().unwrap_or_else(|| json!({}));
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            self.record(auth, "unknown", None, false, "invalid params");
            return HttpReply::json(200, rpc_error(id, -32602, "invalid params"));
        }
        let args = match params.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(other) => other.clone(),
        };
        if !args.is_object() && !args.is_null() {
            self.record(auth, &log_tool(name), None, false, "invalid params");
            return HttpReply::json(200, rpc_error(id, -32602, "invalid params"));
        }
        let tool = log_tool(name);
        if !self.vault.is_unlocked() {
            let item_id = loggable_id(args.get("id").and_then(|v| v.as_str()).unwrap_or(""));
            self.record(auth, &tool, item_id, false, LOCKED_REASON);
            return HttpReply::json(200, rpc_error(id, -32001, LOCKED_REASON));
        }
        match name {
            "search_items" => self.tool_search(auth, id, &args),
            "list_items" => self.tool_list(auth, id),
            "get_item_metadata" => self.tool_metadata(auth, id, &args),
            "get_secret" => self.tool_secret(auth, id, &args).await,
            _ => {
                self.record(auth, "unknown", None, false, "unknown tool");
                HttpReply::json(200, rpc_error(id, -32602, "unknown tool"))
            }
        }
    }

    fn tool_search(&self, auth: &AuthToken, id: &Value, args: &Value) -> HttpReply {
        let query = match optional_string(args, "query") {
            Ok(q) => q,
            Err(()) => {
                self.record(auth, "search_items", None, false, "invalid params");
                return HttpReply::json(200, rpc_error(id, -32602, "invalid params"));
            }
        };
        let ty = match optional_string(args, "type") {
            Ok(t) => t,
            Err(()) => {
                self.record(auth, "search_items", None, false, "invalid params");
                return HttpReply::json(200, rpc_error(id, -32602, "invalid params"));
            }
        };
        if let Some(ty) = ty.as_deref() {
            if !matches!(ty, "login" | "note" | "card") {
                self.record(auth, "search_items", None, false, "invalid item type");
                return tool_result(id, "invalid item type", true);
            }
        }
        let items = self.vault.items();
        let matched: Vec<Value> = items
            .iter()
            .filter(|item| type_matches(item, ty.as_deref()) && query_matches(item, query.as_deref()))
            .map(metadata)
            .collect();
        self.record(auth, "search_items", None, true, "ok");
        match serde_json::to_string(&Value::Array(matched)) {
            Ok(text) => tool_result(id, &text, false),
            Err(_) => {
                HttpReply::json(200, rpc_error(id, -32603, "internal error"))
            }
        }
    }

    fn tool_list(&self, auth: &AuthToken, id: &Value) -> HttpReply {
        let items = self.vault.items();
        let listed: Vec<Value> = items.iter().map(metadata).collect();
        self.record(auth, "list_items", None, true, "ok");
        match serde_json::to_string(&Value::Array(listed)) {
            Ok(text) => tool_result(id, &text, false),
            Err(_) => HttpReply::json(200, rpc_error(id, -32603, "internal error")),
        }
    }

    fn tool_metadata(&self, auth: &AuthToken, id: &Value, args: &Value) -> HttpReply {
        let item_id = match required_string(args, "id") {
            Ok(v) => v,
            Err(()) => {
                self.record(auth, "get_item_metadata", None, false, "invalid params");
                return HttpReply::json(200, rpc_error(id, -32602, "invalid params"));
            }
        };
        let items = self.vault.items();
        let Some(item) = items.iter().find(|item| item.id == item_id) else {
            self.record(auth, "get_item_metadata", loggable_id(&item_id), false, "item not found");
            return tool_result(id, "item not found", true);
        };
        let logged = Some(item.id.clone());
        self.record(auth, "get_item_metadata", logged, true, "ok");
        match serde_json::to_string(&metadata(item)) {
            Ok(text) => tool_result(id, &text, false),
            Err(_) => HttpReply::json(200, rpc_error(id, -32603, "internal error")),
        }
    }

    async fn tool_secret(&self, auth: &AuthToken, id: &Value, args: &Value) -> HttpReply {
        let item_id = match required_string(args, "id") {
            Ok(v) => v,
            Err(()) => {
                self.record(auth, "get_secret", None, false, "invalid params");
                return HttpReply::json(200, rpc_error(id, -32602, "invalid params"));
            }
        };
        let field = match required_string(args, "field") {
            Ok(v) => v,
            Err(()) => {
                self.record(auth, "get_secret", loggable_id(&item_id), false, "invalid params");
                return HttpReply::json(200, rpc_error(id, -32602, "invalid params"));
            }
        };
        if !SECRET_FIELDS.contains(&field.as_str()) {
            self.record(auth, "get_secret", loggable_id(&item_id), false, "invalid field");
            return tool_result(id, "invalid field", true);
        }
        let items = self.vault.items();
        let Some(item) = items.iter().find(|item| item.id == item_id) else {
            self.record(auth, "get_secret", loggable_id(&item_id), false, "item not found");
            return tool_result(id, "item not found", true);
        };
        let logged_id = Some(item.id.clone());
        let request = ApprovalRequest {
            token_name: auth.name.clone(),
            item_id: item.id.clone(),
            item_title: item.title.clone(),
            field: field.clone(),
        };
        // Vault lock is not held across the approval wait.
        let decision = self.approver.decide(&request).await;
        let (allowed, reason, message) = match decision {
            ApprovalDecision::Approved => (true, "approved", ""),
            ApprovalDecision::Denied => (false, "denied", "approval denied"),
            ApprovalDecision::TimedOut => (false, "timeout", "approval denied"),
        };
        if !allowed {
            self.record(auth, "get_secret", logged_id, false, reason);
            return tool_result(id, message, true);
        }
        if !self.vault.is_unlocked() {
            self.record(auth, "get_secret", logged_id, false, LOCKED_REASON);
            return HttpReply::json(200, rpc_error(id, -32001, LOCKED_REASON));
        }
        let items = self.vault.items();
        let Some(item) = items.iter().find(|item| item.id == item_id) else {
            self.record(auth, "get_secret", None, false, "item not found");
            return tool_result(id, "item not found", true);
        };
        let value = field_value(item, &field);
        self.record(auth, "get_secret", Some(item.id.clone()), true, "approved");
        let payload = json!({
            "id": item.id,
            "field": field,
            "value": value,
        });
        match serde_json::to_string(&payload) {
            Ok(text) => tool_result(id, &text, false),
            Err(_) => HttpReply::json(200, rpc_error(id, -32603, "internal error")),
        }
    }

    fn authenticate(&self, authorization: Option<&str>) -> Result<AuthToken, ()> {
        let presented = bearer(authorization).ok_or(())?;
        let hash = hash_token(presented);
        let mut cfg = self.config.lock().map_err(|_| ())?;
        let mut found = None;
        for (index, token) in cfg.tokens.iter().enumerate() {
            if ct_eq(&token.token_hash, &hash) {
                found = Some(index);
                break;
            }
        }
        let index = found.ok_or(())?;
        if cfg.tokens[index].revoked {
            return Err(());
        }
        cfg.tokens[index].last_used_at = Some(vault::now_rfc3339());
        let name = cfg.tokens[index].name.clone();
        let _ = save_json(&self.config_path, &*cfg);
        Ok(AuthToken { name })
    }

    fn record(
        &self,
        auth: &AuthToken,
        tool: &str,
        item_id: Option<String>,
        allowed: bool,
        reason: &'static str,
    ) {
        let entry = AccessLogEntry {
            timestamp: vault::now_rfc3339(),
            token_name: auth.name.clone(),
            tool: tool.to_string(),
            item_id,
            allowed,
            reason: reason.to_string(),
        };
        let mut log = match self.log.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        log.push(entry);
        trim_log(&mut log);
        let _ = save_json(&self.log_path, &*log);
    }
}

const LOCKED_REASON: &str = "SecureVault vault is locked";

pub fn bind_loopback(port: u16) -> std::io::Result<(TcpListener, SocketAddr)> {
    let std_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    std_listener.set_nonblocking(true)?;
    let addr = std_listener.local_addr()?;
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "refusing non-loopback bind",
        ));
    }
    let listener = TcpListener::from_std(std_listener)?;
    Ok((listener, addr))
}

pub async fn run_server(
    listener: TcpListener,
    service: Arc<McpService>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        if !peer.ip().is_loopback() {
                            drop(stream);
                            continue;
                        }
                        let service = service.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let svc = service_fn(move |req| {
                                let service = service.clone();
                                async move { dispatch(service, req).await }
                            });
                            let _ = http1::Builder::new().serve_connection(io, svc).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn dispatch(
    service: Arc<McpService>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let authorization = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let collected = match req.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            let reply = HttpReply::json(400, json!({"error": "bad body"}));
            return Ok(to_response(&reply));
        }
    };
    let reply = if collected.len() > MAX_BODY {
        HttpReply::json(413, json!({"error": "payload too large"}))
    } else {
        service
            .handle_http(&method, &path, authorization.as_deref(), &collected)
            .await
    };
    Ok(to_response(&reply))
}

fn to_response(reply: &HttpReply) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("cache-control", "no-store");
    if let Some(content_type) = reply.content_type {
        builder = builder.header("content-type", content_type);
    }
    if reply.status == 405 {
        builder = builder.header("allow", "POST");
    }
    builder
        .body(Full::new(Bytes::from(reply.body.clone())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn token_info(token: &StoredToken) -> TokenInfo {
    TokenInfo {
        id: token.id.clone(),
        name: token.name.clone(),
        created_at: token.created_at.clone(),
        last_used_at: token.last_used_at.clone(),
    }
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(digest.as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn ct_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn bearer(authorization: Option<&str>) -> Option<&str> {
    let header = authorization?.trim();
    let (scheme, token) = header.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn load_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Option<T> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    atomic_write(path, &bytes).map_err(|e| e.to_string())
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut file = fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    if path.exists() {
        #[cfg(windows)]
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn trim_log(entries: &mut Vec<AccessLogEntry>) {
    if entries.len() > MAX_LOG {
        let extra = entries.len() - MAX_LOG;
        entries.drain(0..extra);
    }
}

fn is_notification(message: &Value) -> bool {
    let Some(object) = message.as_object() else {
        return false;
    };
    if object.get("method").and_then(|v| v.as_str()).is_none() {
        return false;
    }
    match object.get("id") {
        None | Some(Value::Null) => true,
        Some(_) => false,
    }
}

fn rpc_error(id: &Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

fn tool_result(id: &Value, text: &str, is_error: bool) -> HttpReply {
    HttpReply::json(
        200,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": is_error
            }
        }),
    )
}

fn initialize_result(params: Option<&Value>) -> Value {
    let requested = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str())
        .unwrap_or("2025-03-26");
    let protocol_version = match requested {
        "2024-11-05" | "2025-03-26" | "2025-06-18" => requested,
        _ => "2025-03-26",
    };
    json!({
        "protocolVersion": protocol_version,
        "capabilities": {"tools": {"listChanged": false}},
        // serverInfo.name stays SecureVault so existing MCP clients keep working.
        "serverInfo": {"name": "SecureVault", "version": crate::VERSION},
        "instructions": "Metadata tools never return passwords, card numbers, CVV, or notes. get_secret requires a fresh in-app approval every call."
    })
}

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "search_items",
                "description": "Search vault item metadata by an optional query and type. Returns id, title, type, username, url, tags, favorite, created, and updated. Never returns secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Case-insensitive substring matched against title, username, url, and tags."},
                        "type": {"type": "string", "enum": ["login", "note", "card"]}
                    }
                }
            },
            {
                "name": "list_items",
                "description": "List metadata for every vault item. Never returns secrets.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "get_item_metadata",
                "description": "Get metadata for one item by id. Never returns secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"]
                }
            },
            {
                "name": "get_secret",
                "description": "Read one field of an item. Requires a new in-app approval every call. Fields: password, notes, number, cvv, cardholder, expiry, username, url.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "field": {"type": "string", "enum": SECRET_FIELDS}
                    },
                    "required": ["id", "field"]
                }
            }
        ]
    })
}

fn metadata(item: &VaultItem) -> Value {
    json!({
        "id": item.id,
        "title": item.title,
        "type": item.item_type,
        "username": item.username,
        "url": item.url,
        "tags": item.tags,
        "favorite": item.favorite,
        "created": item.created_at,
        "updated": item.updated_at,
    })
}

fn field_value(item: &VaultItem, field: &str) -> Option<String> {
    match field {
        "password" => item.password.clone(),
        "notes" => item.notes.clone(),
        "number" => item.number.clone(),
        "cvv" => item.cvv.clone(),
        "cardholder" => item.cardholder.clone(),
        "expiry" => item.expiry.clone(),
        "username" => item.username.clone(),
        "url" => item.url.clone(),
        _ => None,
    }
}

fn optional_string(args: &Value, key: &str) -> Result<Option<String>, ()> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(()),
    }
}

fn required_string(args: &Value, key: &str) -> Result<String, ()> {
    match args.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(()),
    }
}

fn type_matches(item: &VaultItem, ty: Option<&str>) -> bool {
    match ty {
        None => true,
        Some(ty) => item.item_type == ty,
    }
}

fn query_matches(item: &VaultItem, query: Option<&str>) -> bool {
    let Some(query) = query.map(str::trim).filter(|q| !q.is_empty()) else {
        return true;
    };
    let q = query.to_lowercase();
    if item.title.to_lowercase().contains(&q) {
        return true;
    }
    if item
        .username
        .as_deref()
        .map(|v| v.to_lowercase().contains(&q))
        .unwrap_or(false)
    {
        return true;
    }
    if item
        .url
        .as_deref()
        .map(|v| v.to_lowercase().contains(&q))
        .unwrap_or(false)
    {
        return true;
    }
    item.tags.iter().any(|tag| tag.to_lowercase().contains(&q))
}

fn log_tool(name: &str) -> String {
    if KNOWN_TOOLS.contains(&name) {
        name.to_string()
    } else {
        "unknown".to_string()
    }
}

fn loggable_id(id: &str) -> Option<String> {
    uuid::Uuid::parse_str(id).ok().map(|id| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SECRET_PASSWORD: &str = "pw-SECRET-ALPHA-991";
    const SECRET_NOTE: &str = "note-SECRET-BETA-992";
    const SECRET_NUMBER: &str = "400000SECRETCARD993";
    const SECRET_CVV: &str = "cvv-SECRET-994";
    const LOGIN_ID: &str = "11111111-1111-4111-8111-111111111111";
    const CARD_ID: &str = "22222222-2222-4222-8222-222222222222";

    fn secrets() -> [&'static str; 4] {
        [SECRET_PASSWORD, SECRET_NOTE, SECRET_NUMBER, SECRET_CVV]
    }

    fn assert_clean(label: &str, haystack: &str) {
        for secret in secrets() {
            assert!(
                !haystack.contains(secret),
                "{label} contains secret {secret}: {haystack}"
            );
        }
    }

    struct MemoryVault {
        unlocked: Mutex<bool>,
        items: Mutex<Vec<VaultItem>>,
    }

    impl MemoryVault {
        fn unlocked(items: Vec<VaultItem>) -> Arc<Self> {
            Arc::new(Self {
                unlocked: Mutex::new(true),
                items: Mutex::new(items),
            })
        }

        fn lock(&self) {
            *self.unlocked.lock().unwrap() = false;
        }
    }

    impl VaultView for MemoryVault {
        fn is_unlocked(&self) -> bool {
            *self.unlocked.lock().unwrap()
        }

        fn items(&self) -> Vec<VaultItem> {
            if !self.is_unlocked() {
                return Vec::new();
            }
            self.items.lock().unwrap().clone()
        }
    }

    struct CountingApprover {
        hits: AtomicUsize,
        decision: ApprovalDecision,
    }

    impl SecretApprover for CountingApprover {
        fn decide<'a>(
            &'a self,
            _request: &'a ApprovalRequest,
        ) -> Pin<Box<dyn Future<Output = ApprovalDecision> + Send + 'a>> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            let decision = self.decision;
            Box::pin(async move { decision })
        }
    }

    fn seed_items() -> Vec<VaultItem> {
        vec![
            VaultItem {
                id: LOGIN_ID.into(),
                item_type: "login".into(),
                title: "Naver".into(),
                favorite: true,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-02-01T00:00:00Z".into(),
                username: Some("user@example.com".into()),
                password: Some(SECRET_PASSWORD.into()),
                url: Some("https://naver.example".into()),
                notes: Some(SECRET_NOTE.into()),
                cardholder: None,
                number: None,
                expiry: None,
                cvv: None,
                tags: vec!["personal".into(), "mail".into()],
                ..VaultItem::skeleton()
            },
            VaultItem {
                id: CARD_ID.into(),
                item_type: "card".into(),
                title: "Shinhan".into(),
                favorite: false,
                created_at: "2026-03-01T00:00:00Z".into(),
                updated_at: "2026-03-02T00:00:00Z".into(),
                username: None,
                password: None,
                url: None,
                notes: Some(SECRET_NOTE.into()),
                cardholder: Some("KIM HAVEN".into()),
                number: Some(SECRET_NUMBER.into()),
                expiry: Some("09/28".into()),
                cvv: Some(SECRET_CVV.into()),
                tags: vec!["finance".into()],
                ..VaultItem::skeleton()
            },
        ]
    }

    fn service(
        vault: Arc<dyn VaultView>,
        approver: Arc<dyn SecretApprover>,
    ) -> (tempfile::TempDir, Arc<McpService>) {
        let dir = tempfile::tempdir().unwrap();
        let svc = Arc::new(McpService::open(dir.path(), vault, approver).unwrap());
        (dir, svc)
    }

    fn auth_header(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn rpc(id: i64, method: &str, params: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .unwrap()
    }

    fn call_tool(id: i64, name: &str, arguments: Value) -> Vec<u8> {
        rpc(id, "tools/call", json!({"name": name, "arguments": arguments}))
    }

    fn parse_body(reply: &HttpReply) -> Value {
        if reply.body.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice(&reply.body).unwrap()
    }

    fn tool_text(body: &Value) -> &str {
        body["result"]["content"][0]["text"].as_str().unwrap()
    }

    fn assert_metadata_value(value: &Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    assert_metadata_object(item);
                }
            }
            Value::Object(_) => assert_metadata_object(value),
            other => panic!("unexpected metadata {other}"),
        }
    }

    fn assert_metadata_object(value: &Value) {
        let obj = value.as_object().expect("metadata object");
        for key in [
            "password",
            "notes",
            "number",
            "cvv",
            "cardholder",
            "expiry",
            "itemType",
            "item_type",
            "createdAt",
            "updatedAt",
        ] {
            assert!(!obj.contains_key(key), "forbidden key {key} in {value}");
        }
        for key in ["id", "title", "type", "username", "url", "tags", "favorite", "created", "updated"]
        {
            assert!(obj.contains_key(key), "missing {key}");
        }
        assert!(obj["tags"].is_array());
        assert!(obj["favorite"].is_boolean());
    }

    #[test]
    fn trim_log_keeps_last_1000() {
        let mut entries = Vec::new();
        for index in 0..1005 {
            entries.push(AccessLogEntry {
                timestamp: format!("t{index}"),
                token_name: "t".into(),
                tool: "list_items".into(),
                item_id: None,
                allowed: true,
                reason: "ok".into(),
            });
        }
        trim_log(&mut entries);
        assert_eq!(entries.len(), 1000);
        assert_eq!(entries[0].timestamp, "t5");
        assert_eq!(entries.last().unwrap().timestamp, "t1004");
    }

    #[tokio::test]
    async fn missing_invalid_and_revoked_tokens_are_401() {
        let vault = MemoryVault::unlocked(seed_items());
        let (_dir, svc) = service(vault, Arc::new(AutoDeny));
        let body = call_tool(1, "list_items", json!({}));

        let missing = svc.handle_http("POST", "/mcp", None, &body).await;
        assert_eq!(missing.status, 401);

        let invalid = svc
            .handle_http("POST", "/mcp", Some("Bearer not-a-real-token"), &body)
            .await;
        assert_eq!(invalid.status, 401);

        let issued = svc.issue_token("laptop").unwrap();
        let config = fs::read_to_string(svc.config_path()).unwrap();
        assert!(!config.contains(&issued.token), "plaintext token stored: {config}");
        assert!(config.contains("tokenHash"));

        svc.revoke_token(&issued.info.id).unwrap();
        let header = auth_header(&issued.token);
        let revoked = svc
            .handle_http("POST", "/mcp", Some(&header), &body)
            .await;
        assert_eq!(revoked.status, 401);
        assert_clean("401 body", &String::from_utf8_lossy(&revoked.body));
    }

    #[tokio::test]
    async fn locked_vault_rejects_tool_calls() {
        let vault = MemoryVault::unlocked(seed_items());
        let (_dir, svc) = service(vault.clone(), Arc::new(AutoApprove));
        let issued = svc.issue_token("agent").unwrap();
        let header = auth_header(&issued.token);
        vault.lock();

        let reply = svc
            .handle_http(
                "POST",
                "/mcp",
                Some(&header),
                &call_tool(7, "search_items", json!({"query": "Naver"})),
            )
            .await;
        assert_eq!(reply.status, 200);
        let body = parse_body(&reply);
        assert_eq!(body["error"]["message"], LOCKED_REASON);
        assert_clean("locked response", &String::from_utf8_lossy(&reply.body));

        let log = fs::read_to_string(svc.log_path()).unwrap();
        assert!(log.contains("\"allowed\": false"));
        assert!(log.contains(LOCKED_REASON));
        assert_clean("locked log", &log);
    }

    #[tokio::test]
    async fn metadata_responses_never_contain_secrets() {
        let vault = MemoryVault::unlocked(seed_items());
        let (_dir, svc) = service(vault, Arc::new(AutoDeny));
        let issued = svc.issue_token("agent").unwrap();
        let header = auth_header(&issued.token);

        let cases = [
            call_tool(1, "list_items", json!({})),
            call_tool(2, "search_items", json!({"query": "nav", "type": "login"})),
            call_tool(3, "search_items", json!({"query": SECRET_PASSWORD})),
            call_tool(4, "get_item_metadata", json!({"id": LOGIN_ID})),
            call_tool(5, "get_item_metadata", json!({"id": CARD_ID})),
        ];
        for (index, payload) in cases.iter().enumerate() {
            let reply = svc.handle_http("POST", "/mcp", Some(&header), payload).await;
            assert_eq!(reply.status, 200, "{index}");
            let body = parse_body(&reply);
            let text = tool_text(&body);
            assert_eq!(body["result"]["isError"], false, "{text}");
            let parsed: Value = serde_json::from_str(text).unwrap();
            assert_metadata_value(&parsed);
            assert_clean("metadata", text);
            if index == 1 {
                assert!(text.contains("Naver"));
                assert!(text.contains("user@example.com"));
                assert!(text.contains("personal"));
                assert!(!text.contains("Shinhan"));
            }
            if index == 2 {
                let parsed: Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed, json!([]));
            }
        }
        let log = fs::read_to_string(svc.log_path()).unwrap();
        assert_clean("metadata log", &log);
        assert!(!log.contains(SECRET_PASSWORD));
    }

    #[tokio::test]
    async fn get_secret_auto_deny_and_auto_approve() {
        let vault = MemoryVault::unlocked(seed_items());
        let (_deny_dir, deny_svc) = service(vault.clone(), Arc::new(AutoDeny));
        let deny_token = deny_svc.issue_token("deny-agent").unwrap();
        let deny_header = auth_header(&deny_token.token);
        let payload = call_tool(1, "get_secret", json!({"id": LOGIN_ID, "field": "password"}));
        let denied = deny_svc
            .handle_http("POST", "/mcp", Some(&deny_header), &payload)
            .await;
        let denied_body = parse_body(&denied);
        assert_eq!(denied_body["result"]["isError"], true);
        assert_eq!(tool_text(&denied_body), "approval denied");
        assert_clean("denied secret response", &String::from_utf8_lossy(&denied.body));
        let deny_log = fs::read_to_string(deny_svc.log_path()).unwrap();
        assert!(deny_log.contains("\"allowed\": false"));
        assert!(deny_log.contains("denied"));
        assert!(deny_log.contains(LOGIN_ID));
        assert_clean("denied log", &deny_log);

        let (_allow_dir, allow_svc) = service(vault, Arc::new(AutoApprove));
        let allow_token = allow_svc.issue_token("allow-agent").unwrap();
        let allow_header = auth_header(&allow_token.token);
        let allowed = allow_svc
            .handle_http("POST", "/mcp", Some(&allow_header), &payload)
            .await;
        let allowed_body = parse_body(&allowed);
        assert_eq!(allowed_body["result"]["isError"], false);
        let text = tool_text(&allowed_body);
        assert!(text.contains(SECRET_PASSWORD));
        assert!(!text.contains(SECRET_NOTE));
        assert!(!text.contains(SECRET_NUMBER));
        assert!(!text.contains(SECRET_CVV));
        let allow_log = fs::read_to_string(allow_svc.log_path()).unwrap();
        assert!(allow_log.contains("\"allowed\": true"));
        assert!(allow_log.contains("approved"));
        assert!(allow_log.contains(LOGIN_ID));
        assert_clean("approved log", &allow_log);
        assert!(!allow_log.contains(&allow_token.token));
    }

    #[tokio::test]
    async fn get_secret_asks_for_approval_every_call() {
        let vault = MemoryVault::unlocked(seed_items());
        let counter = Arc::new(CountingApprover {
            hits: AtomicUsize::new(0),
            decision: ApprovalDecision::Denied,
        });
        let (_dir, svc) = service(vault, counter.clone());
        let token = svc.issue_token("counter").unwrap();
        let header = auth_header(&token.token);
        let payload = call_tool(1, "get_secret", json!({"id": LOGIN_ID, "field": "notes"}));
        let _ = svc.handle_http("POST", "/mcp", Some(&header), &payload).await;
        let _ = svc.handle_http("POST", "/mcp", Some(&header), &payload).await;
        assert_eq!(counter.hits.load(Ordering::SeqCst), 2);
        let log = fs::read_to_string(svc.log_path()).unwrap();
        assert_clean("repeated deny log", &log);
        assert_eq!(log.matches("\"allowed\": false").count(), 2);
    }

    #[tokio::test]
    async fn notifications_return_202_and_get_is_405() {
        let vault = MemoryVault::unlocked(seed_items());
        let (_dir, svc) = service(vault, Arc::new(AutoDeny));
        let token = svc.issue_token("n").unwrap();
        let header = auth_header(&token.token);
        let note = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .unwrap();
        let reply = svc.handle_http("POST", "/mcp", Some(&header), &note).await;
        assert_eq!(reply.status, 202);
        assert!(reply.body.is_empty());

        let get = svc.handle_http("GET", "/mcp", Some(&header), b"").await;
        assert_eq!(get.status, 405);
    }

    #[tokio::test]
    async fn http_end_to_end_initialize_list_and_search() {
        let vault = MemoryVault::unlocked(seed_items());
        let (_dir, svc) = service(vault, Arc::new(AutoDeny));
        let token = svc.issue_token("e2e").unwrap();
        let (listener, addr) = bind_loopback(0).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let (_tx, rx) = watch::channel(false);
        let server = svc.clone();
        tokio::spawn(async move {
            run_server(listener, server, rx).await;
        });
        tokio::task::yield_now().await;

        let init = http_post(
            addr,
            Some(&token.token),
            &rpc(
                1,
                "initialize",
                json!({
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0.0.1"}
                }),
            ),
        )
        .await;
        assert_eq!(init.0, 200);
        assert_eq!(init.1["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init.1["result"]["serverInfo"]["name"], "SecureVault");
        assert_eq!(init.1["result"]["serverInfo"]["version"], crate::VERSION);
        assert_eq!(init.1["result"]["capabilities"]["tools"]["listChanged"], false);

        let note = http_post(
            addr,
            Some(&token.token),
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(note.0, 202);

        let tools = http_post(addr, Some(&token.token), &rpc(2, "tools/list", json!({}))).await;
        assert_eq!(tools.0, 200);
        let names: Vec<&str> = tools.1["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["search_items", "list_items", "get_item_metadata", "get_secret"]
        );

        let search = http_post(
            addr,
            Some(&token.token),
            &call_tool(3, "search_items", json!({"query": "finance", "type": "card"})),
        )
        .await;
        assert_eq!(search.0, 200);
        let text = tool_text(&search.1);
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_metadata_value(&parsed);
        assert!(text.contains("Shinhan"));
        assert!(text.contains("finance"));
        assert_clean("e2e search", &search.1.to_string());

        let no_token = http_post(addr, None, &rpc(4, "tools/list", json!({}))).await;
        assert_eq!(no_token.0, 401);

        let get = http_exchange(addr, "GET", Some(&token.token), b"").await;
        assert_eq!(get.0, 405);
    }

    async fn http_post(addr: SocketAddr, token: Option<&str>, body: &[u8]) -> (u16, Value) {
        let (status, bytes) = http_exchange(addr, "POST", token, body).await;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    async fn http_exchange(
        addr: SocketAddr,
        method: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        let mut last_err = String::new();
        for _ in 0..20 {
            match send_once(addr, method, token, body).await {
                Ok(result) => return result,
                Err(err) => {
                    last_err = err;
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
        }
        panic!("http exchange failed: {last_err}");
    }

    async fn send_once(
        addr: SocketAddr,
        method: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| e.to_string())?;
        let io = TokioIo::new(stream);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut builder = Request::builder()
            .method(method)
            .uri("/mcp")
            .header("host", "127.0.0.1")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("content-length", body.len());
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = builder
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| e.to_string())?;
        let response = sender.send_request(request).await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }
}
