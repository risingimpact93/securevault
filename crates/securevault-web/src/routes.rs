use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::stream::StreamExt;
use securevault_core::vault::{self, SettingsPatch, VaultItem};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::{ServeDir, ServeFile};

use crate::{err_json, vault_error, AppState};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordBody {
    password: String,
    #[serde(default)]
    secret_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretKeyBody {
    secret_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableSecretKeyBody {
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableSecretKeyBody {
    password: String,
    secret_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateBody {
    length: u32,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportBody {
    export_password: String,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McpSettingsBody {
    enabled: bool,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct TokenNameBody {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ApproveBody {
    approved: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportBody {
    export_password: String,
    mode: String,
    file_base64: String,
}

#[derive(Debug, Deserialize)]
struct OpenVaultBody {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultLocationBody {
    path: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveConflictBody {
    item_id: String,
    conflict_id: String,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MergePasswordBody {
    path: String,
    password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionView {
    unlocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    csrf_token: Option<String>,
    auto_lock_minutes: u64,
}

pub fn router(state: AppState) -> Router {
    let mut app = Router::new()
        .route("/api/vault-exists", get(vault_exists))
        .route("/api/vaults/discover", get(discover_vaults))
        .route("/api/vaults/open", post(open_existing_vault))
        .route("/api/create-vault", post(create_vault))
        .route("/api/unlock", post(unlock))
        .route("/api/secret-key/status", get(secret_key_status))
        .route("/api/secret-key/import", post(import_secret_key))
        .route("/api/secret-key/enable", post(enable_secret_key))
        .route("/api/secret-key/disable", post(disable_secret_key))
        .route("/api/secret-key/reveal", post(reveal_secret_key))
        .route("/api/lock", post(lock))
        .route("/api/is-unlocked", get(is_unlocked))
        .route("/api/session", get(session))
        .route("/api/about", get(about))
        .route("/api/items", get(list_items).post(add_item).put(update_item))
        .route("/api/items/{id}", delete(delete_item))
        .route("/api/items/{id}/move", post(move_item))
        .route("/api/change-master-password", post(change_master_password))
        .route("/api/generate-password", post(generate_password))
        .route("/api/export-vault", post(export_vault))
        .route("/api/import-vault", post(import_vault))
        .route("/api/mcp/settings", get(mcp_get_settings).post(mcp_set_settings))
        .route("/api/mcp/tokens", post(mcp_issue_token))
        .route("/api/mcp/tokens/{id}", delete(mcp_revoke_token))
        .route("/api/mcp/access-log", get(mcp_access_log))
        .route("/api/approvals", get(list_approvals))
        .route("/api/approvals/{id}", post(respond_approval))
        .route("/api/events", get(events))
        .route("/api/activity", post(activity))
        .route("/api/idle-lock", post(idle_expire))
        .route("/api/settings", get(get_settings).post(set_settings))
        .route("/api/sync/status", get(sync_status))
        .route("/api/sync/conflicts", get(sync_conflicts))
        .route("/api/sync/conflicts/resolve", post(resolve_sync_conflict))
        .route("/api/sync/location", post(set_vault_location))
        .route("/api/sync/merge-password", post(merge_sync_password))
        .route("/api/biometrics/status", get(biometric_status))
        .route("/api/webauthn/register/start", post(webauthn_register_start))
        .route("/api/webauthn/register/finish", post(webauthn_register_finish))
        .route("/api/webauthn/authenticate/start", post(webauthn_auth_start))
        .route("/api/webauthn/authenticate/finish", post(webauthn_auth_finish))
        .route("/api/webauthn/credential", delete(webauthn_remove))
        .route("/mcp", get(mcp_http).post(mcp_http))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024));

    if let Some(dist) = state.dist_dir() {
        if dist.exists() {
            let index = dist.join("index.html");
            let fallback = ServeDir::new(&dist).not_found_service(ServeFile::new(index));
            app = app.fallback_service(fallback);
        }
    }
    app
}

async fn vault_exists(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.vault_exists())
}

async fn discover_vaults(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.discover_vaults())
}

async fn open_existing_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<OpenVaultBody>,
) -> Response {
    if let Err(resp) = state.require_origin(&headers) {
        return resp;
    }
    match state.open_existing_vault(&body.path) {
        Ok(status) => Json(status).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn session(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let minutes = state.auto_lock_minutes();
    if let Some((_, csrf)) = state.lookup_session(&headers) {
        if state.is_unlocked() {
            return Json(SessionView {
                unlocked: true,
                csrf_token: Some(csrf),
                auto_lock_minutes: minutes,
            })
            .into_response();
        }
    }
    Json(SessionView {
        unlocked: false,
        csrf_token: None,
        auto_lock_minutes: minutes,
    })
    .into_response()
}

async fn create_vault(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> Response {
    if let Err(resp) = state.require_origin(&headers) {
        return resp;
    }
    let ip = addr.ip().to_string();
    if let Some(wait) = state.check_login_backoff(&ip) {
        return too_many(wait);
    }
    match state.create_vault(&body.password) {
        Ok(()) => {
            state.clear_login_failures(&ip);
            session_ok(&state, StatusCode::OK)
        }
        Err(err) => vault_error(err),
    }
}

async fn unlock(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> Response {
    if let Err(resp) = state.require_origin(&headers) {
        return resp;
    }
    let ip = addr.ip().to_string();
    if let Some(wait) = state.check_login_backoff(&ip) {
        return too_many(wait);
    }
    match state.unlock_vault_with_secret_key(&body.password, body.secret_key.as_deref()) {
        Ok(()) => {
            state.clear_login_failures(&ip);
            session_ok(&state, StatusCode::OK)
        }
        Err(err) => {
            if matches!(err, securevault_core::vault::VaultError::WrongPassword) {
                let wait = state.record_login_failure(&ip);
                let mut resp = vault_error(err);
                resp.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_str(&wait.as_secs().max(1).to_string())
                        .unwrap_or_else(|_| HeaderValue::from_static("1")),
                );
                return resp;
            }
            vault_error(err)
        }
    }
}

async fn lock(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        // Lock is allowed with a valid session even if idle already fired.
        if let Err(origin) = state.require_origin(&headers) {
            return origin;
        }
        if state.lookup_session(&headers).is_none() {
            state.lock_vault();
            return json_with_clear_cookie(&state, StatusCode::OK, json!({ "ok": true }));
        }
        return resp;
    }
    state.lock_vault();
    json_with_clear_cookie(&state, StatusCode::OK, json!({ "ok": true }))
}

async fn is_unlocked(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let unlocked = state.lookup_session(&headers).is_some() && state.is_unlocked();
    Json(unlocked)
}

async fn secret_key_status(State(state): State<AppState>) -> Response {
    match state.secret_key_status() {
        Ok(status) => Json(status).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn import_secret_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SecretKeyBody>,
) -> Response {
    if let Err(resp) = state.require_origin(&headers) {
        return resp;
    }
    match state.import_secret_key(&body.secret_key) {
        Ok(status) => Json(status).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn enable_secret_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnableSecretKeyBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.enable_secret_key(&body.password) {
        Ok(kit) => Json(kit).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn disable_secret_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DisableSecretKeyBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.disable_secret_key(&body.password, &body.secret_key) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn reveal_secret_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnableSecretKeyBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.reveal_secret_key(&body.password) {
        Ok(kit) => Json(kit).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn about() -> impl IntoResponse {
    Json(json!({
        "version": securevault_core::VERSION,
        "commit": securevault_core::GIT_COMMIT,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MoveBody {
    #[serde(default)]
    before_id: Option<String>,
}

async fn list_items(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    match state.list_items() {
        Ok(items) => Json(items).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn add_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(draft): Json<ItemDraft>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    if let Err(err) = vault::validate_item_type(&draft.item_type) {
        return vault_error(err);
    }
    let now = vault::now_rfc3339();
    let item = VaultItem {
        id: vault::new_id(),
        item_type: draft.item_type,
        title: draft.title,
        favorite: draft.favorite,
        created_at: now.clone(),
        updated_at: now,
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
    };
    match state.add_item(item) {
        Ok(item) => Json(item).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn update_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(item): Json<VaultItem>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.update_item(item) {
        Ok(item) => Json(item).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn delete_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.delete_item(&id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn move_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<MoveBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.move_item(&id, body.before_id) {
        Ok(item) => Json(item).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn change_master_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.change_master_password(&body.current_password, &body.new_password) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn generate_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GenerateBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match vault::generate_password(
        body.length as usize,
        body.upper,
        body.lower,
        body.digits,
        body.symbols,
    ) {
        Ok(password) => Json(password).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn export_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExportBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.export_bytes(&body.export_password) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"vault.khv\"",
            )
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(err) => vault_error(err),
    }
}

async fn import_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ImportBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    if body.mode != "merge" && body.mode != "replace" {
        return err_json(StatusCode::BAD_REQUEST, "mode must be merge or replace");
    }
    let bytes = match B64.decode(body.file_base64.trim()) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return err_json(StatusCode::BAD_REQUEST, "file is required"),
    };
    match state.import_bytes(&bytes, &body.export_password, &body.mode) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn mcp_get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    match state.mcp().public_settings() {
        Ok(settings) => Json(settings).into_response(),
        Err(err) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
}

async fn mcp_set_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<McpSettingsBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    if body.port == 0 {
        return err_json(StatusCode::BAD_REQUEST, "포트는 1에서 65535 사이여야 합니다.");
    }
    match state.mcp().set_listen(body.enabled, body.port) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => err_json(StatusCode::BAD_REQUEST, &err),
    }
}

async fn mcp_issue_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TokenNameBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.mcp().issue_token(&body.name) {
        Ok(issued) => Json(issued).into_response(),
        Err(err) => err_json(StatusCode::BAD_REQUEST, &err),
    }
}

async fn mcp_revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.mcp().revoke_token(&id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => err_json(StatusCode::BAD_REQUEST, &err),
    }
}

async fn mcp_access_log(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    Json(state.mcp().access_log()).into_response()
}

async fn list_approvals(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    Json(json!({ "pending": state.pending_approvals() })).into_response()
}

async fn respond_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ApproveBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.approver().respond(&id, body.approved) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => err_json(StatusCode::NOT_FOUND, &err),
    }
}

async fn sync_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    Json(state.sync_status()).into_response()
}

async fn sync_conflicts(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    match state.sync_conflicts() {
        Ok(conflicts) => Json(conflicts).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn resolve_sync_conflict(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ResolveConflictBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.resolve_sync_conflict(&body.item_id, &body.conflict_id, &body.action) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn set_vault_location(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VaultLocationBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.set_vault_location(&body.path, &body.mode) {
        Ok(status) => Json(status).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn merge_sync_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MergePasswordBody>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.merge_sync_password(&body.path, &body.password) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    let rx = state.subscribe_approvals();
    let stream = BroadcastStream::new(rx).filter_map(|item| async move {
        match item {
            Ok(event) => match Event::default().json_data(event) {
                Ok(ev) => Some(Ok::<Event, std::convert::Infallible>(ev)),
                Err(_) => None,
            },
            Err(_) => None,
        }
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

async fn activity(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    if !state.touch_session(&headers) {
        return err_json(StatusCode::UNAUTHORIZED, "vault is locked");
    }
    Json(json!({ "ok": true })).into_response()
}

/// Ends the browser session the way the idle ticker does.
/// With no PRF wrap the vault key stays in memory so a passkey can resume it.
/// An explicit `/api/lock` still wipes that key.
async fn idle_expire(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_origin(&headers) {
        return resp;
    }
    if state.lookup_session(&headers).is_some() {
        if let Err(resp) = state.require_unlocked_session(&headers, true) {
            return resp;
        }
    }
    state.idle_lock();
    json_with_clear_cookie(&state, StatusCode::OK, json!({ "ok": true }))
}

fn settings_json(settings: &vault::VaultSettings) -> serde_json::Value {
    json!({
        "autoLockMinutes": settings.auto_lock_minutes,
        "lockOnScreenLock": settings.lock_on_screen_lock,
        "biometricsEnabled": settings.biometrics_enabled,
        "passwordIntervalDays": settings.password_interval_days,
        "screenLockSupported": false,
    })
}

async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, false) {
        return resp;
    }
    match state.vault_settings() {
        Ok(settings) => Json(settings_json(&settings)).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn set_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(patch): Json<SettingsPatch>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.update_settings(&patch) {
        Ok(settings) => Json(settings_json(&settings)).into_response(),
        Err(err) => vault_error(err),
    }
}

async fn biometric_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.biometric_status())
}

fn note_passkey_origin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "passkeys require http://localhost"))?;
    crate::webauthn::note_origin(state, origin)
        .map_err(|msg| err_json(StatusCode::BAD_REQUEST, &msg))
}

async fn webauthn_register_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    if let Err(resp) = note_passkey_origin(&state, &headers) {
        return resp;
    }
    match state.webauthn_register_start() {
        Ok(body) => Json(body).into_response(),
        Err(msg) => {
            let status = if msg == "vault is locked" {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            };
            err_json(status, &msg)
        }
    }
}

async fn webauthn_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    if let Err(resp) = note_passkey_origin(&state, &headers) {
        return resp;
    }
    match state.webauthn_register_finish(body) {
        Ok(status) => Json(status).into_response(),
        Err(msg) => err_json(StatusCode::BAD_REQUEST, &msg),
    }
}

async fn webauthn_auth_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_origin(&headers) {
        return resp;
    }
    if let Err(resp) = note_passkey_origin(&state, &headers) {
        return resp;
    }
    match state.webauthn_auth_start() {
        Ok(body) => Json(body).into_response(),
        Err(resp) => resp,
    }
}

async fn webauthn_auth_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = state.require_origin(&headers) {
        return resp;
    }
    if let Err(resp) = note_passkey_origin(&state, &headers) {
        return resp;
    }
    match state.webauthn_auth_finish(body) {
        Ok(()) => session_ok(&state, StatusCode::OK),
        Err(err) => err.into_response(),
    }
}

async fn webauthn_remove(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = state.require_unlocked_session(&headers, true) {
        return resp;
    }
    match state.webauthn_remove() {
        Ok(status) => Json(status).into_response(),
        Err(msg) => {
            let status = if msg == "vault is locked" {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            };
            err_json(status, &msg)
        }
    }
}

async fn mcp_http(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.mcp().enabled() {
        return err_json(StatusCode::NOT_FOUND, "not found");
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let reply = state
        .mcp()
        .handle_http(method.as_str(), "/mcp", authorization, &body)
        .await;
    let mut builder = Response::builder()
        .status(reply.status)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(ct) = reply.content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    if reply.status == 405 {
        builder = builder.header(header::ALLOW, "POST");
    }
    builder
        .body(Body::from(reply.body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn session_ok(state: &AppState, status: StatusCode) -> Response {
    let (id, csrf) = state.issue_session();
    let mut resp = Json(json!({ "csrfToken": csrf })).into_response();
    *resp.status_mut() = status;
    let cookie = state.cookie_header(&id);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&csrf) {
        resp.headers_mut().insert(
            header::HeaderName::from_static("x-csrf-token"),
            value,
        );
    }
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    resp
}

fn json_with_clear_cookie(state: &AppState, status: StatusCode, body: serde_json::Value) -> Response {
    let mut resp = Json(body).into_response();
    *resp.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(&state.clear_cookie_header()) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

fn too_many(wait: Duration) -> Response {
    let secs = wait.as_secs().max(1);
    let mut resp = err_json(StatusCode::TOO_MANY_REQUESTS, "too many attempts");
    resp.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&secs.to_string()).unwrap_or_else(|_| HeaderValue::from_static("1")),
    );
    resp
}
