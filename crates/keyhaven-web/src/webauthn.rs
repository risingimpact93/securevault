//! WebAuthn passkeys. A PRF result wraps the vault key; without PRF the passkey
//! only resumes a vault that is still unlocked in this process.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use keyhaven_core::vault::{self, VaultError, WrappedVaultKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Webauthn, WebauthnBuilder,
};
use zeroize::Zeroize;

use crate::{err_json, AppState};

const PENDING_TTL: Duration = Duration::from_secs(300);

pub(crate) struct Pending {
    kind: PendingKind,
    salt: Vec<u8>,
    expires: Instant,
}

enum PendingKind {
    Register(PasskeyRegistration),
    Authenticate(PasskeyAuthentication),
}

#[derive(Serialize, Deserialize)]
struct WebauthnFile {
    user_id: Uuid,
    #[serde(default)]
    credential: Option<StoredCredential>,
}

#[derive(Serialize, Deserialize)]
struct StoredCredential {
    passkey: Passkey,
    prf_salt: String,
    #[serde(default)]
    wrapped: Option<WrappedVaultKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinishBody {
    credential: Value,
    #[serde(default)]
    prf_first: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BiometricStatus {
    pub available: bool,
    pub configured: bool,
    pub prf: bool,
    pub can_unlock: bool,
    pub password_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub platform: &'static str,
}

impl AppState {
    pub(crate) fn biometric_status(&self) -> BiometricStatus {
        let store = load_store(&self.inner.webauthn_path);
        let configured = store.credential.is_some();
        let prf = store.credential.as_ref().and_then(|c| c.wrapped.as_ref()).is_some();
        let (password_required, reason) = self.password_gate();
        let memory = self.memory_unlocked();
        let can_unlock = configured && !password_required && (prf || memory);
        BiometricStatus {
            available: true,
            configured,
            prf,
            can_unlock,
            password_required,
            reason,
            platform: "web",
        }
    }

    pub(crate) fn webauthn_register_start(&self) -> Result<Value, String> {
        if !self.memory_unlocked() {
            return Err(VaultError::Locked.to_string());
        }
        let store = load_store(&self.inner.webauthn_path);
        let exclude = store
            .credential
            .as_ref()
            .map(|cred| vec![cred.passkey.cred_id().clone()]);
        let (webauthn, _origin) = self.webauthn()?;
        let (ccr, state) = webauthn
            .start_passkey_registration(store.user_id, "keyhaven", "Keyhaven", exclude)
            .map_err(|e| e.to_string())?;
        let mut salt = vec![0u8; vault::KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let mut options = serde_json::to_value(&ccr).map_err(|e| e.to_string())?;
        inject_prf(&mut options, &B64URL.encode(&salt));
        if let Ok(mut pending) = self.inner.pending_webauthn.lock() {
            *pending = Some(Pending {
                kind: PendingKind::Register(state),
                salt,
                expires: Instant::now() + PENDING_TTL,
            });
        }
        let _ = store;
        Ok(json!({ "options": options }))
    }

    pub(crate) fn webauthn_register_finish(&self, body: Value) -> Result<BiometricStatus, String> {
        let body: FinishBody = serde_json::from_value(body).map_err(|e| e.to_string())?;
        let reg: RegisterPublicKeyCredential =
            serde_json::from_value(body.credential).map_err(|e| e.to_string())?;
        let pending = self.take_pending()?;
        let PendingKind::Register(state) = pending.kind else {
            return Err("webauthn ceremony mismatch".into());
        };
        if pending.expires <= Instant::now() {
            return Err("webauthn challenge expired".into());
        }
        let (webauthn, _) = self.webauthn()?;
        let passkey = webauthn
            .finish_passkey_registration(&reg, &state)
            .map_err(|e| e.to_string())?;
        let mut prf = decode_prf(body.prf_first)?;
        let wrapped = if let Some(output) = prf.as_deref() {
            let key = self.memory_key().ok_or_else(|| VaultError::Locked.to_string())?;
            Some(vault::wrap_vault_key(&key, output).map_err(|e| e.to_string())?)
        } else {
            None
        };
        if let Some(buf) = prf.as_mut() {
            buf.zeroize();
        }
        let mut store = load_store(&self.inner.webauthn_path);
        store.credential = Some(StoredCredential {
            passkey,
            prf_salt: B64URL.encode(&pending.salt),
            wrapped,
        });
        save_store(&self.inner.webauthn_path, &store)?;
        self.sync_prf_flag();
        self.set_biometrics_enabled(true)?;
        Ok(self.biometric_status())
    }

    pub(crate) fn webauthn_auth_start(&self) -> Result<Value, axum::response::Response> {
        let store = load_store(&self.inner.webauthn_path);
        let Some(cred) = store.credential.as_ref() else {
            return Err(crate::err_json(
                axum::http::StatusCode::UNAUTHORIZED,
                "biometrics unavailable",
            ));
        };
        if let Some(reason) = self.password_gate_reason() {
            return Err(gate_response(reason));
        }
        let (webauthn, _) = self.webauthn().map_err(|e| err_json(axum::http::StatusCode::BAD_REQUEST, &e))?;
        let (rcr, state) = webauthn
            .start_passkey_authentication(&[cred.passkey.clone()])
            .map_err(|e| err_json(axum::http::StatusCode::BAD_REQUEST, &e.to_string()))?;
        let salt = B64URL
            .decode(cred.prf_salt.as_bytes())
            .unwrap_or_else(|_| vec![0u8; vault::KEY_LEN]);
        let mut options = serde_json::to_value(&rcr).map_err(|e| err_json(axum::http::StatusCode::BAD_REQUEST, &e.to_string()))?;
        inject_prf(&mut options, &B64URL.encode(&salt));
        if let Ok(mut pending) = self.inner.pending_webauthn.lock() {
            *pending = Some(Pending {
                kind: PendingKind::Authenticate(state),
                salt,
                expires: Instant::now() + PENDING_TTL,
            });
        }
        Ok(json!({ "options": options, "prf": cred.wrapped.is_some() }))
    }

    pub(crate) fn webauthn_auth_finish(&self, body: Value) -> Result<(), ResponseError> {
        let body: FinishBody = serde_json::from_value(body).map_err(|e| ResponseError::bad(e.to_string()))?;
        let assertion: PublicKeyCredential =
            serde_json::from_value(body.credential).map_err(|e| ResponseError::bad(e.to_string()))?;
        let pending = self.take_pending().map_err(ResponseError::bad)?;
        let PendingKind::Authenticate(state) = pending.kind else {
            return Err(ResponseError::bad("webauthn ceremony mismatch"));
        };
        if pending.expires <= Instant::now() {
            return Err(ResponseError::bad("webauthn challenge expired"));
        }
        let (webauthn, _) = self.webauthn().map_err(ResponseError::bad)?;
        let result = webauthn
            .finish_passkey_authentication(&assertion, &state)
            .map_err(|e| ResponseError::unauthorized(e.to_string()))?;
        if let Some(reason) = self.password_gate_reason() {
            let _ = self.bump_passkey(&result);
            return Err(ResponseError::gate(reason));
        }
        let mut prf = decode_prf(body.prf_first).map_err(ResponseError::bad)?;
        let outcome = self.finish_prf_or_resume(prf.as_deref(), &result);
        if let Some(buf) = prf.as_mut() {
            buf.zeroize();
        }
        outcome
    }

    pub(crate) fn webauthn_remove(&self) -> Result<BiometricStatus, String> {
        let mut store = load_store(&self.inner.webauthn_path);
        store.credential = None;
        save_store(&self.inner.webauthn_path, &store)?;
        self.sync_prf_flag();
        self.set_biometrics_enabled(false)?;
        Ok(self.biometric_status())
    }

    fn finish_prf_or_resume(
        &self,
        prf: Option<&[u8]>,
        result: &webauthn_rs::prelude::AuthenticationResult,
    ) -> Result<(), ResponseError> {
        let mut store = load_store(&self.inner.webauthn_path);
        if store.credential.is_none() {
            return Err(ResponseError::unauthorized("biometrics unavailable"));
        }
        let memory_key = self.memory_key();
        let mut invalidated = false;
        let mut restored: Option<vault::VaultKey> = None;
        {
            let cred = store.credential.as_mut().expect("credential checked");
            let _ = cred.passkey.update_credential(result);
            if let Some(output) = prf {
                if let Some(key) = memory_key.as_ref() {
                    cred.wrapped = Some(
                        vault::wrap_vault_key(key, output).map_err(|e| ResponseError::bad(e.to_string()))?,
                    );
                } else if let Some(wrapped) = cred.wrapped.clone() {
                    match vault::unwrap_vault_key(&wrapped, output) {
                        Ok(key) => restored = Some(key),
                        Err(_) => {
                            cred.wrapped = None;
                            invalidated = true;
                        }
                    }
                }
            }
        }
        save_store(&self.inner.webauthn_path, &store).map_err(ResponseError::bad)?;
        self.sync_prf_flag();
        if invalidated {
            return Err(ResponseError::unauthorized("biometrics invalidated"));
        }
        if let Some(key) = restored {
            self.unlock_with_existing_key(key).map_err(ResponseError::from_vault)?;
            return Ok(());
        }
        if memory_key.is_some() {
            return Ok(());
        }
        Err(ResponseError::unauthorized("passkey session only"))
    }

    fn bump_passkey(&self, result: &webauthn_rs::prelude::AuthenticationResult) -> Result<(), String> {
        let mut store = load_store(&self.inner.webauthn_path);
        if let Some(cred) = store.credential.as_mut() {
            let _ = cred.passkey.update_credential(result);
        }
        save_store(&self.inner.webauthn_path, &store)
    }

    pub(crate) fn clear_prf_wrap(&self) {
        let mut store = load_store(&self.inner.webauthn_path);
        if let Some(cred) = store.credential.as_mut() {
            cred.wrapped = None;
        }
        let _ = save_store(&self.inner.webauthn_path, &store);
        self.sync_prf_flag();
    }

    pub(crate) fn sync_prf_flag(&self) {
        let prf = load_store(&self.inner.webauthn_path)
            .credential
            .and_then(|c| c.wrapped)
            .is_some();
        if let Ok(mut policy) = self.inner.policy.lock() {
            policy.prf_wrap = prf;
        }
    }

    fn set_biometrics_enabled(&self, enabled: bool) -> Result<(), String> {
        self.with_unlocked_mut(|unlocked| {
            unlocked.data.settings.biometrics_enabled = enabled;
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        if let Ok(guard) = self.inner.unlocked.lock() {
            if let Some(unlocked) = guard.as_ref() {
                if let Ok(mut policy) = self.inner.policy.lock() {
                    policy.settings = unlocked.data.settings.clone();
                }
            }
        }
        Ok(())
    }

    fn webauthn(&self) -> Result<(Webauthn, Url), String> {
        let origin = self
            .inner
            .rp_origin
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .ok_or_else(|| "passkeys require http://localhost".to_string())?;
        let origin = Url::parse(&origin).map_err(|_| "passkeys require http://localhost".to_string())?;
        let webauthn = WebauthnBuilder::new("localhost", &origin)
            .map_err(|e| e.to_string())?
            .rp_name("Keyhaven")
            .build()
            .map_err(|e| e.to_string())?;
        Ok((webauthn, origin))
    }

    fn take_pending(&self) -> Result<Pending, String> {
        let mut guard = self.inner.pending_webauthn.lock().map_err(|_| "lock poisoned".to_string())?;
        guard.take().ok_or_else(|| "webauthn challenge missing".to_string())
    }

    fn password_gate(&self) -> (bool, Option<String>) {
        match self.password_gate_reason() {
            Some(reason) => (true, Some(reason.to_string())),
            None => (false, None),
        }
    }

    pub(crate) fn password_gate_reason(&self) -> Option<&'static str> {
        let Ok(policy) = self.inner.policy.lock() else {
            return Some("restart");
        };
        if !policy.password_verified {
            return Some("restart");
        }
        if vault::password_unlock_expired_now(&policy.settings) {
            return Some("interval");
        }
        None
    }

    fn memory_unlocked(&self) -> bool {
        self.inner
            .unlocked
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    fn memory_key(&self) -> Option<vault::VaultKey> {
        self.inner
            .unlocked
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|u| u.key.clone()))
    }
}

pub(crate) struct ResponseError {
    pub status: axum::http::StatusCode,
    pub error: String,
    pub reason: Option<String>,
}

impl ResponseError {
    fn bad(error: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            error: error.into(),
            reason: None,
        }
    }

    fn unauthorized(error: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::UNAUTHORIZED,
            error: error.into(),
            reason: None,
        }
    }

    fn gate(reason: &'static str) -> Self {
        Self {
            status: axum::http::StatusCode::UNAUTHORIZED,
            error: "master password required".into(),
            reason: Some(reason.into()),
        }
    }

    fn from_vault(err: VaultError) -> Self {
        let status = match &err {
            VaultError::WrongPassword
            | VaultError::Locked
            | VaultError::MasterPasswordRequired
            | VaultError::BiometricsUnavailable
            | VaultError::BiometricsInvalidated
            | VaultError::PasskeySessionOnly
            | VaultError::Cancelled => axum::http::StatusCode::UNAUTHORIZED,
            _ => axum::http::StatusCode::BAD_REQUEST,
        };
        Self {
            status,
            error: err.to_string(),
            reason: None,
        }
    }

    pub(crate) fn into_response(self) -> axum::response::Response {
        let mut body = json!({ "error": self.error });
        if let Some(reason) = self.reason {
            body["reason"] = json!(reason);
        }
        (self.status, axum::Json(body)).into_response()
    }
}

use axum::response::IntoResponse;

fn gate_response(reason: &'static str) -> axum::response::Response {
    ResponseError::gate(reason).into_response()
}

pub(crate) fn load_prf_flag(path: &std::path::Path) -> bool {
    load_store(path).credential.and_then(|c| c.wrapped).is_some()
}

fn load_store(path: &std::path::Path) -> WebauthnFile {
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(file) = serde_json::from_slice::<WebauthnFile>(&bytes) {
            return file;
        }
    }
    WebauthnFile {
        user_id: Uuid::new_v4(),
        credential: None,
    }
}

fn save_store(path: &std::path::Path, file: &WebauthnFile) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?;
    vault::atomic_write(path, &bytes).map_err(|e| e.to_string())
}

fn decode_prf(value: Option<String>) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = B64URL.decode(value.as_bytes()).map_err(|e| e.to_string())?;
    if bytes.len() != vault::KEY_LEN {
        return Err("prf output must be 32 bytes".into());
    }
    Ok(Some(bytes))
}

fn inject_prf(value: &mut Value, salt_b64: &str) {
    let prf = json!({ "eval": { "first": salt_b64 } });
    if value.get("publicKey").is_some() {
        insert_prf(&mut value["publicKey"], prf);
    } else {
        insert_prf(value, prf);
    }
}

fn insert_prf(node: &mut Value, prf: Value) {
    let Some(obj) = node.as_object_mut() else {
        return;
    };
    let ext = obj.entry("extensions").or_insert_with(|| json!({}));
    if !ext.is_object() {
        *ext = json!({});
    }
    if let Some(ext) = ext.as_object_mut() {
        ext.insert("prf".to_string(), prf);
    }
}

/// Remember the browser origin for the next ceremony. Only localhost is a valid RP ID.
pub(crate) fn note_origin(state: &AppState, origin: &str) -> Result<(), String> {
    let url = Url::parse(origin).map_err(|_| "passkeys require http://localhost".to_string())?;
    let host = url.host_str().unwrap_or("");
    if host != "localhost" {
        return Err("passkeys require http://localhost".into());
    }
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err("passkeys require http://localhost".into());
    }
    if let Ok(mut slot) = state.inner.rp_origin.lock() {
        *slot = Some(origin.to_string());
    }
    Ok(())
}

/// Suppress unused import if CreationChallengeResponse is only used via serde.
#[allow(dead_code)]
fn _types(ccr: CreationChallengeResponse) -> CreationChallengeResponse {
    ccr
}
