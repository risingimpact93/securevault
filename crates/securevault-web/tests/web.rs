use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use securevault_core::vault::{self, VaultItem};
use securevault_web::{serve_for_test, Config, CSRF_HEADER, SESSION_COOKIE};
use secrecy::SecretString;
use serde_json::{json, Value};

const MASTER: &str = "web-master-pass-42";

struct CookieJar {
    cookie: Option<String>,
}

impl CookieJar {
    fn new() -> Self {
        Self { cookie: None }
    }

    fn store(&mut self, set_cookie: Option<&str>) {
        if let Some(header) = set_cookie {
            if let Some(pair) = header.split(';').next() {
                let pair = pair.trim();
                if pair.starts_with(&format!("{SESSION_COOKIE}=")) {
                    let value = pair.trim_start_matches(&format!("{SESSION_COOKIE}="));
                    if value.is_empty() {
                        self.cookie = None;
                    } else {
                        self.cookie = Some(pair.to_string());
                    }
                }
            }
        }
    }
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        if self.body.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

async fn exchange(
    port: u16,
    method: &str,
    path: &str,
    origin: bool,
    csrf: Option<&str>,
    cookie: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    exchange_for(
        port,
        false,
        method,
        path,
        origin,
        csrf,
        cookie,
        extra_headers,
        body,
    )
    .await
}

/// Same as `exchange`, but Host and Origin use `localhost` so WebAuthn's RP ID is valid.
async fn exchange_local(
    port: u16,
    method: &str,
    path: &str,
    origin: bool,
    csrf: Option<&str>,
    cookie: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    exchange_for(
        port,
        true,
        method,
        path,
        origin,
        csrf,
        cookie,
        extra_headers,
        body,
    )
    .await
}

async fn exchange_for(
    port: u16,
    localhost: bool,
    method: &str,
    path: &str,
    origin: bool,
    csrf: Option<&str>,
    cookie: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let host = if localhost {
        format!("localhost:{port}")
    } else {
        format!("127.0.0.1:{port}")
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("content-length", body.len());
    if origin {
        let origin_host = if localhost { "localhost" } else { "127.0.0.1" };
        builder = builder.header("origin", format!("http://{origin_host}:{port}"));
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if !body.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("request");
    let response = sender.send_request(request).await.expect("send");
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    HttpResponse {
        status,
        headers,
        body: bytes.to_vec(),
    }
}

async fn json_req(
    port: u16,
    method: &str,
    path: &str,
    jar: Option<&mut CookieJar>,
    csrf: Option<&str>,
    value: Option<&Value>,
) -> HttpResponse {
    let body = value
        .map(|v| serde_json::to_vec(v).unwrap())
        .unwrap_or_default();
    let cookie = jar.as_ref().and_then(|j| j.cookie.clone());
    let res = exchange(
        port,
        method,
        path,
        true,
        csrf,
        cookie.as_deref(),
        &[],
        &body,
    )
    .await;
    if let Some(jar) = jar {
        jar.store(res.header("set-cookie"));
    }
    res
}

async fn json_req_local(
    port: u16,
    method: &str,
    path: &str,
    jar: Option<&mut CookieJar>,
    csrf: Option<&str>,
    value: Option<&Value>,
) -> HttpResponse {
    let body = value
        .map(|v| serde_json::to_vec(v).unwrap())
        .unwrap_or_default();
    let cookie = jar.as_ref().and_then(|j| j.cookie.clone());
    let res = exchange_local(
        port,
        method,
        path,
        true,
        csrf,
        cookie.as_deref(),
        &[],
        &body,
    )
    .await;
    if let Some(jar) = jar {
        jar.store(res.header("set-cookie"));
    }
    res
}

fn sample_item() -> VaultItem {
    VaultItem {
        id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),
        item_type: "login".into(),
        title: "CrossPath".into(),
        favorite: false,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
        username: Some("haven".into()),
        password: Some("desktop-secret-xyz".into()),
        url: Some("https://example.test".into()),
        notes: None,
        cardholder: None,
        number: None,
        expiry: None,
        cvv: None,
        tags: vec!["roundtrip".into()],
        ..VaultItem::skeleton()
    }
}

async fn create_and_unlock(port: u16, jar: &mut CookieJar) -> String {
    let created = json_req(
        port,
        "POST",
        "/api/create-vault",
        Some(jar),
        None,
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(created.status, 200, "{}", String::from_utf8_lossy(&created.body));
    created.json()["csrfToken"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn cookie_flags_secure_and_dev_insecure() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir.path().join("secure"));
    config.dev_insecure_cookie = false;
    let (port, _) = serve_for_test(config).await;
    let res = exchange(
        port,
        "POST",
        "/api/create-vault",
        true,
        None,
        None,
        &[],
        &serde_json::to_vec(&json!({ "password": MASTER })).unwrap(),
    )
    .await;
    assert_eq!(res.status, 200);
    let cookie = res.header("set-cookie").unwrap_or("");
    assert!(cookie.contains(SESSION_COOKIE), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(
        cookie.split(';').any(|p| p.trim().eq_ignore_ascii_case("Secure")),
        "Secure flag missing: {cookie}"
    );

    let dir2 = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir2.path().join("insecure"));
    config.dev_insecure_cookie = true;
    let (port, _) = serve_for_test(config).await;
    let res = exchange(
        port,
        "POST",
        "/api/create-vault",
        true,
        None,
        None,
        &[],
        &serde_json::to_vec(&json!({ "password": MASTER })).unwrap(),
    )
    .await;
    let cookie = res.header("set-cookie").unwrap_or("");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(
        !cookie.split(';').any(|p| p.trim().eq_ignore_ascii_case("Secure")),
        "Secure should be omitted with --dev-insecure-cookie: {cookie}"
    );
}

#[tokio::test]
async fn csrf_and_origin_rejected_on_state_changing_requests() {
    let dir = tempfile::tempdir().unwrap();
    let (port, _) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let cookie = jar.cookie.clone();

    let missing_csrf = exchange(
        port,
        "POST",
        "/api/lock",
        true,
        None,
        cookie.as_deref(),
        &[],
        b"",
    )
    .await;
    assert_eq!(missing_csrf.status, 403);

    let bad_csrf = exchange(
        port,
        "POST",
        "/api/lock",
        true,
        Some("definitely-not-the-token"),
        cookie.as_deref(),
        &[],
        b"",
    )
    .await;
    assert_eq!(bad_csrf.status, 403);

    let bad_origin = exchange(
        port,
        "POST",
        "/api/lock",
        false,
        Some(&csrf),
        cookie.as_deref(),
        &[("origin", "http://evil.example")],
        b"",
    )
    .await;
    assert_eq!(bad_origin.status, 403);

    let ok = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(ok.status, 200);
    let _ = CSRF_HEADER;
}

#[tokio::test]
async fn login_backoff_after_failed_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (port, _) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let _ = create_and_unlock(port, &mut jar).await;

    let fail = json_req(
        port,
        "POST",
        "/api/unlock",
        None,
        None,
        Some(&json!({ "password": "wrong-password" })),
    )
    .await;
    assert_eq!(fail.status, 401);

    let blocked = json_req(
        port,
        "POST",
        "/api/unlock",
        None,
        None,
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(blocked.status, 429);
    assert_eq!(blocked.json()["error"], "too many attempts");
}

#[tokio::test]
async fn idle_auto_lock_rejects_later_requests() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir.path().to_path_buf());
    config.idle_timeout = Duration::from_millis(200);
    config.use_vault_idle = false;
    let (port, _) = serve_for_test(config).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let listed = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(listed.status, 200);

    tokio::time::sleep(Duration::from_millis(450)).await;

    let after = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(after.status, 401);
    assert_eq!(after.json()["error"], "vault is locked");
}

#[tokio::test]
async fn mcp_requires_bearer_token() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir.path().to_path_buf());
    config.mcp_enabled = true;
    let (port, _) = serve_for_test(config).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let enabled = json_req(
        port,
        "POST",
        "/api/mcp/settings",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "enabled": true, "port": 47821 })),
    )
    .await;
    assert_eq!(enabled.status, 200, "{}", String::from_utf8_lossy(&enabled.body));

    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }))
    .unwrap();
    let missing = exchange(port, "POST", "/mcp", false, None, None, &[], &body).await;
    assert_eq!(missing.status, 401);

    let invalid = exchange(
        port,
        "POST",
        "/mcp",
        false,
        None,
        None,
        &[("authorization", "Bearer not-a-token")],
        &body,
    )
    .await;
    assert_eq!(invalid.status, 401);

    let issued = json_req(
        port,
        "POST",
        "/api/mcp/tokens",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "name": "agent" })),
    )
    .await;
    assert_eq!(issued.status, 200, "{}", String::from_utf8_lossy(&issued.body));
    let token = issued.json()["token"].as_str().unwrap().to_string();
    let auth = format!("Bearer {token}");
    let ok = exchange(
        port,
        "POST",
        "/mcp",
        false,
        None,
        None,
        &[("authorization", auth.as_str())],
        &body,
    )
    .await;
    assert_eq!(ok.status, 200);
    let rpc = ok.json();
    let names: Vec<&str> = rpc["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["search_items", "list_items", "get_item_metadata", "get_secret"]
    );
}

#[tokio::test]
async fn get_secret_approval_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir.path().to_path_buf());
    config.mcp_enabled = true;
    config.approval_timeout = Duration::from_millis(400);
    let (port, _) = serve_for_test(config).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let _ = json_req(
        port,
        "POST",
        "/api/mcp/settings",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "enabled": true, "port": 47821 })),
    )
    .await;
    let added = json_req(
        port,
        "POST",
        "/api/items",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({
            "itemType": "login",
            "title": "Naver",
            "favorite": false,
            "password": "secret-for-timeout",
            "tags": []
        })),
    )
    .await;
    assert_eq!(added.status, 200, "{}", String::from_utf8_lossy(&added.body));
    let item_id = added.json()["id"].as_str().unwrap().to_string();

    let issued = json_req(
        port,
        "POST",
        "/api/mcp/tokens",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "name": "timeout-agent" })),
    )
    .await;
    let token = issued.json()["token"].as_str().unwrap().to_string();
    let call = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "get_secret",
            "arguments": { "id": item_id, "field": "password" }
        }
    }))
    .unwrap();
    let started = std::time::Instant::now();
    let auth = format!("Bearer {token}");
    let reply = exchange(
        port,
        "POST",
        "/mcp",
        false,
        None,
        None,
        &[("authorization", auth.as_str())],
        &call,
    )
    .await;
    assert_eq!(reply.status, 200);
    let body = reply.json();
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(body["result"]["content"][0]["text"], "approval denied");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "approval timeout should not wait the full 60s"
    );

    let after = json_req(port, "GET", "/api/approvals", Some(&mut jar), Some(&csrf), None).await;
    let pending = after.json()["pending"].as_array().cloned().unwrap_or_default();
    assert!(pending.is_empty(), "{}", after.json());
}

#[test]
fn vault_file_desktop_and_web_paths_are_interchangeable() {
    let dir = tempfile::tempdir().unwrap();
    let password = SecretString::new("cross-path-master-99".into());

    let desktop_dir = dir.path().join("desktop-data");
    std::fs::create_dir_all(&desktop_dir).unwrap();
    let desktop_file = desktop_dir.join("vault.khv");
    let mut unlocked = vault::create_vault_at(&desktop_file, &password).unwrap();
    unlocked.data.items.push(sample_item());
    vault::persist_unlocked(&desktop_file, &mut unlocked).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (port, _) = serve_for_test(Config::test(desktop_dir.clone())).await;
        let mut jar = CookieJar::new();
        let unlocked_res = json_req(
            port,
            "POST",
            "/api/unlock",
            Some(&mut jar),
            None,
            Some(&json!({ "password": "cross-path-master-99" })),
        )
        .await;
        assert_eq!(unlocked_res.status, 200);
        let csrf = unlocked_res.json()["csrfToken"].as_str().unwrap().to_string();
        let items_res = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
        assert_eq!(items_res.status, 200);
        let items: Vec<VaultItem> = serde_json::from_slice(&items_res.body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "CrossPath");
        assert_eq!(items[0].password.as_deref(), Some("desktop-secret-xyz"));
    });

    let web_dir = dir.path().join("web-data");
    std::fs::create_dir_all(&web_dir).unwrap();
    rt.block_on(async {
        let (port, state) = serve_for_test(Config::test(web_dir.clone())).await;
        let mut jar = CookieJar::new();
        let csrf = create_and_unlock(port, &mut jar).await;
        let added = json_req(
            port,
            "POST",
            "/api/items",
            Some(&mut jar),
            Some(&csrf),
            Some(&json!({
                "itemType": "note",
                "title": "FromWeb",
                "favorite": true,
                "notes": "written-by-web",
                "tags": ["web"]
            })),
        )
        .await;
        assert_eq!(added.status, 200);
        let path = state.vault_path().to_path_buf();
        let loaded = vault::unlock_file(&path, &SecretString::new(MASTER.into())).unwrap();
        assert!(
            loaded
                .data
                .items
                .iter()
                .any(|i| i.title == "FromWeb" && i.notes.as_deref() == Some("written-by-web")),
            "{:?}",
            loaded.data.items
        );
        let parsed = vault::parse_encrypted(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed.version, vault::VAULT_VERSION);
    });
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn strip_prf(value: &mut Value) {
    let Some(node) = (if value.get("publicKey").is_some() {
        value.get_mut("publicKey")
    } else {
        Some(value)
    }) else {
        return;
    };
    if let Some(ext) = node.get_mut("extensions").and_then(|v| v.as_object_mut()) {
        ext.remove("prf");
    }
}

fn soft_authenticator() -> webauthn_authenticator_rs::prelude::WebauthnAuthenticator<
    webauthn_authenticator_rs::softpasskey::SoftPasskey,
> {
    webauthn_authenticator_rs::prelude::WebauthnAuthenticator::new(
        webauthn_authenticator_rs::softpasskey::SoftPasskey::new(true),
    )
}

async fn register_softpasskey(
    port: u16,
    jar: &mut CookieJar,
    csrf: &str,
    auth: &mut webauthn_authenticator_rs::prelude::WebauthnAuthenticator<
        webauthn_authenticator_rs::softpasskey::SoftPasskey,
    >,
    prf: Option<&[u8]>,
) -> Value {
    use webauthn_authenticator_rs::prelude::{CreationChallengeResponse, Url};
    let start = json_req_local(
        port,
        "POST",
        "/api/webauthn/register/start",
        Some(jar),
        Some(csrf),
        Some(&json!({})),
    )
    .await;
    assert_eq!(start.status, 200, "{}", String::from_utf8_lossy(&start.body));
    let mut options = start.json()["options"].clone();
    strip_prf(&mut options);
    let ccr: CreationChallengeResponse = serde_json::from_value(options).expect("creation options");
    let origin = Url::parse(&format!("http://localhost:{port}")).unwrap();
    let reg = auth.do_registration(origin, ccr).expect("softpasskey register");
    let mut body = json!({ "credential": serde_json::to_value(&reg).unwrap() });
    if let Some(prf) = prf {
        body["prfFirst"] = json!(b64url(prf));
    }
    let finish = json_req_local(
        port,
        "POST",
        "/api/webauthn/register/finish",
        Some(jar),
        Some(csrf),
        Some(&body),
    )
    .await;
    assert_eq!(finish.status, 200, "{}", String::from_utf8_lossy(&finish.body));
    finish.json()
}

async fn authenticate_softpasskey(
    port: u16,
    jar: &mut CookieJar,
    auth: &mut webauthn_authenticator_rs::prelude::WebauthnAuthenticator<
        webauthn_authenticator_rs::softpasskey::SoftPasskey,
    >,
    prf: Option<&[u8]>,
) -> HttpResponse {
    use webauthn_authenticator_rs::prelude::{RequestChallengeResponse, Url};
    let start = json_req_local(
        port,
        "POST",
        "/api/webauthn/authenticate/start",
        Some(jar),
        None,
        Some(&json!({})),
    )
    .await;
    if start.status != 200 {
        return start;
    }
    let mut options = start.json()["options"].clone();
    strip_prf(&mut options);
    let challenge: RequestChallengeResponse =
        serde_json::from_value(options).expect("request options");
    let origin = Url::parse(&format!("http://localhost:{port}")).unwrap();
    let assertion = match auth.do_authentication(origin, challenge) {
        Ok(assertion) => assertion,
        Err(_) => {
            return HttpResponse {
                status: 401,
                headers: Vec::new(),
                body: br#"{"error":"softpasskey rejected credential"}"#.to_vec(),
            };
        }
    };
    let mut body = json!({ "credential": serde_json::to_value(&assertion).unwrap() });
    if let Some(prf) = prf {
        body["prfFirst"] = json!(b64url(prf));
    }
    json_req_local(
        port,
        "POST",
        "/api/webauthn/authenticate/finish",
        Some(jar),
        None,
        Some(&body),
    )
    .await
}

#[tokio::test]
async fn background_polls_do_not_extend_idle_activity_does() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir.path().to_path_buf());
    config.idle_timeout = Duration::from_millis(300);
    config.use_vault_idle = false;
    let (port, _) = serve_for_test(config).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;

    tokio::time::sleep(Duration::from_millis(120)).await;
    for _ in 0..4 {
        let poll = json_req(port, "GET", "/api/approvals", Some(&mut jar), Some(&csrf), None).await;
        assert_eq!(poll.status, 200, "{}", String::from_utf8_lossy(&poll.body));
        let session = json_req(port, "GET", "/api/session", Some(&mut jar), Some(&csrf), None).await;
        assert_eq!(session.json()["unlocked"], true);
    }
    tokio::time::sleep(Duration::from_millis(280)).await;
    let expired = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(expired.status, 401);
    assert_eq!(expired.json()["error"], "vault is locked");

    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir.path().to_path_buf());
    config.idle_timeout = Duration::from_millis(300);
    config.use_vault_idle = false;
    let (port, _) = serve_for_test(config).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    tokio::time::sleep(Duration::from_millis(180)).await;
    let ping = json_req(port, "POST", "/api/activity", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    assert_eq!(ping.status, 200, "{}", String::from_utf8_lossy(&ping.body));
    tokio::time::sleep(Duration::from_millis(180)).await;
    let still = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(still.status, 200, "{}", String::from_utf8_lossy(&still.body));
    tokio::time::sleep(Duration::from_millis(400)).await;
    let locked = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(locked.status, 401);
}

#[tokio::test]
async fn vault_settings_live_inside_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let (port, state) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;

    let bad = json_req(
        port,
        "POST",
        "/api/settings",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "autoLockMinutes": 3 })),
    )
    .await;
    assert_eq!(bad.status, 400);
    assert_eq!(bad.json()["error"], "invalid auto-lock choice");

    let bad_days = json_req(
        port,
        "POST",
        "/api/settings",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "passwordIntervalDays": 0 })),
    )
    .await;
    assert_eq!(bad_days.status, 400);
    assert_eq!(bad_days.json()["error"], "invalid password interval");

    let saved = json_req(
        port,
        "POST",
        "/api/settings",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({
            "autoLockMinutes": 10,
            "lockOnScreenLock": true,
            "passwordIntervalDays": 21
        })),
    )
    .await;
    assert_eq!(saved.status, 200, "{}", String::from_utf8_lossy(&saved.body));
    assert_eq!(saved.json()["autoLockMinutes"], 10);
    assert_eq!(saved.json()["lockOnScreenLock"], true);
    assert_eq!(saved.json()["passwordIntervalDays"], 21);
    assert_eq!(saved.json()["screenLockSupported"], false);

    let locked = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    assert_eq!(locked.status, 200);
    let again = json_req(
        port,
        "POST",
        "/api/unlock",
        Some(&mut jar),
        None,
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(again.status, 200, "{}", String::from_utf8_lossy(&again.body));
    let csrf = again.json()["csrfToken"].as_str().unwrap().to_string();
    let loaded_http = json_req(port, "GET", "/api/settings", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(loaded_http.status, 200);
    assert_eq!(loaded_http.json()["autoLockMinutes"], 10);
    assert_eq!(loaded_http.json()["lockOnScreenLock"], true);
    assert_eq!(loaded_http.json()["passwordIntervalDays"], 21);

    let vault_file = state.vault_path();
    let decrypted = vault::unlock_file(&vault_file, &SecretString::new(MASTER.into())).unwrap();
    assert_eq!(decrypted.data.settings.auto_lock_minutes, 10);
    assert!(decrypted.data.settings.lock_on_screen_lock);
    assert_eq!(decrypted.data.settings.password_interval_days, 21);
    let raw = std::fs::read(&vault_file).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(!text.contains("lockOnScreenLock"), "settings must stay inside the ciphertext");
}

#[tokio::test]
async fn passkey_without_prf_only_resumes_memory_session() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::test(dir.path().to_path_buf());
    config.idle_timeout = Duration::from_millis(200);
    config.use_vault_idle = false;
    let (port, _) = serve_for_test(config).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let mut auth = soft_authenticator();
    let status = register_softpasskey(port, &mut jar, &csrf, &mut auth, None).await;
    assert_eq!(status["configured"], true);
    assert_eq!(status["prf"], false);

    tokio::time::sleep(Duration::from_millis(450)).await;
    let idle = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(idle.status, 401);

    let resumed = authenticate_softpasskey(port, &mut jar, &mut auth, None).await;
    assert_eq!(resumed.status, 200, "{}", String::from_utf8_lossy(&resumed.body));
    let csrf = resumed.json()["csrfToken"].as_str().unwrap().to_string();
    let items = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(items.status, 200, "{}", String::from_utf8_lossy(&items.body));

    let locked = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    assert_eq!(locked.status, 200);
    let denied = authenticate_softpasskey(port, &mut jar, &mut auth, None).await;
    assert_eq!(denied.status, 401);
    assert_eq!(denied.json()["error"], "passkey session only");
}

#[tokio::test]
async fn idle_lock_endpoint_keeps_unwrapped_key_for_passkey_resume() {
    let dir = tempfile::tempdir().unwrap();
    let (port, _) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let mut auth = soft_authenticator();
    let status = register_softpasskey(port, &mut jar, &csrf, &mut auth, None).await;
    assert_eq!(status["prf"], false);

    let idle = json_req(port, "POST", "/api/idle-lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    assert_eq!(idle.status, 200, "{}", String::from_utf8_lossy(&idle.body));
    let session = json_req(port, "GET", "/api/session", Some(&mut jar), None, None).await;
    assert_eq!(session.json()["unlocked"], false);

    let resumed = authenticate_softpasskey(port, &mut jar, &mut auth, None).await;
    assert_eq!(resumed.status, 200, "{}", String::from_utf8_lossy(&resumed.body));
}

#[tokio::test]
async fn passkey_prf_wrap_unlocks_after_explicit_lock_and_rejects_wrong_output() {
    let dir = tempfile::tempdir().unwrap();
    let (port, state) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let mut auth = soft_authenticator();
    let prf = [9u8; 32];
    let status = register_softpasskey(port, &mut jar, &csrf, &mut auth, Some(&prf)).await;
    assert_eq!(status["prf"], true);
    assert_eq!(status["configured"], true);

    let locked = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    assert_eq!(locked.status, 200);
    let opened = authenticate_softpasskey(port, &mut jar, &mut auth, Some(&prf)).await;
    assert_eq!(opened.status, 200, "{}", String::from_utf8_lossy(&opened.body));
    let csrf = opened.json()["csrfToken"].as_str().unwrap().to_string();
    let items = json_req(port, "GET", "/api/items", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(items.status, 200);

    let locked = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    assert_eq!(locked.status, 200);
    let wrong = authenticate_softpasskey(port, &mut jar, &mut auth, Some(&[3u8; 32])).await;
    assert_eq!(wrong.status, 401, "{}", String::from_utf8_lossy(&wrong.body));
    assert_eq!(wrong.json()["error"], "biometrics invalidated");
    let after = json_req_local(port, "GET", "/api/biometrics/status", None, None, None).await;
    assert_eq!(after.json()["prf"], false);
    assert_eq!(after.json()["configured"], true);

    let no_wrap = authenticate_softpasskey(port, &mut jar, &mut auth, None).await;
    assert_eq!(no_wrap.status, 401);
    assert_eq!(no_wrap.json()["error"], "passkey session only");

    state.testing_restart_password_gate();
}

#[tokio::test]
async fn passkey_requires_master_password_after_restart_and_interval() {
    let dir = tempfile::tempdir().unwrap();
    let (port, state) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let mut auth = soft_authenticator();
    register_softpasskey(port, &mut jar, &csrf, &mut auth, None).await;

    state.testing_restart_password_gate();
    let restart = json_req_local(
        port,
        "POST",
        "/api/webauthn/authenticate/start",
        Some(&mut jar),
        None,
        Some(&json!({})),
    )
    .await;
    assert_eq!(restart.status, 401);
    assert_eq!(restart.json()["error"], "master password required");
    assert_eq!(restart.json()["reason"], "restart");

    let unlocked = json_req(
        port,
        "POST",
        "/api/unlock",
        Some(&mut jar),
        None,
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(unlocked.status, 200, "{}", String::from_utf8_lossy(&unlocked.body));

    state.testing_expire_password_interval();
    let interval = json_req_local(
        port,
        "POST",
        "/api/webauthn/authenticate/start",
        Some(&mut jar),
        None,
        Some(&json!({})),
    )
    .await;
    assert_eq!(interval.status, 401, "{}", String::from_utf8_lossy(&interval.body));
    assert_eq!(interval.json()["error"], "master password required");
    assert_eq!(interval.json()["reason"], "interval");
}

#[tokio::test]
async fn reregister_and_delete_invalidate_passkey() {
    let dir = tempfile::tempdir().unwrap();
    let (port, state) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let mut first = soft_authenticator();
    register_softpasskey(port, &mut jar, &csrf, &mut first, None).await;

    let mut second = soft_authenticator();
    let replaced = register_softpasskey(port, &mut jar, &csrf, &mut second, None).await;
    assert_eq!(replaced["configured"], true);
    let old = authenticate_softpasskey(port, &mut jar, &mut first, None).await;
    assert_ne!(old.status, 200, "{}", String::from_utf8_lossy(&old.body));

    let removed = json_req_local(
        port,
        "DELETE",
        "/api/webauthn/credential",
        Some(&mut jar),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(removed.status, 200, "{}", String::from_utf8_lossy(&removed.body));
    assert_eq!(removed.json()["configured"], false);
    let settings = json_req(port, "GET", "/api/settings", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(settings.json()["biometricsEnabled"], false);
    let vault_file = state.vault_path();
    let decrypted = vault::unlock_file(&vault_file, &SecretString::new(MASTER.into())).unwrap();
    assert!(!decrypted.data.settings.biometrics_enabled);
    let gone = json_req_local(
        port,
        "POST",
        "/api/webauthn/authenticate/start",
        Some(&mut jar),
        None,
        Some(&json!({})),
    )
    .await;
    assert_eq!(gone.status, 401);
    assert_eq!(gone.json()["error"], "biometrics unavailable");
}

#[test]
fn open_existing_vault_keeps_device_and_rejects_bad_files() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("keyhaven-config.json"), br#"{"deviceId":"device-fixed"}"#).unwrap();
    let vault = dir.path().join("vault.khv");
    let mut bytes = vault::VAULT_MAGIC.to_vec();
    bytes.extend_from_slice(
        br#"{"version":1,"kdf":{"algorithm":"argon2id","m":32,"t":1,"p":1},"salt":"s","nonce":"n","ciphertext":"c"}"#,
    );
    std::fs::write(&vault, &bytes).unwrap();
    let bad = dir.path().join("nope.khv");
    std::fs::write(&bad, b"NOPE").unwrap();
    let short = dir.path().join("short.khv");
    std::fs::write(&short, b"KHV").unwrap();
    let future = dir.path().join("future.khv");
    let mut future_bytes = vault::VAULT_MAGIC.to_vec();
    future_bytes.extend_from_slice(
        br#"{"version":99,"kdf":{"algorithm":"argon2id","m":32,"t":1,"p":1},"salt":"s","nonce":"n","ciphertext":"c"}"#,
    );
    std::fs::write(&future, &future_bytes).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (port, state) = serve_for_test(Config::test(data.clone())).await;
        assert!(state.vault_path().starts_with(&data));
        let listed = json_req(port, "GET", "/api/vaults/discover", None, None, None).await;
        assert_eq!(listed.status, 200, "{}", String::from_utf8_lossy(&listed.body));
        assert!(listed.json().is_array());

        let opened = json_req(
            port,
            "POST",
            "/api/vaults/open",
            None,
            None,
            Some(&json!({ "path": vault.to_string_lossy() })),
        )
        .await;
        assert_eq!(opened.status, 200, "{}", String::from_utf8_lossy(&opened.body));
        assert_eq!(opened.json()["state"], "ready");
        assert_eq!(
            std::fs::canonicalize(state.vault_path()).unwrap(),
            std::fs::canonicalize(&vault).unwrap()
        );

        let wrong = json_req(
            port,
            "POST",
            "/api/vaults/open",
            None,
            None,
            Some(&json!({ "path": bad.to_string_lossy() })),
        )
        .await;
        assert_eq!(wrong.status, 400);
        assert_eq!(wrong.json()["error"], "not a vault");

        let truncated = json_req(
            port,
            "POST",
            "/api/vaults/open",
            None,
            None,
            Some(&json!({ "path": short.to_string_lossy() })),
        )
        .await;
        assert_eq!(truncated.status, 400);
        assert_eq!(truncated.json()["error"], "corrupt");

        let unsupported = json_req(
            port,
            "POST",
            "/api/vaults/open",
            None,
            None,
            Some(&json!({ "path": future.to_string_lossy() })),
        )
        .await;
        assert_eq!(unsupported.status, 400);
        assert_eq!(unsupported.json()["error"], "unsupported version");

        let body = serde_json::to_vec(&json!({ "path": vault.to_string_lossy() })).unwrap();
        let no_origin = exchange(port, "POST", "/api/vaults/open", false, None, None, &[], &body).await;
        assert_eq!(no_origin.status, 403);
    });

    let raw = std::fs::read_to_string(data.join("securevault-config.json")).unwrap();
    let parsed: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed["deviceId"], "device-fixed");
    assert!(parsed["vaultPath"].as_str().unwrap().ends_with("vault.khv"));
    let legacy = std::fs::read_to_string(data.join("keyhaven-config.json")).unwrap();
    assert!(legacy.contains("device-fixed"));
    assert!(!legacy.contains("vaultPath"));
}

#[test]
fn data_dir_env_falls_back_to_legacy_name() {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let names = ["SECUREVAULT_DATA_DIR", "KEYHAVEN_DATA_DIR"];
    let previous: Vec<_> = names.iter().map(|name| std::env::var(name).ok()).collect();
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("from-legacy");
    let preferred = dir.path().join("from-new");
    let cli = dir.path().join("from-cli");
    std::env::remove_var("SECUREVAULT_DATA_DIR");
    std::env::set_var("KEYHAVEN_DATA_DIR", &legacy);
    assert_eq!(securevault_web::resolve_data_dir(None), legacy);
    std::env::set_var("SECUREVAULT_DATA_DIR", "  ");
    assert_eq!(securevault_web::resolve_data_dir(None), legacy);
    std::env::set_var("SECUREVAULT_DATA_DIR", &preferred);
    assert_eq!(securevault_web::resolve_data_dir(None), preferred);
    assert_eq!(securevault_web::resolve_data_dir(Some(cli.clone())), cli);
    for (name, value) in names.iter().zip(previous) {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
}

fn secret_key_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

#[tokio::test]
async fn secret_key_enable_unlock_and_env() {
    let _guard = secret_key_env_lock();
    std::env::remove_var("SECUREVAULT_SECRET_KEY");
    std::env::remove_var("KEYHAVEN_SECRET_KEY");
    let dir = tempfile::tempdir().unwrap();
    let (port, _) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;

    let status = json_req(port, "GET", "/api/secret-key/status", Some(&mut jar), Some(&csrf), None).await;
    assert_eq!(status.status, 200, "{}", String::from_utf8_lossy(&status.body));
    assert_eq!(status.json()["enabled"], false);

    let enabled = json_req(
        port,
        "POST",
        "/api/secret-key/enable",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(enabled.status, 200, "{}", String::from_utf8_lossy(&enabled.body));
    let secret_key = enabled.json()["secretKey"].as_str().unwrap().to_string();
    assert!(secret_key.starts_with("SV1-"));

    let _ = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    jar = CookieJar::new();
    let _ = std::fs::remove_dir_all(dir.path().join("secret-key"));

    let missing = json_req(
        port,
        "POST",
        "/api/unlock",
        Some(&mut jar),
        None,
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(missing.status, 401);
    assert_eq!(missing.json()["error"], "secret key required");

    let unlocked = json_req(
        port,
        "POST",
        "/api/unlock",
        Some(&mut jar),
        None,
        Some(&json!({ "password": MASTER, "secretKey": secret_key })),
    )
    .await;
    assert_eq!(unlocked.status, 200, "{}", String::from_utf8_lossy(&unlocked.body));
    let csrf = unlocked.json()["csrfToken"].as_str().unwrap().to_string();

    let disabled = json_req(
        port,
        "POST",
        "/api/secret-key/disable",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "password": MASTER, "secretKey": secret_key })),
    )
    .await;
    assert_eq!(disabled.status, 200, "{}", String::from_utf8_lossy(&disabled.body));
}

#[tokio::test]
async fn secret_key_rotate_roundtrip() {
    let _guard = secret_key_env_lock();
    std::env::remove_var("SECUREVAULT_SECRET_KEY");
    std::env::remove_var("KEYHAVEN_SECRET_KEY");
    let dir = tempfile::tempdir().unwrap();
    let (port, _) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let enabled = json_req(
        port,
        "POST",
        "/api/secret-key/enable",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(enabled.status, 200, "{}", String::from_utf8_lossy(&enabled.body));
    let old_key = enabled.json()["secretKey"].as_str().unwrap().to_string();
    let vault_path = dir.path().join("vault.khv");
    let before = std::fs::read(&vault_path).unwrap();

    let wrong_pw = json_req(
        port,
        "POST",
        "/api/secret-key/rotate",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "password": "nope-nope-nope", "secretKey": old_key })),
    )
    .await;
    assert_eq!(wrong_pw.status, 401, "{}", String::from_utf8_lossy(&wrong_pw.body));
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);

    let other = securevault_core::secret_key::SecretKey::generate().format_display();
    let wrong_sk = json_req(
        port,
        "POST",
        "/api/secret-key/rotate",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "password": MASTER, "secretKey": other })),
    )
    .await;
    assert_eq!(wrong_sk.status, 401, "{}", String::from_utf8_lossy(&wrong_sk.body));
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);

    let rotated = json_req(
        port,
        "POST",
        "/api/secret-key/rotate",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "password": MASTER, "secretKey": old_key })),
    )
    .await;
    assert_eq!(rotated.status, 200, "{}", String::from_utf8_lossy(&rotated.body));
    let new_key = rotated.json()["secretKey"].as_str().unwrap().to_string();
    assert!(new_key.starts_with("SV1-"));
    assert_ne!(new_key, old_key);

    let bytes = std::fs::read(&vault_path).unwrap();
    let enc = vault::parse_encrypted(&bytes).unwrap();
    assert!(enc.sk_enabled);
    assert_eq!(enc.version, vault::VAULT_VERSION_SK);
    assert!(enc.sk_fingerprint.is_some());
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"skEnabled\":true"));
    assert!(!text.contains(&new_key));
    assert!(!text.contains(&old_key));

    let sk_dir = dir.path().join("secret-key");
    let stored: Vec<_> = std::fs::read_dir(&sk_dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            std::fs::read_to_string(path).unwrap()
        })
        .collect();
    assert_eq!(stored.len(), 1, "old keychain entry should be replaced");
    assert_eq!(stored[0].trim(), new_key);

    let _ = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    jar = CookieJar::new();
    let old_unlock = json_req(
        port,
        "POST",
        "/api/unlock",
        Some(&mut jar),
        None,
        Some(&json!({ "password": MASTER, "secretKey": old_key })),
    )
    .await;
    assert_eq!(old_unlock.status, 401, "{}", String::from_utf8_lossy(&old_unlock.body));

    let new_unlock = json_req(
        port,
        "POST",
        "/api/unlock",
        Some(&mut jar),
        None,
        Some(&json!({ "password": MASTER, "secretKey": new_key })),
    )
    .await;
    assert_eq!(new_unlock.status, 200, "{}", String::from_utf8_lossy(&new_unlock.body));
}

#[tokio::test]
async fn secret_key_env_var_unlocks_without_body() {
    let _guard = secret_key_env_lock();
    let previous = std::env::var("SECUREVAULT_SECRET_KEY").ok();
    let previous_legacy = std::env::var("KEYHAVEN_SECRET_KEY").ok();
    std::env::remove_var("SECUREVAULT_SECRET_KEY");
    std::env::remove_var("KEYHAVEN_SECRET_KEY");

    let dir = tempfile::tempdir().unwrap();
    let (port, _) = serve_for_test(Config::test(dir.path().to_path_buf())).await;
    let mut jar = CookieJar::new();
    let csrf = create_and_unlock(port, &mut jar).await;
    let enabled = json_req(
        port,
        "POST",
        "/api/secret-key/enable",
        Some(&mut jar),
        Some(&csrf),
        Some(&json!({ "password": MASTER })),
    )
    .await;
    assert_eq!(enabled.status, 200, "{}", String::from_utf8_lossy(&enabled.body));
    let secret_key = enabled.json()["secretKey"].as_str().unwrap().to_string();
    let _ = json_req(port, "POST", "/api/lock", Some(&mut jar), Some(&csrf), Some(&json!({}))).await;
    let _ = std::fs::remove_dir_all(dir.path().join("secret-key"));
    std::env::set_var("SECUREVAULT_SECRET_KEY", &secret_key);
    let mut jar = CookieJar::new();
    let unlocked = json_req(
        port,
        "POST",
        "/api/unlock",
        Some(&mut jar),
        None,
        Some(&json!({ "password": MASTER })),
    )
    .await;
    match previous {
        Some(value) => std::env::set_var("SECUREVAULT_SECRET_KEY", value),
        None => std::env::remove_var("SECUREVAULT_SECRET_KEY"),
    }
    match previous_legacy {
        Some(value) => std::env::set_var("KEYHAVEN_SECRET_KEY", value),
        None => std::env::remove_var("KEYHAVEN_SECRET_KEY"),
    }
    assert_eq!(unlocked.status, 200, "{}", String::from_utf8_lossy(&unlocked.body));
}
