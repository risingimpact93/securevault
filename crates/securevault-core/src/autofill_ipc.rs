//! Local IPC between the Chrome native messaging host and the running app.
//!
//! - Transport: a Unix domain socket in `<app data>/autofill/` (dir 0700,
//!   socket 0600). No TCP, nothing listens on the network.
//! - The server checks the peer's UID (same user only) on every connection.
//! - The native host adds the per-install token (file 0600) and the caller
//!   origin Chrome passed on argv; the extension never sees the token.
//! - Protocol: one JSON request line, one JSON response line.
//! - Nothing here logs request contents.

#![cfg(unix)]

use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::autofill::{self, AutofillGate, AutofillRequest, AutofillResponse};
use crate::vault::VaultItem;

/// Chrome native messaging host name (`com.securevault.nmh.json`).
pub const HOST_NAME: &str = "com.securevault.nmh";
/// Extension ID pinned by the public `key` in `extension/chrome/manifest.json`.
pub const EXTENSION_ID: &str = "lldiolamhehhhjchiinofbnbeabnclcm";
/// Max request/response line on the socket.
pub const MAX_LINE: usize = 64 * 1024;
/// Max message we accept from Chrome on stdin (Chrome allows more; we don't need it).
pub const MAX_STDIN_MESSAGE: usize = 64 * 1024;
/// Chrome rejects host → Chrome messages over 1 MB.
pub const MAX_STDOUT_MESSAGE: usize = 1024 * 1024;

pub fn extension_origin() -> String {
    format!("chrome-extension://{EXTENSION_ID}/")
}

#[derive(Debug, Clone)]
pub struct AutofillPaths {
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub token: PathBuf,
}

impl AutofillPaths {
    pub fn new(app_data_dir: &Path) -> Self {
        let dir = app_data_dir.join("autofill");
        Self { socket: dir.join("af.sock"), token: dir.join("token"), dir }
    }
}

/// The app data dir Tauri uses for `identifier`, computed without Tauri so the
/// native host (started by Chrome) finds the same folder.
pub fn default_app_data_dir(identifier: &str) -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Application Support").join(identifier))
    } else {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".local/share"));
        Some(base.join(identifier))
    }
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Create the private directory (0700) and reject one owned by someone else.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    check_owned_private(dir, 0o077)
}

fn check_owned_private(path: &Path, forbidden_bits: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "symlink not allowed"));
    }
    if meta.uid() != current_uid() || meta.mode() & forbidden_bits != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe owner or mode"));
    }
    Ok(())
}

/// Write a fresh random install token (0600). Replaces any previous token.
pub fn rotate_token(paths: &AutofillPaths) -> io::Result<()> {
    ensure_private_dir(&paths.dir)?;
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(raw.as_mut());
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_ref()));
    let tmp = paths.dir.join("token.tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(token.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, &paths.token)
}

/// Read the install token, refusing files that are not ours or readable by others.
pub fn read_token(paths: &AutofillPaths) -> io::Result<Zeroizing<String>> {
    check_owned_private(&paths.token, 0o077)?;
    let mut s = Zeroizing::new(String::new());
    fs::File::open(&paths.token)?.take(256).read_to_string(&mut s)?;
    let trimmed = Zeroizing::new(s.trim().to_string());
    if trimmed.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty token"));
    }
    Ok(trimmed)
}

/// Bind the socket with mode 0600 inside the private dir.
pub fn bind_socket(paths: &AutofillPaths) -> io::Result<UnixListener> {
    ensure_private_dir(&paths.dir)?;
    if let Ok(meta) = fs::symlink_metadata(&paths.socket) {
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "socket path is not a socket"));
        }
        fs::remove_file(&paths.socket)?;
    }
    let listener = UnixListener::bind(&paths.socket)?;
    fs::set_permissions(&paths.socket, Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Gives the handler borrowed access to the unlocked items (`None` = locked).
pub type ItemsAccess = dyn Fn(&mut dyn FnMut(Option<&[VaultItem]>)) + Send + Sync;

fn respond(gate: &AutofillGate, line: &str, items: &ItemsAccess) -> AutofillResponse {
    let Ok(req) = serde_json::from_str::<AutofillRequest>(line) else {
        return AutofillResponse::Denied;
    };
    let mut out = AutofillResponse::Locked;
    items(&mut |view| out = autofill::handle(gate, &req, view));
    out
}

async fn serve_conn(stream: UnixStream, gate: Arc<AutofillGate>, items: Arc<ItemsAccess>, uid: u32) {
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == uid => {}
        _ => return, // other users never get a reply
    }
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r.take(MAX_LINE as u64 + 1));
    let mut line = Zeroizing::new(String::new());
    let read = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await;
    if !matches!(read, Ok(Ok(n)) if n > 0 && n <= MAX_LINE) {
        return;
    }
    let resp = respond(&gate, line.trim_end(), items.as_ref());
    let mut body = Zeroizing::new(serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"status":"denied"}"#.into()));
    body.push('\n');
    let _ = w.write_all(body.as_bytes()).await;
    let _ = w.shutdown().await;
}

/// Accept loop. `uid` is the only peer UID served (normally [`current_uid`]).
pub async fn serve(
    listener: UnixListener,
    gate: Arc<AutofillGate>,
    items: Arc<ItemsAccess>,
    uid: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                tokio::spawn(serve_conn(stream, gate.clone(), items.clone(), uid));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Native host side
// ---------------------------------------------------------------------------

/// Read one Chrome native message (u32 native-endian length + JSON).
/// `Ok(None)` on clean EOF.
pub fn read_message(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_ne_bytes(len) as usize;
    if n == 0 || n > MAX_STDIN_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad message length"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_message(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_STDOUT_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    w.write_all(&(body.len() as u32).to_ne_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Build the socket request: only known fields from the extension, plus the
/// token and the caller origin that Chrome (not the extension) supplied.
pub fn build_request(ext_msg: &[u8], token: &str, caller_origin: &str) -> Option<Zeroizing<String>> {
    let v: Value = serde_json::from_slice(ext_msg).ok()?;
    let obj = v.as_object()?;
    let mut out = serde_json::Map::new();
    for key in ["op", "page_url", "top_url", "item_id", "user_confirmed"] {
        if let Some(val) = obj.get(key) {
            out.insert(key.to_string(), val.clone());
        }
    }
    out.insert("token".into(), json!(token));
    out.insert("caller_origin".into(), json!(caller_origin));
    Some(Zeroizing::new(Value::Object(out).to_string()))
}

async fn ask_app(socket: &Path, request: &str, uid: u32) -> io::Result<Zeroizing<String>> {
    let stream = UnixStream::connect(socket).await?;
    // The listener must belong to the same user as well.
    if stream.peer_cred()?.uid() != uid {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "foreign socket owner"));
    }
    let (r, mut w) = stream.into_split();
    w.write_all(request.as_bytes()).await?;
    w.write_all(b"\n").await?;
    let mut reader = BufReader::new(r.take(MAX_LINE as u64 + 1));
    let mut line = Zeroizing::new(String::new());
    tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timeout"))??;
    if line.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "no reply"));
    }
    Ok(Zeroizing::new(line.trim_end().to_string()))
}

const UNAVAILABLE: &str = r#"{"status":"unavailable"}"#;
const UNAUTHORIZED: &str = r#"{"status":"unauthorized"}"#;

/// Answer one extension message. Never panics, never logs contents.
pub async fn host_answer(paths: &AutofillPaths, caller_origin: &str, ext_msg: &[u8]) -> Zeroizing<String> {
    if caller_origin != extension_origin() {
        return Zeroizing::new(UNAUTHORIZED.into());
    }
    let Ok(token) = read_token(paths) else { return Zeroizing::new(UNAVAILABLE.into()) };
    let Some(req) = build_request(ext_msg, &token, caller_origin) else {
        return Zeroizing::new(r#"{"status":"denied"}"#.into());
    };
    match ask_app(&paths.socket, &req, current_uid()).await {
        Ok(line) => line,
        Err(_) => Zeroizing::new(UNAVAILABLE.into()),
    }
}

/// Run the native messaging host loop on stdin/stdout until Chrome closes stdin.
pub fn run_native_host(paths: &AutofillPaths, caller_origin: &str) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    while let Some(msg) = read_message(&mut input)? {
        let answer = rt.block_on(host_answer(paths, caller_origin, &msg));
        write_message(&mut output, answer.as_bytes())?;
    }
    Ok(())
}

/// Chrome native messaging host manifest JSON for `exe`.
pub fn host_manifest(exe: &Path) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "SecureVault browser autofill bridge",
        "path": exe.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [extension_origin()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn item(id: &str, url: &str) -> VaultItem {
        let mut i = VaultItem::skeleton();
        i.id = id.into();
        i.item_type = "login".into();
        i.title = "Dummy".into();
        i.username = Some("dummy-user".into());
        i.password = Some("dummy-pass".into());
        i.url = Some(url.into());
        i
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        paths: AutofillPaths,
        tx: watch::Sender<bool>,
        locked: Arc<std::sync::Mutex<bool>>,
    }

    async fn start(uid: u32) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AutofillPaths::new(tmp.path());
        rotate_token(&paths).unwrap();
        let token = read_token(&paths).unwrap();
        let gate = Arc::new(AutofillGate::new(&token, vec![extension_origin()]));
        let listener = bind_socket(&paths).unwrap();
        let items = vec![item("1", "github.com"), item("2", "gist.github.com")];
        let locked = Arc::new(std::sync::Mutex::new(false));
        let l2 = locked.clone();
        let access: Arc<ItemsAccess> = Arc::new(move |f: &mut dyn FnMut(Option<&[VaultItem]>)| {
            if *l2.lock().unwrap() { f(None) } else { f(Some(&items)) }
        });
        let (tx, rx) = watch::channel(false);
        tokio::spawn(serve(listener, gate, access, uid, rx));
        Fixture { _tmp: tmp, paths, tx, locked }
    }

    fn msg(v: Value) -> Vec<u8> {
        v.to_string().into_bytes()
    }

    #[tokio::test]
    async fn permissions_are_private() {
        let fx = start(current_uid()).await;
        assert_eq!(fs::metadata(&fx.paths.dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&fx.paths.socket).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&fx.paths.token).unwrap().mode() & 0o777, 0o600);
        // A token readable by others is refused.
        fs::set_permissions(&fx.paths.token, Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&fx.paths).is_err());
        let _ = fx.tx.send(true);
    }

    #[tokio::test]
    async fn end_to_end_and_lock() {
        let fx = start(current_uid()).await;
        let origin = extension_origin();
        let a = host_answer(&fx.paths, &origin, &msg(json!({"op":"candidates","page_url":"https://github.com/login"}))).await;
        let v: Value = serde_json::from_str(&a).unwrap();
        assert_eq!(v["status"], "candidates");
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        assert!(!a.contains("dummy-pass"));

        let a = host_answer(&fx.paths, &origin, &msg(json!({"op":"reveal","item_id":"1","page_url":"https://github.com/"}))).await;
        assert!(a.contains("dummy-pass"));
        let a = host_answer(&fx.paths, &origin, &msg(json!({"op":"reveal","item_id":"2","page_url":"https://github.com/"}))).await;
        assert_eq!(&*a, r#"{"status":"needs_confirmation"}"#);
        let a = host_answer(&fx.paths, &origin, &msg(json!({"op":"reveal","item_id":"1","page_url":"https://github.com.evil.io/","user_confirmed":true}))).await;
        assert_eq!(&*a, r#"{"status":"denied"}"#);

        *fx.locked.lock().unwrap() = true;
        let a = host_answer(&fx.paths, &origin, &msg(json!({"op":"candidates","page_url":"https://github.com/"}))).await;
        assert_eq!(&*a, r#"{"status":"locked"}"#);
        let _ = fx.tx.send(true);
    }

    #[tokio::test]
    async fn extension_cannot_inject_token_or_origin() {
        let fx = start(current_uid()).await;
        let origin = extension_origin();
        // Fields supplied by the extension are ignored; the host's own values win.
        let a = host_answer(&fx.paths, &origin, &msg(json!({"op":"status","token":"x","caller_origin":"chrome-extension://zzz/"}))).await;
        assert_eq!(&*a, r#"{"status":"unlocked"}"#);
        // A different calling extension is refused by the host.
        let a = host_answer(&fx.paths, "chrome-extension://abcdefghijklmnopabcdefghijklmnop/", &msg(json!({"op":"status"}))).await;
        assert_eq!(&*a, UNAUTHORIZED);
        let _ = fx.tx.send(true);
    }

    #[tokio::test]
    async fn wrong_token_is_unauthorized() {
        let fx = start(current_uid()).await;
        let token = read_token(&fx.paths).unwrap();
        rotate_token(&fx.paths).unwrap(); // host now has a different token than the server
        assert_ne!(*read_token(&fx.paths).unwrap(), *token);
        let a = host_answer(&fx.paths, &extension_origin(), &msg(json!({"op":"candidates","page_url":"https://github.com/"}))).await;
        assert_eq!(&*a, UNAUTHORIZED);
        let _ = fx.tx.send(true);
    }

    #[tokio::test]
    async fn other_uid_gets_nothing() {
        let fx = start(current_uid().wrapping_add(1)).await;
        let a = host_answer(&fx.paths, &extension_origin(), &msg(json!({"op":"status"}))).await;
        assert_eq!(&*a, UNAVAILABLE);
        let _ = fx.tx.send(true);
    }

    #[tokio::test]
    async fn app_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AutofillPaths::new(tmp.path());
        rotate_token(&paths).unwrap();
        let a = host_answer(&paths, &extension_origin(), b"{\"op\":\"status\"}").await;
        assert_eq!(&*a, UNAVAILABLE);
    }

    #[test]
    fn framing() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"{\"a\":1}").unwrap();
        let mut cur = io::Cursor::new(buf);
        assert_eq!(read_message(&mut cur).unwrap().unwrap(), b"{\"a\":1}");
        assert!(read_message(&mut cur).unwrap().is_none());
        let mut big = io::Cursor::new(((MAX_STDIN_MESSAGE + 1) as u32).to_ne_bytes().to_vec());
        assert!(read_message(&mut big).is_err());
        assert!(write_message(&mut Vec::new(), &vec![b' '; MAX_STDOUT_MESSAGE + 1]).is_err());
        assert!(build_request(b"[1]", "t", "o").is_none());
        assert!(build_request(b"not json", "t", "o").is_none());
    }

    #[test]
    fn manifest_shape() {
        let m = host_manifest(Path::new("/Applications/SecureVault.app/Contents/MacOS/securevault"));
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["allowed_origins"], json!([format!("chrome-extension://{EXTENSION_ID}/")]));
        assert_eq!(m["name"], HOST_NAME);
    }

    #[test]
    fn extension_id_matches_manifest_key() {
        use sha2::{Digest, Sha256};
        let manifest: Value = serde_json::from_str(include_str!("../../../extension/chrome/manifest.json")).unwrap();
        let der = base64::engine::general_purpose::STANDARD.decode(manifest["key"].as_str().unwrap()).unwrap();
        let hex = Sha256::digest(&der);
        let id: String = hex[..16].iter().flat_map(|b| [b >> 4, b & 15]).map(|n| (b'a' + n) as char).collect();
        assert_eq!(id, EXTENSION_ID);
        // Public key only: a PKCS#8/PKCS#1 private key would be much larger and never parse as SPKI.
        assert!(der.len() < 600);
    }
}
