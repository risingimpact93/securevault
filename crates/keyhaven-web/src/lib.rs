//! Keyhaven web server: session-authenticated HTTP API, static UI, and `/mcp`.

mod approval;
mod routes;
mod webauthn;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum::Router;
use keyhaven_core::mcp::{McpService, VaultView};
use keyhaven_core::sync::{self, ConflictView, SyncStatus};
use keyhaven_core::vault::{self, UnlockedVault, VaultError, VaultItem};
use secrecy::SecretString;
use serde_json::json;
use tokio::net::TcpListener;

use crate::approval::WebApprover;

pub const SESSION_COOKIE: &str = "keyhaven_session";
pub const CSRF_HEADER: &str = "X-CSRF-Token";
pub const DEFAULT_PORT: u16 = 8787;
pub const DEFAULT_IDLE_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: IpAddr,
    pub port: u16,
    pub data_dir: PathBuf,
    pub dist_dir: Option<PathBuf>,
    pub dev_insecure_cookie: bool,
    pub idle_timeout: Duration,
    /// When true, an unlocked vault's auto-lock setting replaces `idle_timeout`.
    /// Tests that need a sub-minute timer set this to false.
    pub use_vault_idle: bool,
    pub approval_timeout: Duration,
    pub mcp_enabled: bool,
}

impl Config {
    pub fn test(data_dir: PathBuf) -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            data_dir,
            dist_dir: None,
            dev_insecure_cookie: true,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_SECS),
            use_vault_idle: true,
            approval_timeout: Duration::from_secs(approval::DEFAULT_APPROVAL_TIMEOUT_SECS),
            mcp_enabled: false,
        }
    }
}

struct PolicyState {
    password_verified: bool,
    settings: vault::VaultSettings,
    prf_wrap: bool,
}

struct Session {
    csrf: String,
    last_activity: Instant,
}

struct LoginBudget {
    failures: u32,
    blocked_until: Instant,
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

struct Inner {
    vault_path: Mutex<PathBuf>,
    device_id: String,
    generation: AtomicU64,
    data_dir: PathBuf,
    unlocked: Arc<Mutex<Option<UnlockedVault>>>,
    sessions: Mutex<HashMap<String, Session>>,
    login_limiter: Mutex<HashMap<String, LoginBudget>>,
    mcp: Arc<McpService>,
    approver: Arc<WebApprover>,
    idle_timeout: Mutex<Duration>,
    policy: Mutex<PolicyState>,
    pending_webauthn: Mutex<Option<webauthn::Pending>>,
    webauthn_path: PathBuf,
    /// Last localhost origin seen on a passkey request. Not a listen address.
    rp_origin: Mutex<Option<String>>,
    config: Config,
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, String> {
        std::fs::create_dir_all(&config.data_dir).map_err(|e| e.to_string())?;
        let local = sync::load_or_create_local_config(&config.data_dir).map_err(|e| e.to_string())?;
        let vault_path = local
            .vault_path
            .unwrap_or_else(|| sync::default_vault_file(&config.data_dir));
        let device_id = local.device_id;
        let webauthn_path = config.data_dir.join("webauthn.json");
        let idle_timeout = config.idle_timeout;
        let prf_wrap = webauthn::load_prf_flag(&webauthn_path);
        let unlocked = Arc::new(Mutex::new(None));
        let approver = WebApprover::new(config.approval_timeout);
        let vault = Arc::new(AppVault {
            unlocked: unlocked.clone(),
        });
        let mcp = Arc::new(McpService::open(
            &config.data_dir,
            vault,
            approver.clone() as Arc<dyn keyhaven_core::mcp::SecretApprover>,
        )?);
        if config.mcp_enabled {
            let _ = mcp.set_listen(true, if config.port == 0 { DEFAULT_PORT } else { config.port });
        }
        let state = Self {
            inner: Arc::new(Inner {
                vault_path: Mutex::new(vault_path),
                device_id,
                generation: AtomicU64::new(0),
                data_dir: config.data_dir.clone(),
                unlocked,
                sessions: Mutex::new(HashMap::new()),
                login_limiter: Mutex::new(HashMap::new()),
                mcp,
                approver,
                idle_timeout: Mutex::new(idle_timeout),
                policy: Mutex::new(PolicyState {
                    password_verified: false,
                    settings: vault::VaultSettings::default(),
                    prf_wrap,
                }),
                pending_webauthn: Mutex::new(None),
                webauthn_path,
                rp_origin: Mutex::new(None),
                config,
            }),
        };
        let ticker = state.clone();
        tokio::spawn(async move {
            let period = idle_check_period(ticker.idle_timeout());
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                ticker.lock_if_idle();
            }
        });
        let syncer = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(sync::SYNC_POLL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                syncer.poll_sync();
            }
        });
        Ok(state)
    }

    pub fn vault_path(&self) -> PathBuf {
        self.inner
            .vault_path
            .lock()
            .expect("vault path")
            .clone()
    }

    fn remember_vault_path(&self, path: PathBuf) -> Result<(), VaultError> {
        sync::save_local_config(
            &self.inner.data_dir,
            &sync::LocalConfig {
                device_id: self.inner.device_id.clone(),
                vault_path: Some(path.clone()),
            },
        )?;
        *self.inner.vault_path.lock().expect("vault path") = path;
        Ok(())
    }

    pub(crate) fn dist_dir(&self) -> Option<PathBuf> {
        self.inner.config.dist_dir.clone()
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    pub(crate) fn mcp(&self) -> &McpService {
        &self.inner.mcp
    }

    pub(crate) fn approver(&self) -> &WebApprover {
        &self.inner.approver
    }

    pub(crate) fn subscribe_approvals(&self) -> tokio::sync::broadcast::Receiver<approval::ApprovalEvent> {
        self.inner.approver.subscribe()
    }

    pub(crate) fn pending_approvals(&self) -> Vec<approval::ApprovalEvent> {
        self.inner.approver.pending()
    }

    pub fn idle_timeout(&self) -> Duration {
        *self.inner.idle_timeout.lock().expect("idle timeout")
    }

    pub fn auto_lock_minutes(&self) -> u64 {
        if self.inner.config.use_vault_idle {
            let Ok(policy) = self.inner.policy.lock() else {
                return u64::from(vault::DEFAULT_AUTO_LOCK_MINUTES);
            };
            return u64::from(policy.settings.auto_lock_minutes.max(1));
        }
        self.idle_timeout().as_secs().div_ceil(60).max(1)
    }

    fn apply_idle(&self, settings: &vault::VaultSettings) {
        if !self.inner.config.use_vault_idle {
            return;
        }
        let secs = u64::from(settings.auto_lock_minutes.max(1)) * 60;
        if let Ok(mut timeout) = self.inner.idle_timeout.lock() {
            *timeout = Duration::from_secs(secs);
        }
    }

    fn cache_settings(&self, settings: &vault::VaultSettings) {
        if let Ok(mut policy) = self.inner.policy.lock() {
            policy.settings = settings.clone();
        }
    }

    pub fn vault_settings(&self) -> Result<vault::VaultSettings, VaultError> {
        self.with_unlocked(|unlocked| unlocked.data.settings.clone())
    }

    pub fn update_settings(&self, patch: &vault::SettingsPatch) -> Result<vault::VaultSettings, VaultError> {
        let settings = self.with_unlocked_mut(|unlocked| {
            unlocked.data.settings.apply_patch(patch)?;
            Ok(unlocked.data.settings.clone())
        })?;
        self.cache_settings(&settings);
        self.apply_idle(&settings);
        Ok(settings)
    }

    /// Drop the in-process master-password gate, as if the server had restarted.
    pub fn testing_restart_password_gate(&self) {
        if let Ok(mut policy) = self.inner.policy.lock() {
            policy.password_verified = false;
        }
    }

    /// Move the last master-password stamp outside the configured interval.
    pub fn testing_expire_password_interval(&self) {
        let path = self.vault_path();
        let mut cached = None;
        if let Ok(mut guard) = self.inner.unlocked.lock() {
            if let Some(unlocked) = guard.as_mut() {
                vault::backdate_password_unlock(&mut unlocked.data.settings, 30);
                let _ = vault::persist_unlocked(&path, unlocked);
                cached = Some(unlocked.data.settings.clone());
            }
        }
        if let Some(settings) = cached {
            self.cache_settings(&settings);
            return;
        }
        if let Ok(mut policy) = self.inner.policy.lock() {
            vault::backdate_password_unlock(&mut policy.settings, 30);
        }
    }

    pub fn vault_exists(&self) -> bool {
        let path = self.vault_path();
        path.exists() || sync::icloud_placeholder(&path).is_some_and(|placeholder| placeholder.exists())
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock_if_idle();
        self.inner
            .unlocked
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    pub fn lock_vault(&self) {
        if let Ok(mut guard) = self.inner.unlocked.lock() {
            *guard = None;
        }
        if let Ok(mut sessions) = self.inner.sessions.lock() {
            sessions.clear();
        }
    }

    pub(crate) fn idle_lock(&self) {
        if let Ok(mut sessions) = self.inner.sessions.lock() {
            sessions.clear();
        }
        let wipe_key = self.inner.policy.lock().map(|p| p.prf_wrap).unwrap_or(false);
        if wipe_key {
            if let Ok(mut guard) = self.inner.unlocked.lock() {
                *guard = None;
            }
        }
    }

    pub fn lock_if_idle(&self) {
        let timeout = self.idle_timeout();
        let now = Instant::now();
        let idle = {
            let Ok(sessions) = self.inner.sessions.lock() else {
                return;
            };
            if sessions.is_empty() {
                return;
            }
            sessions
                .values()
                .map(|s| s.last_activity)
                .max()
                .map(|last| now.duration_since(last) >= timeout)
                .unwrap_or(false)
        };
        if idle {
            self.idle_lock();
        }
    }

    fn with_unlocked<T>(&self, f: impl FnOnce(&UnlockedVault) -> T) -> Result<T, VaultError> {
        self.lock_if_idle();
        let guard = self.inner.unlocked.lock().map_err(|_| VaultError::Locked)?;
        let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(f(unlocked))
    }

    fn with_unlocked_mut<T>(
        &self,
        f: impl FnOnce(&mut UnlockedVault) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        self.lock_if_idle();
        let path = self.vault_path();
        let mut guard = self.inner.unlocked.lock().map_err(|_| VaultError::Locked)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        if unlocked.device_id.is_empty() {
            unlocked.device_id = self.inner.device_id.clone();
        }
        let result = f(unlocked)?;
        unlocked.dirty = true;
        vault::persist_unlocked(&path, unlocked)?;
        self.inner.generation.fetch_add(1, Ordering::Relaxed);
        Ok(result)
    }

    pub fn create_vault(&self, password: &str) -> Result<(), VaultError> {
        let path = self.vault_path();
        let secret = SecretString::new(password.to_string());
        let unlocked = vault::create_vault_at(&path, &secret)?;
        self.install_unlocked(unlocked, true)
    }

    pub fn unlock_vault(&self, password: &str) -> Result<(), VaultError> {
        let path = self.vault_path();
        let secret = SecretString::new(password.to_string());
        let unlocked = vault::unlock_file(&path, &secret)?;
        self.install_unlocked(unlocked, true)
    }

    pub(crate) fn unlock_with_existing_key(&self, key: vault::VaultKey) -> Result<(), VaultError> {
        let path = self.vault_path();
        let unlocked = vault::unlock_file_with_key(&path, &key)?;
        self.install_unlocked(unlocked, false)
    }

    fn install_unlocked(&self, mut unlocked: UnlockedVault, from_password: bool) -> Result<(), VaultError> {
        let path = self.vault_path();
        if unlocked.device_id.is_empty() {
            unlocked.device_id = self.inner.device_id.clone();
        }
        unlocked.bound_path = path.clone();
        if from_password {
            vault::mark_password_unlock(&mut unlocked.data);
            unlocked.dirty = true;
            vault::persist_unlocked(&path, &mut unlocked)?;
            if let Ok(mut policy) = self.inner.policy.lock() {
                policy.password_verified = true;
                policy.settings = unlocked.data.settings.clone();
            }
        } else if vault::password_unlock_expired_now(&unlocked.data.settings) {
            return Err(VaultError::MasterPasswordRequired);
        } else if !unlocked.data.settings.biometrics_enabled {
            return Err(VaultError::BiometricsUnavailable);
        } else {
            sync::pull_vault(&path, &mut unlocked)?;
            self.cache_settings(&unlocked.data.settings);
        }
        self.apply_idle(&unlocked.data.settings);
        *self.inner.unlocked.lock().map_err(|_| VaultError::Locked)? = Some(unlocked);
        self.inner.generation.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn list_items(&self) -> Result<Vec<VaultItem>, VaultError> {
        self.with_unlocked(|u| u.data.items.clone())
    }

    pub fn add_item(&self, item: VaultItem) -> Result<VaultItem, VaultError> {
        let device = self.inner.device_id.clone();
        self.with_unlocked_mut(|u| Ok(sync::insert_new(&mut u.data, item, &device)))
    }

    pub fn update_item(&self, item: VaultItem) -> Result<VaultItem, VaultError> {
        let device = self.inner.device_id.clone();
        self.with_unlocked_mut(|u| sync::update_existing(&mut u.data, item, &device))
    }

    pub fn delete_item(&self, id: &str) -> Result<(), VaultError> {
        let device = self.inner.device_id.clone();
        let id = id.to_string();
        self.with_unlocked_mut(|u| sync::delete_item(&mut u.data, &id, &device))
    }

    pub fn change_master_password(
        &self,
        current: &str,
        new: &str,
    ) -> Result<(), VaultError> {
        let current = SecretString::new(current.to_string());
        let new = SecretString::new(new.to_string());
        self.with_unlocked_mut(|u| u.change_master_password(&current, &new))?;
        // The vault key changed, so a PRF wrap of the old key is no longer valid.
        self.clear_prf_wrap();
        if let Ok(guard) = self.inner.unlocked.lock() {
            if let Some(unlocked) = guard.as_ref() {
                self.cache_settings(&unlocked.data.settings);
            }
        }
        Ok(())
    }

    pub fn export_bytes(&self, export_password: &str) -> Result<Vec<u8>, VaultError> {
        let secret = SecretString::new(export_password.to_string());
        self.with_unlocked(|u| vault::export_bytes(&u.data, &secret))?
    }

    pub fn import_bytes(&self, bytes: &[u8], export_password: &str, mode: &str) -> Result<(), VaultError> {
        let secret = SecretString::new(export_password.to_string());
        let imported = vault::import_bytes(bytes, &secret)?;
        self.with_unlocked_mut(|u| {
            match mode {
                "replace" => u.data = imported.clone(),
                "merge" => u.data.merge(imported.clone()),
                _ => return Err(VaultError::InvalidItemType),
            }
            Ok(())
        })?;
        let settings = self
            .inner
            .unlocked
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|u| u.data.settings.clone()));
        if let Some(settings) = settings {
            self.cache_settings(&settings);
            self.apply_idle(&settings);
        }
        Ok(())
    }

    /// Reload the vault file if iCloud (or another writer) changed it.
    /// Takes the path lock before the vault lock so it cannot deadlock with saves.
    pub fn poll_sync(&self) {
        let path = self.vault_path();
        let Ok(mut guard) = self.inner.unlocked.lock() else {
            return;
        };
        let Some(unlocked) = guard.as_mut() else {
            return;
        };
        if unlocked.device_id.is_empty() {
            unlocked.device_id = self.inner.device_id.clone();
        }
        if !unlocked.bound_path.as_os_str().is_empty() && unlocked.bound_path != path {
            return;
        }
        let before = sync::content_fingerprint(&unlocked.data);
        if sync::pull_vault(&path, unlocked).is_ok() {
            let after = sync::content_fingerprint(&unlocked.data);
            if before != after {
                self.inner.generation.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn sync_status(&self) -> SyncStatus {
        self.poll_sync();
        let path = self.vault_path();
        let guard = self.inner.unlocked.lock().ok();
        let unlocked = guard.as_ref().and_then(|inner| inner.as_ref());
        sync::status_of(
            &path,
            &self.inner.device_id,
            unlocked,
            self.inner.generation.load(Ordering::Relaxed),
            unlocked.is_none(),
        )
    }

    pub fn sync_conflicts(&self) -> Result<Vec<ConflictView>, VaultError> {
        self.with_unlocked(|unlocked| sync::list_conflicts(&unlocked.data))
    }

    pub fn resolve_sync_conflict(&self, item_id: &str, conflict_id: &str, action: &str) -> Result<(), VaultError> {
        let device = self.inner.device_id.clone();
        self.with_unlocked_mut(|unlocked| {
            sync::resolve_conflict(&mut unlocked.data, item_id, conflict_id, action, &device)
        })
    }

    pub fn set_vault_location(&self, raw_path: &str, mode: &str) -> Result<SyncStatus, VaultError> {
        let dest = sync::normalize_path(&sync::user_path(raw_path));
        sync::require_absolute(&dest)?;
        match mode {
            "move" => self.move_vault(dest)?,
            "open" => self.open_vault_at(dest)?,
            _ => return Err(VaultError::InvalidItemType),
        }
        Ok(self.sync_status())
    }

    pub fn merge_sync_password(&self, raw_path: &str, password: &str) -> Result<(), VaultError> {
        let foreign = sync::normalize_path(&sync::user_path(raw_path));
        sync::require_absolute(&foreign)?;
        let main = self.vault_path();
        let secret = SecretString::new(password.to_string());
        {
            let mut guard = self.inner.unlocked.lock().map_err(|_| VaultError::Locked)?;
            let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
            if unlocked.device_id.is_empty() {
                unlocked.device_id = self.inner.device_id.clone();
            }
            sync::merge_with_password(&main, &foreign, &secret, unlocked)?;
            vault::persist_unlocked(&main, unlocked)?;
        }
        self.inner.generation.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn move_vault(&self, dest: PathBuf) -> Result<(), VaultError> {
        let src = self.vault_path();
        {
            let mut guard = self.inner.unlocked.lock().map_err(|_| VaultError::Locked)?;
            let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
            if unlocked.device_id.is_empty() {
                unlocked.device_id = self.inner.device_id.clone();
            }
            unlocked.dirty = true;
            vault::persist_unlocked(&src, unlocked)?;
            unlocked.bound_path = dest.clone();
        }
        if let Err(err) = sync::relocate_vault_file(&src, &dest) {
            if let Ok(mut guard) = self.inner.unlocked.lock() {
                if let Some(unlocked) = guard.as_mut() {
                    unlocked.bound_path = src;
                }
            }
            return Err(err);
        }
        self.remember_vault_path(dest)?;
        self.inner.generation.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn open_vault_at(&self, dest: PathBuf) -> Result<(), VaultError> {
        let exists = dest.exists();
        let placeholder = sync::icloud_placeholder(&dest).is_some_and(|path| path.exists());
        if !exists && placeholder {
            sync::prompt_icloud_download(&dest);
            self.lock_vault();
            self.remember_vault_path(dest)?;
            return Ok(());
        }
        if !exists {
            return Err(VaultError::NotFound);
        }
        let key = {
            let guard = self.inner.unlocked.lock().map_err(|_| VaultError::Locked)?;
            let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
            unlocked.key.clone()
        };
        match vault::unlock_file_with_key(&dest, &key) {
            Ok(opened) => {
                {
                    let mut guard = self.inner.unlocked.lock().map_err(|_| VaultError::Locked)?;
                    let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
                    unlocked.data = opened.data;
                    unlocked.stamp = opened.stamp;
                    unlocked.dirty = false;
                    unlocked.pending_password_files.clear();
                    unlocked.waiting_icloud = false;
                    unlocked.sync_error = None;
                    if unlocked.device_id.is_empty() {
                        unlocked.device_id = self.inner.device_id.clone();
                    }
                    unlocked.bound_path = dest.clone();
                }
                self.remember_vault_path(dest)?;
                self.inner.generation.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(err) if foreign_password(&err) => {
                self.lock_vault();
                self.remember_vault_path(dest)?;
                Err(VaultError::SyncPasswordRequired)
            }
            Err(err) => Err(err),
        }
    }

    pub fn issue_session(&self) -> (String, String) {
        let id = random_hex();
        let csrf = random_hex();
        if let Ok(mut sessions) = self.inner.sessions.lock() {
            sessions.insert(
                id.clone(),
                Session {
                    csrf: csrf.clone(),
                    last_activity: Instant::now(),
                },
            );
        }
        (id, csrf)
    }

    pub fn cookie_header(&self, session_id: &str) -> String {
        let mut cookie = format!("{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Strict");
        if !self.inner.config.dev_insecure_cookie {
            cookie.push_str("; Secure");
        }
        cookie
    }

    pub fn clear_cookie_header(&self) -> String {
        let mut cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
        if !self.inner.config.dev_insecure_cookie {
            cookie.push_str("; Secure");
        }
        cookie
    }

    pub fn lookup_session(&self, headers: &HeaderMap) -> Option<(String, String)> {
        self.lock_if_idle();
        let id = session_id_from(headers)?;
        let sessions = self.inner.sessions.lock().ok()?;
        let session = sessions.get(&id)?;
        Some((id, session.csrf.clone()))
    }

    pub fn touch_session(&self, headers: &HeaderMap) -> bool {
        let Some(id) = session_id_from(headers) else {
            return false;
        };
        let Ok(mut sessions) = self.inner.sessions.lock() else {
            return false;
        };
        let Some(session) = sessions.get_mut(&id) else {
            return false;
        };
        session.last_activity = Instant::now();
        true
    }

    pub fn csrf_ok(&self, headers: &HeaderMap, expected: &str) -> bool {
        headers
            .get(CSRF_HEADER)
            .or_else(|| headers.get("x-csrf-token"))
            .and_then(|v| v.to_str().ok())
            .map(|sent| sent == expected && !sent.is_empty())
            .unwrap_or(false)
    }

    pub fn check_login_backoff(&self, ip: &str) -> Option<Duration> {
        let limiter = self.inner.login_limiter.lock().ok()?;
        let budget = limiter.get(ip)?;
        let now = Instant::now();
        if now < budget.blocked_until {
            Some(budget.blocked_until.saturating_duration_since(now))
        } else {
            None
        }
    }

    pub fn record_login_failure(&self, ip: &str) -> Duration {
        let mut limiter = match self.inner.login_limiter.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let budget = limiter.entry(ip.to_string()).or_insert(LoginBudget {
            failures: 0,
            blocked_until: Instant::now(),
        });
        budget.failures = budget.failures.saturating_add(1);
        let wait = backoff_secs(budget.failures);
        budget.blocked_until = Instant::now() + wait;
        wait
    }

    pub fn clear_login_failures(&self, ip: &str) {
        if let Ok(mut limiter) = self.inner.login_limiter.lock() {
            limiter.remove(ip);
        }
    }

    pub fn require_origin(&self, headers: &HeaderMap) -> Result<(), Response> {
        if origin_matches_host(headers) {
            Ok(())
        } else {
            Err(err_json(StatusCode::FORBIDDEN, "csrf rejected"))
        }
    }

    pub fn require_unlocked_session(&self, headers: &HeaderMap, mutating: bool) -> Result<String, Response> {
        if mutating {
            self.require_origin(headers)?;
        }
        let Some((_, csrf)) = self.lookup_session(headers) else {
            return Err(err_json(StatusCode::UNAUTHORIZED, "vault is locked"));
        };
        if !self.is_unlocked() {
            return Err(err_json(StatusCode::UNAUTHORIZED, "vault is locked"));
        }
        if mutating && !self.csrf_ok(headers, &csrf) {
            return Err(err_json(StatusCode::FORBIDDEN, "csrf rejected"));
        }
        Ok(csrf)
    }
}

pub fn router(state: AppState) -> Router {
    routes::router(state)
}

pub async fn serve(config: Config) -> Result<(), String> {
    let addr = SocketAddr::new(config.bind, config.port);
    if config.bind != IpAddr::V4(Ipv4Addr::LOCALHOST) && config.bind != IpAddr::V6(std::net::Ipv6Addr::LOCALHOST) {
        eprintln!(
            "warning: binding to {} (default is 127.0.0.1). Do not expose this server without TLS and access control.",
            config.bind
        );
    }
    let dist = config.dist_dir.clone();
    let insecure = config.dev_insecure_cookie;
    let state = AppState::new(config)?;
    let app = router(state);
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("Keyhaven web listening on http://{bound}");
    if insecure {
        eprintln!("--dev-insecure-cookie: session cookie is not marked Secure (http localhost only)");
    }
    if let Some(dist) = dist {
        eprintln!("serving UI from {}", dist.display());
    }
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| e.to_string())
}

pub async fn serve_for_test(config: Config) -> (u16, AppState) {
    let bind = config.bind;
    let state = AppState::new(config).expect("web state");
    let app = router(state.clone());
    let listener = TcpListener::bind((bind, 0u16))
        .await
        .expect("bind test port");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (port, state)
}

pub fn default_data_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        #[cfg(target_os = "macos")]
        {
            return PathBuf::from(home).join("Library/Application Support/com.keyhaven.web");
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                return PathBuf::from(appdata).join("com.keyhaven.web");
            }
            return PathBuf::from(home).join("com.keyhaven.web");
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            return PathBuf::from(home).join(".local/share/keyhaven");
        }
    }
    PathBuf::from("keyhaven-data")
}

pub fn default_dist_dir() -> PathBuf {
    let from_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist");
    if from_manifest.exists() {
        return from_manifest;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("dist");
            if candidate.exists() {
                return candidate;
            }
            let up = parent.join("../../dist");
            if up.exists() {
                return up;
            }
        }
    }
    PathBuf::from("dist")
}

pub(crate) fn err_json(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

pub(crate) fn vault_error(err: VaultError) -> Response {
    let status = match &err {
        VaultError::WrongPassword
        | VaultError::Locked
        | VaultError::MasterPasswordRequired
        | VaultError::BiometricsUnavailable
        | VaultError::BiometricsInvalidated
        | VaultError::PasskeySessionOnly
        | VaultError::Cancelled => StatusCode::UNAUTHORIZED,
        VaultError::NotFound | VaultError::ItemNotFound => StatusCode::NOT_FOUND,
        VaultError::AlreadyExists
        | VaultError::SyncPasswordRequired
        | VaultError::WaitingForIcloud => StatusCode::CONFLICT,
        VaultError::AbsolutePathRequired => StatusCode::BAD_REQUEST,
        VaultError::InvalidItemType
        | VaultError::GeneratorLength
        | VaultError::GeneratorCharset
        | VaultError::InvalidAutoLock
        | VaultError::InvalidPasswordInterval => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_REQUEST,
    };
    err_json(status, &err.to_string())
}

fn foreign_password(err: &VaultError) -> bool {
    matches!(
        err,
        VaultError::Tampered
            | VaultError::WrongPassword
            | VaultError::Crypto
            | VaultError::Base64(_)
            | VaultError::Json(_)
            | VaultError::SyncPasswordRequired
    )
}

fn idle_check_period(timeout: Duration) -> Duration {
    let half = timeout / 2;
    if half < Duration::from_millis(50) {
        Duration::from_millis(20)
    } else {
        half.min(Duration::from_secs(1))
    }
}

fn backoff_secs(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(5);
    Duration::from_secs(1u64 << exp)
}

fn random_hex() -> String {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex_encode(&raw)
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

fn session_id_from(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub(crate) fn origin_matches_host(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some((origin_host, origin_port)) = parse_origin(origin) else {
        return false;
    };
    let (host_name, host_port) = split_host_port(host);
    if !host_name.eq_ignore_ascii_case(&origin_host) {
        return false;
    }
    match (host_port, origin_port) {
        (Some(hp), op) => hp == op,
        (None, 80 | 443) => true,
        (None, op) => op == 80 || op == 443,
    }
}

fn parse_origin(origin: &str) -> Option<(String, u16)> {
    let origin = origin.trim();
    let (rest, default_port) = if let Some(rest) = origin.strip_prefix("https://") {
        (rest, 443u16)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (rest, 80u16)
    } else {
        return None;
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    if let Some(stripped) = hostport.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']')?;
        let port = if let Some(p) = rest.strip_prefix(':') {
            p.parse().ok()?
        } else {
            default_port
        };
        return Some((host.to_string(), port));
    }
    if let Some((h, p)) = hostport.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h.to_string(), port));
        }
    }
    Some((hostport.to_string(), default_port))
}

fn split_host_port(host: &str) -> (String, Option<u16>) {
    if let Some(stripped) = host.strip_prefix('[') {
        if let Some((h, rest)) = stripped.split_once(']') {
            let port = rest.strip_prefix(':').and_then(|p| p.parse().ok());
            return (h.to_string(), port);
        }
    }
    if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), Some(port));
        }
    }
    (host.to_string(), None)
}

use rand::RngCore;
