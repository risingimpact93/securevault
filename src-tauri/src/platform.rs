//! Touch ID / Keychain and screen-lock watching.
//! The macOS bodies are compiled only on macOS. Linux and Windows return a disabled stub.

use keyhaven_core::vault::VaultError;
use tauri::AppHandle;

pub fn biometrics_available() -> bool {
    cfg!(target_os = "macos")
}

pub fn screen_lock_supported() -> bool {
    cfg!(target_os = "macos")
}

pub fn store_vault_key(key: &[u8]) -> Result<(), VaultError> {
    #[cfg(target_os = "macos")]
    {
        macos::store_vault_key(key)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = key;
        Err(VaultError::BiometricsUnavailable)
    }
}

pub fn load_vault_key() -> Result<Vec<u8>, VaultError> {
    #[cfg(target_os = "macos")]
    {
        macos::load_vault_key()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(VaultError::BiometricsUnavailable)
    }
}

pub fn delete_vault_key() {
    #[cfg(target_os = "macos")]
    macos::delete_vault_key();
}

pub fn start_screen_lock_watcher(app: AppHandle) {
    #[cfg(target_os = "macos")]
    macos::start_screen_lock_watcher(app);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{c_char, c_void};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{mpsc, OnceLock};

    use block2::RcBlock;
    use keyhaven_core::vault::VaultError;
    use objc2::runtime::Bool;
    use objc2::msg_send;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::base::Error as SecError;
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
        AccessControlOptions, PasswordOptions,
    };
    use tauri::{AppHandle, Emitter, Manager};

    use super::super::AppState;

    const SERVICE: &str = "com.keyhaven.app";
    const ACCOUNT: &str = "vault-key";
    const ERR_SEC_USER_CANCELED: i32 = -128;
    const ERR_SEC_AUTH_FAILED: i32 = -25293;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
    const CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
    const SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;

    type IoConnect = u32;
    type IoObject = u32;
    type Natural = u32;

    static APP: OnceLock<AppHandle> = OnceLock::new();
    static POWER_PORT: AtomicU32 = AtomicU32::new(0);

    #[link(name = "IOKit", kind = "framework")]
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn notify_register_dispatch(
            name: *const c_char,
            out_token: *mut i32,
            queue: *mut c_void,
            handler: &block2::Block<dyn Fn(i32)>,
        ) -> u32;
        // dispatch_get_main_queue() is a C macro; the real symbol is _dispatch_main_q.
        static _dispatch_main_q: u8;
        fn IORegisterForSystemPower(
            refcon: *mut c_void,
            the_port_ref: *mut *mut c_void,
            callback: extern "C" fn(*mut c_void, IoObject, Natural, *mut c_void),
            notifier: *mut IoObject,
        ) -> IoConnect;
        fn IONotificationPortGetRunLoopSource(notify: *mut c_void) -> *mut c_void;
        fn IOAllowPowerChange(kernel_port: IoConnect, notification_id: isize) -> i32;
        fn CFRunLoopGetMain() -> *mut c_void;
        fn CFRunLoopAddSource(run_loop: *mut c_void, source: *mut c_void, mode: *const c_void);
        static kCFRunLoopDefaultMode: *const c_void;
    }

    pub fn store_vault_key(key: &[u8]) -> Result<(), VaultError> {
        if key.len() != 32 {
            return Err(VaultError::Crypto);
        }
        touch_id("금고 키를 키체인에 저장합니다")?;
        let opts = key_options()?;
        set_generic_password_options(key, opts).map_err(map_store_error)
    }

    pub fn load_vault_key() -> Result<Vec<u8>, VaultError> {
        preflight()?;
        match generic_password(key_options()?) {
            Ok(bytes) => Ok(bytes),
            Err(err) => {
                let code = err.code();
                if code == ERR_SEC_USER_CANCELED {
                    return Err(VaultError::Cancelled);
                }
                if code == ERR_SEC_AUTH_FAILED || code == ERR_SEC_ITEM_NOT_FOUND {
                    delete_vault_key();
                    return Err(VaultError::BiometricsInvalidated);
                }
                if code == ERR_SEC_INTERACTION_NOT_ALLOWED {
                    return Err(VaultError::BiometricsUnavailable);
                }
                Err(VaultError::BiometricsUnavailable)
            }
        }
    }

    pub fn delete_vault_key() {
        if let Ok(opts) = key_options() {
            let _ = delete_generic_password_options(opts);
        }
    }

    pub fn start_screen_lock_watcher(app: AppHandle) {
        let _ = APP.set(app);
        unsafe {
            register_notify(c"com.apple.screenIsLocked".as_ptr().cast());
            register_notify(c"com.apple.sessionagent.screenIsLocked".as_ptr().cast());
            let mut port = std::ptr::null_mut();
            let mut notifier: IoObject = 0;
            let root = IORegisterForSystemPower(std::ptr::null_mut(), &mut port, on_power, &mut notifier);
            if root != 0 && !port.is_null() {
                POWER_PORT.store(root, Ordering::Relaxed);
                let source = IONotificationPortGetRunLoopSource(port);
                if !source.is_null() {
                    CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopDefaultMode);
                }
            }
        }
    }

    fn register_notify(name: *const c_char) {
        let mut token = 0;
        unsafe {
            let handler = RcBlock::new(|token: i32| on_screen_locked(token));
            let queue = std::ptr::addr_of!(_dispatch_main_q) as *mut c_void;
            let _ = notify_register_dispatch(name, &mut token, queue, &handler);
        }
    }

    extern "C" fn on_screen_locked(_token: i32) {
        lock_if_enabled();
    }

    extern "C" fn on_power(_refcon: *mut c_void, _service: IoObject, message_type: Natural, argument: *mut c_void) {
        if message_type == CAN_SYSTEM_SLEEP || message_type == SYSTEM_WILL_SLEEP {
            let root = POWER_PORT.load(Ordering::Relaxed);
            if root != 0 {
                unsafe {
                    IOAllowPowerChange(root, argument as isize);
                }
            }
            lock_if_enabled();
        }
    }

    fn lock_if_enabled() {
        let Some(app) = APP.get() else {
            return;
        };
        let state = app.state::<AppState>();
        let enabled = state
            .settings
            .lock()
            .map(|settings| settings.lock_on_screen_lock)
            .unwrap_or(false);
        if !enabled {
            return;
        }
        let was_unlocked = {
            let Ok(mut guard) = state.unlocked.lock() else {
                return;
            };
            let was = guard.is_some();
            *guard = None;
            was
        };
        if was_unlocked {
            let _ = app.emit("vault-locked", ());
        }
    }

    fn preflight() -> Result<(), VaultError> {
        let context = unsafe { LAContext::new() };
        unsafe {
            context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .map_err(|_| VaultError::BiometricsUnavailable)
        }
    }

    fn touch_id(reason: &str) -> Result<(), VaultError> {
        preflight()?;
        let context = unsafe { LAContext::new() };
        let (tx, rx) = mpsc::channel();
        let block = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let code = if error.is_null() {
                0
            } else {
                unsafe { (&*error).code() }
            };
            let _ = tx.send((success.as_bool(), code));
        });
        let reason = NSString::from_str(reason);
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
        let _: () = unsafe {
            msg_send![&*context, evaluatePolicy: policy, localizedReason: &*reason, reply: &*block]
        };
        let (ok, code) = rx.recv().map_err(|_| VaultError::BiometricsUnavailable)?;
        if ok {
            return Ok(());
        }
        if matches!(code, -2 | -3 | -4 | -9) {
            Err(VaultError::Cancelled)
        } else {
            Err(VaultError::BiometricsUnavailable)
        }
    }

    fn key_options() -> Result<PasswordOptions, VaultError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
        )
        .map_err(|_| VaultError::BiometricsUnavailable)?;
        let mut opts = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        opts.set_access_control(access);
        opts.use_protected_keychain();
        if let Ok(group) = std::env::var("KEYHAVEN_KEYCHAIN_ACCESS_GROUP") {
            if !group.is_empty() {
                opts.set_access_group(&group);
            }
        }
        Ok(opts)
    }

    fn map_store_error(err: SecError) -> VaultError {
        if err.code() == ERR_SEC_USER_CANCELED {
            VaultError::Cancelled
        } else {
            VaultError::BiometricsUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biometrics_follow_the_platform() {
        if cfg!(target_os = "macos") {
            assert!(biometrics_available());
            assert!(screen_lock_supported());
        } else {
            assert!(!biometrics_available());
            assert!(!screen_lock_supported());
            let err = store_vault_key(&[7u8; 32]).unwrap_err();
            assert_eq!(err.to_string(), "biometrics unavailable");
            assert_eq!(
                load_vault_key().unwrap_err().to_string(),
                "biometrics unavailable"
            );
        }
    }
}
