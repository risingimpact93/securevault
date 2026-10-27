//! Face ID unlock policy. Pure rules: no keychain, no vault I/O, no UI.
//!
//! Callers pass the current time, `kern.boottime`, stored metadata, and whether
//! the keychain item is still there. The 7-day window and reboot check live
//! here so tests and the iOS app share one set of rules.

use serde::{Deserialize, Serialize};

/// Face ID must be followed by a master-password unlock at least this often.
pub const PASSWORD_REAUTH_SECS: i64 = 7 * 24 * 60 * 60;

/// Device-local Face ID state. Not secret. Lives in app data, not the vault file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BiometricMeta {
    pub enabled: bool,
    /// `kern.boottime` `tv_sec` recorded at enrollment or the last password unlock.
    pub boot_time: i64,
    /// Unix seconds of the last successful master-password unlock on this device.
    pub last_password_unlock: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PasswordReason {
    NotEnabled,
    FirstSetup,
    Rebooted,
    Expired,
    ItemMissing,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricDecision {
    Allowed,
    RequirePassword(PasswordReason),
}

impl BiometricDecision {
    pub fn reason(self) -> Option<PasswordReason> {
        match self {
            BiometricDecision::Allowed => None,
            BiometricDecision::RequirePassword(reason) => Some(reason),
        }
    }

    pub fn allowed(self) -> bool {
        matches!(self, BiometricDecision::Allowed)
    }
}

/// Actions that Face ID must never satisfy. The vault stays unlocked, but the
/// user types the master password again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveAction {
    ViewSecretKey,
    ExportSecretKey,
    EmergencyKit,
    ChangeMasterPassword,
    ManagerDeviceAction,
}

pub fn requires_password(action: SensitiveAction) -> bool {
    matches!(
        action,
        SensitiveAction::ViewSecretKey
            | SensitiveAction::ExportSecretKey
            | SensitiveAction::EmergencyKit
            | SensitiveAction::ChangeMasterPassword
            | SensitiveAction::ManagerDeviceAction
    )
}

/// Whether Face ID may open the vault right now.
///
/// `item_present` is a non-secret existence check (no Face ID prompt).
/// `item_invalidated` is set when a load already failed because Face ID data changed.
pub fn can_use_biometric(
    now: i64,
    current_boot_time: i64,
    meta: Option<&BiometricMeta>,
    item_present: bool,
    item_invalidated: bool,
) -> BiometricDecision {
    let Some(meta) = meta else {
        return BiometricDecision::RequirePassword(PasswordReason::NotEnabled);
    };
    if !meta.enabled {
        return BiometricDecision::RequirePassword(PasswordReason::NotEnabled);
    }
    if item_invalidated {
        return BiometricDecision::RequirePassword(PasswordReason::Invalidated);
    }
    if !item_present {
        return BiometricDecision::RequirePassword(PasswordReason::ItemMissing);
    }
    if meta.last_password_unlock == 0 {
        return BiometricDecision::RequirePassword(PasswordReason::FirstSetup);
    }
    if meta.boot_time != current_boot_time {
        return BiometricDecision::RequirePassword(PasswordReason::Rebooted);
    }
    if now.saturating_sub(meta.last_password_unlock) >= PASSWORD_REAUTH_SECS {
        return BiometricDecision::RequirePassword(PasswordReason::Expired);
    }
    BiometricDecision::Allowed
}

/// Missing or invalidated Face ID material turns the toggle off.
pub fn should_disable_toggle(reason: PasswordReason) -> bool {
    matches!(
        reason,
        PasswordReason::ItemMissing | PasswordReason::Invalidated
    )
}

/// Stamp a successful master-password unlock. When Face ID is on, record the
/// current boot so Face ID works again after that password unlock.
pub fn after_password_unlock(meta: &mut BiometricMeta, now: i64, current_boot_time: i64) {
    meta.last_password_unlock = now;
    if meta.enabled {
        meta.boot_time = current_boot_time;
    }
}

pub fn enroll(now: i64, current_boot_time: i64) -> BiometricMeta {
    BiometricMeta {
        enabled: true,
        boot_time: current_boot_time,
        last_password_unlock: now,
    }
}

pub fn disable(meta: &mut BiometricMeta) {
    meta.enabled = false;
}

/// `kern.boottime` `tv_sec`. iOS only; other targets have nothing to read.
pub fn current_boot_time() -> Option<i64> {
    #[cfg(target_os = "ios")]
    {
        read_kern_boottime()
    }
    #[cfg(not(target_os = "ios"))]
    {
        None
    }
}

#[cfg(target_os = "ios")]
fn read_kern_boottime() -> Option<i64> {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = std::mem::size_of_val(&tv);
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut tv as *mut libc::timeval).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 {
        Some(tv.tv_sec as i64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: i64 = 1_700_000_000;
    const T0: i64 = 1_800_000_000;

    fn enrolled() -> BiometricMeta {
        enroll(T0, BOOT)
    }

    #[test]
    fn off_and_missing_meta_need_password() {
        assert_eq!(
            can_use_biometric(T0, BOOT, None, true, false),
            BiometricDecision::RequirePassword(PasswordReason::NotEnabled)
        );
        let mut meta = enrolled();
        meta.enabled = false;
        assert_eq!(
            can_use_biometric(T0, BOOT, Some(&meta), true, false),
            BiometricDecision::RequirePassword(PasswordReason::NotEnabled)
        );
    }

    #[test]
    fn first_setup_when_enabled_without_a_password_stamp() {
        let meta = BiometricMeta {
            enabled: true,
            boot_time: BOOT,
            last_password_unlock: 0,
        };
        assert_eq!(
            can_use_biometric(T0, BOOT, Some(&meta), true, false),
            BiometricDecision::RequirePassword(PasswordReason::FirstSetup)
        );
    }

    #[test]
    fn reboot_requires_password_until_password_unlock_restamps_boot() {
        let meta = enrolled();
        assert_eq!(
            can_use_biometric(T0 + 60, BOOT + 10, Some(&meta), true, false),
            BiometricDecision::RequirePassword(PasswordReason::Rebooted)
        );
        let mut after = meta.clone();
        after_password_unlock(&mut after, T0 + 120, BOOT + 10);
        assert_eq!(
            can_use_biometric(T0 + 180, BOOT + 10, Some(&after), true, false),
            BiometricDecision::Allowed
        );
        assert_eq!(after.boot_time, BOOT + 10);
        assert_eq!(after.last_password_unlock, T0 + 120);
    }

    #[test]
    fn seven_day_window_allows_just_inside_and_blocks_on_and_after() {
        let meta = enrolled();
        let just_inside = T0 + PASSWORD_REAUTH_SECS - 1;
        assert_eq!(
            can_use_biometric(just_inside, BOOT, Some(&meta), true, false),
            BiometricDecision::Allowed
        );
        let on_boundary = T0 + PASSWORD_REAUTH_SECS;
        assert_eq!(
            can_use_biometric(on_boundary, BOOT, Some(&meta), true, false),
            BiometricDecision::RequirePassword(PasswordReason::Expired)
        );
        let after = T0 + PASSWORD_REAUTH_SECS + 1;
        assert_eq!(
            can_use_biometric(after, BOOT, Some(&meta), true, false),
            BiometricDecision::RequirePassword(PasswordReason::Expired)
        );
    }

    #[test]
    fn missing_or_invalidated_item_requires_password_and_disables_toggle() {
        let meta = enrolled();
        let missing = can_use_biometric(T0, BOOT, Some(&meta), false, false);
        assert_eq!(
            missing,
            BiometricDecision::RequirePassword(PasswordReason::ItemMissing)
        );
        assert!(should_disable_toggle(missing.reason().unwrap()));

        let invalidated = can_use_biometric(T0, BOOT, Some(&meta), true, true);
        assert_eq!(
            invalidated,
            BiometricDecision::RequirePassword(PasswordReason::Invalidated)
        );
        assert!(should_disable_toggle(invalidated.reason().unwrap()));
        assert!(!should_disable_toggle(PasswordReason::Rebooted));
        assert!(!should_disable_toggle(PasswordReason::Expired));
    }

    #[test]
    fn missing_item_wins_over_allowed_window() {
        let meta = enrolled();
        assert_eq!(
            can_use_biometric(T0 + 10, BOOT, Some(&meta), false, false).reason(),
            Some(PasswordReason::ItemMissing)
        );
    }

    #[test]
    fn sensitive_actions_always_require_the_master_password() {
        for action in [
            SensitiveAction::ViewSecretKey,
            SensitiveAction::ExportSecretKey,
            SensitiveAction::EmergencyKit,
            SensitiveAction::ChangeMasterPassword,
            SensitiveAction::ManagerDeviceAction,
        ] {
            assert!(
                requires_password(action),
                "{action:?} must require the master password"
            );
        }
    }

    #[test]
    fn password_unlock_does_not_move_boot_time_when_face_id_is_off() {
        let mut meta = BiometricMeta {
            enabled: false,
            boot_time: BOOT,
            last_password_unlock: 1,
        };
        after_password_unlock(&mut meta, T0, BOOT + 99);
        assert_eq!(meta.last_password_unlock, T0);
        assert_eq!(meta.boot_time, BOOT);
        assert!(!meta.enabled);
    }

    #[test]
    fn disable_clears_the_toggle_only() {
        let mut meta = enrolled();
        disable(&mut meta);
        assert!(!meta.enabled);
        assert_eq!(meta.boot_time, BOOT);
    }
}
