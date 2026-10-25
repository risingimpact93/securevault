//! Vault open/save path used by the iOS app.
//!
//! Crypto, the `.khv` envelope, and merge stay in this crate. iOS calls these
//! functions instead of assigning itself as the Secret Key manager. The desktop
//! and web apps keep calling `unlock_file_with_secret_key` and `persist_unlocked`
//! directly. `resave_ios_vault` is that same persist function.

use std::path::Path;

use secrecy::SecretString;

use crate::secret_key_store::SecretKeyStore;
use crate::vault::{
    persist_unlocked, register_device, unlock_file_with_secret_key, UnlockedVault, VaultError,
};

/// Unlock a vault and register this iPhone without taking the manager role.
pub fn open_ios_vault(
    path: &Path,
    password: &SecretString,
    secret_key: Option<&str>,
    store: Option<&dyn SecretKeyStore>,
    device_id: &str,
    device_name: &str,
) -> Result<UnlockedVault, VaultError> {
    let mut unlocked = unlock_file_with_secret_key(path, password, secret_key, store)?;
    if unlocked.device_id.trim().is_empty() {
        unlocked.device_id = device_id.trim().to_string();
    }
    register_device(&mut unlocked.data, &unlocked.device_id, device_name);
    Ok(unlocked)
}

/// Re-save through the shared merge/encrypt path. Manager fields are left as they are.
pub fn resave_ios_vault(path: &Path, unlocked: &mut UnlockedVault) -> Result<(), VaultError> {
    persist_unlocked(path, unlocked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync;
    use crate::vault::{create_vault_at, parse_encrypted, VaultItem, VAULT_VERSION_SK};
    use secrecy::SecretString;

    #[test]
    fn desktop_and_ios_paths_keep_the_khv_envelope_and_manager() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = SecretString::new("desktop-password".to_string());

        let mut desktop = create_vault_at(&path, &password).unwrap();
        desktop.device_id = "mac-device".to_string();
        register_device(&mut desktop.data, "mac-device", "작업실 Mac");
        let sk = desktop.enable_secret_key(&password).unwrap();
        let fingerprint = sk.fingerprint_b64();
        persist_unlocked(&path, &mut desktop).unwrap();

        let before = std::fs::read(&path).unwrap();
        assert!(before.starts_with(b"{"), "new vaults stay JSON");
        assert!(!before.starts_with(b"KHV1"));
        let before_header = parse_encrypted(&before).unwrap();
        assert_eq!(before_header.version, VAULT_VERSION_SK);
        assert!(before_header.sk_enabled);
        assert_eq!(before_header.sk_fingerprint.as_deref(), Some(fingerprint.as_str()));
        assert_eq!(before_header.kdf.algorithm, "argon2id");
        let salt = before_header.salt.clone();

        let mut ios = open_ios_vault(
            &path,
            &password,
            Some(&sk.format_display()),
            None,
            "iphone-device",
            "iPhone 14 Pro Max",
        )
        .unwrap();
        assert_eq!(ios.device_id, "iphone-device");
        assert_eq!(ios.data.manager_id(), Some("mac-device"));
        assert!(!ios.data.allows_secret_key_change("iphone-device"));
        assert_eq!(
            ios.data.device_record("iphone-device").map(|device| device.name.as_str()),
            Some("iPhone 14 Pro Max")
        );

        let mut item = VaultItem::skeleton();
        item.item_type = "login".to_string();
        item.title = "예시 메일".to_string();
        item.username = Some("ada@example.invalid".to_string());
        item.password = Some("dummy-not-secret".to_string());
        item.notes = Some("더미 데이터".to_string());
        sync::insert_new(&mut ios.data, item, "iphone-device");
        resave_ios_vault(&path, &mut ios).unwrap();

        let after = std::fs::read(&path).unwrap();
        assert!(after.starts_with(b"{"));
        assert!(!after.starts_with(b"KHV1"));
        let after_header = parse_encrypted(&after).unwrap();
        assert_eq!(after_header.version, VAULT_VERSION_SK);
        assert!(after_header.sk_enabled);
        assert_eq!(after_header.sk_fingerprint.as_deref(), Some(fingerprint.as_str()));
        assert_eq!(after_header.kdf.algorithm, "argon2id");
        assert_eq!(after_header.salt, salt);
        assert_ne!(after_header.nonce, before_header.nonce);
        let envelope: serde_json::Value = serde_json::from_slice(&after).unwrap();
        for key in ["version", "kdf", "salt", "nonce", "ciphertext", "skEnabled", "skFingerprint"] {
            assert!(envelope.get(key).is_some(), "missing header field {key}");
        }

        let again = unlock_file_with_secret_key(&path, &password, Some(&sk.format_display()), None).unwrap();
        assert_eq!(again.data.manager_id(), Some("mac-device"));
        assert_eq!(
            again.data.device_record("mac-device").map(|device| device.name.as_str()),
            Some("작업실 Mac")
        );
        assert!(again.data.device_record("iphone-device").is_some());
        assert!(!again.data.allows_secret_key_change("iphone-device"));
        assert!(again.data.items.iter().any(|item| {
            item.username.as_deref() == Some("ada@example.invalid")
                && item.password.as_deref() == Some("dummy-not-secret")
        }));
    }

    #[test]
    fn ios_enable_does_not_claim_the_manager() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.khv");
        let password = SecretString::new("phone-password".to_string());
        let mut phone = create_vault_at(&path, &password).unwrap();
        phone.device_id = "iphone-device".to_string();
        phone
            .enable_secret_key_claiming(&password, false)
            .unwrap();
        assert!(phone.sk_enabled());
        assert!(phone.data.manager_id().is_none());
        assert!(phone.data.device_record("iphone-device").is_some());
        assert!(phone.data.allows_secret_key_change("iphone-device"));

        let mut mac = create_vault_at(&dir.path().join("other.khv"), &password).unwrap();
        mac.device_id = "mac-device".to_string();
        mac.enable_secret_key(&password).unwrap();
        assert_eq!(mac.data.manager_id(), Some("mac-device"));
    }
}
