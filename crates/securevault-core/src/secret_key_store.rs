//! Local Secret Key storage.
//!
//! macOS uses the login keychain (generic password, not iCloud-synced, no
//! access group so unsigned builds work). Other platforms and tests use a
//! file or in-memory store. A future iCloud-synced impl implements the same
//! trait; 0.3.0 never writes the Secret Key next to `vault.khv`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::secret_key::SecretKey;
use crate::vault::VaultError;

pub const KEYCHAIN_SERVICE: &str = "com.securevault.secret-key";

pub trait SecretKeyStore: Send + Sync {
    fn load(&self, vault_id: &str) -> Result<Option<SecretKey>, VaultError>;
    fn store(&self, vault_id: &str, key: &SecretKey) -> Result<(), VaultError>;
    fn delete(&self, vault_id: &str) -> Result<(), VaultError>;
}

/// Login-keychain store. Compiled on every OS so the seam exists; the
/// Security-framework body runs only on macOS.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeychainSecretKeyStore;

impl SecretKeyStore for KeychainSecretKeyStore {
    fn load(&self, vault_id: &str) -> Result<Option<SecretKey>, VaultError> {
        #[cfg(target_os = "macos")]
        {
            macos::load(vault_id)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = vault_id;
            Err(VaultError::SecretKeyStoreUnavailable)
        }
    }

    fn store(&self, vault_id: &str, key: &SecretKey) -> Result<(), VaultError> {
        #[cfg(target_os = "macos")]
        {
            macos::store(vault_id, key)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (vault_id, key);
            Err(VaultError::SecretKeyStoreUnavailable)
        }
    }

    fn delete(&self, vault_id: &str) -> Result<(), VaultError> {
        #[cfg(target_os = "macos")]
        {
            macos::delete(vault_id)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = vault_id;
            Ok(())
        }
    }
}

/// Local files under the app data directory. Never the vault folder.
#[derive(Debug, Clone)]
pub struct FileSecretKeyStore {
    dir: PathBuf,
}

impl FileSecretKeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path_for(&self, vault_id: &str) -> Result<PathBuf, VaultError> {
        if !valid_vault_id(vault_id) {
            return Err(VaultError::InvalidSecretKey);
        }
        Ok(self.dir.join(vault_id))
    }
}

impl SecretKeyStore for FileSecretKeyStore {
    fn load(&self, vault_id: &str) -> Result<Option<SecretKey>, VaultError> {
        let path = self.path_for(vault_id)?;
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Some(SecretKey::parse(&text)?)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn store(&self, vault_id: &str, key: &SecretKey) -> Result<(), VaultError> {
        fs::create_dir_all(&self.dir)?;
        let path = self.path_for(vault_id)?;
        let displayed = key.format_display();
        fs::write(&path, displayed.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn delete(&self, vault_id: &str) -> Result<(), VaultError> {
        let path = self.path_for(vault_id)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

/// In-memory store for tests.
#[derive(Debug, Default, Clone)]
pub struct MemorySecretKeyStore {
    inner: Arc<Mutex<HashMap<String, SecretKey>>>,
}

impl MemorySecretKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretKeyStore for MemorySecretKeyStore {
    fn load(&self, vault_id: &str) -> Result<Option<SecretKey>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::SecretKeyStoreUnavailable)?;
        Ok(guard.get(vault_id).cloned())
    }

    fn store(&self, vault_id: &str, key: &SecretKey) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::SecretKeyStoreUnavailable)?;
        guard.insert(vault_id.to_string(), key.clone());
        Ok(())
    }

    fn delete(&self, vault_id: &str) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::SecretKeyStoreUnavailable)?;
        guard.remove(vault_id);
        Ok(())
    }
}

/// Future iCloud Keychain / CloudKit store. Not used in 0.3.0.
#[derive(Debug, Default, Clone, Copy)]
pub struct IcloudSecretKeyStore;

impl SecretKeyStore for IcloudSecretKeyStore {
    fn load(&self, _vault_id: &str) -> Result<Option<SecretKey>, VaultError> {
        Err(VaultError::SecretKeyStoreUnavailable)
    }

    fn store(&self, _vault_id: &str, _key: &SecretKey) -> Result<(), VaultError> {
        Err(VaultError::SecretKeyStoreUnavailable)
    }

    fn delete(&self, _vault_id: &str) -> Result<(), VaultError> {
        Err(VaultError::SecretKeyStoreUnavailable)
    }
}

/// macOS: login keychain. Elsewhere: a file under `data_dir/secret-key`.
pub fn local_secret_key_store(data_dir: &Path) -> Box<dyn SecretKeyStore> {
    #[cfg(target_os = "macos")]
    {
        let _ = data_dir;
        Box::new(KeychainSecretKeyStore)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(FileSecretKeyStore::new(data_dir.join("secret-key")))
    }
}

fn valid_vault_id(vault_id: &str) -> bool {
    !vault_id.is_empty()
        && vault_id.len() <= 64
        && vault_id.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(target_os = "macos")]
mod macos {
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
        PasswordOptions,
    };

    use super::{SecretKey, KEYCHAIN_SERVICE};
    use crate::vault::VaultError;

    fn options(vault_id: &str) -> PasswordOptions {
        let mut opts = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, vault_id);
        // kSecAttrSynchronizable = false. No access group / data-protection
        // keychain, so unsigned macOS builds can still store the Secret Key.
        opts.set_access_synchronized(Some(false));
        opts
    }

    pub fn load(vault_id: &str) -> Result<Option<SecretKey>, VaultError> {
        match generic_password(options(vault_id)) {
            Ok(bytes) => {
                let text = String::from_utf8(bytes).map_err(|_| VaultError::InvalidSecretKey)?;
                Ok(Some(SecretKey::parse(&text)?))
            }
            Err(err) if err.code() == -25300 => Ok(None), // errSecItemNotFound
            Err(_) => Err(VaultError::SecretKeyStoreUnavailable),
        }
    }

    pub fn store(vault_id: &str, key: &SecretKey) -> Result<(), VaultError> {
        let displayed = key.format_display();
        set_generic_password_options(displayed.as_bytes(), options(vault_id))
            .map_err(|_| VaultError::SecretKeyStoreUnavailable)
    }

    pub fn delete(vault_id: &str) -> Result<(), VaultError> {
        match delete_generic_password_options(options(vault_id)) {
            Ok(()) => Ok(()),
            Err(err) if err.code() == -25300 => Ok(()),
            Err(_) => Err(VaultError::SecretKeyStoreUnavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip_and_delete() {
        let store = MemorySecretKeyStore::new();
        let sk = SecretKey::generate();
        let id = sk.vault_id();
        assert!(store.load(&id).unwrap().is_none());
        store.store(&id, &sk).unwrap();
        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded.as_bytes(), sk.as_bytes());
        store.delete(&id).unwrap();
        assert!(store.load(&id).unwrap().is_none());
    }

    #[test]
    fn file_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretKeyStore::new(dir.path().join("secret-key"));
        let sk = SecretKey::generate();
        let id = sk.vault_id();
        store.store(&id, &sk).unwrap();
        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded.as_bytes(), sk.as_bytes());
        let on_disk = dir.path().join("secret-key").join(&id);
        assert!(on_disk.exists());
        let text = std::fs::read_to_string(&on_disk).unwrap();
        assert!(text.starts_with("SV1-"));
        store.delete(&id).unwrap();
        assert!(!on_disk.exists());
    }

    #[test]
    fn file_store_rejects_path_escape() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretKeyStore::new(dir.path());
        let sk = SecretKey::generate();
        assert!(store.store("../escape", &sk).is_err());
        assert!(store.load("not hex!").is_err());
    }

    #[test]
    fn icloud_store_is_a_disabled_seam() {
        let store = IcloudSecretKeyStore;
        let sk = SecretKey::generate();
        assert!(matches!(
            store.load("abc").unwrap_err(),
            VaultError::SecretKeyStoreUnavailable
        ));
        assert!(matches!(
            store.store("abc", &sk).unwrap_err(),
            VaultError::SecretKeyStoreUnavailable
        ));
    }

    #[test]
    fn local_store_is_file_off_macos() {
        let dir = tempfile::tempdir().unwrap();
        let store = local_secret_key_store(dir.path());
        if cfg!(target_os = "macos") {
            let sk = SecretKey::generate();
            let result = store.store(&sk.vault_id(), &sk);
            assert!(result.is_ok() || matches!(result, Err(VaultError::SecretKeyStoreUnavailable)));
        } else {
            let sk = SecretKey::generate();
            store.store(&sk.vault_id(), &sk).unwrap();
            assert!(dir.path().join("secret-key").join(sk.vault_id()).exists());
        }
    }
}
