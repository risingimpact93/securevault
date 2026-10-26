//! File access for the vault file itself.
//!
//! Desktop and web use `std::fs` (the default). On iOS the picked `.khv` lives
//! outside the app container and is only reachable through a security-scoped
//! bookmark, so the app installs a [`VaultIo`] backend for that one path and
//! every read, write, and stat of it goes through the backend instead.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Size and modification time of the vault file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStat {
    pub modified: Option<SystemTime>,
    pub len: u64,
}

pub trait VaultIo: Send + Sync {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Replace the whole file. Must not leave a partial file on failure where avoidable.
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()>;
    /// `Ok(None)` when the file does not exist.
    fn stat(&self, path: &Path) -> io::Result<Option<VaultStat>>;
}

type Backend = (PathBuf, Arc<dyn VaultIo>);

static BACKEND: RwLock<Option<Backend>> = RwLock::new(None);

/// Route IO for `path` through `io` until [`clear_backend`] or another install.
pub fn install_backend(path: &Path, io: Arc<dyn VaultIo>) {
    if let Ok(mut slot) = BACKEND.write() {
        *slot = Some((path.to_path_buf(), io));
    }
}

pub fn clear_backend() {
    if let Ok(mut slot) = BACKEND.write() {
        *slot = None;
    }
}

fn backend_for(path: &Path) -> Option<Arc<dyn VaultIo>> {
    let slot = BACKEND.read().ok()?;
    let (owned, io) = slot.as_ref()?;
    (owned.as_path() == path).then(|| io.clone())
}

/// True when `path` is served by an installed backend (no sibling access possible).
pub fn is_scoped(path: &Path) -> bool {
    backend_for(path).is_some()
}

pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    match backend_for(path) {
        Some(io) => io.read(path),
        None => std::fs::read(path),
    }
}

pub fn stat(path: &Path) -> io::Result<Option<VaultStat>> {
    if let Some(io) = backend_for(path) {
        return io.stat(path);
    }
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(VaultStat {
            modified: meta.modified().ok(),
            len: meta.len(),
        })),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn exists(path: &Path) -> bool {
    match backend_for(path) {
        Some(io) => matches!(io.stat(path), Ok(Some(_))),
        None => path.exists(),
    }
}

/// Replace the vault file. Desktop keeps the temp-file + rename write.
pub fn write(path: &Path, data: &[u8]) -> Result<(), crate::vault::VaultError> {
    match backend_for(path) {
        Some(io) => io.write(path, data).map_err(Into::into),
        None => crate::vault::atomic_write(path, data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemIo {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        writes: Mutex<u32>,
    }

    impl VaultIo for MemIo {
        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        }
        fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
            *self.writes.lock().unwrap() += 1;
            self.files.lock().unwrap().insert(path.to_path_buf(), data.to_vec());
            Ok(())
        }
        fn stat(&self, path: &Path) -> io::Result<Option<VaultStat>> {
            Ok(self.files.lock().unwrap().get(path).map(|bytes| VaultStat {
                modified: Some(SystemTime::UNIX_EPOCH),
                len: bytes.len() as u64,
            }))
        }
    }

    /// The whole create/unlock/save/merge cycle runs without touching the
    /// directory of the scoped file (it does not exist on disk at all).
    #[test]
    fn scoped_backend_serves_every_vault_operation() {
        use crate::vault::{create_empty_vault, persist_unlocked, serialize_encrypted, unlock_file};
        use secrecy::SecretString;
        let path = PathBuf::from("/nonexistent-scope-dir/iCloud/Vault/vault.khv");
        let mem = Arc::new(MemIo::default());
        let password = SecretString::new("dummy-password".to_string());
        let (_, _, _, enc, _) = create_empty_vault(&password).unwrap();
        mem.files
            .lock()
            .unwrap()
            .insert(path.clone(), serialize_encrypted(&enc).unwrap());
        install_backend(&path, mem.clone());
        assert!(is_scoped(&path));
        assert!(exists(&path));
        let mut unlocked = unlock_file(&path, &password).unwrap();
        unlocked.device_id = "iphone".into();
        unlocked.dirty = true;
        persist_unlocked(&path, &mut unlocked).unwrap();
        assert!(*mem.writes.lock().unwrap() >= 1);
        let again = unlock_file(&path, &password).unwrap();
        assert!(again.data.revision >= 1);
        clear_backend();
        assert!(!exists(&path));
    }
}
