//! iOS backend for `securevault_core::vault_io`: every read, write, and stat of
//! the picked vault goes through the Swift plugin, which resolves the bookmark,
//! starts security-scoped access, downloads the iCloud item if needed, and runs
//! a coordinated read or write, then stops access.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use securevault_core::vault_io::{self, VaultIo, VaultStat};
use securevault_ios::{ScopedFile, ScopedFileReply};

use crate::ios_access;

const BACKUPS_KEPT: usize = 5;

pub struct IosVaultIo {
    file: ScopedFile<tauri::Wry>,
    bookmark: Mutex<String>,
    data_dir: PathBuf,
    last_read: Mutex<Option<Vec<u8>>>,
}

fn io_err(message: String) -> io::Error {
    io::Error::other(message)
}

fn mtime(reply: &ScopedFileReply) -> Option<SystemTime> {
    (reply.mtime_ms > 0).then(|| UNIX_EPOCH + Duration::from_millis(reply.mtime_ms as u64))
}

impl IosVaultIo {
    fn bookmark(&self) -> String {
        self.bookmark.lock().map(|value| value.clone()).unwrap_or_default()
    }

    /// iOS made a fresh bookmark because the old one was stale; keep it.
    fn refresh(&self, reply: &ScopedFileReply) {
        let Some(fresh) = reply.bookmark.as_ref().filter(|value| !value.is_empty()) else {
            return;
        };
        if let Ok(mut slot) = self.bookmark.lock() {
            *slot = fresh.clone();
        }
        let _ = ios_access::save_record(
            &self.data_dir,
            &ios_access::VaultAccessRecord {
                path: reply.path.clone(),
                bookmark: fresh.clone(),
            },
        );
    }

    /// Keep the previous file contents in Application Support, never beside the vault.
    fn backup_previous(&self, path: &Path) {
        let Some(previous) = self.last_read.lock().ok().and_then(|slot| slot.clone()) else {
            return;
        };
        let dir = self.data_dir.join("vault-backups");
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("vault.khv");
        let millis = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let _ = std::fs::write(dir.join(format!("{name}.{millis}.bak")), previous);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let mut files: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            files.sort();
            while files.len() > BACKUPS_KEPT {
                let _ = std::fs::remove_file(files.remove(0));
            }
        }
    }
}

impl VaultIo for IosVaultIo {
    fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
        let reply = self.file.read(&self.bookmark()).map_err(io_err)?;
        self.refresh(&reply);
        let bytes = STANDARD
            .decode(reply.data.as_deref().unwrap_or_default())
            .map_err(|err| io_err(format!("[읽기] 플러그인 응답을 해석하지 못했습니다. ({err})")))?;
        if let Ok(mut slot) = self.last_read.lock() {
            *slot = Some(bytes.clone());
        }
        Ok(bytes)
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        self.backup_previous(path);
        let reply = self.file.write(&self.bookmark(), STANDARD.encode(data)).map_err(io_err)?;
        self.refresh(&reply);
        if let Ok(mut slot) = self.last_read.lock() {
            *slot = Some(data.to_vec());
        }
        Ok(())
    }

    fn stat(&self, _path: &Path) -> io::Result<Option<VaultStat>> {
        let reply = self.file.stat(&self.bookmark()).map_err(io_err)?;
        self.refresh(&reply);
        if reply.exists == Some(false) {
            return Ok(None);
        }
        Ok(Some(VaultStat {
            modified: mtime(&reply),
            len: reply.size,
        }))
    }
}

/// Route the vault at `path` through the plugin using `bookmark`.
pub fn install(app: &tauri::AppHandle, path: &Path, bookmark: &str, data_dir: &Path) -> Result<(), String> {
    let file = securevault_ios::scoped_file(app)
        .ok_or_else(|| "[접근] vault-access 플러그인이 등록되지 않았습니다.".to_string())?;
    vault_io::install_backend(
        path,
        Arc::new(IosVaultIo {
            file,
            bookmark: Mutex::new(bookmark.to_string()),
            data_dir: data_dir.to_path_buf(),
            last_read: Mutex::new(None),
        }),
    );
    Ok(())
}

/// CI self-test: write, read back, and stat a dummy file through a bookmark,
/// exercising the same Swift path (resolve, scope, coordinate) the vault uses.
pub fn self_test(app: &tauri::AppHandle) -> Result<String, String> {
    let file = securevault_ios::scoped_file(app).ok_or("플러그인 없음")?;
    let dir = std::env::temp_dir().join("securevault-io-selftest");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let target = dir.join("selftest.khv");
    std::fs::write(&target, b"dummy-before").map_err(|e| e.to_string())?;
    let bookmark = file.make_bookmark(&target.display().to_string())?;
    let payload = b"dummy-not-secret-selftest";
    let written = file.write(&bookmark, STANDARD.encode(payload))?;
    let read = file.read(&bookmark)?;
    let bytes = STANDARD.decode(read.data.unwrap_or_default()).map_err(|e| e.to_string())?;
    if bytes != payload {
        return Err("[읽기] 되읽은 내용이 쓴 내용과 다릅니다.".into());
    }
    let stat = file.stat(&bookmark)?;
    if stat.exists != Some(true) || stat.size != payload.len() as u64 {
        return Err(format!("[접근] stat 결과가 맞지 않습니다: exists={:?} size={}", stat.exists, stat.size));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(format!("io-roundtrip write-mode={}", written.mode.unwrap_or_default()))
}
