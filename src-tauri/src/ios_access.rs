//! Security-scoped vault access stored beside the app config, not inside `.khv`
//! and not inside `securevault-config.json` (that file is rewritten as a whole).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "vault-access.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultAccessRecord {
    pub path: String,
    #[serde(default)]
    pub bookmark: String,
}

pub fn access_file(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

pub fn load_record(dir: &Path) -> Option<VaultAccessRecord> {
    let text = std::fs::read_to_string(access_file(dir)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save_record(dir: &Path, record: &VaultAccessRecord) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    let text = serde_json::to_string_pretty(record).map_err(|err| err.to_string())?;
    std::fs::write(access_file(dir), text).map_err(|err| err.to_string())
}

/// Copy a picker temp file into the app sandbox when a bookmark cannot be made.
pub fn copy_into_app_dir(dir: &Path, source: &Path) -> Result<PathBuf, String> {
    let name = source
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| {
            !value.is_empty() && *value != "." && *value != ".." && !value.contains(['/', '\\'])
        })
        .unwrap_or("vault.khv");
    let dest_dir = dir.join("imported");
    std::fs::create_dir_all(&dest_dir).map_err(|err| err.to_string())?;
    let dest = dest_dir.join(name);
    std::fs::copy(source, &dest).map_err(|err| err.to_string())?;
    Ok(dest)
}

/// Resolve a stored bookmark on iOS, otherwise the recorded path when it still exists.
pub fn restore(dir: &Path) -> Option<PathBuf> {
    let record = load_record(dir)?;
    #[cfg(target_os = "ios")]
    if !record.bookmark.trim().is_empty() {
        if let Some((path, refreshed)) = crate::ios_bookmark::resolve_bookmark(&record.bookmark) {
            if let Some(bookmark) = refreshed {
                let _ = save_record(
                    dir,
                    &VaultAccessRecord {
                        path: path.display().to_string(),
                        bookmark,
                    },
                );
            }
            return Some(path);
        }
    }
    let path = PathBuf::from(&record.path);
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sv-ios-access-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bookmark_record_roundtrip_and_restore_without_security_scope() {
        let dir = temp_dir("record");
        let vault = dir.join("vault.khv");
        std::fs::write(&vault, b"not-a-real-vault").unwrap();
        let record = VaultAccessRecord {
            path: vault.display().to_string(),
            bookmark: String::new(),
        };
        save_record(&dir, &record).unwrap();
        assert_eq!(load_record(&dir).as_ref(), Some(&record));
        assert_eq!(restore(&dir), Some(vault));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_fallback_keeps_dummy_bytes() {
        let dir = temp_dir("copy");
        let source = dir.join("picked.khv");
        std::fs::write(&source, b"dummy-not-secret").unwrap();
        let copied = copy_into_app_dir(&dir, &source).unwrap();
        assert_eq!(std::fs::read(&copied).unwrap(), b"dummy-not-secret");
        assert!(copied.starts_with(dir.join("imported")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
