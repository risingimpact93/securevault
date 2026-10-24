//! Copy a previous install's local data into the new app-data directory.
//!
//! Callers pass both directories (or the new directory, whose sibling name is
//! the old identifier). Nothing here touches the shared `.khv` format.
//! Originals stay in the old directory. A marker makes a finished copy idempotent.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::sync::{CONFIG_FILE, LEGACY_CONFIG_FILE};
use crate::vault::VaultError;

/// Written after a successful copy. A later launch does not copy again.
pub const MARKER_FILE: &str = ".migrated-from-keyhaven";
/// Set when the macOS keychain copy from `com.keyhaven.app` fails.
pub const TOUCH_ID_REREGISTER_FILE: &str = "touch-id-reregister";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    Migrated,
    /// The new directory already has `securevault-config.json`.
    SkippedExisting,
    /// The marker from a previous copy is present.
    SkippedMarker,
    NothingToMigrate,
}

/// `new_dir`'s file name is a current identifier. The old directory is the
/// sibling with the previous identifier (`com.keyhaven.app`, and the web names).
pub fn legacy_directory_name(new_name: &str) -> Option<&'static str> {
    match new_name {
        "com.securevault.app" => Some("com.keyhaven.app"),
        "com.securevault.web" => Some("com.keyhaven.web"),
        "securevault" => Some("keyhaven"),
        "securevault-data" => Some("keyhaven-data"),
        _ => None,
    }
}

pub fn migrate_sibling_data_dir(new_dir: &Path) -> Result<MigrationOutcome, VaultError> {
    let Some(name) = new_dir.file_name().and_then(|value| value.to_str()) else {
        return Ok(MigrationOutcome::NothingToMigrate);
    };
    let Some(old_name) = legacy_directory_name(name) else {
        return Ok(MigrationOutcome::NothingToMigrate);
    };
    let old_dir = match new_dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(old_name),
        _ => PathBuf::from(old_name),
    };
    migrate_app_data(new_dir, &old_dir)
}

/// Copy `old_dir` into `new_dir` when the new folder has no config yet.
pub fn migrate_app_data(new_dir: &Path, old_dir: &Path) -> Result<MigrationOutcome, VaultError> {
    if paths_overlap(new_dir, old_dir) {
        return Ok(MigrationOutcome::NothingToMigrate);
    }
    if new_dir.join(MARKER_FILE).is_file() {
        return Ok(MigrationOutcome::SkippedMarker);
    }
    if new_dir.join(CONFIG_FILE).is_file() {
        return Ok(MigrationOutcome::SkippedExisting);
    }
    if !old_dir.is_dir() {
        return Ok(MigrationOutcome::NothingToMigrate);
    }
    copy_tree(old_dir, new_dir)?;
    fs::write(new_dir.join(MARKER_FILE), b"ok\n")?;
    Ok(MigrationOutcome::Migrated)
}

pub fn record_touch_id_reregister(data_dir: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(data_dir)?;
    fs::write(data_dir.join(TOUCH_ID_REREGISTER_FILE), b"1\n")?;
    Ok(())
}

pub fn touch_id_reregister_pending(data_dir: &Path) -> bool {
    data_dir.join(TOUCH_ID_REREGISTER_FILE).is_file()
}

pub fn clear_touch_id_reregister(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join(TOUCH_ID_REREGISTER_FILE));
}

fn paths_overlap(a: &Path, b: &Path) -> bool {
    if a.as_os_str().is_empty() || b.as_os_str().is_empty() {
        return false;
    }
    a == b || a.starts_with(b) || b.starts_with(a)
}

fn copy_tree(old_dir: &Path, new_dir: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(new_dir)?;
    copy_dir(old_dir, old_dir, new_dir)
}

fn copy_dir(current: &Path, old_root: &Path, new_root: &Path) -> Result<(), VaultError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let rel = path.strip_prefix(old_root).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
        })?;
        let dest = new_root.join(rel);
        if file_type.is_dir() {
            fs::create_dir_all(&dest)?;
            copy_dir(&path, old_root, new_root)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if rel.components().count() == 1 && entry.file_name() == LEGACY_CONFIG_FILE {
            if new_root.join(CONFIG_FILE).exists() {
                continue;
            }
            let bytes = fs::read(&path)?;
            fs::write(new_root.join(CONFIG_FILE), rewrite_config_bytes(&bytes, old_root, new_root))?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        if !dest.exists() {
            fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}

fn rewrite_config_bytes(bytes: &[u8], old_dir: &Path, new_dir: &Path) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<Value>(bytes) else {
        return bytes.to_vec();
    };
    if let Some(path) = value.get("vaultPath").and_then(|item| item.as_str()).map(str::to_string) {
        let rewritten = map_internal_path(&path, old_dir, new_dir);
        if rewritten != path {
            if let Some(object) = value.as_object_mut() {
                object.insert("vaultPath".to_string(), Value::String(rewritten));
            }
        }
    }
    serde_json::to_vec_pretty(&value).unwrap_or_else(|_| bytes.to_vec())
}

/// A vault path inside `old_dir` (the default `vault.khv`) moves with the copy.
/// An external path such as iCloud Drive stays as stored.
fn map_internal_path(path: &str, old_dir: &Path, new_dir: &Path) -> String {
    let old = path_text(old_dir);
    if path == old {
        return path_text(new_dir);
    }
    for separator in ['/', '\\'] {
        let prefix = format!("{old}{separator}");
        if let Some(rest) = path.strip_prefix(&prefix) {
            return new_dir.join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().trim_end_matches(['/', '\\']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::load_or_create_local_config;

    fn write_old_tree(old: &Path, config: &str) {
        fs::create_dir_all(old.join("sync-backups")).unwrap();
        fs::write(old.join(LEGACY_CONFIG_FILE), config).unwrap();
        fs::write(old.join("vault.khv"), b"vault-bytes").unwrap();
        fs::write(old.join("sync-backups").join("one.khv"), b"backup-bytes").unwrap();
        fs::write(old.join("webauthn.json"), b"passkey-bytes").unwrap();
        fs::write(old.join("mcp-config.json"), b"mcp-bytes").unwrap();
    }

    #[test]
    fn migration_rewrites_internal_paths_and_leaves_originals() {
        let base = tempfile::tempdir().unwrap();
        let old = base.path().join("com.keyhaven.app");
        let new_dir = base.path().join("com.securevault.app");
        let internal = old.join("vault.khv");
        let config = format!(
            r#"{{"deviceId":"device-1","vaultPath":"{}","extra":"keep"}}"#,
            internal.display()
        );
        write_old_tree(&old, &config);
        let original_config = fs::read(old.join(LEGACY_CONFIG_FILE)).unwrap();

        let outcome = migrate_sibling_data_dir(&new_dir).unwrap();
        assert_eq!(outcome, MigrationOutcome::Migrated);

        let raw = fs::read(new_dir.join(CONFIG_FILE)).unwrap();
        let parsed: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed["deviceId"], "device-1");
        assert_eq!(parsed["extra"], "keep");
        let expected = new_dir.join("vault.khv").to_string_lossy().into_owned();
        assert_eq!(parsed["vaultPath"].as_str(), Some(expected.as_str()));
        assert_eq!(fs::read(new_dir.join("vault.khv")).unwrap(), b"vault-bytes");
        assert_eq!(
            fs::read(new_dir.join("sync-backups").join("one.khv")).unwrap(),
            b"backup-bytes"
        );
        assert_eq!(fs::read(new_dir.join("webauthn.json")).unwrap(), b"passkey-bytes");
        assert_eq!(fs::read(new_dir.join("mcp-config.json")).unwrap(), b"mcp-bytes");
        assert!(new_dir.join("vault.khv").extension().unwrap() == "khv");
        assert!(!new_dir.join(LEGACY_CONFIG_FILE).exists());
        assert!(new_dir.join(MARKER_FILE).is_file());

        assert_eq!(fs::read(old.join(LEGACY_CONFIG_FILE)).unwrap(), original_config);
        assert_eq!(fs::read(old.join("vault.khv")).unwrap(), b"vault-bytes");
        assert_eq!(
            fs::read(old.join("sync-backups").join("one.khv")).unwrap(),
            b"backup-bytes"
        );
        assert_eq!(fs::read(old.join("webauthn.json")).unwrap(), b"passkey-bytes");

        let loaded = load_or_create_local_config(&new_dir).unwrap();
        assert_eq!(loaded.device_id, "device-1");
        assert_eq!(
            loaded.vault_path.as_deref(),
            Some(new_dir.join("vault.khv").as_path())
        );
    }

    #[test]
    fn migration_keeps_external_vault_path() {
        let base = tempfile::tempdir().unwrap();
        let old = base.path().join("com.keyhaven.app");
        let new_dir = base.path().join("com.securevault.app");
        let external = base.path().join("iCloud Drive").join("Vault").join("vault.khv");
        let config = format!(
            r#"{{"deviceId":"device-ext","vaultPath":"{}"}}"#,
            external.display()
        );
        write_old_tree(&old, &config);

        assert_eq!(
            migrate_app_data(&new_dir, &old).unwrap(),
            MigrationOutcome::Migrated
        );
        let parsed: Value = serde_json::from_slice(&fs::read(new_dir.join(CONFIG_FILE)).unwrap()).unwrap();
        assert_eq!(parsed["deviceId"], "device-ext");
        let expected = external.to_string_lossy().into_owned();
        assert_eq!(parsed["vaultPath"].as_str(), Some(expected.as_str()));
        let loaded = load_or_create_local_config(&new_dir).unwrap();
        assert_eq!(loaded.device_id, "device-ext");
        assert_eq!(loaded.vault_path.as_deref(), Some(external.as_path()));
        assert_eq!(fs::read(old.join("vault.khv")).unwrap(), b"vault-bytes");
    }

    #[test]
    fn migration_is_idempotent_via_marker() {
        let base = tempfile::tempdir().unwrap();
        let old = base.path().join("com.keyhaven.web");
        let new_dir = base.path().join("com.securevault.web");
        let internal = old.join("vault.khv");
        let config = format!(
            r#"{{"deviceId":"device-1","vaultPath":"{}"}}"#,
            internal.display()
        );
        write_old_tree(&old, &config);
        assert_eq!(
            migrate_sibling_data_dir(&new_dir).unwrap(),
            MigrationOutcome::Migrated
        );

        fs::write(new_dir.join("vault.khv"), b"edited").unwrap();
        assert_eq!(
            migrate_sibling_data_dir(&new_dir).unwrap(),
            MigrationOutcome::SkippedMarker
        );
        assert_eq!(fs::read(new_dir.join("vault.khv")).unwrap(), b"edited");
        assert_eq!(fs::read(old.join("vault.khv")).unwrap(), b"vault-bytes");

        fs::remove_file(new_dir.join(CONFIG_FILE)).unwrap();
        fs::write(new_dir.join("vault.khv"), b"edited-2").unwrap();
        assert_eq!(
            migrate_app_data(&new_dir, &old).unwrap(),
            MigrationOutcome::SkippedMarker
        );
        assert_eq!(fs::read(new_dir.join("vault.khv")).unwrap(), b"edited-2");
        assert!(!new_dir.join(CONFIG_FILE).exists());
        assert!(old.join(LEGACY_CONFIG_FILE).is_file());
    }

    #[test]
    fn migration_skips_when_new_config_exists() {
        let base = tempfile::tempdir().unwrap();
        let old = base.path().join("keyhaven");
        let new_dir = base.path().join("securevault");
        write_old_tree(
            &old,
            r#"{"deviceId":"old-device","vaultPath":"/cloud/Vault/vault.khv"}"#,
        );
        fs::create_dir_all(&new_dir).unwrap();
        fs::write(
            new_dir.join(CONFIG_FILE),
            br#"{"deviceId":"keep-me","vaultPath":"/cloud/Vault/vault.khv"}"#,
        )
        .unwrap();

        assert_eq!(
            migrate_sibling_data_dir(&new_dir).unwrap(),
            MigrationOutcome::SkippedExisting
        );
        let parsed: Value = serde_json::from_slice(&fs::read(new_dir.join(CONFIG_FILE)).unwrap()).unwrap();
        assert_eq!(parsed["deviceId"].as_str(), Some("keep-me"));
        assert!(!new_dir.join("vault.khv").exists());
        assert!(!new_dir.join(MARKER_FILE).exists());
        assert_eq!(fs::read(old.join("vault.khv")).unwrap(), b"vault-bytes");
        assert_eq!(
            migrate_sibling_data_dir(&new_dir).unwrap(),
            MigrationOutcome::SkippedExisting
        );
    }

    #[test]
    fn sibling_names_map_old_identifiers() {
        assert_eq!(
            legacy_directory_name("com.securevault.app"),
            Some("com.keyhaven.app")
        );
        assert_eq!(
            legacy_directory_name("com.securevault.web"),
            Some("com.keyhaven.web")
        );
        assert_eq!(legacy_directory_name("securevault"), Some("keyhaven"));
        assert_eq!(
            legacy_directory_name("securevault-data"),
            Some("keyhaven-data")
        );
        assert_eq!(legacy_directory_name("notes"), None);

        let base = tempfile::tempdir().unwrap();
        let new_dir = base.path().join("not-an-app");
        fs::create_dir_all(base.path().join("keyhaven")).unwrap();
        assert_eq!(
            migrate_sibling_data_dir(&new_dir).unwrap(),
            MigrationOutcome::NothingToMigrate
        );
    }

    #[test]
    fn touch_id_flag_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!touch_id_reregister_pending(dir.path()));
        record_touch_id_reregister(dir.path()).unwrap();
        assert!(touch_id_reregister_pending(dir.path()));
        clear_touch_id_reregister(dir.path());
        assert!(!touch_id_reregister_pending(dir.path()));
    }
}
