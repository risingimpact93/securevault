//! Shared SecureVault vault crypto, on-disk format, and MCP tool logic.
//!
//! Newly written `.khv` files use the historical JSON envelope so older builds
//! can open them. A leading `KHV1` prefix is still accepted when reading.
//! `VERSION` is the crate version. `GIT_COMMIT` is injected by `build.rs`.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_COMMIT: &str = env!("SECUREVAULT_GIT_HASH");

pub mod mcp;
pub mod migrate;
pub mod order;
pub mod secret_key;
pub mod secret_key_store;
pub mod sync;
pub mod vault;

/// Read `SECUREVAULT_{suffix}`. When that variable is missing or blank, read
/// `KEYHAVEN_{suffix}`.
pub fn env_var(suffix: &str) -> Option<String> {
    fn nonempty(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }
    let primary = format!("SECUREVAULT_{suffix}");
    let legacy = format!("KEYHAVEN_{suffix}");
    nonempty(&primary).or_else(|| nonempty(&legacy))
}

#[cfg(test)]
mod env_tests {
    use super::env_var;
    use std::sync::Mutex;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|err| err.into_inner())
    }

    #[test]
    fn env_var_prefers_new_name_and_falls_back() {
        let _guard = env_lock();
        let names = ["SECUREVAULT_MIGRATE_PROBE", "KEYHAVEN_MIGRATE_PROBE"];
        let previous: Vec<_> = names
            .iter()
            .map(|name| std::env::var(name).ok())
            .collect();
        std::env::remove_var("SECUREVAULT_MIGRATE_PROBE");
        std::env::set_var("KEYHAVEN_MIGRATE_PROBE", "from-old");
        assert_eq!(env_var("MIGRATE_PROBE").as_deref(), Some("from-old"));
        std::env::set_var("SECUREVAULT_MIGRATE_PROBE", "   ");
        assert_eq!(env_var("MIGRATE_PROBE").as_deref(), Some("from-old"));
        std::env::set_var("SECUREVAULT_MIGRATE_PROBE", "from-new");
        assert_eq!(env_var("MIGRATE_PROBE").as_deref(), Some("from-new"));
        std::env::remove_var("SECUREVAULT_MIGRATE_PROBE");
        std::env::remove_var("KEYHAVEN_MIGRATE_PROBE");
        assert_eq!(env_var("MIGRATE_PROBE"), None);
        for (name, value) in names.iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}
