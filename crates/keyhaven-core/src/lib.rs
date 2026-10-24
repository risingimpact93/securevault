//! Shared SecureVault vault crypto, on-disk format, and MCP tool logic.
//!
//! The on-disk envelope and bundle id stay `com.keyhaven.app`. `VERSION` is the
//! crate version. `GIT_COMMIT` is injected by `build.rs`.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_COMMIT: &str = env!("KEYHAVEN_GIT_HASH");

pub mod mcp;
pub mod order;
pub mod sync;
pub mod vault;
