use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed=build.rs");
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let git_meta = Path::new(&manifest).join("../../.git");
        if git_meta.exists() {
            println!("cargo:rerun-if-changed={}", git_meta.display());
        }
        let head = git_meta.join("HEAD");
        if head.exists() {
            println!("cargo:rerun-if-changed={}", head.display());
        }
    }
    let hash = resolve_hash();
    println!("cargo:rustc-env=KEYHAVEN_GIT_HASH={hash}");
}

fn resolve_hash() -> String {
    if let Some(hash) = git_short() {
        return hash;
    }
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        let sha = sha.trim();
        if !sha.is_empty() {
            let n = sha.chars().count().min(12);
            return sha.chars().take(n).collect();
        }
    }
    "unknown".to_string()
}

fn git_short() -> Option<String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(manifest)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    if text.is_empty() || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(text.to_string())
}
