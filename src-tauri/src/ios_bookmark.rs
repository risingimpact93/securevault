//! NSURL bookmark create/resolve. iOS only. `WithSecurityScope` is macOS-only;
//! document bookmarks use `MinimalBookmark` and `WithoutUI`.

use std::mem::forget;
use std::path::PathBuf;
use std::ptr::NonNull;

use base64::{engine::general_purpose::STANDARD, Engine};
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{
    NSData, NSString, NSURL, NSURLBookmarkCreationOptions, NSURLBookmarkResolutionOptions,
};

fn nsdata_to_vec(data: &NSData) -> Vec<u8> {
    let len = data.length();
    let mut buf = vec![0u8; len];
    if len > 0 {
        unsafe {
            data.getBytes_length(NonNull::new(buf.as_mut_ptr().cast()).expect("buffer"), len);
        }
    }
    buf
}

pub fn create_bookmark(path: &std::path::Path) -> Option<String> {
    let text = path.to_string_lossy();
    let ns_path = NSString::from_str(&text);
    let url = NSURL::fileURLWithPath(&ns_path);
    let data = url
        .bookmarkDataWithOptions_includingResourceValuesForKeys_relativeToURL_error(
            NSURLBookmarkCreationOptions::MinimalBookmark,
            None,
            None,
        )
        .ok()?;
    Some(STANDARD.encode(nsdata_to_vec(&data)))
}

/// Resolve bookmark data, start security-scoped access, and leak the URL so the
/// scope stays alive until the process exits.
pub fn resolve_bookmark(bookmark_b64: &str) -> Option<PathBuf> {
    let bytes = STANDARD.decode(bookmark_b64.trim()).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let data = unsafe { NSData::dataWithBytes_length(bytes.as_ptr().cast(), bytes.len()) };
    let mut stale = Bool::NO;
    let url: Retained<NSURL> = unsafe {
        NSURL::URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error(
            &data,
            NSURLBookmarkResolutionOptions::WithoutUI,
            None,
            &mut stale,
        )
        .ok()?
    };
    let _started = unsafe { url.startAccessingSecurityScopedResource() };
    let path = url.path().map(|value| value.to_string()).unwrap_or_default();
    forget(url);
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}
