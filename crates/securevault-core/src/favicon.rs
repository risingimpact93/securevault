//! Site icons (favicons) for entries.
//!
//! Pure helpers: origin normalisation, `<link rel=icon>` parsing, image
//! sniffing, and an on-disk cache that lives in the app data directory
//! (never inside the vault file). The network fetch itself is done by the
//! app shell; it only ever talks to the entry's own HTTPS origin.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Cached icons are refetched after this long.
pub const ICON_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// A failed lookup is retried after this long.
pub const NEGATIVE_TTL_SECS: i64 = 24 * 60 * 60;
/// Largest HTML page or icon we read.
pub const MAX_BYTES: usize = 256 * 1024;
/// How many `<link>` candidates we try before `/favicon.ico`.
pub const MAX_CANDIDATES: usize = 3;

/// The HTTPS origin an entry's icon may be fetched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconOrigin {
    /// Lower-case host, without port.
    pub host: String,
    pub port: Option<u16>,
}

impl IconOrigin {
    /// `https://host[:port]`
    pub fn base(&self) -> String {
        match self.port {
            Some(port) => format!("https://{}:{}", self.host, port),
            None => format!("https://{}", self.host),
        }
    }

    pub fn page_url(&self) -> String {
        format!("{}/", self.base())
    }

    pub fn favicon_ico(&self) -> String {
        format!("{}/favicon.ico", self.base())
    }

    /// Cache key: hex SHA-256 of `host[:port]`, so file names never carry the host.
    pub fn cache_key(&self) -> String {
        let id = match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        };
        let digest = Sha256::digest(id.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Turn what the user typed in an entry's URL field into an HTTPS origin.
/// `http://` is upgraded to HTTPS; other schemes, IP literals, `localhost`
/// and single-label/internal names return `None` (no request is made).
pub fn icon_origin(entry_url: &str) -> Option<IconOrigin> {
    let raw = entry_url.trim();
    if raw.is_empty() || raw.chars().any(char::is_whitespace) {
        return None;
    }
    let rest = match raw.find("://") {
        Some(idx) => {
            let scheme = raw[..idx].to_ascii_lowercase();
            if scheme != "https" && scheme != "http" {
                return None;
            }
            &raw[idx + 3..]
        }
        None => {
            let prefix = raw.split(':').next().unwrap_or("").to_ascii_lowercase();
            if matches!(prefix.as_str(), "mailto" | "javascript" | "tel" | "sms" | "otpauth" | "file" | "data" | "ftp" | "about") {
                return None;
            }
            if raw.contains(':') && !raw.contains('@') && !raw.split(':').nth(1).is_some_and(|p| p.chars().next().is_some_and(|c| c.is_ascii_digit())) {
                // "mailto:x", "otpauth:..." and similar.
                return None;
            }
            raw
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    if authority.starts_with('[') {
        return None; // IPv6 literal
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().ok()?;
            (h, if port == 443 { None } else { Some(port) })
        }
        None => (authority, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || !host.contains('.') || host.len() > 253 {
        return None;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    if host.split('.').any(|label| label.is_empty() || label.len() > 63) {
        return None;
    }
    if host.split('.').all(|label| label.chars().all(|c| c.is_ascii_digit())) {
        return None; // IPv4 literal
    }
    let tld = host.rsplit('.').next().unwrap_or("");
    if host == "localhost"
        || host.ends_with(".localhost")
        || matches!(tld, "local" | "internal" | "lan" | "home" | "invalid" | "test" | "example")
    {
        return None;
    }
    Some(IconOrigin { host, port })
}

/// Like [`icon_origin`] but also accepts reserved demo hosts (`*.invalid`).
/// Only used to key the bundled demo icons; never for network requests.
pub fn demo_host(entry_url: &str) -> Option<String> {
    let raw = entry_url.trim();
    let rest = raw.split_once("://").map(|(_, r)| r).unwrap_or(raw);
    let host = rest.split(['/', '?', '#', ':']).next()?.to_ascii_lowercase();
    host.ends_with(".example.invalid").then_some(host)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinkIcon {
    href: String,
    rank: u32,
}

/// Find icon URLs in a page's HTML, best first, restricted to the same origin
/// (relative, root-relative, protocol-relative or absolute on the same host).
pub fn parse_icon_links(html: &str, origin: &IconOrigin) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut found: Vec<LinkIcon> = Vec::new();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<link") {
        let start = pos + start;
        let Some(end_rel) = lower[start..].find('>') else { break };
        let end = start + end_rel;
        pos = end + 1;
        let tag = &html[start + 5..end];
        let attrs = parse_attrs(tag);
        let rel = attr(&attrs, "rel").unwrap_or_default().to_ascii_lowercase();
        let rels: Vec<&str> = rel.split_whitespace().collect();
        let base_rank = if rels.contains(&"apple-touch-icon") || rels.contains(&"apple-touch-icon-precomposed") {
            300
        } else if rels.contains(&"icon") {
            200
        } else {
            continue;
        };
        let Some(href) = attr(&attrs, "href") else { continue };
        let Some(url) = resolve_href(&href, origin) else { continue };
        let size = attr(&attrs, "sizes")
            .and_then(|s| {
                s.split_whitespace()
                    .filter_map(|v| v.to_ascii_lowercase().split('x').next().and_then(|n| n.parse::<u32>().ok()))
                    .max()
            })
            .unwrap_or(32)
            .min(256);
        let svg_bonus = if url.to_ascii_lowercase().ends_with(".svg") { 40 } else { 0 };
        let rank = base_rank + size / 4 + svg_bonus;
        if !found.iter().any(|f| f.href == url) {
            found.push(LinkIcon { href: url, rank });
        }
    }
    found.sort_by(|a, b| b.rank.cmp(&a.rank));
    found.into_iter().map(|f| f.href).collect()
}

/// Candidate URLs to try, in order: page links (capped), then `/favicon.ico`.
pub fn icon_candidates(html: Option<&str>, origin: &IconOrigin) -> Vec<String> {
    let mut out: Vec<String> = html
        .map(|h| parse_icon_links(h, origin))
        .unwrap_or_default()
        .into_iter()
        .take(MAX_CANDIDATES)
        .collect();
    let ico = origin.favicon_ico();
    if !out.contains(&ico) {
        out.push(ico);
    }
    out
}

fn resolve_href(href: &str, origin: &IconOrigin) -> Option<String> {
    let href = decode_entities(href.trim());
    if href.is_empty() {
        return None;
    }
    let lower = href.to_ascii_lowercase();
    if lower.starts_with("data:") || lower.starts_with("javascript:") {
        return None;
    }
    let absolute = if lower.starts_with("https://") || lower.starts_with("http://") {
        href.clone()
    } else if let Some(rest) = href.strip_prefix("//") {
        format!("https://{rest}")
    } else if href.starts_with('/') {
        format!("{}{}", origin.base(), href)
    } else if href.contains(':') && !href.contains('/') {
        return None;
    } else {
        format!("{}/{}", origin.base(), href.trim_start_matches("./"))
    };
    let target = icon_origin(&absolute)?;
    if target != *origin {
        return None;
    }
    // Always request over HTTPS on the entry's own origin.
    let path_start = absolute.find("://").map(|i| i + 3).unwrap_or(0);
    let path = absolute[path_start..]
        .find('/')
        .map(|i| &absolute[path_start + i..])
        .unwrap_or("/");
    let path = path.split('#').next().unwrap_or("/");
    Some(format!("{}{}", origin.base(), path))
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&").replace("&#38;", "&").replace("&quot;", "\"").replace("&#47;", "/")
}

fn parse_attrs(tag: &str) -> Vec<(String, String)> {
    let bytes = tag.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' && bytes[i] != b'/' {
            i += 1;
        }
        if name_start == i {
            i += 1;
            continue;
        }
        let name = tag[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let vstart = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = tag[vstart..i.min(bytes.len())].to_string();
                i += 1;
            } else {
                let vstart = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = tag[vstart..i].to_string();
            }
        }
        out.push((name, value));
    }
    out
}

fn attr(attrs: &[(String, String)], name: &str) -> Option<String> {
    attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

/// MIME type if `bytes` is a supported image (by content, not by header).
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 4 || bytes.len() > MAX_BYTES {
        return None;
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if bytes.starts_with(&[0, 0, 1, 0]) || bytes.starts_with(&[0, 0, 2, 0]) {
        return Some("image/x-icon");
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_ascii_lowercase();
    let head = head.trim_start_matches('\u{feff}').trim_start();
    if head.starts_with("<svg") || (head.starts_with("<?xml") && head.contains("<svg")) {
        return Some("image/svg+xml");
    }
    None
}

pub fn data_url(mime: &str, bytes: &[u8]) -> String {
    format!(
        "data:{};base64,{}",
        mime,
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

/// Bundled icons for the dummy demo entries (demo mode only).
pub fn demo_icon(host: &str) -> Option<String> {
    let (bg, glyph) = match host.split('.').next()? {
        "mail" => ("#d93025", "✉"),
        "bank" => ("#1a73e8", "₩"),
        "shop" => ("#f29900", "🛒"),
        "cloud" => ("#4285f4", "☁"),
        "code" => ("#24292f", "&lt;/&gt;"),
        "chat" => ("#00a884", "💬"),
        "video" => ("#ff0033", "▶"),
        "music" => ("#fc3c44", "♪"),
        "travel" => ("#0b8a7a", "✈"),
        "telecom" => ("#7b1fa2", "📶"),
        "gov" => ("#003a70", "⚖"),
        "work" => ("#5f6368", "🏢"),
        _ => return None,
    };
    let svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='{bg}'/><text x='32' y='43' font-size='30' text-anchor='middle' fill='#fff' font-family='-apple-system,Helvetica,sans-serif'>{glyph}</text></svg>"
    );
    Some(data_url("image/svg+xml", svg.as_bytes()))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CacheMeta {
    origin: String,
    /// Time of the last *successful* lookup (icon found, or site had none).
    #[serde(default)]
    fetched_at: Option<i64>,
    /// Mime of the stored icon; `None` = no icon stored.
    #[serde(default)]
    mime: Option<String>,
    /// Time of the last failed fetch (offline, timeout, bad response).
    /// Tracked separately so a failure never touches a good icon.
    #[serde(default)]
    failed_at: Option<i64>,
}

/// Result of a cache lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheHit {
    /// Use this icon now; no fetch needed (fresh, or expired but a refetch
    /// failed recently, so we back off and keep showing it).
    Icon(String),
    /// No icon and a recent lookup found none / failed: show the avatar.
    Missing,
    /// Fetch again. `previous` is an expired icon to show meanwhile and to
    /// fall back on if the fetch fails.
    Stale { previous: Option<String> },
}

/// Icon cache in `<data_dir>/site-icons/`, one `<sha256(host)>.json` +
/// `<sha256(host)>.img` pair per origin. Separate from the vault file and
/// local to this device.
pub struct IconCache {
    dir: PathBuf,
}

fn recent(t: Option<i64>, now: i64, ttl: i64) -> bool {
    t.is_some_and(|t| (0..ttl).contains(&(now - t)))
}

impl IconCache {
    pub fn new(data_dir: &Path) -> Self {
        Self { dir: data_dir.join("site-icons") }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn paths(&self, origin: &IconOrigin) -> (PathBuf, PathBuf) {
        let key = origin.cache_key();
        (self.dir.join(format!("{key}.json")), self.dir.join(format!("{key}.img")))
    }

    fn meta(&self, origin: &IconOrigin) -> Option<CacheMeta> {
        let raw = fs::read(self.paths(origin).0).ok()?;
        let meta = serde_json::from_slice::<CacheMeta>(&raw).ok()?;
        (meta.origin == origin.base()).then_some(meta)
    }

    /// The stored icon regardless of age.
    fn stored_icon(&self, origin: &IconOrigin, meta: &CacheMeta) -> Option<String> {
        let mime = meta.mime.as_deref()?;
        let bytes = fs::read(self.paths(origin).1).ok()?;
        sniff_image(&bytes)?;
        Some(data_url(mime, &bytes))
    }

    pub fn get(&self, origin: &IconOrigin, now: i64) -> CacheHit {
        let Some(meta) = self.meta(origin) else { return CacheHit::Stale { previous: None } };
        let icon = self.stored_icon(origin, &meta);
        match icon {
            Some(icon) if recent(meta.fetched_at, now, ICON_TTL_SECS) => CacheHit::Icon(icon),
            Some(icon) if recent(meta.failed_at, now, NEGATIVE_TTL_SECS) => CacheHit::Icon(icon),
            Some(icon) => CacheHit::Stale { previous: Some(icon) },
            None if meta.mime.is_none()
                && (recent(meta.fetched_at, now, NEGATIVE_TTL_SECS) || recent(meta.failed_at, now, NEGATIVE_TTL_SECS)) =>
            {
                CacheHit::Missing
            }
            None => CacheHit::Stale { previous: None },
        }
    }

    /// A successful fetch found this icon: the only way an icon is replaced.
    pub fn put_icon(&self, origin: &IconOrigin, mime: &str, bytes: &[u8], now: i64) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let (meta_path, img_path) = self.paths(origin);
        let tmp = img_path.with_extension("img.tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &img_path)?;
        let meta = CacheMeta { origin: origin.base(), fetched_at: Some(now), mime: Some(mime.to_string()), failed_at: None };
        fs::write(&meta_path, serde_json::to_vec(&meta).map_err(io::Error::other)?)
    }

    /// The fetch failed (offline, timeout, no usable icon). Records the time
    /// only; a previously stored icon is kept as is and still shown.
    pub fn put_failure(&self, origin: &IconOrigin, now: i64) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut meta = self.meta(origin).unwrap_or_else(|| CacheMeta { origin: origin.base(), ..Default::default() });
        meta.failed_at = Some(now);
        fs::write(self.paths(origin).0, serde_json::to_vec(&meta).map_err(io::Error::other)?)
    }

    /// Record a fetch outcome and return what to display: the new icon on
    /// success, otherwise the previous (possibly expired) icon, otherwise
    /// `None` so the UI shows the initial avatar.
    pub fn record(
        &self,
        origin: &IconOrigin,
        fetched: Option<(&str, &[u8])>,
        previous: Option<String>,
        now: i64,
    ) -> Option<String> {
        match fetched {
            Some((mime, bytes)) if sniff_image(bytes).is_some() => {
                let _ = self.put_icon(origin, mime, bytes, now);
                Some(data_url(mime, bytes))
            }
            _ => {
                let _ = self.put_failure(origin, now);
                previous.or_else(|| self.meta(origin).and_then(|m| self.stored_icon(origin, &m)))
            }
        }
    }

    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_dir_all(&self.dir) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(host: &str) -> IconOrigin {
        IconOrigin { host: host.into(), port: None }
    }

    #[test]
    fn origin_normalises_entry_urls() {
        assert_eq!(icon_origin("https://Mail.Example.com/inbox?x=1"), Some(o("mail.example.com")));
        assert_eq!(icon_origin("http://example.com"), Some(o("example.com")));
        assert_eq!(icon_origin("example.com/login"), Some(o("example.com")));
        assert_eq!(icon_origin("user:pw@example.com"), Some(o("example.com")));
        assert_eq!(icon_origin("https://user@example.com:443/"), Some(o("example.com")));
        assert_eq!(
            icon_origin("https://example.com:8443/a"),
            Some(IconOrigin { host: "example.com".into(), port: Some(8443) })
        );
        assert_eq!(icon_origin("example.com:8443").unwrap().base(), "https://example.com:8443");
    }

    #[test]
    fn origin_rejects_non_web_and_private_targets() {
        for bad in [
            "",
            "   ",
            "ftp://example.com",
            "javascript:alert(1)",
            "mailto:a@example.com",
            "https://localhost/",
            "https://192.168.0.1/",
            "https://[::1]/",
            "https://router/",
            "https://nas.local/",
            "https://mail.example.invalid",
            "https://exa mple.com",
            "https://ex_ample.com",
        ] {
            assert_eq!(icon_origin(bad), None, "{bad}");
        }
    }

    #[test]
    fn cache_key_hides_host_and_is_stable() {
        let key = o("example.com").cache_key();
        assert_eq!(key.len(), 64);
        assert!(!key.contains("example"));
        assert_eq!(key, o("example.com").cache_key());
        assert_ne!(key, o("www.example.com").cache_key());
    }

    #[test]
    fn parses_and_ranks_icon_links() {
        let html = r#"<html><head>
            <LINK REL="shortcut icon" href="/favicon-16.png" sizes="16x16">
            <link rel=icon href='icons/32.png' sizes='32x32'>
            <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=2&amp;x=1">
            <link rel="stylesheet" href="/site.css">
            <link rel="icon" href="https://cdn.other.net/icon.png">
            <link rel="icon" href="//example.com/proto.svg" type="image/svg+xml">
            <link rel="icon" href="data:image/png;base64,AAAA">
        </head></html>"#;
        let links = parse_icon_links(html, &o("example.com"));
        assert_eq!(
            links,
            vec![
                "https://example.com/apple-touch-icon.png?v=2&x=1",
                "https://example.com/proto.svg",
                "https://example.com/icons/32.png",
                "https://example.com/favicon-16.png",
            ]
        );
    }

    #[test]
    fn candidates_cap_links_and_end_with_favicon_ico() {
        let html = (0..6)
            .map(|i| format!("<link rel=icon href=/i{i}.png>"))
            .collect::<String>();
        let c = icon_candidates(Some(&html), &o("example.com"));
        assert_eq!(c.len(), MAX_CANDIDATES + 1);
        assert_eq!(c.last().unwrap(), "https://example.com/favicon.ico");
        assert_eq!(icon_candidates(None, &o("example.com")), vec!["https://example.com/favicon.ico"]);
        let http_same = "<link rel=icon href=http://example.com/a.ico>";
        assert_eq!(icon_candidates(Some(http_same), &o("example.com"))[0], "https://example.com/a.ico");
    }

    #[test]
    fn sniffs_only_images() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\n0000"), Some("image/png"));
        assert_eq!(sniff_image(&[0, 0, 1, 0, 1, 0]), Some("image/x-icon"));
        assert_eq!(sniff_image(b"<?xml version='1.0'?><svg></svg>"), Some("image/svg+xml"));
        assert_eq!(sniff_image(b"<!doctype html><html>"), None);
        assert_eq!(sniff_image(b"{\"a\":1}"), None);
        assert_eq!(sniff_image(&vec![0x89; MAX_BYTES + 1]), None);
    }

    fn temp_cache() -> (PathBuf, IconCache) {
        let dir = std::env::temp_dir().join(format!("sv-icons-{}", uuid::Uuid::new_v4()));
        let cache = IconCache::new(&dir);
        (dir, cache)
    }
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nrest";
    const PNG2: &[u8] = b"\x89PNG\r\n\x1a\nnewer";

    #[test]
    fn cache_ttl_and_clear() {
        let (dir, cache) = temp_cache();
        let origin = o("example.com");
        assert_eq!(cache.get(&origin, 1000), CacheHit::Stale { previous: None });
        cache.put_icon(&origin, "image/png", PNG, 1000).unwrap();
        assert_eq!(cache.get(&origin, 1060), CacheHit::Icon(data_url("image/png", PNG)));
        // Expired: refetch, but keep the old icon on hand.
        assert_eq!(
            cache.get(&origin, 1000 + ICON_TTL_SECS),
            CacheHit::Stale { previous: Some(data_url("image/png", PNG)) }
        );
        // A different origin with the same key file never matches.
        assert_eq!(cache.get(&o("other.com"), 1060), CacheHit::Stale { previous: None });
        cache.clear().unwrap();
        assert!(!cache.dir().exists());
        cache.clear().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offline_expired_cache_keeps_old_icon() {
        let (dir, cache) = temp_cache();
        let origin = o("example.com");
        cache.put_icon(&origin, "image/png", PNG, 0).unwrap();
        let later = ICON_TTL_SECS + 10;
        let CacheHit::Stale { previous } = cache.get(&origin, later) else { panic!("expected stale") };
        // Fetch fails (offline): still show the old icon.
        let shown = cache.record(&origin, None, previous, later);
        assert_eq!(shown, Some(data_url("image/png", PNG)));
        // Backed off for a day, and the icon is still served, not erased.
        assert_eq!(cache.get(&origin, later + 60), CacheHit::Icon(data_url("image/png", PNG)));
        // After the back-off it retries, still offering the old icon.
        assert_eq!(
            cache.get(&origin, later + NEGATIVE_TTL_SECS),
            CacheHit::Stale { previous: Some(data_url("image/png", PNG)) }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failure_never_overwrites_a_good_icon() {
        let (dir, cache) = temp_cache();
        let origin = o("example.com");
        cache.put_icon(&origin, "image/png", PNG, 0).unwrap();
        // Failure even without `previous` (forced refresh) keeps the stored icon.
        assert_eq!(cache.record(&origin, None, None, 50), Some(data_url("image/png", PNG)));
        // A bogus "image" counts as a failure, not a replacement.
        assert_eq!(cache.record(&origin, Some(("image/png", b"<html>")), None, 60), Some(data_url("image/png", PNG)));
        assert_eq!(cache.get(&origin, 70), CacheHit::Icon(data_url("image/png", PNG)));
        // Only a successful fetch replaces it, and clears the failure mark.
        assert_eq!(cache.record(&origin, Some(("image/png", PNG2)), None, 80), Some(data_url("image/png", PNG2)));
        assert_eq!(cache.get(&origin, 90), CacheHit::Icon(data_url("image/png", PNG2)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_cache_and_failure_falls_back_to_avatar() {
        let (dir, cache) = temp_cache();
        let origin = o("example.com");
        assert_eq!(cache.record(&origin, None, None, 100), None);
        assert_eq!(cache.get(&origin, 160), CacheHit::Missing);
        assert_eq!(cache.get(&origin, 100 + NEGATIVE_TTL_SECS), CacheHit::Stale { previous: None });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn demo_icons_only_for_demo_hosts() {
        assert_eq!(demo_host("https://mail.example.invalid"), Some("mail.example.invalid".into()));
        assert_eq!(demo_host("https://mail.example.com"), None);
        assert!(demo_icon("mail.example.invalid").unwrap().starts_with("data:image/svg+xml;base64,"));
    }
}
