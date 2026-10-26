//! Live site-icon lookup for entries. Only the entry's own HTTPS origin is
//! contacted (its home page, then the icons it links, then /favicon.ico);
//! no third-party favicon service, no cookies, no referrer, and no entry
//! data beyond the host in the request. Results are cached under the app
//! data directory (`site-icons/`), never in the vault file.

use std::sync::OnceLock;
use std::time::Duration;

use securevault_core::favicon::{self, CacheHit, IconCache, IconOrigin, MAX_BYTES};
use tokio::sync::Semaphore;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REDIRECTS: usize = 3;

fn limiter() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(4))
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `www.example.com` and `example.com` count as the same site for redirects.
fn same_site(a: &str, b: &str) -> bool {
    a == b || a.strip_prefix("www.") == Some(b) || b.strip_prefix("www.") == Some(a)
}

fn client(origin_host: String) -> Result<reqwest::Client, String> {
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        let ok = attempt.previous().len() < MAX_REDIRECTS
            && attempt.url().scheme() == "https"
            && attempt.url().host_str().is_some_and(|h| same_site(&h.to_ascii_lowercase(), &origin_host));
        if ok {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .redirect(policy)
        .referer(false)
        .https_only(true)
        .user_agent("SecureVault-SiteIcon/1")
        .build()
        .map_err(|e| e.to_string())
}

/// GET with a byte cap. Returns (final host, content-type, body) on 2xx.
async fn get_capped(client: &reqwest::Client, url: &str) -> Option<(String, String, Vec<u8>)> {
    let mut resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    if resp.content_length().is_some_and(|len| len as usize > MAX_BYTES) {
        return None;
    }
    let host = resp.url().host_str().unwrap_or_default().to_ascii_lowercase();
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        if body.len() + chunk.len() > MAX_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some((host, ctype, body))
}

async fn fetch_icon(origin: &IconOrigin) -> Option<(&'static str, Vec<u8>)> {
    let client = client(origin.host.clone()).ok()?;
    let html = match get_capped(&client, &origin.page_url()).await {
        Some((host, ctype, body)) if ctype.contains("html") => {
            let text = String::from_utf8_lossy(&body).into_owned();
            // Resolve links against the page we actually landed on (www-variant ok).
            let page_origin = favicon::icon_origin(&format!("https://{host}"))
                .filter(|o| same_site(&o.host, &origin.host))
                .map(|o| IconOrigin { port: origin.port, ..o })
                .unwrap_or_else(|| origin.clone());
            Some((text, page_origin))
        }
        _ => None,
    };
    let mut candidates = match &html {
        Some((text, page_origin)) => favicon::icon_candidates(Some(text.as_str()), page_origin),
        None => Vec::new(),
    };
    let ico = origin.favicon_ico();
    if !candidates.contains(&ico) {
        candidates.push(ico);
    }
    for url in candidates {
        if let Some((_, ctype, body)) = get_capped(&client, &url).await {
            if ctype.contains("html") || ctype.starts_with("text/plain") {
                continue;
            }
            if let Some(mime) = favicon::sniff_image(&body) {
                return Some((mime, body));
            }
        }
    }
    None
}

/// Data URL for the entry's site icon, or `None` (show the letter avatar).
/// `force` skips the cache (pull-to-refresh / refresh button).
pub async fn site_icon(data_dir: std::path::PathBuf, url: &str, force: bool, demo: bool) -> Option<String> {
    if demo {
        if let Some(host) = favicon::demo_host(url) {
            return favicon::demo_icon(&host);
        }
    }
    let origin = favicon::icon_origin(url)?;
    let cache = IconCache::new(&data_dir);
    let previous = match cache.get(&origin, now()) {
        CacheHit::Icon(data) if !force => return Some(data),
        CacheHit::Missing if !force => return None,
        CacheHit::Icon(data) => Some(data),
        CacheHit::Missing => None,
        CacheHit::Stale { previous } => previous,
    };
    let Ok(_permit) = limiter().acquire().await else { return previous };
    let fetched = fetch_icon(&origin).await;
    // Success replaces the icon; any failure keeps (and returns) the old one.
    cache.record(&origin, fetched.as_ref().map(|(m, b)| (*m, b.as_slice())), previous, now())
}

pub fn clear(data_dir: &std::path::Path) -> Result<(), String> {
    IconCache::new(data_dir).clear().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_site_matching() {
        assert!(same_site("example.com", "www.example.com"));
        assert!(same_site("www.example.com", "example.com"));
        assert!(!same_site("evil.com", "example.com"));
        assert!(!same_site("example.com.evil.com", "example.com"));
    }

    #[tokio::test]
    async fn demo_icons_need_demo_mode_and_never_touch_network() {
        let dir = std::env::temp_dir().join("sv-site-icon-test");
        assert!(site_icon(dir.clone(), "https://mail.example.invalid", false, true).await.is_some());
        // Outside demo mode the reserved host is rejected before any request.
        assert!(site_icon(dir.clone(), "https://mail.example.invalid", false, false).await.is_none());
        assert!(site_icon(dir, "https://localhost/", true, false).await.is_none());
    }

    /// Manual live check: `cargo test -p securevault live_fetch -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_fetch() {
        let dir = std::env::temp_dir().join("sv-site-icon-live");
        let _ = clear(&dir);
        for url in ["github.com", "https://www.rust-lang.org/learn", "naver.com"] {
            let icon = site_icon(dir.clone(), url, true, false).await;
            println!("{url}: {:?}", icon.as_ref().map(|d| (&d[..30.min(d.len())], d.len())));
            assert!(icon.is_some());
        }
    }
}
