//! Browser autofill core: site matching (phishing defence) and a
//! transport-agnostic request handler used by the Chrome/Safari bridges.
//!
//! Rules (docs/autofill-plan.md §2.6):
//! - the page must be `https`;
//! - same site = same registrable domain (eTLD+1 via the Public Suffix List);
//! - exact host+port → may fill on the user's normal action;
//!   other subdomain of the same site → only after an explicit click;
//! - a frame whose registrable domain differs from the top frame gets nothing;
//! - IP addresses and hosts that are themselves public suffixes match exactly only;
//! - while the vault is locked nothing is returned, not even titles;
//! - every reveal re-checks the origin; callers must present the install token.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Host, Url};
use zeroize::Zeroize;

use crate::psl;
use crate::vault::VaultItem;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SiteHost {
    Domain(String),
    Ip(String),
}

/// A parsed, normalized site (host is lowercase ASCII/punycode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    scheme: String,
    host: SiteHost,
    port: u16,
}

impl Site {
    fn parse_url(raw: &str) -> Option<Url> {
        let raw = raw.trim();
        if raw.is_empty() || raw.chars().any(char::is_whitespace) {
            return None;
        }
        let with_scheme = if raw.contains("://") {
            raw.to_string()
        } else {
            format!("https://{raw}")
        };
        Url::parse(&with_scheme).ok()
    }

    fn from_url(u: &Url) -> Option<Site> {
        let scheme = u.scheme().to_string();
        if scheme != "https" && scheme != "http" {
            return None;
        }
        let host = match u.host()? {
            Host::Domain(d) => {
                let d = d.trim_end_matches('.').to_ascii_lowercase();
                if d.is_empty() {
                    return None;
                }
                SiteHost::Domain(d)
            }
            Host::Ipv4(ip) => SiteHost::Ip(ip.to_string()),
            Host::Ipv6(ip) => SiteHost::Ip(ip.to_string()),
        };
        let port = u.port_or_known_default()?;
        Some(Site { scheme, host, port })
    }

    /// Page URL as reported by the browser. Only `https` pages are accepted.
    pub fn page(raw: &str) -> Option<Site> {
        let u = Url::parse(raw.trim()).ok()?;
        let s = Self::from_url(&u)?;
        (s.scheme == "https").then_some(s)
    }

    /// URL stored on a vault item (scheme optional; defaults to https).
    pub fn entry(raw: &str) -> Option<Site> {
        Self::from_url(&Self::parse_url(raw)?)
    }

    /// Host as shown to the user (punycode is kept, never decoded).
    pub fn display_host(&self) -> &str {
        match &self.host {
            SiteHost::Domain(d) | SiteHost::Ip(d) => d,
        }
    }

    fn registrable(&self) -> Option<String> {
        match &self.host {
            SiteHost::Domain(d) => psl::registrable_domain(d),
            SiteHost::Ip(_) => None,
        }
    }

    fn same_host_port(&self, other: &Site) -> bool {
        // Entries saved as http:// still match the https page on the same
        // host; the port must then be the https default.
        let other_port = if other.scheme == "http" && other.port == 80 { 443 } else { other.port };
        self.host == other.host && self.port == other_port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchLevel {
    /// Same host and port: fill on the user's normal action.
    Exact,
    /// Same registrable domain, different subdomain: fill only after a click.
    SameSite,
    None,
}

/// Decide how `entry_url` relates to the page in a given frame.
/// `top_url` is the top-level document; pass `None` when the page is the top frame.
pub fn match_site(page_url: &str, top_url: Option<&str>, entry_url: &str) -> MatchLevel {
    let Some(page) = Site::page(page_url) else { return MatchLevel::None };
    if let Some(top) = top_url {
        let Some(top) = Site::page(top) else { return MatchLevel::None };
        let same_frame_site = page.same_host_port(&top)
            || matches!((page.registrable(), top.registrable()), (Some(a), Some(b)) if a == b);
        if !same_frame_site {
            return MatchLevel::None;
        }
    }
    let Some(entry) = Site::entry(entry_url) else { return MatchLevel::None };
    if page.same_host_port(&entry) {
        return MatchLevel::Exact;
    }
    match (page.registrable(), entry.registrable()) {
        (Some(a), Some(b)) if a == b => MatchLevel::SameSite,
        _ => MatchLevel::None,
    }
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

/// Per-install authorization: the token's hash and the one allowed extension origin.
pub struct AutofillGate {
    token_hash: [u8; 32],
    allowed_origins: Vec<String>,
}

impl fmt::Debug for AutofillGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutofillGate").field("allowed_origins", &self.allowed_origins).finish_non_exhaustive()
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl AutofillGate {
    pub fn new(token: &str, allowed_origins: Vec<String>) -> Self {
        Self { token_hash: sha256(token.as_bytes()), allowed_origins }
    }

    pub fn authorize(&self, token: &str, caller_origin: &str) -> bool {
        let tok_ok = !token.is_empty() && ct_eq(&self.token_hash, &sha256(token.as_bytes()));
        let origin_ok = self.allowed_origins.iter().any(|o| o == caller_origin);
        tok_ok & origin_ok
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Status,
    Candidates { page_url: String, #[serde(default)] top_url: Option<String> },
    Reveal {
        item_id: String,
        page_url: String,
        #[serde(default)]
        top_url: Option<String>,
        /// Set only when the user explicitly clicked this candidate.
        #[serde(default)]
        user_confirmed: bool,
    },
}

#[derive(Clone, Deserialize)]
pub struct AutofillRequest {
    pub token: String,
    pub caller_origin: String,
    #[serde(flatten)]
    pub op: Op,
}

impl fmt::Debug for AutofillRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutofillRequest").field("op", &self.op).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub level: MatchLevel,
    pub host: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential { .. }")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AutofillResponse {
    Unauthorized,
    Locked,
    Unlocked,
    Candidates { items: Vec<Candidate> },
    Credential { credential: Credential },
    /// Same site but a different subdomain: the UI must ask for a click.
    NeedsConfirmation,
    Denied,
}

fn is_login(item: &VaultItem) -> bool {
    item.item_type == "login"
}

/// Handle one request. `items` is `None` while the vault is locked.
pub fn handle(gate: &AutofillGate, req: &AutofillRequest, items: Option<&[VaultItem]>) -> AutofillResponse {
    if !gate.authorize(&req.token, &req.caller_origin) {
        return AutofillResponse::Unauthorized;
    }
    let Some(items) = items else { return AutofillResponse::Locked };
    match &req.op {
        Op::Status => AutofillResponse::Unlocked,
        Op::Candidates { page_url, top_url } => {
            let mut out: Vec<Candidate> = items
                .iter()
                .filter(|i| is_login(i))
                .filter_map(|i| {
                    let url = i.url.as_deref()?;
                    let level = match_site(page_url, top_url.as_deref(), url);
                    if level == MatchLevel::None {
                        return None;
                    }
                    Some(Candidate {
                        id: i.id.clone(),
                        title: i.title.clone(),
                        username: i.username.clone(),
                        level,
                        host: Site::entry(url).map(|s| s.display_host().to_string()).unwrap_or_default(),
                    })
                })
                .collect();
            out.sort_by_key(|c| if c.level == MatchLevel::Exact { 0 } else { 1 });
            AutofillResponse::Candidates { items: out }
        }
        Op::Reveal { item_id, page_url, top_url, user_confirmed } => {
            let Some(item) = items.iter().find(|i| &i.id == item_id && is_login(i)) else {
                return AutofillResponse::Denied;
            };
            let Some(url) = item.url.as_deref() else { return AutofillResponse::Denied };
            // Re-check the origin right before handing out the password.
            match match_site(page_url, top_url.as_deref(), url) {
                MatchLevel::Exact => {}
                MatchLevel::SameSite if *user_confirmed => {}
                MatchLevel::SameSite => return AutofillResponse::NeedsConfirmation,
                MatchLevel::None => return AutofillResponse::Denied,
            }
            AutofillResponse::Credential {
                credential: Credential {
                    username: item.username.clone().unwrap_or_default(),
                    password: item.password.clone().unwrap_or_default(),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use MatchLevel::{Exact, SameSite};
    const NO: MatchLevel = MatchLevel::None;

    fn m(page: &str, entry: &str) -> MatchLevel {
        match_site(page, None, entry)
    }

    #[test]
    fn exact_and_scheme_less_entries() {
        assert_eq!(m("https://github.com/login", "https://github.com"), Exact);
        assert_eq!(m("https://github.com/login", "github.com"), Exact);
        assert_eq!(m("https://GitHub.com./login", "github.com"), Exact);
        assert_eq!(m("https://github.com/login", "http://github.com"), Exact);
    }

    #[test]
    fn http_downgrade_is_refused() {
        assert_eq!(m("http://github.com/login", "https://github.com"), NO);
        assert_eq!(m("http://github.com/login", "http://github.com"), NO);
        assert_eq!(m("ftp://github.com", "github.com"), NO);
        assert_eq!(m("javascript:alert(1)", "github.com"), NO);
        assert_eq!(m("data:text/html,x", "github.com"), NO);
    }

    #[test]
    fn lookalike_domains() {
        assert_eq!(m("https://github.com.evil.io/", "github.com"), NO);
        assert_eq!(m("https://githuh.com/", "github.com"), NO);
        assert_eq!(m("https://evilgithub.com/", "github.com"), NO);
        assert_eq!(m("https://github.co/", "github.com"), NO);
        assert_eq!(m("https://github.com@evil.com/", "github.com"), NO);
        assert_eq!(m("https://naver.com-login.kr/", "naver.com"), NO);
    }

    #[test]
    fn idn_homograph() {
        // Cyrillic 'а' in "аpple.com" becomes punycode and never matches apple.com.
        assert_eq!(m("https://аpple.com/", "apple.com"), NO);
        assert_eq!(m("https://xn--pple-43d.com/", "apple.com"), NO);
        let p = Site::page("https://аpple.com/").unwrap();
        assert!(p.display_host().starts_with("xn--"));
        // A genuine IDN entry matches its own punycode form.
        assert_eq!(m("https://xn--3e0b707e.kr/", "한국.kr"), Exact);
    }

    #[test]
    fn subdomains_need_click() {
        assert_eq!(m("https://login.example.com/", "example.com"), SameSite);
        assert_eq!(m("https://example.com/", "accounts.example.com"), SameSite);
        assert_eq!(m("https://a.example.com/", "b.example.com"), SameSite);
        assert_eq!(m("https://example.com:8443/", "example.com"), SameSite);
    }

    #[test]
    fn public_suffix_hosts() {
        assert_eq!(m("https://alice.github.io/", "bob.github.io"), NO);
        assert_eq!(m("https://x.alice.github.io/", "alice.github.io"), SameSite);
        assert_eq!(m("https://naver.co.kr/", "daum.co.kr"), NO);
        assert_eq!(m("https://www.naver.co.kr/", "naver.co.kr"), SameSite);
        assert_eq!(m("https://a.co.kr/", "co.kr"), NO);
        assert_eq!(m("https://co.kr/", "co.kr"), Exact);
        assert_eq!(m("https://foo.appspot.com/", "bar.appspot.com"), NO);
    }

    #[test]
    fn ip_addresses_match_exactly_only() {
        assert_eq!(m("https://192.168.0.10/", "https://192.168.0.10"), Exact);
        assert_eq!(m("https://192.168.0.10/", "192.168.0.11"), NO);
        assert_eq!(m("https://192.168.0.10:8443/", "192.168.0.10"), NO);
        assert_eq!(m("https://[::1]/", "https://[::1]"), Exact);
        assert_eq!(m("https://10.0.0.1/", "1.10.0.0.1.example.com"), NO);
    }

    #[test]
    fn iframes() {
        let e = "accounts.example.com";
        assert_eq!(match_site("https://accounts.example.com/f", Some("https://www.example.com/"), e), Exact);
        assert_eq!(match_site("https://accounts.example.com/f", Some("https://evil.com/"), e), NO);
        assert_eq!(match_site("https://accounts.example.com/f", Some("http://www.example.com/"), e), NO);
        assert_eq!(match_site("https://alice.github.io/", Some("https://bob.github.io/"), "alice.github.io"), NO);
    }

    fn item(id: &str, url: &str) -> VaultItem {
        let mut i = VaultItem::skeleton();
        i.id = id.into();
        i.item_type = "login".into();
        i.title = format!("title-{id}");
        i.username = Some("dummy-user".into());
        i.password = Some("dummy-pass".into());
        i.url = Some(url.into());
        i
    }

    const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

    fn gate() -> AutofillGate {
        AutofillGate::new("install-token", vec![ORIGIN.into()])
    }

    fn req(op: Op) -> AutofillRequest {
        AutofillRequest { token: "install-token".into(), caller_origin: ORIGIN.into(), op }
    }

    fn reveal(id: &str, page: &str, top: Option<&str>, confirmed: bool) -> Op {
        Op::Reveal { item_id: id.into(), page_url: page.into(), top_url: top.map(Into::into), user_confirmed: confirmed }
    }

    #[test]
    fn locked_vault_gives_out_nothing() {
        let r = handle(&gate(), &req(Op::Candidates { page_url: "https://github.com/".into(), top_url: None }), None);
        assert_eq!(r, AutofillResponse::Locked);
        let r = handle(&gate(), &req(reveal("1", "https://github.com/", None, true)), None);
        assert_eq!(r, AutofillResponse::Locked);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"status":"locked"}"#);
    }

    #[test]
    fn unauthorized_callers() {
        let items = vec![item("1", "github.com")];
        let mut bad_tok = req(Op::Status);
        bad_tok.token = "wrong".into();
        assert_eq!(handle(&gate(), &bad_tok, Some(&items)), AutofillResponse::Unauthorized);
        let mut empty = req(Op::Status);
        empty.token = String::new();
        assert_eq!(handle(&AutofillGate::new("", vec![ORIGIN.into()]), &empty, Some(&items)), AutofillResponse::Unauthorized);
        let mut bad_origin = req(reveal("1", "https://github.com/", None, true));
        bad_origin.caller_origin = "chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/".into();
        assert_eq!(handle(&gate(), &bad_origin, Some(&items)), AutofillResponse::Unauthorized);
        // Unauthorized even while locked: lock state is not leaked either.
        assert_eq!(handle(&gate(), &bad_tok, None), AutofillResponse::Unauthorized);
    }

    #[test]
    fn candidates_and_reveal() {
        let mut note = item("n", "github.com");
        note.item_type = "note".into();
        let items = vec![item("1", "github.com"), item("2", "gist.github.com"), item("3", "evil.com"), note];
        let r = handle(&gate(), &req(Op::Candidates { page_url: "https://github.com/login".into(), top_url: None }), Some(&items));
        let AutofillResponse::Candidates { items: c } = r else { panic!() };
        assert_eq!(c.iter().map(|c| (c.id.as_str(), c.level)).collect::<Vec<_>>(), vec![("1", Exact), ("2", SameSite)]);

        let ok = handle(&gate(), &req(reveal("1", "https://github.com/login", None, false)), Some(&items));
        assert!(matches!(ok, AutofillResponse::Credential { ref credential } if credential.password == "dummy-pass"));
        assert_eq!(format!("{ok:?}").contains("dummy-pass"), false);

        assert_eq!(handle(&gate(), &req(reveal("2", "https://github.com/", None, false)), Some(&items)), AutofillResponse::NeedsConfirmation);
        assert!(matches!(handle(&gate(), &req(reveal("2", "https://github.com/", None, true)), Some(&items)), AutofillResponse::Credential { .. }));
        // Origin re-check: an id obtained elsewhere is useless on another site.
        assert_eq!(handle(&gate(), &req(reveal("1", "https://evil.com/", None, true)), Some(&items)), AutofillResponse::Denied);
        assert_eq!(handle(&gate(), &req(reveal("1", "http://github.com/", None, true)), Some(&items)), AutofillResponse::Denied);
        assert_eq!(handle(&gate(), &req(reveal("1", "https://github.com/", Some("https://evil.com/"), true)), Some(&items)), AutofillResponse::Denied);
        assert_eq!(handle(&gate(), &req(reveal("n", "https://github.com/", None, true)), Some(&items)), AutofillResponse::Denied);
        assert_eq!(handle(&gate(), &req(reveal("missing", "https://github.com/", None, true)), Some(&items)), AutofillResponse::Denied);
    }

    #[test]
    fn request_json_shape() {
        let r: AutofillRequest = serde_json::from_str(
            r#"{"token":"t","caller_origin":"o","op":"reveal","item_id":"1","page_url":"https://a.com/"}"#,
        ).unwrap();
        assert!(matches!(r.op, Op::Reveal { user_confirmed: false, .. }));
        assert!(!format!("{r:?}").contains("\"t\""));
    }
}
