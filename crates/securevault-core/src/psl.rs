//! Public Suffix List lookup (registrable domain / eTLD+1).
//!
//! The list is vendored at build time (`data/public_suffix_list.dat`) so the
//! app never fetches it at runtime. Both ICANN and PRIVATE sections are used,
//! so `alice.github.io` and `bob.github.io` are different sites.

use std::collections::HashSet;
use std::sync::OnceLock;

const PSL_DAT: &str = include_str!("../data/public_suffix_list.dat");

struct Rules {
    normal: HashSet<String>,
    wildcard: HashSet<String>,
    exception: HashSet<String>,
}

fn to_ascii(rule: &str) -> Option<String> {
    if rule.is_ascii() {
        Some(rule.to_ascii_lowercase())
    } else {
        idna::domain_to_ascii(rule).ok()
    }
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut r = Rules {
            normal: HashSet::new(),
            wildcard: HashSet::new(),
            exception: HashSet::new(),
        };
        for line in PSL_DAT.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let rule = line.split_whitespace().next().unwrap_or("");
            if let Some(rest) = rule.strip_prefix('!') {
                if let Some(a) = to_ascii(rest) {
                    r.exception.insert(a);
                }
            } else if let Some(rest) = rule.strip_prefix("*.") {
                if let Some(a) = to_ascii(rest) {
                    r.wildcard.insert(a);
                }
            } else if let Some(a) = to_ascii(rule) {
                r.normal.insert(a);
            }
        }
        r
    })
}

/// Number of rules loaded (sanity check for tests).
pub fn rule_count() -> usize {
    let r = rules();
    r.normal.len() + r.wildcard.len() + r.exception.len()
}

/// Public suffix of an already-normalized ASCII (punycode) lowercase host.
pub fn public_suffix(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || !host.is_ascii() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let r = rules();
    for i in 0..labels.len() {
        let cand = labels[i..].join(".");
        if r.exception.contains(&cand) {
            return Some(labels[i + 1..].join("."));
        }
        if r.normal.contains(&cand) {
            return Some(cand);
        }
        if i + 1 < labels.len() && r.wildcard.contains(&labels[i + 1..].join(".")) {
            return Some(cand);
        }
    }
    // Default rule "*": the last label.
    labels.last().map(|s| s.to_string())
}

/// Registrable domain (eTLD+1). `None` when the host itself is a public suffix.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.');
    let ps = public_suffix(host)?;
    if host == ps {
        return None;
    }
    let prefix = &host[..host.len() - ps.len() - 1];
    let last = prefix.rsplit('.').next()?;
    Some(format!("{last}.{ps}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_list() {
        assert!(rule_count() > 5000);
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("www.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("login.naver.co.kr").as_deref(), Some("naver.co.kr"));
        assert_eq!(registrable_domain("co.kr"), None);
        assert_eq!(registrable_domain("github.io"), None);
        assert_eq!(registrable_domain("alice.github.io").as_deref(), Some("alice.github.io"));
        assert_eq!(registrable_domain("x.alice.github.io").as_deref(), Some("alice.github.io"));
        assert_eq!(registrable_domain("com"), None);
        // Wildcard + exception rules (*.ck, !www.ck).
        assert_eq!(registrable_domain("foo.bar.ck").as_deref(), Some("foo.bar.ck"));
        assert_eq!(registrable_domain("www.ck").as_deref(), Some("www.ck"));
        // IDN TLD rule stored as unicode in the list.
        assert_eq!(public_suffix("xn--e1afmkfd.xn--p1ai").as_deref(), Some("xn--p1ai"));
    }
}
