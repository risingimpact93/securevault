//! Lexicographic fractional order keys.
//!
//! A key sorts with ordinary string order. `key_between` always returns a key
//! strictly inside the open interval, so a list can be reordered without
//! renumbering the other items. The shape matches the usual base-62 scheme:
//! `key_between(None, None) == "a0"`.

const DIGITS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn idx(c: u8) -> Option<usize> {
    DIGITS.iter().position(|&digit| digit == c)
}

fn digit(index: usize) -> char {
    DIGITS[index] as char
}

fn mid_index() -> usize {
    DIGITS.len() / 2
}

/// A key strictly after `before` and strictly before `after`.
/// `None` is an open end. An inverted or empty bound falls through to a key
/// that still sorts on the requested side of the bound that is present.
pub fn key_between(before: Option<&str>, after: Option<&str>) -> String {
    let before = before.filter(|value| !value.is_empty());
    let after = after.filter(|value| !value.is_empty());
    match (before, after) {
        (None, None) => "a0".to_string(),
        (Some(lo), None) => key_after(lo),
        (None, Some(hi)) => key_before(hi),
        (Some(lo), Some(hi)) if lo < hi => between_keys(lo, hi),
        (Some(lo), Some(_)) => key_after(lo),
    }
}

fn integer_len(head: u8) -> Option<usize> {
    match head {
        b'a'..=b'z' => Some((head - b'a') as usize + 2),
        b'A'..=b'Z' => Some((b'Z' - head) as usize + 2),
        _ => None,
    }
}

fn split_key(key: &str) -> Option<(&str, &str)> {
    let bytes = key.as_bytes();
    let head = *bytes.first()?;
    let len = integer_len(head)?;
    if key.len() < len {
        return None;
    }
    if !bytes[..len].iter().skip(1).all(|c| idx(*c).is_some()) {
        return None;
    }
    if !bytes[len..].iter().all(|c| idx(*c).is_some()) {
        return None;
    }
    Some((&key[..len], &key[len..]))
}

fn key_after(key: &str) -> String {
    let Some((int_part, frac)) = split_key(key) else {
        return format!("{key}{}", digit(mid_index()));
    };
    if frac.is_empty() {
        if let Some(next) = increment_integer(int_part) {
            return next;
        }
    }
    format!("{int_part}{}", midpoint(frac, None))
}

fn key_before(key: &str) -> String {
    let Some((int_part, frac)) = split_key(key) else {
        return fallback_before(key);
    };
    if int_part < key {
        return int_part.to_string();
    }
    decrement_integer(int_part).unwrap_or_else(|| format!("{int_part}{}", midpoint("", Some(frac))))
}

fn between_keys(lo: &str, hi: &str) -> String {
    let (Some((ia, fa)), Some((ib, fb))) = (split_key(lo), split_key(hi)) else {
        return fallback_between(lo, hi);
    };
    if ia == ib {
        return format!("{ia}{}", midpoint(fa, Some(fb)));
    }
    if let Some(next) = increment_integer(ia) {
        if next.as_str() < hi {
            return next;
        }
    }
    format!("{ia}{}", midpoint(fa, None))
}

fn midpoint(a: &str, b: Option<&str>) -> String {
    midpoint_at(a, b, 0)
}

fn midpoint_at(a: &str, b: Option<&str>, depth: usize) -> String {
    if depth > 64 {
        return format!("{a}{}", digit(mid_index()));
    }
    if let Some(b) = b {
        if b.is_empty() || a >= b {
            return append_mid(a);
        }
        let ab = a.as_bytes();
        let bb = b.as_bytes();
        let mut n = 0;
        while n < bb.len() {
            let ac = if n < ab.len() { ab[n] } else { DIGITS[0] };
            if ac != bb[n] || idx(bb[n]).is_none() {
                break;
            }
            n += 1;
        }
        if n > 0 {
            let rest_a = if n < a.len() { &a[n..] } else { "" };
            return format!("{}{}", &b[..n], midpoint_at(rest_a, Some(&b[n..]), depth + 1));
        }
        let digit_a = if a.is_empty() { 0 } else { idx(ab[0]).unwrap_or(0) };
        let Some(digit_b) = bb.first().copied().and_then(idx) else {
            return append_mid(a);
        };
        if digit_b > digit_a + 1 {
            return digit(digit_a + (digit_b - digit_a) / 2).to_string();
        }
        let rest = if a.len() > 1 { &a[1..] } else { "" };
        return format!("{}{}", digit(digit_a), midpoint_at(rest, None, depth + 1));
    }
    append_mid(a)
}

fn append_mid(a: &str) -> String {
    if a.is_empty() {
        return digit(mid_index()).to_string();
    }
    let mut chars: Vec<u8> = a.as_bytes().to_vec();
    let mut index = chars.len() - 1;
    loop {
        let di = idx(chars[index]).unwrap_or(0);
        if di + 1 < DIGITS.len() {
            chars[index] = DIGITS[di + 1];
            chars.truncate(index + 1);
            return String::from_utf8(chars).unwrap_or_else(|_| format!("{a}{}", digit(mid_index())));
        }
        if index == 0 {
            chars.push(DIGITS[mid_index()]);
            return String::from_utf8(chars).unwrap_or_else(|_| format!("{a}{}", digit(mid_index())));
        }
        index -= 1;
    }
}

fn increment_integer(raw: &str) -> Option<String> {
    let head = *raw.as_bytes().first()?;
    let mut digs: Vec<u8> = raw.as_bytes()[1..].to_vec();
    if digs.len() + 1 != integer_len(head)? {
        return None;
    }
    let mut carry = true;
    for slot in digs.iter_mut().rev() {
        if !carry {
            break;
        }
        let index = idx(*slot)?;
        if index + 1 == DIGITS.len() {
            *slot = DIGITS[0];
        } else {
            *slot = DIGITS[index + 1];
            carry = false;
        }
    }
    if !carry {
        let mut out = vec![head];
        out.extend(digs);
        return Some(String::from_utf8(out).ok()?);
    }
    match head {
        b'Z' => Some("a0".to_string()),
        b'z' => None,
        b'a'..=b'y' => {
            let mut out = vec![head + 1];
            out.extend(std::iter::repeat(DIGITS[0]).take(digs.len() + 1));
            Some(String::from_utf8(out).ok()?)
        }
        b'A'..=b'Y' => {
            let mut out = vec![head + 1];
            if digs.len() > 1 {
                out.extend_from_slice(&digs[1..]);
            }
            Some(String::from_utf8(out).ok()?)
        }
        _ => None,
    }
}

fn decrement_integer(raw: &str) -> Option<String> {
    let head = *raw.as_bytes().first()?;
    let mut digs: Vec<u8> = raw.as_bytes()[1..].to_vec();
    if digs.len() + 1 != integer_len(head)? {
        return None;
    }
    let mut borrow = true;
    for slot in digs.iter_mut().rev() {
        if !borrow {
            break;
        }
        let index = idx(*slot)?;
        if index == 0 {
            *slot = DIGITS[DIGITS.len() - 1];
        } else {
            *slot = DIGITS[index - 1];
            borrow = false;
        }
    }
    if !borrow {
        let mut out = vec![head];
        out.extend(digs);
        return Some(String::from_utf8(out).ok()?);
    }
    match head {
        b'a' => Some(format!("Z{}", digit(DIGITS.len() - 1))),
        b'A' => None,
        b'b'..=b'z' => {
            let mut out = vec![head - 1];
            if digs.len() > 1 {
                out.extend_from_slice(&digs[1..]);
            }
            Some(String::from_utf8(out).ok()?)
        }
        b'B'..=b'Z' => {
            let mut out = vec![head - 1, DIGITS[DIGITS.len() - 1]];
            out.extend(digs);
            Some(String::from_utf8(out).ok()?)
        }
        _ => None,
    }
}

fn fallback_before(key: &str) -> String {
    let mut bytes = key.as_bytes().to_vec();
    for index in (0..bytes.len()).rev() {
        if bytes[index] > b' ' {
            bytes[index] -= 1;
            bytes.truncate(index + 1);
            bytes.push(b'V');
            return String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    format!(" {key}")
}

fn fallback_between(lo: &str, hi: &str) -> String {
    let candidate = format!("{lo}{}", digit(mid_index()));
    if candidate.as_str() > lo && candidate.as_str() < hi {
        return candidate;
    }
    fallback_before(hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_positions() {
        assert_eq!(key_between(None, None), "a0");
        assert_eq!(key_between(Some("a0"), None), "a1");
        assert_eq!(key_between(Some("a1"), None), "a2");
        assert_eq!(key_between(None, Some("a0")), "Zz");
        assert_eq!(key_between(Some("a0"), Some("a1")), "a0V");
        let between = key_between(Some("Zz"), Some("a0"));
        assert!(between.as_str() > "Zz", "{between}");
        assert!(between.as_str() < "a0", "{between}");
    }

    #[test]
    fn repeated_inserts_stay_strictly_sorted() {
        let mut keys = vec![key_between(None, None)];
        for _ in 0..24 {
            let end = key_between(Some(keys.last().unwrap()), None);
            assert!(end.as_str() > keys.last().unwrap().as_str());
            keys.push(end);
            let start = key_between(None, Some(&keys[0]));
            assert!(start.as_str() < keys[0].as_str(), "{start} < {}", keys[0]);
            keys.insert(0, start);
            let at = keys.len() / 2;
            let mid = key_between(Some(&keys[at - 1]), Some(&keys[at]));
            assert!(mid.as_str() > keys[at - 1].as_str(), "{mid} > {}", keys[at - 1]);
            assert!(mid.as_str() < keys[at].as_str(), "{mid} < {}", keys[at]);
            keys.insert(at, mid);
        }
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        let mut unique = sorted.clone();
        unique.dedup();
        assert_eq!(unique.len(), sorted.len());
    }
}
