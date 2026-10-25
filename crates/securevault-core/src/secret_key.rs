//! 1Password-style Secret Key (2SKD).
//!
//! The Secret Key is 160 bits from the OS CSPRNG. It is never written to the
//! vault file. The public header stores only an enabled flag and an 8-byte
//! fingerprint.

use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::vault::{VaultError, VaultKey, KEY_LEN};

pub const SECRET_KEY_LEN: usize = 20;
pub const SECRET_KEY_FINGERPRINT_LEN: usize = 8;
pub const SECRET_KEY_PREFIX: &str = "SV1";
pub const HKDF_INFO: &[u8] = b"securevault-2skd-v1";
const FP_DOMAIN: &[u8] = b"securevault-sk-fp-v1";
const CS_DOMAIN: &[u8] = b"securevault-sk-cs-v1";
const CHECKSUM_CHARS: usize = 6;
const PAYLOAD_CHARS: usize = 32 + CHECKSUM_CHARS;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; SECRET_KEY_LEN],
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for SecretKey {}

impl SecretKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.bytes
    }

    pub fn fingerprint(&self) -> [u8; SECRET_KEY_FINGERPRINT_LEN] {
        fingerprint_of(&self.bytes)
    }

    pub fn fingerprint_b64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        B64.encode(self.fingerprint())
    }

    /// Keychain / file-store account. Hex of the public fingerprint.
    pub fn vault_id(&self) -> String {
        hex(&self.fingerprint())
    }

    pub fn format_display(&self) -> String {
        let mut payload = BASE32_NOPAD.encode(&self.bytes);
        payload.push_str(&checksum_group(&self.bytes));
        grouped(SECRET_KEY_PREFIX, &payload)
    }

    pub fn parse(input: &str) -> Result<Self, VaultError> {
        let compact = normalize(input);
        if compact.is_empty() {
            return Err(VaultError::InvalidSecretKey);
        }
        if compact.len() < SECRET_KEY_PREFIX.len()
            || !compact.starts_with(SECRET_KEY_PREFIX)
        {
            return Err(VaultError::InvalidSecretKeyPrefix);
        }
        let rest = &compact[SECRET_KEY_PREFIX.len()..];
        if rest.len() != PAYLOAD_CHARS {
            return Err(VaultError::InvalidSecretKey);
        }
        if !rest.chars().all(is_base32_char) {
            return Err(VaultError::InvalidSecretKey);
        }
        let (data_chars, checksum_chars) = rest.split_at(32);
        let decoded = BASE32_NOPAD
            .decode(data_chars.as_bytes())
            .map_err(|_| VaultError::InvalidSecretKey)?;
        if decoded.len() != SECRET_KEY_LEN {
            return Err(VaultError::InvalidSecretKey);
        }
        let mut bytes = [0u8; SECRET_KEY_LEN];
        bytes.copy_from_slice(&decoded);
        if checksum_group(&bytes) != checksum_chars {
            bytes.zeroize();
            return Err(VaultError::InvalidSecretKeyChecksum);
        }
        Ok(Self { bytes })
    }
}

pub fn fingerprint_of(bytes: &[u8]) -> [u8; SECRET_KEY_FINGERPRINT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(FP_DOMAIN);
    hasher.update(bytes);
    let hash = hasher.finalize();
    let mut out = [0u8; SECRET_KEY_FINGERPRINT_LEN];
    out.copy_from_slice(&hash[..SECRET_KEY_FINGERPRINT_LEN]);
    out
}

pub fn fingerprint_b64_of(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    B64.encode(fingerprint_of(bytes))
}

pub fn vault_id_from_fingerprint_b64(fingerprint_b64: &str) -> Result<String, VaultError> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let bytes = B64.decode(fingerprint_b64)?;
    if bytes.len() != SECRET_KEY_FINGERPRINT_LEN {
        return Err(VaultError::Corrupt);
    }
    Ok(hex(&bytes))
}

pub fn decode_fingerprint_b64(fingerprint_b64: &str) -> Result<[u8; SECRET_KEY_FINGERPRINT_LEN], VaultError> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let bytes = B64.decode(fingerprint_b64)?;
    if bytes.len() != SECRET_KEY_FINGERPRINT_LEN {
        return Err(VaultError::Corrupt);
    }
    let mut out = [0u8; SECRET_KEY_FINGERPRINT_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// HKDF-SHA256(ikm = Argon2id output, salt = Secret Key bytes, info = "securevault-2skd-v1").
pub fn apply_2skd(argon_key: &VaultKey, secret_key: &SecretKey) -> Result<VaultKey, VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(secret_key.as_bytes()), argon_key.as_bytes());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| VaultError::Crypto)?;
    VaultKey::try_from_slice(&okm)
}

pub fn fingerprints_equal(left: &str, right: &str) -> bool {
    left == right
}

fn checksum_group(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CS_DOMAIN);
    hasher.update(bytes);
    let hash = hasher.finalize();
    let bits = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) >> 2;
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut chars = String::with_capacity(CHECKSUM_CHARS);
    for i in (0..CHECKSUM_CHARS).rev() {
        let idx = ((bits >> (5 * i)) & 0x1f) as usize;
        chars.push(ALPH[idx] as char);
    }
    chars
}

fn grouped(prefix: &str, payload: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + payload.len() + payload.len() / 6 + 1);
    out.push_str(prefix);
    for chunk in payload.as_bytes().chunks(6) {
        out.push('-');
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    out
}

fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

fn is_base32_char(ch: char) -> bool {
    matches!(ch, 'A'..='Z' | '2'..='7')
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{derive_key, default_kdf_params, random_salt};
    use secrecy::SecretString;

    #[test]
    fn format_roundtrip_and_grouping() {
        let sk = SecretKey::generate();
        let displayed = sk.format_display();
        assert!(displayed.starts_with("SV1-"));
        assert!(displayed.chars().filter(|ch| *ch == '-').count() >= 6);
        let parsed = SecretKey::parse(&displayed).unwrap();
        assert_eq!(parsed.as_bytes(), sk.as_bytes());
        assert_eq!(parsed.fingerprint(), sk.fingerprint());
    }

    #[test]
    fn parse_ignores_dashes_whitespace_and_case() {
        let sk = SecretKey::from_bytes([7u8; SECRET_KEY_LEN]);
        let displayed = sk.format_display();
        let lower = displayed.to_ascii_lowercase().replace('-', " - ");
        let parsed = SecretKey::parse(&lower).unwrap();
        assert_eq!(parsed.as_bytes(), sk.as_bytes());
        let compact = displayed.replace('-', "");
        assert_eq!(SecretKey::parse(&compact).unwrap().as_bytes(), sk.as_bytes());
    }

    #[test]
    fn parse_rejects_bad_prefix_charset_length_checksum() {
        assert!(matches!(
            SecretKey::parse("").unwrap_err(),
            VaultError::InvalidSecretKey
        ));
        assert!(matches!(
            SecretKey::parse("AB1-AAAAAA-AAAAAA-AAAAAA-AAAAAA-AAAAAA-AAAAAA-AA").unwrap_err(),
            VaultError::InvalidSecretKeyPrefix
        ));
        assert!(matches!(
            SecretKey::parse("SV1-SHORT").unwrap_err(),
            VaultError::InvalidSecretKey
        ));
        let sk = SecretKey::generate();
        let mut displayed = sk.format_display();
        // Flip a payload character that is not the checksum group.
        let bytes: Vec<char> = displayed.chars().collect();
        let mut flipped = String::new();
        let mut changed = false;
        for (i, ch) in bytes.iter().enumerate() {
            if !changed && i > 4 && *ch != '-' && *ch != 'A' {
                flipped.push('A');
                changed = true;
            } else {
                flipped.push(*ch);
            }
        }
        assert!(changed);
        let err = SecretKey::parse(&flipped).unwrap_err();
        assert!(matches!(
            err,
            VaultError::InvalidSecretKeyChecksum | VaultError::InvalidSecretKey
        ));
        displayed.push('A');
        assert!(matches!(
            SecretKey::parse(&displayed).unwrap_err(),
            VaultError::InvalidSecretKey
        ));
        assert!(matches!(
            SecretKey::parse("SV1-!!!!!!-!!!!!!-!!!!!!-!!!!!!-!!!!!!-!!!!!!-!!").unwrap_err(),
            VaultError::InvalidSecretKey
        ));
    }

    #[test]
    fn checksum_detects_single_group_corruption() {
        let sk = SecretKey::generate();
        let displayed = sk.format_display();
        let parts: Vec<&str> = displayed.split('-').collect();
        assert!(parts.len() >= 3);
        let mut corrupt = parts.clone();
        let last = corrupt.len() - 1;
        // Corrupt the checksum group.
        corrupt[last] = if corrupt[last].starts_with('A') { "BBBBBB" } else { "AAAAAA" };
        // Last group may be 2 chars; keep same length.
        let last_len = parts[last].len();
        let replacement: String = "A".repeat(last_len);
        if replacement == parts[last] {
            corrupt[last] = "B".repeat(last_len).as_str();
            let joined = {
                let mut rebuilt = Vec::new();
                for (i, part) in parts.iter().enumerate() {
                    if i == last {
                        rebuilt.push("B".repeat(last_len));
                    } else {
                        rebuilt.push((*part).to_string());
                    }
                }
                rebuilt.join("-")
            };
            assert!(matches!(
                SecretKey::parse(&joined).unwrap_err(),
                VaultError::InvalidSecretKeyChecksum
            ));
        } else {
            let _ = corrupt;
            let joined = {
                let mut rebuilt = Vec::new();
                for (i, part) in parts.iter().enumerate() {
                    if i == last {
                        rebuilt.push("A".repeat(last_len));
                    } else {
                        rebuilt.push((*part).to_string());
                    }
                }
                rebuilt.join("-")
            };
            if joined == displayed {
                // checksum already all-A; use B
                let joined = {
                    let mut rebuilt = Vec::new();
                    for (i, part) in parts.iter().enumerate() {
                        if i == last {
                            rebuilt.push("B".repeat(last_len));
                        } else {
                            rebuilt.push((*part).to_string());
                        }
                    }
                    rebuilt.join("-")
                };
                assert!(matches!(
                    SecretKey::parse(&joined).unwrap_err(),
                    VaultError::InvalidSecretKeyChecksum
                ));
            } else {
                assert!(matches!(
                    SecretKey::parse(&joined).unwrap_err(),
                    VaultError::InvalidSecretKeyChecksum
                ));
            }
        }
    }

    #[test]
    fn fingerprint_is_8_bytes_and_domain_separated() {
        let sk = SecretKey::from_bytes([9u8; SECRET_KEY_LEN]);
        let fp = sk.fingerprint();
        assert_eq!(fp.len(), 8);
        let mut plain = Sha256::new();
        plain.update(sk.as_bytes());
        let plain = plain.finalize();
        assert_ne!(&fp[..], &plain[..8]);
        assert_eq!(sk.vault_id().len(), 16);
        assert!(sk.vault_id().chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn hkdf_changes_the_argon_key_and_is_deterministic() {
        let password = SecretString::new("hkdf-master".into());
        let params = default_kdf_params();
        let salt = random_salt();
        let argon = derive_key(&password, &salt, &params).unwrap();
        let sk = SecretKey::from_bytes([3u8; SECRET_KEY_LEN]);
        let a = apply_2skd(&argon, &sk).unwrap();
        let b = apply_2skd(&argon, &sk).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), argon.as_bytes());
        let other = SecretKey::from_bytes([4u8; SECRET_KEY_LEN]);
        let c = apply_2skd(&argon, &other).unwrap();
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn display_never_embeds_raw_bytes_as_utf8() {
        let sk = SecretKey::from_bytes([0xff; SECRET_KEY_LEN]);
        let displayed = sk.format_display();
        assert!(displayed.starts_with("SV1-"));
        assert!(!displayed.as_bytes().contains(&0xff));
    }
}
