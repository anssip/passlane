//! Minimal hex and unpadded base64url codecs.
//!
//! Kept dependency-free on purpose: the crate's wire encodings are part of
//! the protocol surface, and a self-contained implementation keeps the
//! encoding rules stable regardless of crate upgrades.

use crate::error::{Error, Result};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Lower-case hex decoding; accepts only even-length, lower-case input.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return Err(Error::Encoding("hex string has odd length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Error::Encoding(format!(
            "invalid hex character '{}'",
            char::from(c)
        ))),
    }
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url encoding (RFC 4648 §5, without `=` padding).
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 0x3f] as char);
        out.push(B64URL[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 0x3f] as char);
        }
    }
    out
}

/// Unpadded base64url decoding; rejects padding, whitespace and `+/`.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 4 == 1 {
        return Err(Error::Encoding(
            "base64url string has invalid length".into(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => {
                return Err(Error::Encoding(format!(
                    "invalid base64url character '{}'",
                    char::from(c)
                )));
            }
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        for len in [0usize, 1, 2, 20, 32] {
            let bytes: Vec<u8> = (0..len as u8).collect();
            assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn hex_rejects_uppercase_and_odd() {
        assert!(hex_decode("AB").is_err());
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("0g").is_err());
    }

    #[test]
    fn base64url_vectors() {
        // RFC 4648 §5 test vectors, padding stripped.
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
        for (plain, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                base64url_decode(encoded).unwrap(),
                plain,
                "decode {encoded}"
            );
        }
    }

    #[test]
    fn base64url_rejects_standard_alphabet_and_padding() {
        assert!(base64url_decode("Zm9v+").is_err());
        assert!(base64url_decode("Zg==").is_err());
        assert!(base64url_decode("Zg=").is_err());
        assert!(base64url_decode("A").is_err());
    }

    #[test]
    fn base64url_roundtrip_random_lengths() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            let enc = base64url_encode(&bytes);
            assert_eq!(base64url_decode(&enc).unwrap(), bytes, "len {len}");
        }
    }
}
