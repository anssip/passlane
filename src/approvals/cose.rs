//! Minimal CBOR/COSE parsing for the Phase 0 enrollment ceremony
//! (SPEC §6, passlane#51).
//!
//! The enrollment blob the approval page pastes back carries the passkey's
//! credential public key as a CBOR-encoded COSE_Key (RFC 9052) — the exact
//! bytes WebAuthn put into `attestedCredentialData`. This module decodes it
//! into the 65-byte uncompressed SEC1 point the protocol pins as
//! `sig_pub`.
//!
//! The decoder is deliberately minimal: definite lengths only, strict
//! trailing-garbage and duplicate-label rejection, and exactly the value
//! set a P-256 ES256 COSE_Key must carry. Unknown COSE members are ignored
//! (COSE permits extensions); anything that misstates the key type,
//! algorithm, curve, or coordinates is rejected rather than guessed at — a
//! malformed key must never be pinned.

use passlane_approval::error::{Error, Result};

/// A parsed COSE EC2 key. Only the ES256 (P-256) profile is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseEc2Key {
    /// The `crv` coordinate (`-1`): only `1` (P-256) is accepted.
    pub crv: u8,
    /// The `x` coordinate (`-2`), exactly 32 bytes.
    pub x: Vec<u8>,
    /// The `y` coordinate (`-3`), exactly 32 bytes.
    pub y: Vec<u8>,
}

impl CoseEc2Key {
    /// The 65-byte uncompressed SEC1 point `0x04 ‖ x ‖ y` the protocol
    /// pins as the passkey verifying key.
    pub fn to_sec1(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x);
        out[33..65].copy_from_slice(&self.y);
        out
    }
}

/// COSE key labels this profile interprets (RFC 9052 §7).
const KTY: i64 = 1;
const ALG: i64 = 3;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;
/// `kty: 2` — EC2.
const KTY_EC2: i64 = 2;
/// `alg: -7` — ES256 (ECDSA w/ SHA-256), the only WebAuthn algorithm the
/// protocol's signature verification implements.
const ALG_ES256: i64 = -7;
/// `crv: 1` — P-256.
const CRV_P256: i64 = 1;

/// Parse a CBOR-encoded COSE_Key into the ES256/P-256 profile.
///
/// Rejects anything the pinned key must not be: other key types or
/// algorithms, other curves, missing or wrong-length coordinates, duplicate
/// labels, non-canonical encodings, and trailing bytes. Unknown labels are
/// ignored (COSE allows extension members; they cannot affect the pinned
/// key material).
pub fn parse_cose_ec2_p256(bytes: &[u8]) -> Result<CoseEc2Key> {
    let (value, consumed) = cbor_item(bytes)?;
    if consumed != bytes.len() {
        return Err(Error::Malformed(format!(
            "COSE key has {} trailing bytes",
            bytes.len() - consumed
        )));
    }
    let CborValue::Map(entries) = value else {
        return Err(Error::Malformed("COSE key is not a CBOR map".into()));
    };

    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    let mut seen: Vec<i64> = Vec::new();
    for (k, v) in &entries {
        // Only integer labels are interpreted; COSE profiles for key
        // material define no text-labelled members, and an unrecognized
        // one cannot change the key bytes being pinned.
        let CborValue::Int(label) = k else {
            continue;
        };
        if seen.contains(label) {
            return Err(Error::Malformed(format!(
                "COSE key label {label} appears twice"
            )));
        }
        seen.push(*label);
        match *label {
            KTY => kty = Some(expect_int(v, "kty")?),
            ALG => alg = Some(expect_int(v, "alg")?),
            CRV => crv = Some(expect_int(v, "crv")?),
            X => x = Some(expect_bytes(v, "x")?),
            Y => y = Some(expect_bytes(v, "y")?),
            _ => {}
        }
    }
    if kty != Some(KTY_EC2) {
        return Err(Error::Malformed("COSE key is not kty=EC2 (2)".into()));
    }
    if alg != Some(ALG_ES256) {
        return Err(Error::Malformed(
            "COSE key algorithm is not ES256 (-7); the protocol verifies only ES256 passkeys".into(),
        ));
    }
    if crv != Some(CRV_P256) {
        return Err(Error::Malformed("COSE key curve is not P-256".into()));
    }
    let x = x.ok_or_else(|| Error::Malformed("COSE key is missing x (-2)".into()))?;
    let y = y.ok_or_else(|| Error::Malformed("COSE key is missing y (-3)".into()))?;
    if x.len() != 32 {
        return Err(Error::Malformed(format!(
            "COSE x coordinate must be 32 bytes, got {}",
            x.len()
        )));
    }
    if y.len() != 32 {
        return Err(Error::Malformed(format!(
            "COSE y coordinate must be 32 bytes, got {}",
            y.len()
        )));
    }
    Ok(CoseEc2Key {
        crv: CRV_P256 as u8,
        x,
        y,
    })
}

fn expect_int(v: &CborValue, name: &str) -> Result<i64> {
    match v {
        CborValue::Int(i) => Ok(*i),
        other => Err(Error::Malformed(format!(
            "COSE {name} must be an integer, got {other:?}"
        ))),
    }
}

fn expect_bytes(v: &CborValue, name: &str) -> Result<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Ok(b.clone()),
        other => Err(Error::Malformed(format!(
            "COSE {name} must be a byte string, got {other:?}"
        ))),
    }
}

/// The subset of CBOR the COSE keys may use. No floats, no indefinite
/// lengths, no tags — a WebAuthn credential public key never needs them.
#[derive(Debug, Clone, PartialEq)]
enum CborValue {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
}

/// Decode one CBOR item, returning it and the number of bytes consumed.
fn cbor_item(bytes: &[u8]) -> Result<(CborValue, usize)> {
    let (&major, rest) = bytes.split_first().ok_or_else(|| malformed("empty CBOR input"))?;
    let mt = major >> 5;
    let info = major & 0x1f;
    let (arg, rest) = read_argument(info, rest)?;
    let head_len = bytes.len() - rest.len();
    match mt {
        0 => Ok((CborValue::Int(arg as i64), head_len)),
        1 => {
            // Negative integers encode -1 - n.
            if arg > i64::MAX as u64 {
                return Err(malformed("negative integer out of range"));
            }
            Ok((CborValue::Int(-1 - arg as i64), head_len))
        }
        2 => {
            let (b, rest) = take(rest, arg as usize)?;
            Ok((CborValue::Bytes(b.to_vec()), bytes.len() - rest.len()))
        }
        3 => {
            let (b, rest) = take(rest, arg as usize)?;
            let text = String::from_utf8(b.to_vec())
                .map_err(|_| malformed("CBOR text string is not UTF-8"))?;
            Ok((CborValue::Text(text), bytes.len() - rest.len()))
        }
        4 => {
            let mut items = Vec::new();
            let mut consumed = head_len;
            for _ in 0..arg {
                let (item, n) = cbor_item(&bytes[consumed..])?;
                items.push(item);
                consumed += n;
            }
            Ok((CborValue::Array(items), consumed))
        }
        5 => {
            let mut entries = Vec::new();
            let mut consumed = head_len;
            for _ in 0..arg {
                let (k, n) = cbor_item(&bytes[consumed..])?;
                consumed += n;
                let (v, n) = cbor_item(&bytes[consumed..])?;
                consumed += n;
                entries.push((k, v));
            }
            Ok((CborValue::Map(entries), consumed))
        }
        other => Err(malformed(&format!(
            "unsupported CBOR major type {other}"
        ))),
    }
}

/// Read a CBOR argument: immediate value or definite-length extension.
fn read_argument(info: u8, rest: &[u8]) -> Result<(u64, &[u8])> {
    match info {
        0..=23 => Ok((info as u64, rest)),
        24 => {
            let (b, rest) = take(rest, 1)?;
            Ok((b[0] as u64, rest))
        }
        25 => {
            let (b, rest) = take(rest, 2)?;
            Ok((u16::from_be_bytes([b[0], b[1]]) as u64, rest))
        }
        26 => {
            let (b, rest) = take(rest, 4)?;
            Ok((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, rest))
        }
        27 => {
            let (b, rest) = take(rest, 8)?;
            Ok((
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                rest,
            ))
        }
        31 => Err(malformed("indefinite CBOR lengths are not accepted")),
        _ => Err(malformed("reserved CBOR additional information")),
    }
}

fn take(bytes: &[u8], n: usize) -> Result<(&[u8], &[u8])> {
    if bytes.len() < n {
        return Err(malformed("CBOR input truncated"));
    }
    Ok(bytes.split_at(n))
}

fn malformed(msg: &str) -> Error {
    Error::Malformed(format!("COSE/CBOR: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// {1:2, 3:-7, -1:1, -2:bstr(32) 0x11.., -3:bstr(32) 0x22..} — the
    /// exact shape Chrome and Safari put into attestedCredentialData.
    fn canonical_cose_key() -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0xa5); // map(5)
        out.extend_from_slice(&[0x01, 0x02]); // 1: 2 (EC2)
        out.extend_from_slice(&[0x03, 0x26]); // 3: -7 (ES256)
        out.extend_from_slice(&[0x20, 0x01]); // -1: 1 (P-256)
        out.extend_from_slice(&[0x21, 0x58, 0x20]); // -2: bstr(32)
        out.extend_from_slice(&[0x11; 32]);
        out.extend_from_slice(&[0x22, 0x58, 0x20]); // -3: bstr(32)
        out.extend_from_slice(&[0x22; 32]);
        out
    }

    #[test]
    fn parses_canonical_es256_key() {
        let key = parse_cose_ec2_p256(&canonical_cose_key()).unwrap();
        assert_eq!(key.crv, 1);
        assert_eq!(key.x, vec![0x11; 32]);
        assert_eq!(key.y, vec![0x22; 32]);
        let sec1 = key.to_sec1();
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &[0x11; 32]);
        assert_eq!(&sec1[33..], &[0x22; 32]);
    }

    #[test]
    fn derived_point_must_satisfy_key_validation() {
        // The derived SEC1 point feeds the protocol's own key validation:
        // a real on-curve point passes, the fixed test bytes do not.
        let key = parse_cose_ec2_p256(&canonical_cose_key()).unwrap();
        assert!(passlane_approval::keys::PublicKey::from_bytes(&key.to_sec1()).is_err());

        // A genuine P-256 point (from the protocol crate's test identity
        // keys) round-trips: COSE -> SEC1 -> PublicKey.
        let mut rng = rand::rngs::OsRng;
        let id = passlane_approval::keys::IdentityKeys::generate(&mut rng).unwrap();
        let pub_bytes = id.verifying_key().to_sec1_bytes();
        let mut cose = Vec::new();
        cose.push(0xa5);
        cose.extend_from_slice(&[0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
        cose.extend_from_slice(&[0x21, 0x58, 0x20]);
        cose.extend_from_slice(&pub_bytes[1..33]);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&pub_bytes[33..65]);
        let key = parse_cose_ec2_p256(&cose).unwrap();
        assert_eq!(&key.to_sec1()[..], &pub_bytes[..]);
        assert!(passlane_approval::keys::PublicKey::from_bytes(&key.to_sec1()).is_ok());
    }

    #[test]
    fn member_order_does_not_matter() {
        // CBOR maps are unordered; accept a shuffled key.
        let mut out = Vec::new();
        out.push(0xa5);
        out.extend_from_slice(&[0x20, 0x01]); // -1: 1
        out.extend_from_slice(&[0x03, 0x26]); // 3: -7
        out.extend_from_slice(&[0x22, 0x58, 0x20]); // -3 first
        out.extend_from_slice(&[0x33; 32]);
        out.extend_from_slice(&[0x01, 0x02]); // 1: 2
        out.extend_from_slice(&[0x21, 0x58, 0x20]); // -2
        out.extend_from_slice(&[0x44; 32]);
        let key = parse_cose_ec2_p256(&out).unwrap();
        assert_eq!(key.x, vec![0x44; 32]);
        assert_eq!(key.y, vec![0x33; 32]);
    }

    #[test]
    fn unknown_members_are_ignored() {
        // COSE permits extension members (e.g. 2: "kid"); they must not
        // block enrollment, and they cannot alter the pinned bytes.
        let mut out = canonical_cose_key();
        out[0] = 0xa6; // map(6)
        out.extend_from_slice(&[0x02, 0x63, b'k', b'i', b'd']); // 2: "kid"
        assert!(parse_cose_ec2_p256(&out).is_ok());
    }

    #[test]
    fn rejects_wrong_kty_alg_crv() {
        let mut k = canonical_cose_key();
        k[2] = 1; // kty: OKP
        assert!(parse_cose_ec2_p256(&k).is_err());

        let mut k = canonical_cose_key();
        k[4] = 0x25; // alg -8 (Ed25519)
        assert!(parse_cose_ec2_p256(&k).is_err());

        let mut k = canonical_cose_key();
        k[6] = 0x02; // crv: secp384r1
        assert!(parse_cose_ec2_p256(&k).is_err());
    }

    #[test]
    fn rejects_wrong_types_for_known_labels() {
        let mut k = canonical_cose_key();
        k[1] = 0x22; // 1: bstr (kty must be int)
        assert!(parse_cose_ec2_p256(&k).is_err());
    }

    #[test]
    fn rejects_missing_coordinates() {
        let mut k = canonical_cose_key();
        k[0] = 0xa3; // map(3) — only kty/alg/-1 remain
        k.truncate(7);
        assert!(parse_cose_ec2_p256(&k).is_err());
    }

    #[test]
    fn rejects_wrong_lengths_truncation_and_empty() {
        let mut short = canonical_cose_key();
        short.truncate(short.len() - 1);
        assert!(parse_cose_ec2_p256(&short).is_err());

        // x shorter than 32
        let mut k = Vec::new();
        k.push(0xa3);
        k.extend_from_slice(&[0x01, 0x02]);
        k.extend_from_slice(&[0x21, 0x58, 0x10]);
        k.extend_from_slice(&[0u8; 16]);
        assert!(parse_cose_ec2_p256(&k).is_err());

        assert!(parse_cose_ec2_p256(&[]).is_err());
    }

    #[test]
    fn rejects_trailing_bytes_and_duplicates() {
        let mut k = canonical_cose_key();
        k.push(0x00);
        assert!(parse_cose_ec2_p256(&k).is_err());

        // A duplicated kty label must not smuggle a second value.
        let mut k = canonical_cose_key();
        k[0] = 0xa6;
        k.extend_from_slice(&[0x01, 0x01]); // 1: 1 (again, different value)
        assert!(parse_cose_ec2_p256(&k).is_err());

        // Non-map input.
        assert!(parse_cose_ec2_p256(&[0x01]).is_err());
    }

    #[test]
    fn rejects_indefinite_lengths() {
        let mut k = Vec::new();
        k.push(0xbf); // map, indefinite length
        k.extend_from_slice(&[0x01, 0x02]);
        k.push(0xff); // break
        assert!(parse_cose_ec2_p256(&k).is_err());
    }
}
