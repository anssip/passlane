//! Reading a vault's KDF seed without opening the vault.
//!
//! The seed is the challenge a phone-held key answers (SPEC §7). It sits
//! in the KDBX4 outer header in cleartext, so the CLI can ask for an
//! unlock while the vault is locked — no factor is needed to *mint* the
//! request. keepass-ng passes these same bytes to the challenge-response
//! key when it opens the file, and a test pins the two together.

use passlane_core::vault::entities::Error;

/// KDBX files start with the signature 0x9AA2D903, stored little-endian
/// (KeePass file format spec, "File Signature"). Spelled as the spec's
/// word so the byte order is derived, not retyped.
const KDBX_SIGNATURE: u32 = 0x9A_A2_D9_03;
/// The signature of the KDBX 3 and 4 formats (KDB / KDBX 2 have others).
const KDBX_LATEST_SIGNATURE: u32 = 0xB5_4B_FB_67;
/// Outer-header field holding the key derivation parameters.
const HEADER_KDF_PARAMS: u8 = 11;
/// Outer-header field marking the end of the header.
const HEADER_END: u8 = 0;
/// The version word of a variant dictionary.
const VARIANT_DICTIONARY_VERSION: u16 = 0x0100;
/// Variant-dictionary entry types (see keepass-ng's variant_dictionary).
const BYTES_TYPE_ID: u8 = 0x42;
const VARIANT_DICTIONARY_END: u8 = 0x00;
/// The seed of every KDF KDBX4 defines (AES-KDF and Argon2) is 32 bytes.
const SEED_LEN: usize = 32;

/// A minimal reader over a byte slice that fails instead of panicking on
/// truncated input: a vault header is untrusted until keepass-ng has
/// verified it, and this runs before that.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or_else(truncated)?;
        let out = self.bytes.get(self.pos..end).ok_or_else(truncated)?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

fn truncated() -> Error {
    Error::new("the vault file is truncated (it ends inside the header)")
}

/// The 32-byte KDF seed of the KDBX4 vault at `path`, read from the outer
/// header without decrypting anything.
pub(crate) fn read_kdf_seed(path: &str) -> Result<[u8; 32], Error> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::new(&format!(
            "Could not read vault file '{path}' to find its challenge: {e}"
        ))
    })?;
    parse_kdf_seed(&bytes).map_err(|e| Error::new(&format!("{}: {}", path, e.message)))
}

/// [`read_kdf_seed`] over bytes already in memory.
pub(crate) fn parse_kdf_seed(bytes: &[u8]) -> Result<[u8; 32], Error> {
    let mut r = Reader { bytes, pos: 0 };

    if r.take(4)? != KDBX_SIGNATURE.to_le_bytes() {
        return Err(Error::new("not a KeePass database (bad file signature)"));
    }
    let signature = r.u32()?;
    let minor = r.u16()?;
    let major = r.u16()?;
    if signature != KDBX_LATEST_SIGNATURE || major != 4 {
        return Err(Error::new(&format!(
            "a phone-held key needs a KDBX 4 vault; this file is KDBX {major}.{minor} \
             (re-save it with passlane or another KeePass client to upgrade)"
        )));
    }

    // Header fields: (type: u8, length: u32 LE, value). The seed is in the
    // key-derivation parameters, a variant dictionary.
    let mut kdf_params = None;
    loop {
        let field_type = r.u8()?;
        let len = r.u32()? as usize;
        let value = r.take(len)?;
        match field_type {
            HEADER_END => break,
            HEADER_KDF_PARAMS => kdf_params = Some(value),
            _ => {}
        }
    }
    let params = kdf_params
        .ok_or_else(|| Error::new("the vault header has no key derivation parameters"))?;
    seed_from_variant_dictionary(params)
}

/// The `S` ("seed"/"salt") byte array of a KDBX4 key-derivation variant
/// dictionary, parsed the way keepass-ng parses it: a version word, then
/// (type, name length u32, name, value length u32, value) entries, ended
/// by a zero type.
fn seed_from_variant_dictionary(buffer: &[u8]) -> Result<[u8; 32], Error> {
    let mut r = Reader {
        bytes: buffer,
        pos: 0,
    };
    if r.u16()? != VARIANT_DICTIONARY_VERSION {
        return Err(Error::new(
            "the vault header's key derivation parameters have an unsupported version",
        ));
    }
    let mut seed = None;
    while r.pos + 9 < buffer.len() {
        let value_type = r.u8()?;
        let name_len = r.u32()? as usize;
        let name = r.take(name_len)?;
        let value_len = r.u32()? as usize;
        let value = r.take(value_len)?;
        if value_type == BYTES_TYPE_ID && name == b"S" {
            seed = Some(value);
        }
    }
    if r.u8()? != VARIANT_DICTIONARY_END {
        return Err(Error::new(
            "the vault header's key derivation parameters are not terminated",
        ));
    }
    let seed = seed
        .ok_or_else(|| Error::new("the vault header's key derivation parameters carry no seed"))?;
    let seed: [u8; SEED_LEN] = seed.try_into().map_err(|_| {
        Error::new(&format!(
            "the vault's key derivation seed is {} bytes, not {SEED_LEN}",
            seed.len()
        ))
    })?;
    Ok(seed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use keepass_ng::ChallengeResponseKey;
    use passlane_core::vault::keepass_vault::KeepassVault;
    use passlane_core::vault::vault_trait::PasswordVault;
    use std::sync::{Arc, Mutex};

    /// Open `path` with a responder that captures the challenge keepass-ng
    /// passes it — the ground truth for what the header reader must return.
    fn challenge_keepass_passes(path: &str, password: &str) -> Vec<u8> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_key = Arc::clone(&seen);
        let key = ChallengeResponseKey::External(Arc::new(move |challenge| {
            seen_in_key.lock().unwrap().push(challenge.to_vec());
            Ok(vec![0u8; 20])
        }));
        // The answer is wrong on purpose; only the challenge is of interest.
        let _ = KeepassVault::open(password, path, None, Some(&key));
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            1,
            "keepass-ng challenges the key exactly once on open"
        );
        seen[0].clone()
    }

    /// A one-entry vault encrypted with `kdf`, written through keepass-ng's
    /// public API (the vault type's own database handle is private).
    fn new_vault(dir: &std::path::Path, name: &str, kdf: keepass_ng::KdfConfig) -> String {
        use keepass_ng::db::Database;
        use keepass_ng::{DatabaseConfig, DatabaseKey};
        let path = dir.join(name);
        let mut config = DatabaseConfig::default();
        config.kdf_config = kdf;
        let db = Database::new(config);
        let mut file = std::fs::File::create(&path).unwrap();
        db.save(&mut file, DatabaseKey::new().with_password("master-pw"))
            .unwrap();
        path.to_str().unwrap().to_string()
    }

    fn argon2d() -> keepass_ng::KdfConfig {
        keepass_ng::KdfConfig::Argon2 {
            iterations: 2,
            memory: 1024 * 1024,
            parallelism: 1,
            version: keepass_ng::Argon2Version::Version13,
        }
    }

    #[test]
    fn reads_exactly_the_bytes_keepass_ng_challenges_with() {
        let dir = tempfile::tempdir().unwrap();
        for (name, kdf) in [
            ("argon2d.kdbx", argon2d()),
            (
                "argon2id.kdbx",
                keepass_ng::KdfConfig::Argon2id {
                    iterations: 2,
                    memory: 1024 * 1024,
                    parallelism: 1,
                    version: keepass_ng::Argon2Version::Version13,
                },
            ),
            ("aes.kdbx", keepass_ng::KdfConfig::Aes { rounds: 10 }),
        ] {
            let path = new_vault(dir.path(), name, kdf);
            assert_eq!(
                read_kdf_seed(&path).unwrap().to_vec(),
                challenge_keepass_passes(&path, "master-pw"),
                "{name}"
            );
        }
    }

    #[test]
    fn the_signature_constants_match_what_keepass_ng_writes() {
        // The reader's constants are checked against a file keepass-ng
        // itself produced, so a typo cannot pass a self-consistent test.
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(
            dir.path(),
            "sig.kdbx",
            keepass_ng::KdfConfig::Aes { rounds: 10 },
        );
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            bytes[..8],
            [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5][..]
        );
        assert_eq!(bytes[..4], KDBX_SIGNATURE.to_le_bytes());
        assert_eq!(bytes[4..8], KDBX_LATEST_SIGNATURE.to_le_bytes());
        assert_eq!(
            u16::from_le_bytes([bytes[10], bytes[11]]),
            4,
            "major version"
        );
    }

    #[test]
    fn the_seed_rotates_on_every_save() {
        // Which is why every save needs a fresh answer (SPEC §7).
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(
            dir.path(),
            "vault.kdbx",
            keepass_ng::KdfConfig::Aes { rounds: 10 },
        );
        let before = read_kdf_seed(&path).unwrap();
        let mut vault = KeepassVault::open("master-pw", &path, None, None).unwrap();
        vault
            .save_one_credential(passlane_core::vault::entities::Credential::new(
                None, "pw", "Example", "user", None, None,
            ))
            .unwrap();
        drop(vault);
        let after = read_kdf_seed(&path).unwrap();
        assert_ne!(before, after);
        assert_eq!(
            after,
            read_kdf_seed(&path).unwrap(),
            "stable until the next save"
        );
    }

    #[test]
    fn rejects_files_that_are_not_kdbx4_or_are_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");

        std::fs::write(&path, b"not a database at all").unwrap();
        let err = read_kdf_seed(path.to_str().unwrap()).unwrap_err();
        assert!(
            err.message.contains("bad file signature"),
            "{}",
            err.message
        );

        // The KDBX signature followed by a KDBX 3 version word.
        let mut kdbx3 = KDBX_SIGNATURE.to_le_bytes().to_vec();
        kdbx3.extend_from_slice(&KDBX_LATEST_SIGNATURE.to_le_bytes());
        kdbx3.extend_from_slice(&1u16.to_le_bytes());
        kdbx3.extend_from_slice(&3u16.to_le_bytes());
        std::fs::write(&path, &kdbx3).unwrap();
        let err = read_kdf_seed(path.to_str().unwrap()).unwrap_err();
        assert!(err.message.contains("KDBX 3.1"), "{}", err.message);
        assert!(
            err.message.contains("needs a KDBX 4 vault"),
            "{}",
            err.message
        );

        // A real vault, cut inside its outer header at every awkward spot:
        // never a panic, always an error that names the file.
        let real = new_vault(
            dir.path(),
            "real.kdbx",
            keepass_ng::KdfConfig::Aes { rounds: 10 },
        );
        let bytes = std::fs::read(&real).unwrap();
        let whole = read_kdf_seed(&real).unwrap();
        for cut in [0usize, 3, 4, 7, 8, 11, 12, 13, 17, 20, 33, 40, 60] {
            std::fs::write(&path, &bytes[..cut]).unwrap();
            let err = read_kdf_seed(path.to_str().unwrap()).unwrap_err();
            assert!(
                err.message.contains("vault.kdbx"),
                "cut {cut}: {}",
                err.message
            );
        }

        // The seed lives in the outer header, so a file cut anywhere after
        // the header still yields it. keepass-ng would refuse to open such
        // a file; minting a request for its seed is harmless.
        for cut in [bytes.len() / 2, bytes.len() - 1] {
            std::fs::write(&path, &bytes[..cut]).unwrap();
            assert_eq!(
                read_kdf_seed(path.to_str().unwrap()).unwrap(),
                whole,
                "cut {cut}"
            );
        }

        // A header without the key derivation parameters at all.
        let mut no_kdf = KDBX_SIGNATURE.to_le_bytes().to_vec();
        no_kdf.extend_from_slice(&KDBX_LATEST_SIGNATURE.to_le_bytes());
        no_kdf.extend_from_slice(&1u16.to_le_bytes());
        no_kdf.extend_from_slice(&4u16.to_le_bytes());
        no_kdf.push(HEADER_END);
        no_kdf.extend_from_slice(&0u32.to_le_bytes());
        let err = parse_kdf_seed(&no_kdf).unwrap_err();
        assert!(
            err.message.contains("no key derivation parameters"),
            "{}",
            err.message
        );

        // A missing file.
        let err = read_kdf_seed(dir.path().join("absent.kdbx").to_str().unwrap()).unwrap_err();
        assert!(
            err.message.contains("Could not read vault file"),
            "{}",
            err.message
        );
    }

    /// A variant dictionary from (type, name, value) entries.
    fn dictionary(entries: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
        let mut vd = VARIANT_DICTIONARY_VERSION.to_le_bytes().to_vec();
        for (value_type, name, value) in entries {
            vd.push(*value_type);
            vd.extend_from_slice(&(name.len() as u32).to_le_bytes());
            vd.extend_from_slice(name);
            vd.extend_from_slice(&(value.len() as u32).to_le_bytes());
            vd.extend_from_slice(value);
        }
        vd.push(VARIANT_DICTIONARY_END);
        vd
    }

    #[test]
    fn variant_dictionary_edges() {
        let seed = [0xab; SEED_LEN];
        // Well-formed: a UInt32 and the seed, ended by a zero type. The
        // seed is found whatever its position among the other entries.
        for entries in [
            vec![
                (0x04, &b"I"[..], &2u32.to_le_bytes()[..]),
                (BYTES_TYPE_ID, &b"S"[..], &seed[..]),
            ],
            vec![
                (BYTES_TYPE_ID, &b"S"[..], &seed[..]),
                (0x05, &b"M"[..], &1u64.to_le_bytes()[..]),
            ],
        ] {
            let vd = dictionary(&entries);
            assert_eq!(parse_header(&vd).unwrap(), seed);
        }

        // A seed of the wrong length.
        let vd = dictionary(&[(BYTES_TYPE_ID, &b"S"[..], &[0xab; 16][..])]);
        let err = parse_header(&vd).unwrap_err();
        assert!(err.message.contains("16 bytes, not 32"), "{}", err.message);

        // A string-typed "S" is not the seed.
        let vd = dictionary(&[(0x18, &b"S"[..], &seed[..])]);
        assert!(
            parse_header(&vd)
                .unwrap_err()
                .message
                .contains("carry no seed")
        );

        // No seed entry at all.
        let vd = dictionary(&[(0x04, &b"R"[..], &10u32.to_le_bytes()[..])]);
        assert!(
            parse_header(&vd)
                .unwrap_err()
                .message
                .contains("carry no seed")
        );

        // Not terminated, or cut inside an entry.
        let full = dictionary(&[(BYTES_TYPE_ID, &b"S"[..], &seed[..])]);
        for cut in [full.len() - 1, 12, 30, full.len() - 5] {
            let err = parse_header(&full[..cut]).unwrap_err();
            assert!(
                err.message.contains("not terminated") || err.message.contains("truncated"),
                "cut {cut}: {}",
                err.message
            );
        }

        // Wrong dictionary version.
        let mut wrong = full.clone();
        wrong[1] = 0x02;
        let err = parse_header(&wrong).unwrap_err();
        assert!(
            err.message.contains("unsupported version"),
            "{}",
            err.message
        );
    }

    fn parse_header(vd: &[u8]) -> Result<[u8; 32], Error> {
        let mut header = KDBX_SIGNATURE.to_le_bytes().to_vec();
        header.extend_from_slice(&KDBX_LATEST_SIGNATURE.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&4u16.to_le_bytes());
        header.push(HEADER_KDF_PARAMS);
        header.extend_from_slice(&(vd.len() as u32).to_le_bytes());
        header.extend_from_slice(vd);
        header.push(HEADER_END);
        header.extend_from_slice(&0u32.to_le_bytes());
        parse_kdf_seed(&header)
    }
}
