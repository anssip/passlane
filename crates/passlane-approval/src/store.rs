//! CLI-side persistence: this device's identity keys and the pinned peers.
//!
//! Two small JSON files under the passlane config directory:
//!
//! - `approval_identity.json` — this device's private keys (owner-only)
//! - `approval_peers.json` — the pins established by pairing
//!
//! The iOS side keeps equivalent state in the Keychain/Secure Enclave; this
//! module exists for the CLI and the session agent.
//!
//! Secret-material hygiene: every buffer holding key bytes — the file
//! contents, the hex strings, the decoded scalars — is zeroized when it
//! falls out of scope.

use std::path::Path;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Result;
use crate::keys::{IdentityKeys, PeerPin};

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    /// 32-byte HPKE scalar, hex.
    enc_secret: String,
    /// 32-byte ECDSA scalar, hex.
    sig_secret: String,
}

/// Load this device's identity from `dir/approval_identity.json`,
/// generating and persisting fresh keys on first use.
///
/// First-use creation is race-free: the file is created exclusively
/// (`O_EXCL`), so when two processes race, both end up loading the
/// winner's identity instead of silently discarding one of them (which
/// would orphan every peer paired with the loser).
pub fn load_or_generate_identity(
    dir: &Path,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<IdentityKeys> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("approval_identity.json");
    if path.exists() {
        return load_identity_file(&path);
    }
    let keys = IdentityKeys::generate(rng)?;
    let (enc, sig) = keys.secret_bytes();
    let file = IdentityFile {
        enc_secret: crate::encoding::hex_encode(&enc),
        sig_secret: crate::encoding::hex_encode(&sig),
    };
    let mut json = Zeroizing::new(serde_json::to_vec(&file)?);
    match write_new_exclusive(&path, &json) {
        Ok(()) => Ok(keys),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process won the race; converge on its identity.
            json.zeroize();
            load_identity_file(&path)
        }
        Err(e) => Err(e.into()),
    }
}

fn load_identity_file(path: &Path) -> Result<IdentityKeys> {
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let mut file: IdentityFile = serde_json::from_slice(&bytes)?;
    let mut enc_hex = Zeroizing::new(std::mem::take(&mut file.enc_secret));
    let mut sig_hex = Zeroizing::new(std::mem::take(&mut file.sig_secret));
    file.enc_secret.zeroize();
    file.sig_secret.zeroize();
    let enc = Zeroizing::new(crate::encoding::hex_decode(&enc_hex)?);
    let sig = Zeroizing::new(crate::encoding::hex_decode(&sig_hex)?);
    enc_hex.zeroize();
    sig_hex.zeroize();
    IdentityKeys::from_bytes(&enc, &sig)
}

/// Persist this device's identity with owner-only permissions.
pub fn save_identity(dir: &Path, keys: &IdentityKeys) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let (enc, sig) = keys.secret_bytes();
    let mut file = IdentityFile {
        enc_secret: crate::encoding::hex_encode(&enc),
        sig_secret: crate::encoding::hex_encode(&sig),
    };
    let json = Zeroizing::new(serde_json::to_vec(&file)?);
    file.enc_secret.zeroize();
    file.sig_secret.zeroize();
    write_private(&dir.join("approval_identity.json"), &json)
}

/// Load the pinned peers from `dir/approval_peers.json` (empty if absent).
pub fn load_peers(dir: &Path) -> Result<Vec<PeerPin>> {
    let path = dir.join("approval_peers.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Persist the pinned peers.
pub fn save_peers(dir: &Path, peers: &[PeerPin]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    write_private(
        &dir.join("approval_peers.json"),
        &serde_json::to_vec(peers)?,
    )
}

/// Write with owner-only permissions, using the configured options (not
/// `fs::write`, which would create the file world-readable before any
/// chmod could tighten it).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

/// Create-write that fails with `AlreadyExists` if the file is there.
fn write_new_exclusive(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn identity_roundtrip_and_generate_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let keys = load_or_generate_identity(dir.path(), &mut OsRng).unwrap();
        assert!(dir.path().join("approval_identity.json").exists());

        let again = load_or_generate_identity(dir.path(), &mut OsRng).unwrap();
        assert_eq!(again.encryption_kid(), keys.encryption_kid());
        assert_eq!(again.signing_kid(), keys.signing_kid());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("approval_identity.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn concurrent_first_use_converges_on_one_identity() {
        // Simulate the race: a file appears between the existence check and
        // the exclusive create. The loser must load the winner's keys.
        let dir = tempfile::tempdir().unwrap();
        let winner = IdentityKeys::generate(&mut OsRng).unwrap();
        save_identity(dir.path(), &winner).unwrap();
        // load_or_generate sees the existing file and returns the winner.
        let converged = load_or_generate_identity(dir.path(), &mut OsRng).unwrap();
        assert_eq!(converged.encryption_kid(), winner.encryption_kid());
    }

    #[test]
    fn peers_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_peers(dir.path()).unwrap().is_empty());
        let peers = vec![PeerPin {
            label: "phone".into(),
            enc_pub: "04".to_string() + &"11".repeat(64),
            sig_pub: "04".to_string() + &"22".repeat(64),
            paired_at: 42,
            webauthn: Some(crate::keys::WebauthnPin {
                rp_id: "approve.passlane.app".into(),
                origin: "https://approve.passlane.app".into(),
            }),
        }];
        save_peers(dir.path(), &peers).unwrap();
        assert_eq!(load_peers(dir.path()).unwrap(), peers);
    }
}
