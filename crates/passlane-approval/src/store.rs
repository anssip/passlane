//! CLI-side persistence: this device's identity keys and the pinned peers.
//!
//! Two small JSON files under the passlane config directory:
//!
//! - `approval_identity.json` — this device's private keys (owner-only)
//! - `approval_peers.json` — the pins established by pairing
//!
//! The iOS side keeps equivalent state in the Keychain/Secure Enclave; this
//! module exists for the CLI and the session agent.

use std::path::Path;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

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
pub fn load_or_generate_identity(
    dir: &Path,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<IdentityKeys> {
    let path = dir.join("approval_identity.json");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        let file: IdentityFile = serde_json::from_slice(&bytes)?;
        let enc = crate::encoding::hex_decode(&file.enc_secret)?;
        let sig = crate::encoding::hex_decode(&file.sig_secret)?;
        return IdentityKeys::from_bytes(&enc, &sig);
    }
    let keys = IdentityKeys::generate(rng)?;
    save_identity(dir, &keys)?;
    Ok(keys)
}

/// Persist this device's identity with owner-only permissions.
pub fn save_identity(dir: &Path, keys: &IdentityKeys) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let (enc, sig) = keys.secret_bytes();
    let file = IdentityFile {
        enc_secret: crate::encoding::hex_encode(&enc),
        sig_secret: crate::encoding::hex_encode(&sig),
    };
    write_private(
        &dir.join("approval_identity.json"),
        &serde_json::to_vec(&file)?,
    )
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

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    std::fs::write(path, bytes)?;
    // Belt and braces for pre-existing files.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
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
