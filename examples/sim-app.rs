//! The passlane app-side simulator — a dev tool for desk-verifying the
//! phone-side ceremonies (passlane#84): pairing, and answering the
//! approval requests of a phone-held key. It is the passlane-ios
//! pairing/approval service in miniature: same crate, same protocol,
//! same recovery-sheet gating, no UI.
//!
//! ```sh
//! # Terminal A (a pty — pairing prompts): run 'passlane approvals pair',
//! # give the printed link to the simulator, then paste the blob the
//! # simulator prints back at the CLI's prompt.
//! cargo run --example sim-app -- pair '<pair.html#s=…&e=… link>' --state sim.json
//!
//! # Answer an approval link the CLI emitted (approve.html#…). EnrollKey
//! # demands the recovery sheet first: the secret is printed once, and
//! # --scan-back acknowledges that a copy exists outside the screen.
//! cargo run --example sim-app -- answer '<approve.html#… link>' --state sim.json [--scan-back]
//! ```
//!
//! State (`--state`, default `.sim-app-state.json` in the cwd): the
//! app's protocol identity (raw secrets, hex), the CLI it paired with,
//! and the phone-held key secrets it has created, by vault id. It is a
//! scratch file for verification — delete it freely.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use passlane_approval::envelope::Envelope;
use passlane_approval::keys::{IdentityKeys, PeerPin, PublicKey};
use passlane_approval::message::{Body, Decision, DeviceInfo, Operation, Scope, SecretHex};
use passlane_approval::pairing::{PairingSecret, open_pairing_request, seal_pairing_response};
use passlane_approval::policy::Policy;
use passlane_approval::replay::InMemoryNonceStore;
use rand::RngCore;
use rand::rngs::OsRng;
use sha1::Sha1;
use zeroize::Zeroizing;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut command = None;
    let mut link = None;
    let mut state_path = PathBuf::from(".sim-app-state.json");
    let mut scan_back = false;
    let mut rest = args.into_iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "pair" | "answer" => command = Some(arg),
            "--state" => state_path = PathBuf::from(rest.next().expect("--state needs a path")),
            "--scan-back" => scan_back = true,
            other => link = Some(other.to_string()),
        }
    }
    let (Some(command), Some(link)) = (command, link) else {
        eprintln!(
            "usage: sim-app pair|answer <link> [--state <file>] [--scan-back]\n\n\
             pair   <pair.html#s=…&e=… link>   pair with the CLI that printed it\n\
             answer <approve.html#… link>     answer an approval request\n\
             --state <file>  state file (default .sim-app-state.json)\n\
             --scan-back     the recovery sheet was printed and read back from a copy"
        );
        std::process::exit(2);
    };
    let mut state = State::load(&state_path);
    let result = match command.as_str() {
        "pair" => pair(&link, &mut state, &state_path),
        "answer" => answer(&link, &mut state, &state_path, scan_back),
        _ => unreachable!(),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// The persisted app: its identity, the CLI it paired with, and the
/// phone-held key secrets it created (by vault id).
#[derive(Default)]
struct State {
    enc_secret: Vec<u8>,
    sig_secret: Vec<u8>,
    cli_enc: Vec<u8>,
    cli_sig: Vec<u8>,
    keys: HashMap<String, Vec<u8>>,
}

impl State {
    fn load(path: &Path) -> Self {
        let Ok(bytes) = std::fs::read(path) else {
            return Self::default();
        };
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("state file is JSON");
        let hex_field = |name: &str| -> Vec<u8> {
            doc.get(name)
                .and_then(|v| v.as_str())
                .map(|h| passlane_approval::encoding::hex_decode(h).expect("hex in state"))
                .unwrap_or_default()
        };
        let keys = doc
            .get("keys")
            .and_then(|k| k.as_object())
            .map(|map| {
                map.iter()
                    .map(|(vault, secret)| {
                        (
                            vault.clone(),
                            passlane_approval::encoding::hex_decode(
                                secret.as_str().expect("secret is hex"),
                            )
                            .expect("hex secret"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            enc_secret: hex_field("enc_secret"),
            sig_secret: hex_field("sig_secret"),
            cli_enc: hex_field("cli_enc"),
            cli_sig: hex_field("cli_sig"),
            keys,
        }
    }

    fn save(&self, path: &Path) {
        let doc = serde_json::json!({
            "enc_secret": passlane_approval::encoding::hex_encode(&self.enc_secret),
            "sig_secret": passlane_approval::encoding::hex_encode(&self.sig_secret),
            "cli_enc": passlane_approval::encoding::hex_encode(&self.cli_enc),
            "cli_sig": passlane_approval::encoding::hex_encode(&self.cli_sig),
            "keys": self
                .keys
                .iter()
                .map(|(vault, secret)| {
                    (
                        vault.clone(),
                        serde_json::Value::String(passlane_approval::encoding::hex_encode(secret)),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&doc).unwrap()).expect("state writes");
    }

    fn identity(&self) -> IdentityKeys {
        IdentityKeys::from_bytes(&self.enc_secret, &self.sig_secret).expect("usable identity")
    }

    fn cli_pin(&self) -> PeerPin {
        PeerPin::new(
            "cli",
            PublicKey::from_bytes(&self.cli_enc).expect("CLI enc key"),
            PublicKey::from_bytes(&self.cli_sig).expect("CLI sig key"),
            0,
        )
    }
}

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The pairing ceremony's app side: scan the link, open the request,
/// show both confirmation codes, hand back the sealed response.
fn pair(link: &str, state: &mut State, state_path: &Path) -> Result<(), String> {
    if !state.enc_secret.is_empty() {
        return Err("this simulator is already paired; delete the state file to pair again".into());
    }
    let fragment = link.split_once('#').ok_or("the link has no fragment")?.1;
    let (s, e) = fragment
        .split_once("&e=")
        .ok_or("the pair link has no s=…&e=… fragment")?;
    let secret = PairingSecret::from_bytes(
        &passlane_approval::encoding::hex_decode(s.trim_start_matches("s="))
            .map_err(|e| format!("the pairing secret is not valid hex: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let request = Envelope::from_base64url(e).map_err(|e| format!("bad request envelope: {e}"))?;

    let app = IdentityKeys::generate(&mut OsRng).map_err(|e| format!("keygen: {e}"))?;
    let policy = Policy::default();
    let (_body, cli_pin) = open_pairing_request(
        &secret,
        &request,
        now_secs(),
        &policy,
        &mut InMemoryNonceStore::default(),
    )
    .map_err(|e| format!("the app rejected the pairing request: {e}"))?;

    // What the app shows: the CLI-side code (over the keys from the
    // request), then the mutual code (over both identities) — the human
    // compares the second against the terminal's.
    let app_enc = passlane_approval::encoding::hex_encode(&app.encryption_public());
    let app_sig = passlane_approval::encoding::hex_encode(&app.verifying_key().to_sec1_bytes());
    println!(
        "App shows — CLI code:    {}",
        secret.confirmation_code(&cli_pin.enc_pub, &cli_pin.sig_pub)
    );
    println!(
        "App shows — mutual code: {}",
        secret.mutual_confirmation_code(&cli_pin.enc_pub, &cli_pin.sig_pub, &app_enc, &app_sig)
    );

    let response = seal_pairing_response(
        &mut OsRng,
        &secret,
        &app,
        &cli_pin,
        &request,
        DeviceInfo {
            kind: "phone".into(),
            name: "simulator".into(),
            version: "1".into(),
        },
        now_secs(),
        &policy,
    )
    .map_err(|e| format!("could not seal the response: {e}"))?;

    let (enc_secret, sig_secret) = app.secret_bytes();
    state.enc_secret = enc_secret.to_vec();
    state.sig_secret = sig_secret.to_vec();
    state.cli_enc = cli_pin
        .enc_pub_bytes()
        .map_err(|e| format!("the CLI enc key is unusable: {e}"))?
        .to_vec();
    state.cli_sig = passlane_approval::encoding::hex_decode(&cli_pin.sig_pub)
        .map_err(|e| format!("the CLI sig key is not hex: {e}"))?;
    state.save(state_path);
    println!(
        "Paste this back at the terminal's prompt:\n{}",
        response.to_base64url()
    );
    Ok(())
}

/// Answer an approval request like the app does: open it, honor the
/// recovery-sheet gate at EnrollKey, answer with the vault key's HMAC.
/// A key created at EnrollKey is kept for the vault's later save/unlock
/// requests.
fn answer(link: &str, state: &mut State, state_path: &Path, scan_back: bool) -> Result<(), String> {
    if state.enc_secret.is_empty() {
        return Err("not paired yet: run 'sim-app pair <link>' first".into());
    }
    let fragment = link.split_once('#').ok_or("the link has no fragment")?.1;
    let request =
        Envelope::from_base64url(fragment).map_err(|e| format!("bad request envelope: {e}"))?;
    let app = state.identity();
    let cli_pin = state.cli_pin();
    let policy = Policy::default();
    let body = passlane_approval::envelope::open(
        &app,
        std::slice::from_ref(&cli_pin),
        &request,
        now_secs(),
        &policy,
        &mut InMemoryNonceStore::default(),
    )
    .map_err(|e| format!("the app rejected the request: {e}"))?;
    let Body::ApprovalRequest {
        vault_id,
        vault_name,
        operation,
        challenge,
        ..
    } = &*body
    else {
        return Err("not an approval request".into());
    };
    let challenge = challenge
        .as_ref()
        .and_then(|c| c.as_bytes().ok())
        .map(|b| b.to_vec())
        .ok_or("no challenge in the request")?;

    let created_sheet: Option<String>;
    let secret: Zeroizing<Vec<u8>> = match operation {
        Operation::EnrollKey => {
            // The gate (SPEC §7): the key is created, its sheet shown,
            // and no answer is sent until the sheet has been copied.
            // The secret below is the one enrolled when the gate passes,
            // so the sheet printed after it is the copy that matters.
            let mut secret = Zeroizing::new(vec![0u8; 20]);
            OsRng.fill_bytes(&mut secret);
            if !scan_back {
                return Err(
                    "EnrollKey: the app is showing its recovery sheet and refuses to answer \
                     until the secret has been copied. Re-run this command with --scan-back \
                     to acknowledge the copy — the enrolled key's sheet is printed then."
                        .into(),
                );
            }
            let sheet = passlane_approval::encoding::hex_encode(&secret);
            println!("Recovery sheet — secret (hex): {sheet}");
            println!("  (write this down: it is the only other copy of the key)");
            created_sheet = Some(sheet);
            secret
        }
        _ => {
            created_sheet = None;
            Zeroizing::new(
                state
                    .keys
                    .get(vault_id)
                    .cloned()
                    .ok_or_else(|| format!("this app holds no key for vault '{vault_id}'"))?,
            )
        }
    };

    let answer = hmac_sha1(&secret, &challenge);
    let response = passlane_approval::envelope::seal_reply(
        &mut OsRng,
        &app,
        &cli_pin,
        Body::ApprovalResponse {
            decision: Decision::Allow,
            scope: Scope::Once,
            response: Some(SecretHex::from_bytes(&answer)),
        },
        &request.header().rid,
        now_secs(),
        &policy,
    )
    .map_err(|e| format!("could not seal the response: {e}"))?;
    println!(
        "Answered ({} for vault '{}') — paste this back, or 'passlane approve --response':\n{}",
        describe(operation),
        vault_name,
        response.to_base64url()
    );
    if created_sheet.is_some() {
        state.keys.insert(vault_id.clone(), secret.to_vec());
        state.save(state_path);
    }
    Ok(())
}

fn describe(operation: &Operation) -> &'static str {
    match operation {
        Operation::Reveal { .. } => "reveal",
        Operation::Unlock => "unlock",
        Operation::Save => "save",
        Operation::EnrollKey => "create a phone-held key",
    }
}
