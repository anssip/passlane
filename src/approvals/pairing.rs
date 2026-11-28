//! The CLI side of pairing with the iOS app (passlane#84, SPEC §5).
//!
//! Pairing is how a phone becomes a pinned approver before any key is
//! shared: this terminal generates a 32-byte pairing secret, seals its
//! own public keys into a PSK-sealed pairing request, and puts both in
//! the fragment of a `pair.html` link — printed as text plus a terminal
//! QR, exactly like approval links. The app that scans the link opens
//! the request, both sides show two confirmation codes, and the app's
//! sealed pairing response is pasted back here; the phone's pin is
//! stored only after the human confirms the mutual code.
//!
//! Two human checks, per SPEC §5:
//!
//! - the **CLI-side code** with the link — it authenticates this
//!   terminal to the app (a swapped QR carrying substituted CLI keys
//!   changes it);
//! - the **mutual code** after the response — it authenticates the
//!   responder to this terminal. An attacker who read the QR holds the
//!   secret and can forge a cryptographically valid response for their
//!   own keys; only the code comparison detects the substitution.
//!
//! Nothing is pinned unless every check passes, and the pairing secret
//! is discarded when the ceremony ends. The QR scan is the out-of-band
//! channel — pairing must not travel over a relay (SPEC §5) — so the
//! ceremony is interactive by design.

use std::path::Path;

use passlane_approval::envelope::Envelope;
use passlane_approval::keys::PeerPin;
use passlane_approval::message::DeviceInfo;
use passlane_approval::pairing::{PairingSecret, open_pairing_response, seal_pairing_request};
use passlane_approval::policy::Policy;
use passlane_approval::replay::{FileNonceStore, NonceStore};
use rand::rngs::OsRng;

use super::{load_identity, nonce_store_path, now_secs, page_url, pin_approver, render_qr};

/// `<page>/pair.html#s=<secret hex>&e=<envelope>` — the pairing link
/// (passlane#84). The app — not the page — consumes it: iOS routes the
/// domain's links there through `apple-app-site-association`. Both
/// parameters ride the fragment, which no client ever sends to the
/// host: the pairing secret must reach the domain even less than an
/// envelope does.
pub fn pair_link(page: &str, secret_hex: &str, envelope_b64url: &str) -> String {
    format!(
        "{}/pair.html#s={secret_hex}&e={envelope_b64url}",
        page.trim_end_matches('/')
    )
}

/// What the terminal shows while pairing.
pub struct ShownPairing<'a> {
    /// The full `https://…/pair.html#s=…&e=…` link.
    pub link: &'a str,
    /// The CLI-side confirmation code (SPEC §5's first human check):
    /// the app must show the same twelve digits from the decrypted
    /// request before anything continues.
    pub cli_code: &'a str,
}

/// The terminal during a pairing ceremony. Injected so the ceremony is
/// testable without one — the same seam the link transport uses.
pub trait PairingUi {
    /// Show the link, a QR to scan, and the CLI-side confirmation code.
    fn show(&self, shown: &ShownPairing<'_>);
    /// The pairing response the app pasted back. `None` cancels.
    fn read_response(&self, prompt: &str) -> Option<String>;
    /// One yes/no question — the mutual-code check. A terminal that
    /// cannot ask answers no.
    fn confirm(&self, question: &str) -> bool;
}

/// The real terminal: the link on stdout, the QR, the codes and the
/// instructions on stderr (stdout stays parseable), the response
/// through a prompt.
pub struct TerminalPairingUi;

impl PairingUi for TerminalPairingUi {
    fn show(&self, shown: &ShownPairing<'_>) {
        println!("Pair with the passlane app — open this link there (scan or paste it):");
        println!("{}", shown.link);
        match render_qr(shown.link) {
            Ok(qr) => eprintln!("{qr}"),
            Err(e) => eprintln!("(no QR: {e})"),
        }
        eprintln!(
            "Confirmation code: {} — the app must show the same code on its pairing screen. \
             If it differs, cancel: a substituted link would pin the wrong device.",
            shown.cli_code
        );
    }

    fn read_response(&self, prompt: &str) -> Option<String> {
        match inquire::Text::new(prompt).prompt() {
            Ok(text) if !text.trim().is_empty() => Some(text),
            _ => None,
        }
    }

    fn confirm(&self, question: &str) -> bool {
        // Default no: persisting a pin is an affirmative act, and a
        // prompt that fails — no terminal after all — declines rather
        // than blocks.
        inquire::Confirm::new(question)
            .with_default(false)
            .prompt()
            .unwrap_or(false)
    }
}

/// Pair with the iOS app (SPEC §5) and return the phone's pin: seal a
/// pairing request under a fresh pairing secret, show the `pair.html`
/// link and QR with the CLI-side confirmation code, read the app's
/// pasted pairing response, open it against this CLI's identity, and
/// pin the phone only once the human confirms the mutual code.
///
/// Interactive by design (the QR scan is the out-of-band channel, so
/// the response is pasted right here); callers gate on a terminal
/// before starting. The pin remembers the page base it was paired
/// under, so later approval links target the same deployment — a
/// custom `--page` today keeps targeting that deployment tomorrow.
pub fn pair_app(
    dir: &Path,
    page_explicit: Option<&str>,
    ui: &dyn PairingUi,
) -> Result<PeerPin, String> {
    let page = page_url(page_explicit);
    let identity = load_identity(dir)?;
    let secret = PairingSecret::generate(&mut OsRng);
    // A pairing is a single-shot human ceremony — scan, compare two
    // codes across devices, paste — so it carries the ceremony TTL
    // (passlane#73), like enrollments and saves.
    let policy = Policy::default().for_ceremony();
    let request = seal_pairing_request(
        &mut OsRng,
        &secret,
        &identity,
        DeviceInfo {
            kind: "cli".into(),
            name: crate::agent::requester(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        now_secs(),
        &policy,
    )
    .map_err(|e| format!("could not seal the pairing request: {e}"))?;

    let cli_enc = passlane_approval::encoding::hex_encode(&identity.encryption_public());
    let cli_sig =
        passlane_approval::encoding::hex_encode(&identity.verifying_key().to_sec1_bytes());
    let link = pair_link(&page, &secret.to_hex(), &request.to_base64url());
    // SPEC §5's first human check: printed with the link, compared
    // against what the app shows from the decrypted request.
    let cli_code = secret.confirmation_code(&cli_enc, &cli_sig);
    ui.show(&ShownPairing {
        link: &link,
        cli_code: &cli_code,
    });

    let prompt = "Paste the pairing response the app produced (leave empty to cancel)";
    let Some(blob) = ui.read_response(prompt) else {
        return Err(
            "pairing aborted: no response was given, so nothing was pinned. Without the app, \
             the approval page is still a path: run 'passlane approvals enroll', then re-run \
             this command."
                .into(),
        );
    };
    let cleaned: String = blob.chars().filter(|c| !c.is_whitespace()).collect();
    let envelope = Envelope::from_base64url(&cleaned)
        .map_err(|e| format!("the pairing response is not a valid envelope: {e}"))?;
    // The response must answer THIS pairing. The binding proof covers
    // the rid cryptographically, but the cleartext header is checkable
    // before anything is verified or spent: another ceremony's response
    // (or an approval response pasted by mistake) is refused without
    // burning its replay nonce.
    if envelope.header().t != passlane_approval::message::MessageType::PairingResponse as u8
        || envelope.header().rid != request.header().rid
    {
        let short = &request.header().rid[..request.header().rid.len().min(8)];
        return Err(format!(
            "the pasted response does not answer this pairing request ({short}) — it belongs \
             to a different ceremony, or is not a pairing response. Re-run the command to pair \
             again."
        ));
    }

    // Verification runs with the replay store's exclusive lock held —
    // and ONLY that long: the store is dropped (its lock released)
    // before the human question below, so an undecided prompt can never
    // block another pairing or a `passlane approve --response` in
    // another process.
    let pin = {
        let mut nonces = FileNonceStore::load(&nonce_store_path(dir))
            .map_err(|e| format!("replay store: {e}"))?;
        // The clock is read here, under the store's lock: a timestamp
        // captured before waiting for it could accept a response that
        // expired while this process waited (the same discipline
        // `passlane approve --response` applies).
        let now = now_secs();
        // Pruning under the store's own lock, before the rewrite, keeps
        // `.approval_nonces` bounded by the replay window.
        nonces.prune(now);
        // The decision must sit inside THIS ceremony's window, and the
        // paste must arrive within its total-lifetime bound (SPEC §4's
        // discipline, applied to pairing) — checked before the nonce is
        // spent, like the rid: the response's own freshness alone would
        // accept a response sealed long after this pairing request died.
        policy
            .validate_reply(
                request.header().ts,
                request.header().exp,
                envelope.header(),
                now,
            )
            .map_err(|e| format!("the pairing response failed verification: {e}"))?;
        let (_body, pin) =
            open_pairing_response(&identity, &secret, &envelope, now, &policy, &mut nonces)
                .map_err(|e| format!("the pairing response failed verification: {e}"))?;
        nonces
            .save()
            .map_err(|e| format!("could not persist the replay store: {e}"))?;
        pin
    };

    // SPEC §5's second human check: the mutual code, computed here from
    // the decrypted response keys and on the app from the request. This
    // is the only thing that distinguishes a substituted response — an
    // attacker who read the QR can forge a valid proof for their own
    // keys — from the genuine phone, so nothing is pinned until the
    // human says the codes match.
    let mutual = secret.mutual_confirmation_code(&cli_enc, &cli_sig, &pin.enc_pub, &pin.sig_pub);
    let confirmed = ui.confirm(&format!(
        "Mutual confirmation code: {mutual} — does the app show the same code?"
    ));
    if !confirmed {
        return Err(
            "pairing aborted: the codes did not match, so nothing was pinned. If you suspect a \
             substituted link or response, compare full key fingerprints instead (see \
             crates/passlane-approval/SPEC.md §5); otherwise re-run the command to pair again."
                .into(),
        );
    }

    pin_approver(dir, pin.clone(), Some(&page))?;
    Ok(pin)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use passlane_approval::encoding::hex_encode;
    use passlane_approval::keys::{IdentityKeys, PublicKey};
    use passlane_approval::message::{Body, Decision, Scope};
    use passlane_approval::pairing::{open_pairing_request, seal_pairing_response};
    use passlane_approval::replay::InMemoryNonceStore;
    use passlane_approval::store::load_peers;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// The app side of the ceremony (the passlane-ios pairing service in
    /// miniature): scans the link, opens the request under the pairing
    /// secret, computes both codes the app shows, and seals its response.
    struct MockApp {
        keys: IdentityKeys,
        label: &'static str,
    }

    impl MockApp {
        fn new(label: &'static str) -> Self {
            Self {
                keys: IdentityKeys::generate(&mut OsRng).unwrap(),
                label,
            }
        }

        /// What the app does with the pair link: the CLI-side code it
        /// echoes (first human check), the mutual code it shows, and the
        /// response blob it hands back for pasting.
        fn pair(&self, link: &str) -> (String, String, String) {
            let fragment = link.split_once('#').unwrap().1;
            let (s, e) = fragment.split_once("&e=").unwrap();
            let secret = PairingSecret::from_bytes(
                &passlane_approval::encoding::hex_decode(s.trim_start_matches("s=")).unwrap(),
            )
            .unwrap();
            let request = Envelope::from_base64url(e).unwrap();
            let (_body, cli_pin) = open_pairing_request(
                &secret,
                &request,
                now_secs(),
                &Policy::default(),
                &mut InMemoryNonceStore::default(),
            )
            .unwrap();
            let cli_code = secret.confirmation_code(&cli_pin.enc_pub, &cli_pin.sig_pub);
            let mutual = secret.mutual_confirmation_code(
                &cli_pin.enc_pub,
                &cli_pin.sig_pub,
                &hex_encode(&self.keys.encryption_public()),
                &hex_encode(&self.keys.verifying_key().to_sec1_bytes()),
            );
            let response = seal_pairing_response(
                &mut OsRng,
                &secret,
                &self.keys,
                &cli_pin,
                &request,
                DeviceInfo {
                    kind: "phone".into(),
                    name: self.label.into(),
                    version: "1".into(),
                },
                now_secs(),
                &Policy::default(),
            )
            .unwrap();
            (cli_code, mutual, response.to_base64url())
        }

        /// The pin the app keeps of the CLI, to open its later requests.
        fn cli_pin(cli: &IdentityKeys) -> PeerPin {
            PeerPin::new(
                "cli",
                PublicKey(cli.encryption_public()),
                PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
                0,
            )
        }

        /// Open a later approval request sealed to this app and answer
        /// with a plain signed Allow (the app path carries no WebAuthn
        /// assertion). Returns None when the app cannot open it — a
        /// request not sealed to this app.
        fn answer(&self, cli: &IdentityKeys, request: &Envelope) -> Option<String> {
            let body = passlane_approval::envelope::open(
                &self.keys,
                std::slice::from_ref(&Self::cli_pin(cli)),
                request,
                now_secs(),
                &Policy::default(),
                &mut InMemoryNonceStore::default(),
            )
            .ok()?;
            assert!(
                matches!(&*body, Body::ApprovalRequest { .. }),
                "what the app opened is an approval request"
            );
            Some(
                passlane_approval::envelope::seal_reply(
                    &mut OsRng,
                    &self.keys,
                    &Self::cli_pin(cli),
                    Body::ApprovalResponse {
                        decision: Decision::Allow,
                        scope: Scope::Once,
                        response: None,
                    },
                    &request.header().rid,
                    now_secs(),
                    &Policy::default(),
                )
                .unwrap()
                .to_base64url(),
            )
        }
    }

    /// A scripted terminal. `on_show` runs when the link appears — it
    /// stands in for the person who scans it with the app — and its
    /// return value is the response pasted back. `confirm` supplies the
    /// mutual-code answer; `confirmations` records the questions asked.
    struct ScriptedUi {
        shown: RefCell<Option<(String, String)>>,
        paste: RefCell<Option<String>>,
        confirmations: RefCell<Vec<String>>,
        confirm: bool,
        on_show: Option<OnShow>,
    }

    /// What the person does when the pair link appears: given the link,
    /// the response to paste back.
    type OnShow = Box<dyn Fn(&str) -> Option<String>>;

    impl ScriptedUi {
        fn new(confirm: bool, on_show: Option<OnShow>) -> Self {
            Self {
                shown: RefCell::new(None),
                paste: RefCell::new(None),
                confirmations: RefCell::new(Vec::new()),
                confirm,
                on_show,
            }
        }

        fn shown_cli_code(&self) -> String {
            self.shown.borrow().as_ref().unwrap().1.clone()
        }
    }

    impl PairingUi for ScriptedUi {
        fn show(&self, shown: &ShownPairing<'_>) {
            *self.shown.borrow_mut() = Some((shown.link.to_string(), shown.cli_code.to_string()));
            if let Some(on_show) = &self.on_show {
                *self.paste.borrow_mut() = on_show(shown.link);
            }
        }

        fn read_response(&self, _prompt: &str) -> Option<String> {
            self.paste.borrow().clone()
        }

        fn confirm(&self, question: &str) -> bool {
            self.confirmations.borrow_mut().push(question.to_string());
            self.confirm
        }
    }

    /// A scripted terminal whose person pairs with the app the link
    /// targets: the app's two codes are captured in `codes`, its
    /// response is pasted back.
    fn pairing_terminal(
        app: &Rc<MockApp>,
        confirm: bool,
        codes: &Rc<RefCell<Option<(String, String)>>>,
    ) -> ScriptedUi {
        let app = app.clone();
        let codes = codes.clone();
        ScriptedUi::new(
            confirm,
            Some(Box::new(move |link| {
                let (cli_code, mutual, response) = app.pair(link);
                *codes.borrow_mut() = Some((cli_code, mutual));
                Some(response)
            })),
        )
    }

    #[test]
    fn pair_link_carries_secret_and_envelope_in_the_fragment_only() {
        let secret_hex = "ab".repeat(32);
        let link = pair_link("https://page.example", &secret_hex, "UExBUA");
        assert_eq!(
            link,
            format!("https://page.example/pair.html#s={secret_hex}&e=UExBUA")
        );
        // Fragment-only transport: neither the secret nor the envelope
        // appears before the '#'.
        let (before, fragment) = link.split_once('#').unwrap();
        assert!(fragment.starts_with("s=ab"));
        assert!(fragment.ends_with("e=UExBUA"));
        assert!(!before.contains("abab"));
        assert!(!before.contains("UExBUA"));
    }

    #[test]
    fn a_real_pair_link_renders_as_a_qr() {
        // A pairing link carries a 64-hex-char secret plus a full
        // request envelope — the longest link the CLI emits — so the
        // renderer must still produce square, quiet-zoned output.
        let identity = IdentityKeys::generate(&mut OsRng).unwrap();
        let secret = PairingSecret::generate(&mut OsRng);
        let request = seal_pairing_request(
            &mut OsRng,
            &secret,
            &identity,
            DeviceInfo {
                kind: "cli".into(),
                name: "mbp".into(),
                version: "4".into(),
            },
            now_secs(),
            &Policy::default().for_ceremony(),
        )
        .unwrap();
        let link = pair_link(
            "https://approve.northernpeaks.dev",
            &secret.to_hex(),
            &request.to_base64url(),
        );
        assert!(link.starts_with("https://approve.northernpeaks.dev/pair.html#s="));
        let qr = render_qr(&link).expect("a pair link encodes");
        let lines: Vec<&str> = qr.lines().collect();
        assert!(lines.len() > 8, "a QR with quiet zone has padding rows");
        assert!(lines.iter().all(|l| !l.is_empty()));
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
    }

    #[test]
    fn the_pairing_roundtrip_pins_the_app_and_later_approvals_seal_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let app = Rc::new(MockApp::new("anssi-iphone"));
        let codes = Rc::new(RefCell::new(None));
        let ui = pairing_terminal(&app, true, &codes);

        let pin = pair_app(dir.path(), None, &ui).expect("the pairing completes");

        // The phone is pinned under its own label, with no WebAuthn data
        // (the app signs directly; only the Phase 0 page carries a
        // passkey).
        assert_eq!(pin.label, "anssi-iphone");
        assert_eq!(pin.enc_pub, hex_encode(&app.keys.encryption_public()));
        assert!(pin.webauthn.is_none());
        let peers = load_peers(dir.path()).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].label, "anssi-iphone");

        // The CLI-side code the app echoed matches the terminal's (the
        // first human check), and the mutual code was asked (the second).
        let (app_cli_code, app_mutual) = codes.borrow().clone().unwrap();
        assert_eq!(app_cli_code, ui.shown_cli_code());
        assert_eq!(ui.confirmations.borrow().len(), 1);
        assert!(
            ui.confirmations.borrow()[0].contains("Mutual confirmation code"),
            "{}",
            ui.confirmations.borrow()[0]
        );
        // The mutual code the app shows is a twelve-digit, two-group
        // code (SPEC §5's format).
        assert_eq!(app_mutual.len(), 13, "formatted 123456-789012");
        assert!(app_mutual.chars().nth(6).is_some_and(|c| c == '-'));

        // A subsequent approval seals to the new pin: the pending record
        // names the phone as its holder, the link rides the page base the
        // pairing remembered (the canonical default here), and the app
        // can open the request it is sealed to and answer it — the answer
        // verifies.
        let cli = load_identity(dir.path()).unwrap();
        let emitted = super::super::emit_approval_request(
            dir.path(),
            "work",
            "GitHub",
            "uuid-github",
            "password",
            "tester",
        )
        .expect("emission succeeds against the paired app");
        let pending = super::super::pending::PendingStore::load(dir.path())
            .unwrap()
            .records()
            .to_vec();
        let record = pending.iter().find(|r| r.rid == emitted.rid).unwrap();
        assert_eq!(
            record.holder_kid.as_deref(),
            Some(pin.enc_kid().unwrap().as_str())
        );
        assert!(
            emitted
                .link
                .starts_with("https://approve.northernpeaks.dev/approve.html#"),
            "the approval link rides the page base the pairing remembered: {}",
            emitted.link
        );
        let request = Envelope::from_base64url(emitted.link.split_once('#').unwrap().1).unwrap();
        let blob = app
            .answer(&cli, &request)
            .expect("the app opens the request");
        let verified = super::super::verify_response(
            dir.path(),
            &blob,
            super::super::Disposition::Grant,
            &|_| Ok(()),
        )
        .expect("the app's answer verifies against the pin");
        assert!(matches!(
            verified.outcome,
            super::super::ApproveOutcome::Allowed { .. }
        ));
    }

    #[test]
    fn a_response_decided_outside_this_ceremonys_window_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        // The app answers this run's request, but its decision is
        // stamped far in the past (a stale blob, or a lying clock):
        // this ceremony's window governs, not the response's own
        // freshness — a response sealed after the pairing request died
        // must not pin anything.
        let ui = ScriptedUi::new(
            true,
            Some(Box::new(|link| {
                let fragment = link.split_once('#').unwrap().1;
                let (s, e) = fragment.split_once("&e=").unwrap();
                let secret = PairingSecret::from_bytes(
                    &passlane_approval::encoding::hex_decode(s.trim_start_matches("s=")).unwrap(),
                )
                .unwrap();
                let request = Envelope::from_base64url(e).unwrap();
                let app = IdentityKeys::generate(&mut OsRng).unwrap();
                let (_body, cli_pin) = open_pairing_request(
                    &secret,
                    &request,
                    now_secs(),
                    &Policy::default(),
                    &mut InMemoryNonceStore::default(),
                )
                .unwrap();
                // The decision predates the request beyond the skew window.
                let stale_decision = now_secs().saturating_sub(1100);
                let response = seal_pairing_response(
                    &mut OsRng,
                    &secret,
                    &app,
                    &cli_pin,
                    &request,
                    DeviceInfo {
                        kind: "phone".into(),
                        name: "anssi-iphone".into(),
                        version: "1".into(),
                    },
                    stale_decision,
                    &Policy::default(),
                )
                .unwrap();
                Some(response.to_base64url())
            })),
        );

        let err = pair_app(dir.path(), None, &ui).unwrap_err();
        assert!(err.contains("failed verification"), "{err}");
        // Refused before the nonce was spent or the human was asked.
        assert!(load_peers(dir.path()).unwrap().is_empty());
        assert!(
            ui.confirmations.borrow().is_empty(),
            "the mutual code is never offered for a dead response"
        );
    }

    #[test]
    fn a_declined_mutual_code_pins_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let app = Rc::new(MockApp::new("anssi-iphone"));
        let codes = Rc::new(RefCell::new(None));
        // The paste verified, the response was genuine — but the human
        // said the codes do not match, so nothing may be pinned.
        let ui = pairing_terminal(&app, false, &codes);

        let err = pair_app(dir.path(), None, &ui).unwrap_err();
        assert!(err.contains("the codes did not match"), "{err}");
        assert!(err.contains("nothing was pinned"), "{err}");
        assert!(load_peers(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn an_empty_paste_cancels_with_the_page_path_guidance() {
        let dir = tempfile::tempdir().unwrap();
        let ui = ScriptedUi::new(true, None);
        let err = pair_app(dir.path(), None, &ui).unwrap_err();
        assert!(err.contains("pairing aborted"), "{err}");
        assert!(err.contains("'passlane approvals enroll'"), "{err}");
        assert!(load_peers(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_response_from_another_pairing_is_refused_before_verification() {
        let dir = tempfile::tempdir().unwrap();
        // A different ceremony's pairing: fresh secret, fresh request.
        let other_cli = IdentityKeys::generate(&mut OsRng).unwrap();
        let other_secret = PairingSecret::generate(&mut OsRng);
        let other_request = seal_pairing_request(
            &mut OsRng,
            &other_secret,
            &other_cli,
            DeviceInfo {
                kind: "cli".into(),
                name: "other".into(),
                version: "1".into(),
            },
            now_secs(),
            &Policy::default().for_ceremony(),
        )
        .unwrap();
        let app = MockApp::new("anssi-iphone");
        let other_response = seal_pairing_response(
            &mut OsRng,
            &other_secret,
            &app.keys,
            &MockApp::cli_pin(&other_cli),
            &other_request,
            DeviceInfo {
                kind: "phone".into(),
                name: "anssi-iphone".into(),
                version: "1".into(),
            },
            now_secs(),
            &Policy::default(),
        )
        .unwrap()
        .to_base64url();

        let ui = ScriptedUi {
            shown: RefCell::new(None),
            paste: RefCell::new(Some(other_response)),
            confirmations: RefCell::new(Vec::new()),
            confirm: true,
            on_show: None,
        };
        let err = pair_app(dir.path(), None, &ui).unwrap_err();
        assert!(
            err.contains("does not answer this pairing request"),
            "{err}"
        );
        // Refused before verification, so nothing was spent or pinned —
        // and the mutual code was never even asked.
        assert!(load_peers(dir.path()).unwrap().is_empty());
        assert!(ui.confirmations.borrow().is_empty());
    }
}
