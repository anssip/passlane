use std::io::IsTerminal;
use std::sync::Arc;

use clap::ArgMatches;
use keepass_ng::ChallengeResponseKey;
use passlane_core::challenge::ChallengeFactor;
use passlane_core::hwkey::HwKeyConfig;
use passlane_core::vault::keepass_vault::KeepassVault;
use zeroize::Zeroize;

use crate::actions::{
    Action, ChallengeKey, at_a_terminal, hardware_key_needs_a_terminal, unlock_keepass,
};
use crate::hwkey;
use crate::phone_key::ResponseSource;
use crate::phone_key::transport::LinkTransport;
use crate::session_agent::{SessionFactors, session_factors};
use crate::vault_registry::{self, PhoneKeyConfig, VaultConfig};
use passlane_core::vault::entities::Error;

pub struct HwKeyAction {
    pub command: HwKeyCommand,
}

/// `hwkey add --phone`: enrol the vault with a key held by another device.
#[derive(Debug, Clone, Default)]
pub struct PhoneAdd {
    /// Approval page base URL, for pairing when nothing is pinned yet.
    pub page: Option<String>,
    /// Label of the pinned approver that should hold the key.
    pub approver: Option<String>,
}

pub enum HwKeyCommand {
    Add {
        slot: Option<u8>,
        serial: Option<u32>,
        phone: Option<PhoneAdd>,
    },
    Remove {
        secret: bool,
    },
    Status,
}

impl HwKeyAction {
    pub fn new(matches: &ArgMatches) -> HwKeyAction {
        match matches.subcommand() {
            Some(("add", sub)) => HwKeyAction {
                command: HwKeyCommand::Add {
                    slot: sub
                        .get_one::<String>("slot")
                        .and_then(|s| s.parse::<u8>().ok()),
                    serial: sub.get_one::<u32>("serial").copied(),
                    phone: sub
                        .get_one::<bool>("phone")
                        .is_some_and(|v| *v)
                        .then(|| PhoneAdd {
                            page: sub.get_one::<String>("page").cloned(),
                            approver: sub.get_one::<String>("approver").cloned(),
                        }),
                },
            },
            Some(("remove", sub)) => HwKeyAction {
                command: HwKeyCommand::Remove {
                    secret: sub.get_one::<bool>("secret").is_some_and(|v| *v),
                },
            },
            _ => HwKeyAction {
                command: HwKeyCommand::Status,
            },
        }
    }
}

/// Which challenge-response factor a vault is enrolled with.
#[derive(Debug, Clone)]
enum Enrolled {
    Hwkey(HwKeyConfig),
    Phone(PhoneKeyConfig),
}

impl Enrolled {
    /// What to tell someone who tries to add a second factor.
    fn already_enrolled(&self, vault: &str) -> Error {
        let what = match self {
            Enrolled::Hwkey(_) => "A hardware key",
            Enrolled::Phone(_) => "A phone-held key",
        };
        Error::new(&format!(
            "{what} is already enrolled for vault '{vault}'. Remove it first with 'passlane \
             hwkey remove'."
        ))
    }
}

fn enrolled(config: &VaultConfig) -> Option<Enrolled> {
    if let Some(hwkey) = &config.hwkey {
        return Some(Enrolled::Hwkey(hwkey.clone()));
    }
    config.phone_key.clone().map(Enrolled::Phone)
}

impl Action for HwKeyAction {
    fn run(&self) -> Result<String, Error> {
        match &self.command {
            HwKeyCommand::Add {
                slot,
                serial,
                phone,
            } => match phone {
                Some(phone) => self.run_add_phone(phone),
                None => self.run_add_hwkey(*slot, *serial),
            },
            HwKeyCommand::Remove { secret } => self.run_remove(*secret),
            HwKeyCommand::Status => self.run_status(),
        }
    }
}

impl HwKeyAction {
    fn run_add_hwkey(&self, slot: Option<u8>, serial: Option<u32>) -> Result<String, Error> {
        let config = vault_registry::current()?;
        if let Some(enrolled) = enrolled(&config) {
            return Err(enrolled.already_enrolled(&config.name));
        }
        // Enrolling needs the new key touched to re-save the vault, and
        // perhaps the slot asked for. Neither happens for a command
        // without a terminal: refuse before anything is resolved or asked.
        if !at_a_terminal() {
            return Err(Error::new(&format!(
                "Enrolling a hardware key for vault '{}' needs the key touched to re-save the \
                 vault. Run 'passlane hwkey add' from a terminal with the key connected.",
                config.name
            )));
        }
        // Fail fast if no key is connected, before asking for the password.
        let (challenge_factor, hwkey_config) = hwkey::resolve_new_key(slot, serial)?;

        // The vault takes no challenge-response factor yet; the new one is
        // challenged by the save below.
        let mut vault = unlock_keepass(ChallengeKey::Given(None))?.vault;
        // The re-save challenges the new key, proving the enrollment
        // before the config is persisted.
        vault.update_challenge_factor(Some(challenge_factor))?;
        if let Err(e) = vault_registry::set_hwkey(&config.name, Some(hwkey_config.clone())) {
            // The vault now requires the key but passlane would not know
            // to use it (no persisted config): roll the factor back or
            // the vault can no longer be opened via passlane.
            if let Err(rollback) = vault.update_challenge_factor(None) {
                eprintln!(
                    "Warning: failed to roll back the hardware key enrollment: {}",
                    rollback
                );
            }
            return Err(e);
        }

        hwkey::print_backup_reminder();
        Ok(format!("Hardware key enrolled for vault '{}'", config.name))
    }

    /// `hwkey add --phone` (passlane#53): pair if needed, have the holder
    /// create the vault's key and its recovery sheet, then re-key.
    fn run_add_phone(&self, add: &PhoneAdd) -> Result<String, Error> {
        let config = vault_registry::current()?;
        if let Some(enrolled) = enrolled(&config) {
            return Err(enrolled.already_enrolled(&config.name));
        }

        // 1. Who holds the key. An already-pinned approver is used unless
        //    told otherwise; with none pinned, pair first.
        let holder = choose_holder(add.approver.as_deref(), add.page.as_deref())?;
        let holder_kid = holder
            .enc_kid()
            .map_err(|e| Error::new(&format!("the pinned approver's key is unusable: {e}")))?;
        println!(
            "Asking '{}' to create the key for vault '{}'. On that device: print or save the \
             recovery sheet it shows, then scan or type the secret back from that copy — the \
             key is not enrolled until you do.",
            holder.label, config.name
        );
        println!("{}", enrollment_approval_notice());

        let dir = crate::approvals::state_dir();
        let source = Arc::new(LinkTransport::new(
            &dir,
            holder,
            crate::agent::requester(),
            Arc::new(crate::session_agent::AgentAnswerStore),
        ));

        // 2. Open the vault on the factors it has today — through the
        //    unlock chain, like any command — then create the key (gated
        //    on the recovery sheet) and re-key.
        let unlocked = unlock_keepass(ChallengeKey::Given(None))?;
        let mut password = unlocked.factors.master_password.to_string();
        let recorded = enroll_and_record(
            &config,
            &password,
            &mut { unlocked }.vault,
            holder_kid,
            source,
            &|entry| vault_registry::set_phone_key(&config.name, entry),
        );
        password.zeroize();
        let enrolled = recorded?;

        Ok(format!(
            "Phone-held key enrolled for vault '{}' ({}). Every open and save now asks that \
             device for an approval; 'passlane unlock --session <secs>' holds one approval in \
             the session agent for repeated use. Keep the recovery sheet offline: without \
             that device, it is the only way in ('passlane hwkey remove --secret').",
            config.name,
            crate::actions::approvals::describe_holder(
                &enrolled,
                crate::approvals::load_peers_pinned(&crate::approvals::state_dir()),
            )
        ))
    }

    fn run_remove(&self, secret: bool) -> Result<String, Error> {
        let config = vault_registry::current()?;
        let Some(enrolled) = enrolled(&config) else {
            return Err(Error::new(&format!(
                "No hardware key or phone-held key is enrolled for vault '{}'.",
                config.name
            )));
        };
        // How the vault opens for the removal: recovery types its secret
        // in (a prompt, so a terminal); the enrolled factor otherwise —
        // the key on its device, or the holder over the link transport,
        // with a live session's held answer used first by the chain.
        let recovery_key;
        let key = match (&enrolled, secret) {
            (Enrolled::Phone(_), true) | (Enrolled::Hwkey(_), true) => {
                if !at_a_terminal() {
                    return Err(Error::new(&format!(
                        "Recovery needs the backed-up secret typed in. Run 'passlane hwkey remove \
                         --secret' for vault '{}' from a terminal.",
                        config.name
                    )));
                }
                recovery_key = hwkey::recovery_key_from_prompt()?;
                ChallengeKey::Given(Some(&recovery_key))
            }
            (Enrolled::Hwkey(hwkey_config), false) => match session_factors(&config.name)? {
                // A live session holds the vault's key factor: the key
                // itself is not needed, and no touch is asked for.
                SessionFactors::WithKeyFactor => ChallengeKey::Enrolled,
                held => {
                    // Without the key factor held, the enrolled key has to
                    // be touched.
                    if !at_a_terminal() {
                        return Err(hardware_key_needs_a_terminal(
                            &config,
                            held == SessionFactors::PasswordOnly,
                        ));
                    }
                    recovery_key =
                        ChallengeFactor::yubikey(hwkey_config.slot, hwkey_config.serial)?;
                    ChallengeKey::Given(Some(&recovery_key))
                }
            },
            // A phone-gated vault: the chain holds the session's answer or
            // asks the holder, exactly as for any command.
            (Enrolled::Phone(_), false) => ChallengeKey::Enrolled,
        };
        let mut vault = unlock_keepass(key)?.vault;
        // Delete the config before touching the vault: if deletion
        // fails, abort with the vault still protected by the factor,
        // rather than stripping the factor first and leaving passlane
        // demanding a factor the vault no longer requires.
        record_factor(&config.name, None)?;
        // A save without the factor needs no challenge.
        if let Err(e) = vault.update_challenge_factor(None) {
            // The vault on disk still requires the factor; put the config
            // back so passlane keeps using it.
            if let Err(restore_err) = record_factor(&config.name, Some(&enrolled)) {
                return Err(Error::new(&format!(
                    "Removing the second factor from the vault failed: {}. Restoring the \
                     enrollment also failed: {}. The vault still needs the factor — for a \
                     hardware key, re-add it to vault '{}' in {}; for a phone-held key, the \
                     device's key and the recovery sheet still open it.",
                    e,
                    restore_err,
                    config.name,
                    vault_registry::registry_file_display(),
                )));
            }
            return Err(e);
        }

        Ok(format!(
            "Second factor removed from vault '{}'. It now opens with the master password (and \
             keyfile) only. The recovery sheet and the device's key no longer open this vault.",
            config.name
        ))
    }

    fn run_status(&self) -> Result<String, Error> {
        let VaultConfig {
            name,
            path,
            hwkey,
            phone_key,
            ..
        } = vault_registry::current()?;
        let mut lines = Vec::new();
        match hwkey {
            Some(config) => {
                let serial = config
                    .serial
                    .map(|s| format!(" (key serial {})", s))
                    .unwrap_or_default();
                lines.push(format!(
                    "Hardware key enrolled for vault '{}': challenge-response slot {}{}",
                    name, config.slot, serial
                ));
            }
            None => lines.push(format!("No hardware key enrolled for vault '{}'.", name)),
        }
        let peers = crate::approvals::load_peers_pinned(&crate::approvals::state_dir());
        lines.push(match &phone_key {
            Some(phone_key) => format!(
                "Phone-held key enrolled for vault '{}': {}",
                name,
                crate::actions::approvals::describe_holder(phone_key, peers)
            ),
            None => format!("No phone-held key enrolled for vault '{}'.", name),
        });
        lines.push(format!("Vault '{}': {}", name, path));
        match ChallengeResponseKey::get_available_yubikeys() {
            Ok(keys) if keys.is_empty() => lines.push(String::from("No hardware keys detected.")),
            Ok(keys) => {
                lines.push(String::from("Connected hardware keys:"));
                for key in keys {
                    let name = key
                        .name
                        .as_deref()
                        .map(|n| format!(" ({})", n))
                        .unwrap_or_default();
                    lines.push(format!("  serial {}{}", key.serial_number, name));
                }
            }
            Err(e) => lines.push(format!("Could not list hardware keys: {}", e)),
        }
        Ok(lines.join("\n"))
    }
}

/// The enrollment ceremony's approval count, announced before the first
/// request goes out (passlane#72): the second approval's link arriving
/// unannounced after the first paste is when users lose track of which
/// response is current, so the sequence is named up front.
fn enrollment_approval_notice() -> &'static str {
    "This enrollment needs 2 approvals from that device: create the key, then save the vault \
     with it. Each approval answers its own fresh request — paste only the response the \
     terminal is waiting for; a response from an earlier request is refused."
}

/// Record (or clear) the vault's enrolled factor in the registry.
fn record_factor(vault: &str, factor: Option<&Enrolled>) -> Result<(), Error> {
    match factor {
        Some(Enrolled::Hwkey(hwkey)) => vault_registry::set_hwkey(vault, Some(hwkey.clone())),
        Some(Enrolled::Phone(phone)) => vault_registry::set_phone_key(vault, Some(phone.clone())),
        None => {
            vault_registry::set_hwkey(vault, None)?;
            vault_registry::set_phone_key(vault, None)
        }
    }
}

/// [`record_factor`] against an explicit registry directory (tests).
#[cfg(test)]
fn record_factor_to(
    dir: &std::path::Path,
    vault: &str,
    factor: Option<&Enrolled>,
) -> Result<(), Error> {
    match factor {
        Some(Enrolled::Hwkey(hwkey)) => {
            vault_registry::set_hwkey_to(dir, vault, Some(hwkey.clone()))
        }
        Some(Enrolled::Phone(phone)) => {
            vault_registry::set_phone_key_to(dir, vault, Some(phone.clone()))
        }
        None => {
            vault_registry::set_hwkey_to(dir, vault, None)?;
            vault_registry::set_phone_key_to(dir, vault, None)
        }
    }
}

/// The pinned approver that will hold the vault's key: the one named by
/// `--approver`, else the only one pinned, else the person's choice — and
/// when nothing is pinned at all, the **app pairing** ceremony runs first
/// (passlane#84). The page path stays explicit: a user without the app
/// runs `passlane approvals enroll` beforehand, and this command then
/// finds that pin here.
///
/// A terminal is needed only where a prompt cannot be avoided: pairing,
/// or choosing between several pinned approvers. With one pinned (or
/// `--approver`), everything else — the holder's answers and, through
/// the session agent, even the password — can arrive without a terminal,
/// so enrollment works over SSH or from an agent platform too.
fn choose_holder(
    approver: Option<&str>,
    page: Option<&str>,
) -> Result<passlane_approval::keys::PeerPin, Error> {
    let peers = crate::approvals::load_peers_pinned(&crate::approvals::state_dir())
        .map_err(|e| Error::new(&e))?;
    if approver.is_none() && peers.len() != 1 && !std::io::stdin().is_terminal() {
        return Err(Error::new(&match peers.as_slice() {
            [] => "nothing is pinned yet, and pairing needs an interactive terminal: run \
                   'passlane approvals pair' at a terminal — or 'passlane approvals enroll' \
                   for the approval-page path — then re-run this command"
                .to_string(),
            many => format!(
                "several approvers are pinned ({}), and choosing needs an interactive \
                 terminal: name one with --approver <label>",
                many.iter()
                    .map(|peer| peer.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }));
    }
    if let Some(label) = approver {
        return peers
            .iter()
            .find(|peer| peer.label == label)
            .cloned()
            .ok_or_else(|| {
                let known: Vec<&str> = peers.iter().map(|peer| peer.label.as_str()).collect();
                Error::new(&format!(
                    "No pinned approver labeled '{label}'. {}",
                    if known.is_empty() {
                        "Nothing is pinned yet; run this without --approver to pair the app \
                         first (or 'passlane approvals enroll' for the approval page)."
                            .to_string()
                    } else {
                        format!("Pinned approvers: {}.", known.join(", "))
                    }
                ))
            });
    }
    match peers.as_slice() {
        [] => {
            println!(
                "No approver is pinned yet, so pair first: the iOS app you pair now will hold \
                 the key for this vault. (No app? Cancel here, run 'passlane approvals enroll' \
                 to pin the approval page, then re-run this command.)"
            );
            Ok(crate::actions::approvals::pair_approver(page)?)
        }
        [one] => {
            println!(
                "The pinned approver '{}' will hold the key (override with --approver).",
                one.label
            );
            Ok(one.clone())
        }
        many => {
            let labels: Vec<&str> = many.iter().map(|peer| peer.label.as_str()).collect();
            let choice = inquire::Select::new(
                "Which device should hold the key for this vault?",
                labels.clone(),
            )
            .prompt()
            .map_err(|_| Error::new("enrollment aborted: no device was chosen"))?;
            many.iter()
                .find(|peer| peer.label == choice)
                .cloned()
                .ok_or_else(|| Error::new("internal: the chosen approver disappeared"))
        }
    }
}

/// Enrol the vault with its holder's new key and record the factor.
///
/// `record` persists the registry entry. If it fails, the re-key is undone
/// (the vault goes back to opening on its old factors alone): a vault that
/// needs the phone while passlane does not know to ask would be locked
/// out of its own CLI.
fn enroll_and_record(
    config: &VaultConfig,
    password: &str,
    vault: &mut KeepassVault,
    holder_kid: String,
    source: Arc<dyn ResponseSource>,
    record: &dyn Fn(Option<PhoneKeyConfig>) -> Result<(), Error>,
) -> Result<PhoneKeyConfig, Error> {
    // The holder-side identity, derived (not random): a resumed
    // enrollment — the re-run that consumes an approval given to the
    // first — asks under the same id the first one did, so the holder's
    // key is found; and a later rename keeps it, since the path does not
    // move.
    let vault_uid = PhoneKeyConfig::assigned_vault_uid(&holder_kid, &config.path);
    let enrollment = crate::phone_key::enroll::enroll(config, vault, password, &vault_uid, source)?;
    let phone_key = PhoneKeyConfig {
        holder_kid,
        vault_uid: Some(vault_uid),
        enrolled_at: enrollment.enrolled_at,
    };
    if let Err(e) = record(Some(phone_key.clone())) {
        return match crate::phone_key::enroll::rollback_enrollment(vault) {
            Ok(()) => Err(Error::new(&format!(
                "{} The phone-held key was not enrolled; the vault is as it was.",
                e.message
            ))),
            Err(rollback) => Err(Error::new(&format!(
                "{} Rolling the phone-held key back also failed: {}. The vault file now needs \
                 the phone-held key, but passlane does not know that yet — retry 'passlane \
                 hwkey add --phone', or recover with the recovery sheet ('passlane hwkey \
                 remove --secret').",
                e.message, rollback
            ))),
        };
    }
    Ok(phone_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_key::tests::MockPhone;
    use crate::phone_key::{Answer, open_key};
    use passlane_approval::message::Operation;
    use passlane_core::vault::vault_trait::PasswordVault;

    const SECRET: [u8; 20] = [0x3c; 20];
    const KID: &str = "0123456789abcdef";

    /// A registered-style config for a fresh vault with no second factor.
    fn plain_vault(dir: &std::path::Path) -> (VaultConfig, Vec<u8>) {
        let path = dir.join("vault.kdbx");
        let path = path.to_str().unwrap();
        KeepassVault::new(path, "master-pw", None, None).unwrap();
        let config = VaultConfig {
            name: "work".to_string(),
            path: path.to_string(),
            keyfile: None,
            hwkey: None,
            phone_key: None,
        };
        (config.clone(), std::fs::read(&config.path).unwrap())
    }

    /// A holder that will not answer: the phone is lost.
    struct LostPhone;

    impl ResponseSource for LostPhone {
        fn respond(
            &self,
            _: &crate::phone_key::PhoneRequest,
        ) -> Result<Answer, crate::phone_key::ResponseError> {
            Err(crate::phone_key::ResponseError::Unavailable(
                "the phone is lost".into(),
            ))
        }
    }

    #[test]
    fn enrolling_records_the_factor_and_the_vault_needs_the_phone() {
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        let recorded = std::cell::RefCell::new(Vec::new());

        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let enrolled = enroll_and_record(
            &config,
            "master-pw",
            &mut vault,
            KID.to_string(),
            phone.clone(),
            &|entry| {
                recorded.borrow_mut().push(entry);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(recorded.borrow().len(), 1);
        assert_eq!(recorded.borrow()[0], Some(enrolled.clone()));
        assert_eq!(enrolled.holder_kid, KID);
        assert!(enrolled.enrolled_at > 0);
        assert_ne!(std::fs::read(&config.path).unwrap(), before);
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_err());
        let key = open_key(&config, phone).unwrap();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", &config.path, None, Some(&key))
                .is_ok()
        );
    }

    #[test]
    fn a_failed_registry_write_rolls_the_re_key_back() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));

        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let err = enroll_and_record(
            &config,
            "master-pw",
            &mut vault,
            KID.to_string(),
            phone,
            &|_| Err(Error::new("registry is read-only")),
        )
        .unwrap_err();
        assert!(
            err.message.contains("registry is read-only"),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("the vault is as it was"),
            "{}",
            err.message
        );
        // And it is: no second factor needed again.
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_ok());
    }

    #[test]
    fn a_refusal_never_reaches_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        phone.refuse(crate::phone_key::ResponseError::Denied("no".into()));

        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let err = enroll_and_record(
            &config,
            "master-pw",
            &mut vault,
            KID.to_string(),
            phone,
            &|_| panic!("nothing may be recorded for a refused enrollment"),
        )
        .unwrap_err();
        assert!(
            err.message.contains("refused by the approver: no"),
            "{}",
            err.message
        );
        assert_eq!(std::fs::read(&config.path).unwrap(), before);
    }

    #[test]
    fn removing_a_phone_key_by_phone_strips_the_factor() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let enrolled = enroll_and_record(
            &config,
            "master-pw",
            &mut vault,
            KID.to_string(),
            phone.clone(),
            &|_| Ok(()),
        )
        .unwrap();

        // Opening to remove it needs one approval; the save that strips
        // the factor needs none.
        let mark = phone.mark();
        let key = open_key(&config, phone.clone()).unwrap();
        let recorded = std::cell::RefCell::new(Vec::new());
        remove_factor(
            &config,
            "master-pw",
            &key,
            Enrolled::Phone(enrolled),
            &|left| {
                recorded.borrow_mut().push(left.is_some());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*recorded.borrow(), vec![false]);
        assert_eq!(
            phone
                .asked_since(mark)
                .iter()
                .map(|r| r.operation.clone())
                .collect::<Vec<_>>(),
            [Operation::Unlock],
            "one approval, for the open — the strip itself asks nothing"
        );
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_ok());
    }

    /// The strip-and-forget half of [`HwKeyAction::run_remove`], with the
    /// registry writes injected: record(None) before the re-save, and the
    /// enrollment put back when the re-save fails.
    fn remove_factor(
        config: &VaultConfig,
        password: &str,
        challenge_response: &ChallengeFactor,
        enrolled: Enrolled,
        record: &dyn Fn(Option<&Enrolled>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut vault = KeepassVault::open_with_challenge_factor(
            password,
            &config.path,
            None,
            Some(challenge_response),
        )?;
        record(None)?;
        // A save without the factor needs no challenge.
        if let Err(e) = vault.update_challenge_response(None) {
            if let Err(restore_err) = record(Some(&enrolled)) {
                return Err(Error::new(&format!(
                    "Removing the second factor from the vault failed: {}. Restoring the \
                     enrollment also failed: {}.",
                    e, restore_err
                )));
            }
            return Err(e);
        }
        Ok(())
    }

    /// The acceptance criterion for a lost phone: the secret on the
    /// recovery sheet — read back as `LocalChallenge`, which is what a
    /// YubiKey programmed from the sheet computes too — still gets in.
    #[test]
    fn the_recovery_sheet_secret_removes_a_lost_phones_key() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let enrolled = enroll_and_record(
            &config,
            "master-pw",
            &mut vault,
            KID.to_string(),
            phone,
            &|_| Ok(()),
        )
        .unwrap();

        // The phone is gone: opening it the normal way has no answer.
        let key = open_key(&config, Arc::new(LostPhone)).unwrap();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", &config.path, None, Some(&key))
                .is_err(),
            "a lost phone cannot open the vault"
        );

        // Recover with the sheet.
        let from_sheet = ChallengeFactor::from_existing_secret_hex(
            &passlane_approval::encoding::hex_encode(&SECRET),
        )
        .unwrap();
        let vault = KeepassVault::open_with_challenge_factor(
            "master-pw",
            &config.path,
            None,
            Some(&from_sheet),
        )
        .expect("the sheet secret opens the vault");
        assert_eq!(vault.grep(None).len(), 0);

        remove_factor(
            &config,
            "master-pw",
            &from_sheet,
            Enrolled::Phone(enrolled),
            &|_| Ok(()),
        )
        .unwrap();
        let vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        assert!(vault.grep(None).is_empty());
    }

    /// The registry entry is removed first; if the re-save that strips
    /// the factor then fails, the entry is put back — otherwise passlane
    /// would stop asking for a factor the vault still needs.
    #[test]
    fn a_failed_strip_puts_the_enrollment_back() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let enrolled = enroll_and_record(
            &config,
            "master-pw",
            &mut vault,
            KID.to_string(),
            phone.clone(),
            &|_| Ok(()),
        )
        .unwrap();
        let enrolled_bytes = std::fs::read(&config.path).unwrap();
        let mark = phone.mark();
        let key = open_key(&config, phone.clone()).unwrap();

        // `record` runs between the open and the re-save. Its first call
        // swaps the vault file for a directory, so the atomic save cannot
        // rename over it; its second call puts the file back.
        let parked = dir.path().join("parked.kdbx");
        let recorded = std::cell::RefCell::new(Vec::new());
        let err = remove_factor(
            &config,
            "master-pw",
            &key,
            Enrolled::Phone(enrolled.clone()),
            &|left| {
                match left {
                    None => {
                        std::fs::rename(&config.path, &parked).unwrap();
                        std::fs::create_dir(&config.path).unwrap();
                    }
                    Some(restored) => {
                        std::fs::remove_dir(&config.path).unwrap();
                        std::fs::rename(&parked, &config.path).unwrap();
                        let Enrolled::Phone(restored) = restored else {
                            panic!("a phone-held key is restored as one");
                        };
                        assert_eq!(restored, &enrolled, "the same enrollment is restored");
                    }
                }
                recorded.borrow_mut().push(left.is_some());
                Ok(())
            },
        )
        .unwrap_err();
        let _ = &err;
        assert_eq!(
            *recorded.borrow(),
            vec![false, true],
            "removed, then put back"
        );

        // The vault is byte for byte as it was, and still needs the phone.
        assert_eq!(std::fs::read(&config.path).unwrap(), enrolled_bytes);
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_err());
        let key = open_key(&config, phone.clone()).unwrap();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", &config.path, None, Some(&key))
                .is_ok()
        );
        assert_eq!(
            phone.asked_since(mark).len(),
            2,
            "one approval per open; the failed save never asked"
        );
    }

    #[test]
    fn a_failed_registry_removal_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let enrolled = enroll_and_record(
            &config,
            "master-pw",
            &mut vault,
            KID.to_string(),
            phone.clone(),
            &|_| Ok(()),
        )
        .unwrap();
        let enrolled_bytes = std::fs::read(&config.path).unwrap();
        assert_ne!(enrolled_bytes, before);

        let mark = phone.mark();
        let key = open_key(&config, phone.clone()).unwrap();
        let err = remove_factor(
            &config,
            "master-pw",
            &key,
            Enrolled::Phone(enrolled),
            &|_| Err(Error::new("registry is read-only")),
        )
        .unwrap_err();
        assert_eq!(err.message, "registry is read-only");
        // The vault was not touched: it still needs exactly one approval
        // to open, from the phone that enrolled it.
        assert_eq!(std::fs::read(&config.path).unwrap(), enrolled_bytes);
        assert_eq!(
            phone.asked_since(mark).len(),
            1,
            "only the open asked; no save happened"
        );
    }

    #[test]
    fn the_enrollment_announces_its_approval_sequence_up_front() {
        // passlane#72: the ceremony's approvals must be countable by the
        // user — the count, both steps, and the one-paste rule.
        let notice = enrollment_approval_notice();
        assert!(notice.contains("2 approvals"), "{notice}");
        assert!(notice.contains("create the key"), "{notice}");
        assert!(notice.contains("save the vault"), "{notice}");
        assert!(
            notice.contains("only the response the terminal is waiting for"),
            "{notice}"
        );
        assert!(
            notice.contains("refused"),
            "it warns that an earlier request's response does not pass: {notice}"
        );
    }

    #[test]
    fn the_second_factor_messages_name_what_is_enrolled() {
        let hw = Enrolled::Hwkey(HwKeyConfig {
            slot: 2,
            serial: None,
        });
        let ph = Enrolled::Phone(PhoneKeyConfig {
            holder_kid: KID.into(),
            vault_uid: None,
            enrolled_at: 1,
        });
        let message = hw.already_enrolled("work").message;
        assert!(message.starts_with("A hardware key is already enrolled for vault 'work'"));
        assert!(message.contains("'passlane hwkey remove'"));
        assert!(
            ph.already_enrolled("work")
                .message
                .starts_with("A phone-held key")
        );
    }

    #[test]
    fn record_factor_writes_the_right_field() {
        let dir = tempfile::tempdir().unwrap();
        crate::vault_registry::add_vault_to(
            dir.path(),
            VaultConfig {
                name: "work".into(),
                path: "/abs/work.kdbx".into(),
                keyfile: None,
                hwkey: None,
                phone_key: None,
            },
        )
        .unwrap();
        let phone = Enrolled::Phone(PhoneKeyConfig {
            holder_kid: KID.into(),
            vault_uid: None,
            enrolled_at: 7,
        });
        record_factor_to(dir.path(), "work", Some(&phone)).unwrap();
        let vaults = crate::vault_registry::load_from(dir.path()).unwrap();
        assert_eq!(
            crate::vault_registry::find(&vaults, "work")
                .unwrap()
                .phone_key,
            Some(PhoneKeyConfig {
                holder_kid: KID.into(),
                vault_uid: None,
                enrolled_at: 7
            })
        );
        assert_eq!(
            crate::vault_registry::find(&vaults, "work").unwrap().hwkey,
            None
        );
        record_factor_to(dir.path(), "work", None).unwrap();
        let vaults = crate::vault_registry::load_from(dir.path()).unwrap();
        assert!(
            crate::vault_registry::find(&vaults, "work")
                .unwrap()
                .phone_key
                .is_none()
        );
    }
}
