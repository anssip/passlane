use passlane_approval::message::Scope;

use crate::actions::{Action, unlock};
use crate::completion_cache;
use crate::keychain;
use crate::phone_key::{Answer, PhoneRequest};
use crate::vault_registry;
use crate::vault_registry::VaultConfig;
use passlane_core::vault::entities::Error;

pub struct UnlockAction {
    /// Hold the unlock factors in the session agent (memory only) for
    /// this many seconds instead of storing the password in the keychain.
    session_secs: Option<u64>,
}

impl UnlockAction {
    pub fn new(session_secs: Option<u64>) -> UnlockAction {
        UnlockAction { session_secs }
    }
}

/// What became of a phone-held key's answer under `unlock --session`.
#[derive(Debug, PartialEq, Eq)]
enum Held {
    /// The vault has no phone-held key.
    NotPhoneGated,
    /// The answer is in the agent until this unix time.
    Until(u64),
    /// No answer was obtained in this process.
    NoAnswer,
    /// The agent refused it; the agent's message.
    Refused(String),
}

/// `unlock --session` on a phone-gated vault: hold the answer that opened
/// the vault alongside the password, so the session really covers repeated
/// use — otherwise every command would have to ask the phone again.
///
/// `opened_with` yields the answer this process obtained for the vault's
/// current seed; `hold` hands (vault, challenge, answer, scope) to the
/// agent.
#[allow(clippy::type_complexity)]
fn hold_phone_answer(
    config: &VaultConfig,
    secs: u64,
    opened_with: impl FnOnce() -> Option<(PhoneRequest, Answer)>,
    hold: impl FnOnce(&str, &str, &[u8], Scope) -> Result<u64, Error>,
) -> Held {
    if config.phone_key.is_none() {
        return Held::NotPhoneGated;
    }
    let Some((request, answer)) = opened_with() else {
        return Held::NoAnswer;
    };
    // The wire carries a u32; the agent enforces its own, lower, cap.
    let seconds = secs.min(u32::MAX as u64) as u32;
    match hold(
        &config.name,
        &request.challenge_hex(),
        answer.response.as_slice(),
        Scope::Timed { seconds },
    ) {
        Ok(until) => Held::Until(until),
        Err(e) => Held::Refused(e.message),
    }
}

impl Action for UnlockAction {
    fn run(&self) -> Result<String, Error> {
        let config = vault_registry::current()?;
        if self.session_secs.is_some() {
            // Fail before prompting for the password if there is no
            // agent to hold the session.
            crate::session_agent::connect_or_error()?;
        }
        let vault = unlock()?;
        match self.session_secs {
            None => {
                keychain::save_master_password(&config.name, &vault.get_master_password())?;
                completion_cache::update_cache(&vault);
                Ok(format!("Vault '{}' unlocked", config.name))
            }
            Some(secs) => {
                let expires_at = crate::session_agent::create_unlock_session(
                    &config.name,
                    &vault.get_master_password(),
                    secs,
                )?;
                // The answer, if a phone gave one, goes in next — the
                // answer never outlives the password it opens with.
                let held = hold_phone_answer(
                    &config,
                    secs,
                    crate::phone_key::take_last_open_answer,
                    |vault, challenge, answer, scope| {
                        crate::session_agent::create_challenge_response_session(
                            vault,
                            challenge,
                            &passlane_approval::encoding::hex_encode(answer),
                            scope,
                        )
                    },
                );
                completion_cache::update_cache(&vault);
                let when = chrono::DateTime::from_timestamp(expires_at as i64, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| format!("+{secs}s"));
                let phone = match held {
                    Held::NotPhoneGated => String::new(),
                    Held::Until(_) => {
                        " The phone's approval is held with it, so commands will not ask \
                         again until then."
                            .to_string()
                    }
                    Held::NoAnswer => {
                        " The phone's approval could not be kept: each command will ask \
                         the phone again."
                            .to_string()
                    }
                    Held::Refused(message) => {
                        format!(
                            " The phone's approval could not be kept ({message}): each \
                             command will ask the phone again."
                        )
                    }
                };
                Ok(format!(
                    "Vault '{}' unlocked — the session agent holds the unlock factors until \
                     {} (memory only, nothing stored in the keychain; 'passlane lock' revokes \
                     it early).{}",
                    config.name, when, phone
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passlane_approval::message::Operation;
    use zeroize::Zeroizing;

    fn config(phone: bool) -> VaultConfig {
        VaultConfig {
            name: "work".into(),
            path: "/nonexistent/work.kdbx".into(),
            keyfile: None,
            hwkey: None,
            phone_key: phone.then(|| crate::vault_registry::PhoneKeyConfig {
                holder_kid: "0123456789abcdef".into(),
                enrolled_at: 1,
            }),
        }
    }

    fn opened() -> (PhoneRequest, Answer) {
        (
            PhoneRequest {
                vault_id: "work".into(),
                vault_name: "work".into(),
                operation: Operation::Unlock,
                challenge: [0xab; 32],
            },
            Answer {
                response: Zeroizing::new(vec![7; 20]),
                origin: crate::phone_key::AnswerOrigin::LinkTransport,
            },
        )
    }

    #[test]
    fn a_vault_without_a_phone_key_holds_nothing_extra() {
        let held = hold_phone_answer(
            &config(false),
            900,
            || panic!("never consulted"),
            |_, _, _, _| panic!("nothing is held"),
        );
        assert_eq!(held, Held::NotPhoneGated);
    }

    #[test]
    fn the_opening_answer_is_held_for_the_sessions_duration() {
        let held = hold_phone_answer(
            &config(true),
            900,
            || Some(opened()),
            |vault, challenge, answer, scope| {
                assert_eq!(vault, "work");
                assert_eq!(challenge, "ab".repeat(32));
                assert_eq!(answer, &[7u8; 20]);
                assert_eq!(scope, Scope::Timed { seconds: 900 });
                Ok(1_900)
            },
        );
        assert_eq!(held, Held::Until(1_900));
    }

    #[test]
    fn without_an_answer_nothing_is_held_and_nobody_is_asked() {
        let held = hold_phone_answer(
            &config(true),
            900,
            || None,
            |_, _, _, _| panic!("there is nothing to hold"),
        );
        assert_eq!(held, Held::NoAnswer);
    }

    #[test]
    fn an_agent_that_refuses_is_reported_not_hidden() {
        let held = hold_phone_answer(
            &config(true),
            900,
            || Some(opened()),
            |_, _, _, _| Err(Error::new("session agent error: gone")),
        );
        assert_eq!(held, Held::Refused("session agent error: gone".into()));
    }

    #[test]
    fn an_absurd_duration_is_clamped_to_the_wire_type() {
        let held = hold_phone_answer(
            &config(true),
            u64::MAX,
            || Some(opened()),
            |_, _, _, scope| {
                assert_eq!(scope, Scope::Timed { seconds: u32::MAX });
                Ok(0)
            },
        );
        assert_eq!(held, Held::Until(0));
    }
}
