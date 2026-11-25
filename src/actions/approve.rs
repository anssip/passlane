//! `passlane approve --response <blob>` (passlane#51): verify the
//! approver's answer with the protocol crate and release (or refuse) the
//! pending request it answers.
//!
//! A reveal's answer is a grant the ask flow consumes on re-run. The
//! answer to an unlock or save request is different in kind: it is the
//! bytes that open a vault (passlane#53). They are handed to the session
//! agent — memory only — for the command that is waiting or will be
//! re-run, and to nothing else: with no agent running the command refuses
//! before anything is recorded, so the same response can be presented
//! again once one is.

use clap::ArgMatches;

use passlane_approval::message::Scope;

use passlane_core::vault::entities::{AgentPolicy, Error};

use crate::actions::Action;
use crate::agent::ApprovalLog;
use crate::approvals::pending::RequestKind;
use crate::approvals::{ApproveOutcome, Disposition, ResponseHandoff};

pub struct ApproveAction {
    /// The pasted response envelope, or `@<file>` to read it from a file.
    response: String,
}

impl ApproveAction {
    pub fn new(matches: &ArgMatches) -> Self {
        Self {
            response: matches
                .get_one::<String>("response")
                .cloned()
                .unwrap_or_default(),
        }
    }

    /// The blob itself: pasted directly, or `@file` (scripting and tests).
    fn response_blob(&self) -> Result<String, Error> {
        let trimmed = self.response.trim();
        if let Some(path) = trimmed.strip_prefix('@') {
            std::fs::read_to_string(path)
                .map_err(|e| Error::new(&format!("could not read the response file '{path}': {e}")))
        } else {
            Ok(trimmed.to_string())
        }
    }
}

/// What the verification hands a challenge response over to: the session
/// agent. Failing here leaves the response unrecorded and presentable
/// again.
fn keep_in_session_agent(handoff: &ResponseHandoff<'_>) -> Result<(), String> {
    // The agent that takes the answer must be able to hold it as long as
    // the approver granted it: an agent started here (passlane#77) gets
    // a cap accommodating that scope.
    let needed = match handoff.scope {
        Scope::Once => 0,
        Scope::Timed { seconds } => seconds as u64,
    };
    hand_over(
        handoff,
        &move || {
            crate::session_agent::connect_or_start(needed)
                .map(|_| ())
                .map_err(|e| e.message)
        },
        &|vault, challenge, answer, scope| {
            crate::session_agent::create_challenge_response_session(vault, challenge, answer, scope)
                .map(|_| ())
        },
    )
}

/// An agent that can take an answer: (vault, challenge, answer-hex, scope).
type Hold = dyn Fn(&str, &str, &str, Scope) -> Result<(), Error>;

/// Makes an agent reachable (starting one when allowed); `Err` explains
/// why none could serve, and nothing has been handed over.
type Connect = dyn Fn() -> Result<(), String>;

/// [`keep_in_session_agent`] with the agent injected: `connect` ensures
/// an agent is reachable (or says why not), `hold` hands the answer over.
fn hand_over(handoff: &ResponseHandoff<'_>, connect: &Connect, hold: &Hold) -> Result<(), String> {
    if let Err(why) = connect() {
        return Err(format!(
            "this response (request {}…) carries the answer that {} but there is nowhere to \
             keep it: {why} Start 'passlane-agent' (see docs/features/session-agent.md) and \
             present the response again, or re-run the command in an interactive terminal \
             and paste the response at its prompt",
            rid_short(handoff.rid),
            match handoff.kind {
                RequestKind::Save => format!("saves vault '{}'", handoff.vault),
                _ => format!("opens vault '{}'", handoff.vault),
            }
        ));
    }
    let scope = match handoff.scope {
        Scope::Once => Scope::Once,
        Scope::Timed { seconds } => Scope::Timed { seconds },
    };
    let answer = passlane_approval::encoding::hex_encode(handoff.response);
    hold(
        handoff.vault,
        handoff.challenge.unwrap_or_default(),
        &answer,
        scope,
    )
    .map_err(|e| e.message)
}

/// The first characters of a request id, for messages.
fn rid_short(rid: &str) -> &str {
    &rid[..rid.len().min(8)]
}

impl Action for ApproveAction {
    fn run(&self) -> Result<String, Error> {
        let blob = self.response_blob()?;
        let verified = crate::approvals::verify_response(
            &crate::approvals::state_dir(),
            &blob,
            Disposition::Grant,
            &keep_in_session_agent,
        )
        .map_err(|e| Error::new(&e))?;
        let log = ApprovalLog::default_path();

        let is_reveal = verified.kind == RequestKind::Reveal;

        match verified.outcome {
            ApproveOutcome::Allowed {
                rid,
                vault,
                entry,
                field,
                once,
                until,
                ..
            } => {
                if is_reveal {
                    log.log_decision(&rid, &vault, &entry, &field, AgentPolicy::Ask, true);
                    let reuse = if once {
                        "The grant is single-use.".to_string()
                    } else {
                        format!(
                            "The grant is reusable until {}.",
                            chrono::DateTime::from_timestamp(i64::try_from(until).unwrap_or(0), 0)
                                .map(|t| t.to_rfc3339())
                                .unwrap_or_else(|| until.to_string())
                        )
                    };
                    return Ok(format!(
                        "Approved: revealing the {field} of '{entry}' in vault '{vault}' \
                         (request {}…). {reuse} Re-run the command that asked for it to proceed.",
                        rid_short(&rid)
                    ));
                }
                log.log_challenge_decision(&rid, &vault, verified.kind.label(), true);
                let target = match verified.kind {
                    RequestKind::Save => format!("saving vault '{vault}'"),
                    RequestKind::EnrollKey => {
                        format!("enrolling a phone-held key for vault '{vault}'")
                    }
                    _ => format!("opening vault '{vault}'"),
                };
                let next = match verified.kind {
                    // The command that is saving is still running, waiting.
                    RequestKind::Save => "The command that is saving continues now.",
                    // Commands that could not wait have exited: re-run them.
                    RequestKind::EnrollKey => "Re-run 'passlane hwkey add --phone' to continue.",
                    _ => "Re-run the command to proceed; the answer is used once.",
                };
                Ok(format!(
                    "Approved: {target} (request {}…). The answer is held in memory by the \
                     session agent — nowhere else. {next}",
                    rid_short(&rid)
                ))
            }
            ApproveOutcome::Denied {
                rid,
                vault,
                entry,
                field,
                reason,
            } => {
                if is_reveal {
                    log.log_decision(&rid, &vault, &entry, &field, AgentPolicy::Ask, false);
                    let why = reason.map(|r| format!(" Reason: {r}.")).unwrap_or_default();
                    return Err(Error::new(&format!(
                        "The approver denied revealing the {field} of '{entry}' in vault \
                         '{vault}' (request {}…). The entry stays withheld.{why}",
                        rid_short(&rid)
                    )));
                }
                log.log_challenge_decision(&rid, &vault, verified.kind.label(), false);
                let why = reason.map(|r| format!(" Reason: {r}.")).unwrap_or_default();
                Err(Error::new(&format!(
                    "The approver denied {} (request {}…). Nothing was opened or saved.{why}",
                    match verified.kind {
                        RequestKind::Save => format!("saving vault '{vault}'"),
                        RequestKind::EnrollKey => {
                            format!("enrolling a phone-held key for vault '{vault}'")
                        }
                        _ => format!("opening vault '{vault}'"),
                    },
                    rid_short(&rid)
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff(kind: RequestKind) -> ResponseHandoff<'static> {
        let challenge = Box::leak("ab".repeat(32).into_boxed_str());
        let rid = Box::leak("a".repeat(32).into_boxed_str());
        ResponseHandoff {
            rid,
            vault: "work",
            kind,
            challenge: Some(challenge),
            response: &[7u8; 20],
            scope: Scope::Once,
        }
    }

    /// Without an agent the answer has nowhere to go: refused with a way
    /// forward, the reason carried through, and nothing handed over.
    #[test]
    fn without_an_agent_the_handoff_refuses_with_a_way_forward() {
        let not_running = "the session agent is not running (no listener on \
                           /run/user/501/passlane-agent.sock)";
        for kind in [RequestKind::Unlock, RequestKind::Save] {
            let err = hand_over(
                &handoff(kind),
                &move || Err(not_running.to_string()),
                &|_, _, _, _| panic!("nothing may be handed over without an agent"),
            )
            .unwrap_err();
            assert!(err.contains("nowhere to keep it"), "{err}");
            assert!(err.contains(not_running), "{err}");
            assert!(err.contains("'passlane-agent'"), "{err}");
            assert!(err.contains("present the response again"), "{err}");
            assert!(err.contains("interactive terminal"), "{err}");
        }
        let err = hand_over(
            &handoff(RequestKind::Unlock),
            &move || Err(not_running.to_string()),
            &|_, _, _, _| panic!(),
        )
        .unwrap_err();
        assert!(err.contains("opens vault 'work'"), "{err}");
        let err = hand_over(
            &handoff(RequestKind::Save),
            &move || Err(not_running.to_string()),
            &|_, _, _, _| panic!(),
        )
        .unwrap_err();
        assert!(err.contains("saves vault 'work'"), "{err}");
    }

    /// An agent that cannot be reached for a configured-socket reason
    /// (or any other) surfaces its own explanation, not a generic
    /// "not running" — the depositor must see what is actually wrong.
    #[test]
    fn an_unusable_agent_surfaces_its_own_reason() {
        let err = hand_over(
            &handoff(RequestKind::Unlock),
            &move || {
                Err("session agent error: no passlane-agent is listening on \
                     /tmp/dead.sock, the socket named by PASSLANE_AGENT_SOCK. Start it with \
                     'passlane-agent' (see docs/features/session-agent.md for autostart \
                     setup), or unset PASSLANE_AGENT_SOCK to use the keychain or the \
                     password prompt instead."
                    .to_string())
            },
            &|_, _, _, _| panic!("nothing may be handed over"),
        )
        .unwrap_err();
        assert!(err.contains("nowhere to keep it"), "{err}");
        assert!(err.contains("unset PASSLANE_AGENT_SOCK"), "{err}");
    }

    /// With an agent the answer goes there as lower-case hex, keyed by
    /// its challenge, with the scope the approver granted.
    #[test]
    fn with_an_agent_the_answer_is_held_in_memory() {
        for kind in [RequestKind::Unlock, RequestKind::Save] {
            hand_over(
                &handoff(kind),
                &|| Ok(()),
                &|vault, challenge, answer, scope| {
                    assert_eq!(vault, "work");
                    assert_eq!(challenge, "ab".repeat(32));
                    assert_eq!(answer, "07".repeat(20));
                    assert_eq!(scope, Scope::Once);
                    Ok(())
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn an_enrollment_answer_is_held_for_the_re_run() {
        // 'hwkey add --phone' without a terminal exits with its link and
        // is re-run once the owner has approved from elsewhere.
        hand_over(
            &handoff(RequestKind::EnrollKey),
            &|| Ok(()),
            &|vault, challenge, answer, scope| {
                assert_eq!(vault, "work");
                assert_eq!(challenge, "ab".repeat(32));
                assert_eq!(answer, "07".repeat(20));
                assert_eq!(scope, Scope::Once);
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn an_agent_that_refuses_is_reported() {
        let err = hand_over(&handoff(RequestKind::Unlock), &|| Ok(()), &|_, _, _, _| {
            Err(Error::new("session agent error: socket closed"))
        })
        .unwrap_err();
        assert!(err.contains("socket closed"), "{err}");
    }
}
