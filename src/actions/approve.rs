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
    hand_over(
        handoff,
        crate::session_agent::agent_running(),
        &|vault, challenge, answer, scope| {
            crate::session_agent::create_challenge_response_session(
                vault, challenge, &answer, scope,
            )
            .map(|_| ())
        },
    )
}

/// [`keep_in_session_agent`] with the agent injected: `running` says
/// whether one would take the answer, `hold` hands it over.
fn hand_over(
    handoff: &ResponseHandoff<'_>,
    running: bool,
    hold: &dyn Fn(&str, &str, &str, Scope) -> Result<(), Error>,
) -> Result<(), String> {
    // Enrollment is answered where it started: that terminal is waiting
    // for the paste and goes on to re-key the vault itself.
    if handoff.kind == RequestKind::EnrollKey {
        return Err(
            "an enrollment request is answered at the terminal that started it: paste this \
             response there (the enrollment re-keys the vault itself)"
                .into(),
        );
    }
    if !running {
        return Err(format!(
            "this response (request {}…) carries the answer that {} but there is nowhere to \
             keep it: the session agent is not running. Start 'passlane-agent' (see \
             docs/features/session-agent.md) and present the response again, or re-run the \
             command in an interactive terminal and paste the response at its prompt",
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
                    _ => format!("opening vault '{vault}'"),
                };
                let next = match verified.kind {
                    // The command that is saving is still running, waiting.
                    RequestKind::Save => "The command that is saving continues now.",
                    // A command that could not wait has exited: re-run it.
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
    /// forward, and nothing is handed over.
    #[test]
    fn without_an_agent_the_handoff_refuses_with_a_way_forward() {
        for kind in [RequestKind::Unlock, RequestKind::Save] {
            let err = hand_over(&handoff(kind), false, &|_, _, _, _| {
                panic!("nothing may be handed over without an agent")
            })
            .unwrap_err();
            assert!(err.contains("nowhere to keep it"), "{err}");
            assert!(err.contains("'passlane-agent'"), "{err}");
            assert!(err.contains("present the response again"), "{err}");
            assert!(err.contains("interactive terminal"), "{err}");
        }
        let err =
            hand_over(&handoff(RequestKind::Unlock), false, &|_, _, _, _| panic!()).unwrap_err();
        assert!(err.contains("opens vault 'work'"), "{err}");
        let err =
            hand_over(&handoff(RequestKind::Save), false, &|_, _, _, _| panic!()).unwrap_err();
        assert!(err.contains("saves vault 'work'"), "{err}");
    }

    /// With an agent the answer goes there as lower-case hex, keyed by
    /// its challenge, with the scope the approver granted.
    #[test]
    fn with_an_agent_the_answer_is_held_in_memory() {
        for kind in [RequestKind::Unlock, RequestKind::Save] {
            hand_over(&handoff(kind), true, &|vault, challenge, answer, scope| {
                assert_eq!(vault, "work");
                assert_eq!(challenge, "ab".repeat(32));
                assert_eq!(answer, "07".repeat(20));
                assert_eq!(scope, Scope::Once);
                Ok(())
            })
            .unwrap();
        }
    }

    #[test]
    fn enrollment_is_answered_where_it_started() {
        let err = hand_over(&handoff(RequestKind::EnrollKey), true, &|_, _, _, _| {
            panic!("enrollment answers are not held by the agent")
        })
        .unwrap_err();
        assert!(
            err.contains("answered at the terminal that started it"),
            "{err}"
        );
    }

    #[test]
    fn an_agent_that_refuses_is_reported() {
        let err = hand_over(&handoff(RequestKind::Unlock), true, &|_, _, _, _| {
            Err(Error::new("session agent error: socket closed"))
        })
        .unwrap_err();
        assert!(err.contains("socket closed"), "{err}");
    }
}
