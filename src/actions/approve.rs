//! `passlane approve --response <blob>` (passlane#51): verify the
//! approver's answer with the protocol crate and release (or refuse) the
//! pending request it answers.

use clap::ArgMatches;

use passlane_core::vault::entities::{AgentPolicy, Error};

use crate::actions::Action;
use crate::agent::ApprovalLog;

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

impl Action for ApproveAction {
    fn run(&self) -> Result<String, Error> {
        let blob = self.response_blob()?;
        let outcome =
            crate::approvals::approve_response(&crate::approvals::state_dir(), &blob)
                .map_err(|e| Error::new(&e))?;
        let log = ApprovalLog::default_path();

        match outcome {
            crate::approvals::ApproveOutcome::Allowed {
                rid,
                vault,
                entry,
                field,
                once,
                until,
                has_unlock_response,
            } => {
                log.log_decision(&rid, &vault, &entry, &field, AgentPolicy::Ask, true);
                let target = if entry.is_empty() {
                    format!("unlocking vault '{vault}'")
                } else {
                    format!("revealing the {field} of '{entry}' in vault '{vault}'")
                };
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
                let unlock_note = if has_unlock_response {
                    " The response also carries an unlock factor; vault opening consumes it once phone-held keys ship (passlane#53)."
                } else {
                    ""
                };
                Ok(format!(
                    "Approved: {target} (request {}…). {reuse} Re-run the command that asked for it to proceed.{unlock_note}",
                    &rid[..8.min(rid.len())],
                ))
            }
            crate::approvals::ApproveOutcome::Denied {
                rid,
                vault,
                entry,
                field,
                reason,
            } => {
                log.log_decision(&rid, &vault, &entry, &field, AgentPolicy::Ask, false);
                let target = if entry.is_empty() {
                    format!("unlocking vault '{vault}'")
                } else {
                    format!("revealing the {field} of '{entry}' in vault '{vault}'")
                };
                let why = reason
                    .map(|r| format!(" Reason: {r}."))
                    .unwrap_or_default();
                Err(Error::new(&format!(
                    "The approver denied {target} (request {}…). The entry stays withheld.{why}",
                    &rid[..8.min(rid.len())],
                )))
            }
        }
    }
}
