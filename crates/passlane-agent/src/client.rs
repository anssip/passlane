//! The blocking client the `passlane` CLI (and tests) use to talk to a
//! running agent. One request is outstanding per connection at a time;
//! for pushed events use [`AgentClient::subscribe`].

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use passlane_approval::message::Scope;
use zeroize::Zeroizing;

use crate::error::AgentError;
use crate::protocol::{
    Event, GrantSpec, Request, Response, SessionInfo, decode, read_frame, write_frame,
};

/// A connection to a running agent.
pub struct AgentClient {
    stream: UnixStream,
    path: PathBuf,
}

/// What [`AgentClient::ping`] learned about the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongInfo {
    /// Protocol dialect version.
    pub version: u32,
    /// The agent's session-duration cap, seconds.
    pub max_session_secs: u64,
    /// Live session count.
    pub sessions: usize,
}

/// A freshly created session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSession {
    /// Session id.
    pub id: String,
    /// Expiry, unix seconds (`None` for `once`).
    pub expires_at: Option<u64>,
}

/// The answer to a reveal check: allowed (with the covering session's
/// expiry, or `None` when a `once` approval was just consumed) or not
/// covered by any live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealAnswer {
    /// A live session covers the reveal. `until` is its expiry (unix
    /// seconds) for timed sessions, or `None` for a consumed `once`
    /// approval.
    Allowed {
        /// Expiry of the covering session, if any.
        until: Option<u64>,
    },
    /// No live session covers this reveal.
    Denied,
}

impl AgentClient {
    /// Connect to the agent listening on `path`. Connection-refused and
    /// no-such-socket map to [`AgentError::NotRunning`] so callers can
    /// degrade gracefully (the agent is optional).
    pub fn connect(path: &Path) -> Result<AgentClient, AgentError> {
        match UnixStream::connect(path) {
            Ok(stream) => Ok(AgentClient {
                stream,
                path: path.to_path_buf(),
            }),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                Err(AgentError::NotRunning(path.display().to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The socket this client is connected to.
    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    fn call(&mut self, request: Request) -> Result<Response, AgentError> {
        write_frame(&mut self.stream, &request)?;
        let frame = read_frame(&mut self.stream)?;
        match decode(&frame)? {
            Response::Error { code, message } => Err(AgentError::Server { code, message }),
            response => Ok(response),
        }
    }

    /// Probe the agent: version, session cap and live session count.
    pub fn ping(&mut self) -> Result<PongInfo, AgentError> {
        match self.call(Request::Ping)? {
            Response::Pong {
                version,
                max_session_secs,
                sessions,
            } => Ok(PongInfo {
                version,
                max_session_secs,
                sessions,
            }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Create a session. `Err(AgentError::Server { code:
    /// ErrorCode::TooLong, .. })` means the requested duration exceeds
    /// the agent's cap.
    pub fn create_session(
        &mut self,
        vault: &str,
        grant: GrantSpec,
        scope: Scope,
    ) -> Result<CreatedSession, AgentError> {
        match self.call(Request::CreateSession {
            vault: vault.to_string(),
            grant,
            scope,
        })? {
            Response::SessionCreated { id, expires_at } => Ok(CreatedSession { id, expires_at }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Fetch a vault's unlock factors from a live session (consuming a
    /// `once`-scoped one).
    pub fn get_unlock_factors(&mut self, vault: &str) -> Result<Zeroizing<String>, AgentError> {
        match self.call(Request::GetUnlockFactors {
            vault: vault.to_string(),
        })? {
            Response::UnlockFactors { master_password } => Ok(master_password.into_inner()),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Does a live reveal session cover this entry field? A `Some`
    /// answer consumes a `once`-scoped approval; `Denied` means the
    /// caller falls back to the ask flow.
    pub fn check_reveal(
        &mut self,
        vault: &str,
        entry: &str,
        field: &str,
    ) -> Result<RevealAnswer, AgentError> {
        match self.call(Request::CheckReveal {
            vault: vault.to_string(),
            entry: entry.to_string(),
            field: field.to_string(),
        })? {
            Response::RevealCheck { allowed, until } => Ok(if allowed {
                RevealAnswer::Allowed { until }
            } else {
                RevealAnswer::Denied
            }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Live sessions, oldest first. Never contains secrets.
    pub fn list_sessions(&mut self) -> Result<Vec<SessionInfo>, AgentError> {
        match self.call(Request::ListSessions)? {
            Response::Sessions { list } => Ok(list),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke one session by id.
    pub fn revoke_session(&mut self, id: &str) -> Result<usize, AgentError> {
        match self.call(Request::RevokeSession { id: id.to_string() })? {
            Response::Revoked { count } => Ok(count),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke every session of one vault.
    pub fn revoke_vault(&mut self, vault: &str) -> Result<usize, AgentError> {
        match self.call(Request::RevokeVault {
            vault: vault.to_string(),
        })? {
            Response::Revoked { count } => Ok(count),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke every session.
    pub fn revoke_all(&mut self) -> Result<usize, AgentError> {
        match self.call(Request::RevokeAll)? {
            Response::Revoked { count } => Ok(count),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke everything the agent holds (it keeps running).
    pub fn lock(&mut self) -> Result<(), AgentError> {
        match self.call(Request::Lock)? {
            Response::Locked => Ok(()),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Turn this connection into an event stream. After subscribing, the
    /// agent pushes [`Event`] frames (revocation, expiry, lock
    /// notifications); no further requests can be sent on it.
    pub fn subscribe(mut self) -> Result<EventStream, AgentError> {
        match self.call(Request::Subscribe)? {
            Response::Subscribed => Ok(EventStream {
                stream: self.stream,
            }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }
}

/// A subscribed connection receiving pushed events.
pub struct EventStream {
    stream: UnixStream,
}

impl EventStream {
    /// Block until the next event, or error when the agent goes away.
    pub fn next_event(&mut self) -> Result<Event, AgentError> {
        let frame = read_frame(&mut self.stream)?;
        decode(&frame)
    }
}
