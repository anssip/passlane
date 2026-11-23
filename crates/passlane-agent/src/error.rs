//! Errors for the session agent's client and server.

use std::path::PathBuf;

use crate::protocol::ErrorCode;

/// Everything that can go wrong talking to (or running) the agent.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Nothing is listening on the socket — the agent is not running.
    #[error("the session agent is not running (no listener on {0})")]
    NotRunning(String),
    /// `PASSLANE_AGENT_SOCK` names a socket nothing is listening on.
    /// Unlike [`AgentError::NotRunning`] this is a configuration error,
    /// not an absent optional agent: the caller asked for this specific
    /// one, and quietly falling back to a prompt would hide that.
    #[error("no passlane-agent is listening on {0}, the socket named by PASSLANE_AGENT_SOCK")]
    NotListening(PathBuf),
    /// Another agent already owns the socket.
    #[error("another passlane-agent is already listening on {0}")]
    AlreadyRunning(std::path::PathBuf),
    /// The agent speaks another protocol dialect: one of the two binaries
    /// is stale. Continuing would work with silently incomplete factors.
    #[error("the session agent speaks protocol v{agent}, this client speaks v{client}")]
    VersionMismatch {
        /// Dialect the agent reported.
        agent: u32,
        /// Dialect this client speaks.
        client: u32,
    },
    /// Underlying I/O failure.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The peer spoke nonsense (bad frame, bad JSON, wrong message).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The agent answered with an application-level error.
    #[error("{message} ({code:?})")]
    Server {
        /// Machine-readable error class.
        code: ErrorCode,
        /// Human-readable detail.
        message: String,
    },
}
