//! Errors for the session agent's client and server.

use crate::protocol::ErrorCode;

/// Everything that can go wrong talking to (or running) the agent.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Nothing is listening on the socket — the agent is not running.
    #[error("the session agent is not running (no listener on {0})")]
    NotRunning(String),
    /// Another agent already owns the socket.
    #[error("another passlane-agent is already listening on {0}")]
    AlreadyRunning(std::path::PathBuf),
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
