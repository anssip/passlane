//! The passlane session agent (passlane#54): a small `ssh-agent`-style
//! daemon that holds vault unlock factors and timed approvals **in memory
//! only**, until they expire, are revoked, or the agent stops.
//!
//! - [`server`] runs inside the `passlane-agent` binary and listens on a
//!   Unix domain socket (0600, per-user directory).
//! - [`client`] is the thin blocking client the `passlane` CLI uses to
//!   consult the agent when unlocking a vault or resolving an approval.
//! - [`protocol`] is the wire format shared by both: length-prefixed JSON
//!   frames of [`protocol::Request`] / [`protocol::Response`], plus pushed
//!   [`protocol::Event`]s on subscribed connections (cooperative
//!   "forget it" notification when a session is revoked or expires).
//!
//! Sessions reuse the approval protocol's scope model
//! (`passlane_approval::Scope`: once / timed), so a timed approval granted
//! by the phone (once the link transport ships) becomes exactly one agent
//! session.
//!
//! Nothing in this crate writes key material to disk — the only file the
//! daemon ever creates is its socket. Session key material is held in
//! `zeroize`-protected buffers and wiped on expiry, revocation, lock and
//! shutdown. See docs/features/session-agent.md for the full design.

#![cfg(unix)]
#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod protocol;
pub mod server;
pub mod session;

use std::path::PathBuf;

/// Environment variable that overrides the agent socket path for both the
/// daemon and CLI clients (the `SSH_AUTH_SOCK` of passlane).
pub const SOCKET_ENV: &str = "PASSLANE_AGENT_SOCK";

/// The socket file name inside the runtime directory.
pub const SOCKET_FILENAME: &str = "passlane-agent.sock";

/// Where the agent's socket lives: `$PASSLANE_AGENT_SOCK`, else
/// `$XDG_RUNTIME_DIR/passlane-agent.sock` (Linux, per-user and 0700 by
/// spec), else `$TMPDIR/passlane-agent.sock` (macOS, where TMPDIR is
/// per-user). `None` when no per-user runtime directory is known — the
/// caller should then ask for an explicit path rather than fall back to a
/// shared directory like `/tmp`.
pub fn default_socket_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(SOCKET_ENV)
        && !p.is_empty()
    {
        return Some(PathBuf::from(p));
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR")
        && !dir.is_empty()
    {
        return Some(PathBuf::from(dir).join(SOCKET_FILENAME));
    }
    if let Some(dir) = std::env::var_os("TMPDIR")
        && !dir.is_empty()
    {
        return Some(PathBuf::from(dir).join(SOCKET_FILENAME));
    }
    None
}

pub use client::AgentClient;
pub use error::AgentError;
