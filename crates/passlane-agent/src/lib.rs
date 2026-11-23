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
//!
//! The daemon and its transport are Unix-only (macOS, Linux). The
//! protocol, session and error types compile everywhere so the CLI —
//! which is built on Windows too — can link this crate and degrade
//! gracefully: on non-Unix platforms there is never an agent to talk to,
//! and [`AgentClient::connect`] fails with [`AgentError::NotRunning`].

#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod protocol;
#[cfg(unix)]
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
/// per-user). Candidate runtime directories that are writable by anyone
/// but the user (a shared `/tmp`, say) are rejected — another user could
/// pre-create the socket path and receive the secrets sent to it. `None`
/// when no private per-user runtime directory is known — the caller
/// should then ask for an explicit path rather than fall back to a shared
/// directory. Non-Unix platforms have no Unix domain sockets: `None`
/// unless `PASSLANE_AGENT_SOCK` is set (for symmetry; the client still
/// refuses to connect).
pub fn default_socket_path() -> Option<PathBuf> {
    socket_path_from(|name| std::env::var_os(name))
}

/// [`default_socket_path`] with the environment injected. Tests drive
/// this instead of changing the process environment, which every other
/// thread in the process — including the ones creating temporary
/// directories — reads concurrently.
pub fn socket_path_from(
    mut getenv: impl FnMut(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    if let Some(p) = getenv(SOCKET_ENV)
        && !p.is_empty()
    {
        return Some(PathBuf::from(p));
    }
    #[cfg(unix)]
    {
        for var in ["XDG_RUNTIME_DIR", "TMPDIR"] {
            if let Some(dir) = getenv(var)
                && !dir.is_empty()
                && runtime_dir_is_private(&dir)
            {
                return Some(PathBuf::from(dir).join(SOCKET_FILENAME));
            }
        }
    }
    None
}

/// A runtime directory qualifies only when it is not writable by group
/// or others. An attacker cannot chmod a directory they do not own, so
/// this is enough to rule out shared directories like `/tmp` being used
/// through a stray `TMPDIR`.
#[cfg(unix)]
fn runtime_dir_is_private(dir: &std::ffi::OsStr) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(dir) {
        Ok(meta) => meta.permissions().mode() & 0o022 == 0,
        Err(_) => false,
    }
}

pub use client::AgentClient;
pub use error::AgentError;
