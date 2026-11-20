//! The `passlane-agent` binary: run the session agent until it is
//! stopped. Foreground by design — launchd/systemd/user-session managers
//! own the lifetime (see docs/features/session-agent.md).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::{Command, arg};
#[cfg(unix)]
use passlane_agent::AgentError;
#[cfg(unix)]
use passlane_agent::server::{
    AgentConfig, AgentServer, HARD_MAX_SESSION_SECS, default_max_session_secs,
};

#[cfg(unix)]
fn main() {
    env_logger::init();
    let matches = Command::new("passlane-agent")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Hold passlane vault unlock approvals in memory only, ssh-agent style: sessions live until expiry, revoke, lock or shutdown, and never touch disk.")
        .arg(
            arg!(--socket <PATH> "Unix domain socket to listen on. Defaults to $PASSLANE_AGENT_SOCK, else $XDG_RUNTIME_DIR/passlane-agent.sock, else $TMPDIR/passlane-agent.sock.")
                .env("PASSLANE_AGENT_SOCK"),
        )
        .arg(
            clap::Arg::new("max-session-secs")
                .long("max-session-secs")
                .value_name("SECONDS")
                .help("Longest session this agent will hold (default 900). Requests beyond it are refused; values above the hard cap are rejected.")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            clap::Arg::new("sweep-ms")
                .long("sweep-ms")
                .value_name("MILLIS")
                .help("Expired-session sweep interval in milliseconds (tests).")
                .value_parser(clap::value_parser!(u64))
                .hide(true),
        )
        .get_matches();

    let socket = matches
        .get_one::<String>("socket")
        .map(PathBuf::from)
        .or_else(passlane_agent::default_socket_path)
        .unwrap_or_else(|| {
            eprintln!(
                "No socket path known: pass --socket PATH or set {} (no per-user runtime \
                 directory found via XDG_RUNTIME_DIR or TMPDIR).",
                passlane_agent::SOCKET_ENV
            );
            std::process::exit(1);
        });

    let requested_cap = matches
        .get_one::<u64>("max-session-secs")
        .copied()
        .unwrap_or_else(default_max_session_secs);
    if requested_cap > HARD_MAX_SESSION_SECS {
        eprintln!(
            "--max-session-secs {requested_cap} exceeds the hard cap of {HARD_MAX_SESSION_SECS}s; \
             no session may be held that long."
        );
        std::process::exit(1);
    }

    let mut config = AgentConfig::new(&socket).with_max_session_secs(requested_cap);
    if let Some(ms) = matches.get_one::<u64>("sweep-ms").copied() {
        config = config.with_sweep_interval(std::time::Duration::from_millis(ms));
    }

    let server = match AgentServer::bind(config) {
        Ok(server) => server,
        Err(AgentError::AlreadyRunning(path)) => {
            eprintln!(
                "Another passlane-agent is already listening on {}. Not starting a second one.",
                path.display()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Could not bind the agent socket: {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "passlane-agent {} listening on {} (session cap {}s) — Ctrl+C to stop",
        env!("CARGO_PKG_VERSION"),
        socket.display(),
        requested_cap
    );

    let handle = Arc::new(Mutex::new(Some(server.handle())));
    {
        let handle = Arc::clone(&handle);
        ctrlc::set_handler(move || {
            if let Ok(mut guard) = handle.lock()
                && let Some(handle) = guard.take()
            {
                handle.stop();
            }
        })
        .expect("failed to install the signal handler");
    }

    match server.serve() {
        Ok(()) => {
            eprintln!("passlane-agent stopped; every session was dropped and wiped.");
        }
        Err(e) => {
            eprintln!("agent error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("passlane-agent needs a Unix domain socket; it supports macOS and Linux.");
    std::process::exit(1);
}
