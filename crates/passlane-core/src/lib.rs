//! Platform-independent passlane core.
//!
//! Everything the CLI and mobile builds must share lives here: the
//! KeePass-backed vault ([`vault`]), the password generator ([`generator`])
//! and the pure hardware-key logic ([`hwkey`]). The `passlane` CLI crate
//! keeps only interactive plumbing — prompts, REPL, keychain, clipboard —
//! and consumes this crate, so there is a single kdbx implementation
//! instead of two drifting copies.
//!
//! The `usb` cargo feature (off by default, enabled by the CLI) turns on
//! real hardware-key support; without it the vault still opens with
//! password, keyfile and local challenge-response (recovery) factors.

pub mod generator;
pub mod hwkey;
pub mod vault;
