//! Freshness and rate-limit policy.
//!
//! The same [`Policy`] values guard both directions: the CLI validates
//! responses and the phone/page validates requests. Clock skew between a Mac
//! and an iPhone is minutes at worst, so the default window of 120 seconds is
//! generous without opening replay room.

use std::collections::HashMap;
use std::time::Instant;

use crate::error::{Error, Result};
use crate::message::Header;

/// Freshness limits applied to every opened envelope, plus the session-scope
/// cap. One struct so the CLI, agent and app all agree on the numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// How long a sealed message stays valid (sets `header.exp = now + ttl`).
    pub ttl_secs: u64,
    /// Ceiling on message TTLs a receiver is willing to accept.
    pub max_ttl_secs: u64,
    /// How far a sender timestamp may lie in the future (or past, combined
    /// with expiry) from the receiver's clock.
    pub max_clock_skew_secs: u64,
    /// Ceiling on `Scope::Timed` seconds.
    pub max_session_secs: u64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            ttl_secs: 300,
            max_ttl_secs: 900,
            max_clock_skew_secs: 120,
            max_session_secs: 900,
        }
    }
}

impl Policy {
    /// Check header freshness against `now`.
    ///
    /// Order matters for error quality: clock sanity first (reject
    /// future-dated and stale timestamps), then TTL abuse, then expiry.
    pub fn validate(&self, header: &Header, now: u64) -> Result<()> {
        let skew = self.max_clock_skew_secs;
        if header.ts > now + skew {
            return Err(Error::ClockSkew(header.ts));
        }
        // A timestamp far in the past can only be legal if the message is
        // still inside its own expiry; `ts + max_ttl < now` means stale
        // regardless of what `exp` claims next.
        if header.ts + self.max_ttl_secs + skew < now {
            return Err(Error::ClockSkew(header.ts));
        }
        if header.exp <= header.ts {
            return Err(Error::Ttl);
        }
        if header.exp - header.ts > self.max_ttl_secs {
            return Err(Error::Ttl);
        }
        if now >= header.exp {
            return Err(Error::Expired(header.exp));
        }
        Ok(())
    }

    /// Validate a requested session scope.
    pub fn validate_scope(&self, scope: crate::message::Scope) -> Result<()> {
        let seconds = scope.seconds();
        if seconds > self.max_session_secs {
            return Err(Error::SessionTooLong(seconds));
        }
        Ok(())
    }
}

/// Hook for approval-prompt throttling (approval-fatigue resistance).
///
/// The phone side should refuse to *display* more than a bounded number of
/// requests per sender per window; the CLI should throttle request emission.
pub trait RateLimiter {
    /// Returns true if an event for `key` is allowed right now.
    fn allows(&mut self, key: &str) -> bool;
}

/// Reference sliding-window limiter: at most `max` events per `window`.
pub struct SlidingWindowRateLimiter {
    max: usize,
    window_secs: u64,
    events: HashMap<String, Vec<Instant>>,
}

impl SlidingWindowRateLimiter {
    /// At most `max` events per `window_secs` per key.
    pub fn new(max: usize, window_secs: u64) -> Self {
        Self {
            max,
            window_secs,
            events: HashMap::new(),
        }
    }
}

impl RateLimiter for SlidingWindowRateLimiter {
    fn allows(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = self.window_secs;
        let bucket = self.events.entry(key.to_string()).or_default();
        bucket.retain(|t| now.duration_since(*t).as_secs() < cutoff);
        if bucket.len() >= self.max {
            return false;
        }
        bucket.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(ts: u64, exp: u64) -> Header {
        Header {
            v: crate::message::VERSION,
            t: 3,
            n: "00".repeat(16),
            ts,
            exp,
            skid: "a".repeat(16),
            rkid: "b".repeat(16),
            rid: "c".repeat(16),
        }
    }

    #[test]
    fn fresh_message_passes() {
        let policy = Policy::default();
        assert!(policy.validate(&header(1000, 1100), 1050).is_ok());
    }

    #[test]
    fn expired_message_rejected() {
        let policy = Policy::default();
        assert!(matches!(
            policy.validate(&header(1000, 1100), 1100),
            Err(Error::Expired(1100))
        ));
        assert!(policy.validate(&header(1000, 1100), 1500).is_err());
    }

    #[test]
    fn future_timestamp_rejected() {
        let policy = Policy::default();
        let skew = policy.max_clock_skew_secs;
        assert!(
            policy
                .validate(&header(1000 + skew, 1000 + skew + 10), 1000)
                .is_ok()
        );
        let result = policy.validate(&header(1000 + skew + 1, 1000 + skew + 11), 1000);
        match result {
            Err(Error::ClockSkew(ts)) => assert_eq!(ts, 1000 + skew + 1),
            other => panic!("expected ClockSkew, got {other:?}"),
        }
    }

    #[test]
    fn stale_timestamp_rejected() {
        let policy = Policy::default();
        let now = 10_000;
        let old_ts = now - policy.max_ttl_secs - policy.max_clock_skew_secs - 1;
        assert!(policy.validate(&header(old_ts, now + 100), now).is_err());
    }

    #[test]
    fn oversized_ttl_rejected() {
        let policy = Policy::default();
        assert!(matches!(
            policy.validate(&header(1000, 1000 + policy.max_ttl_secs + 1), 1001),
            Err(Error::Ttl)
        ));
        // exp <= ts is nonsense
        assert!(policy.validate(&header(1000, 1000), 999).is_err());
    }

    #[test]
    fn scope_caps() {
        let policy = Policy::default();
        assert!(policy.validate_scope(crate::message::Scope::Once).is_ok());
        assert!(
            policy
                .validate_scope(crate::message::Scope::Timed {
                    seconds: policy.max_session_secs as u32
                })
                .is_ok()
        );
        assert!(
            policy
                .validate_scope(crate::message::Scope::Timed {
                    seconds: policy.max_session_secs as u32 + 1
                })
                .is_err()
        );
    }

    #[test]
    fn sliding_window_limiter() {
        let mut limiter = SlidingWindowRateLimiter::new(2, 3600);
        assert!(limiter.allows("a"));
        assert!(limiter.allows("a"));
        assert!(!limiter.allows("a"));
        assert!(limiter.allows("b"));
    }
}
