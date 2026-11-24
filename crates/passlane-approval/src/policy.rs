//! Freshness and rate-limit policy.
//!
//! The same [`Policy`] values guard both directions: the CLI validates
//! responses and the phone/page validates requests. Clock skew between a Mac
//! and an iPhone is minutes at worst, so the default window of 120 seconds is
//! generous without opening replay room.
//!
//! Responses are validated by **decision time, not redemption time**
//! (SPEC §4, passlane#73): a relay round trip — link, phone, passkey,
//! copy, paste — can outlast the request's validity, and a decision the
//! approver made in time must not be voided by slow transport. The
//! decision time is the response header's authenticated `ts`; redemption
//! is bounded by [`Policy::redemption_deadline`] so the replay window
//! stays small.

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
    /// TTL for single-shot human ceremonies (`enroll_key`, `save`):
    /// printing a recovery sheet and finding a terminal routinely takes
    /// longer than an agent reveal, and approval fatigue is not the
    /// constraint there (passlane#73).
    pub ceremony_ttl_secs: u64,
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
            ceremony_ttl_secs: 900,
            max_ttl_secs: 900,
            max_clock_skew_secs: 120,
            max_session_secs: 900,
        }
    }
}

/// How many request TTLs a response may outlive its request and still be
/// redeemed (SPEC §4's total-lifetime bound). Two: one TTL for the
/// decision, one for the relay.
pub const REDEMPTION_TTL_FACTOR: u64 = 2;

impl Policy {
    /// This policy with the ceremony TTL in force — for `enroll_key` and
    /// `save` requests, whose relay round trip is a single-shot human
    /// ceremony rather than an agent reveal.
    pub fn for_ceremony(&self) -> Self {
        Self {
            ttl_secs: self.ceremony_ttl_secs,
            ..*self
        }
    }

    /// The latest a response to a request with this freshness window may
    /// be redeemed, whatever the approver's clock says: request creation
    /// plus [`REDEMPTION_TTL_FACTOR`] request TTLs. Both ends of the
    /// comparison are the redeeming machine's own clock (it minted the
    /// request), so no skew allowance applies.
    pub fn redemption_deadline(&self, request_ts: u64, request_exp: u64) -> u64 {
        let ttl = request_exp.saturating_sub(request_ts);
        request_ts.saturating_add(REDEMPTION_TTL_FACTOR * ttl)
    }

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

    /// Check the freshness of an approval **response** against the request
    /// it answers, by when the decision was made rather than when the
    /// response is redeemed (SPEC §4, passlane#73).
    ///
    /// - The response's `ts` is the approver's clock at the decision; the
    ///   request's `ts`/`exp` are the requester's. Skew tolerance applies
    ///   at both edges of the window: a decision stamped up to
    ///   [`Self::max_clock_skew_secs`] before the request existed or after
    ///   it expired still counts as in time.
    /// - The response's own `exp` no longer bounds redemption — a response
    ///   redeemed past it is accepted provided the decision was timely —
    ///   but its TTL shape is still checked.
    /// - Redemption is bounded: `now` must fall before
    ///   [`Self::redemption_deadline`], keeping the replay window small.
    pub fn validate_reply(
        &self,
        request_ts: u64,
        request_exp: u64,
        response: &Header,
        now: u64,
    ) -> Result<()> {
        let skew = self.max_clock_skew_secs;
        // Clock sanity of the response itself, as in [`Self::validate`]:
        // a decision stamped in the future is bogus regardless.
        if response.ts > now + skew {
            return Err(Error::ClockSkew(response.ts));
        }
        // TTL shape of the response: it was sealed for a bounded lifetime
        // even though redemption may outlive it.
        if response.exp <= response.ts {
            return Err(Error::Ttl);
        }
        if response.exp - response.ts > self.max_ttl_secs {
            return Err(Error::Ttl);
        }
        // The decision must have been made inside the request's validity
        // window, on the approver's clock, within skew of the requester's.
        let window_start = request_ts.saturating_sub(skew);
        let window_end = request_exp.saturating_add(skew);
        if response.ts < window_start || response.ts > window_end {
            return Err(Error::DecisionOutsideWindow {
                ts: response.ts,
                window_start,
                window_end,
            });
        }
        // Late redemption is allowed, but bounded (SPEC §4).
        let deadline = self.redemption_deadline(request_ts, request_exp);
        if now >= deadline {
            return Err(Error::RedemptionTooLate { now, deadline });
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

    // -- late redemption (passlane#73, SPEC §4) --

    /// The relay round trip outlasts the request: the decision `ts` is
    /// inside the window, the redemption is past `exp` — accepted.
    #[test]
    fn reply_decided_in_time_redeemed_late_is_accepted() {
        let policy = Policy::default();
        let (ts, exp) = (1000, 1300); // request window, ttl 300
        // Decided at 1250 (in time), redeemed at 1450 (past exp, inside
        // the bound 1000 + 2*300 = 1600).
        let response = header(1250, 1550);
        assert!(policy.validate_reply(ts, exp, &response, 1450).is_ok());
        // Even the very last second of the bound.
        assert!(policy.validate_reply(ts, exp, &response, 1599).is_ok());
    }

    /// Past the total-lifetime bound, nothing redeems: the replay window
    /// stays bounded no matter how timely the decision was.
    #[test]
    fn reply_past_the_redemption_bound_is_refused() {
        let policy = Policy::default();
        let (ts, exp) = (1000, 1300);
        let response = header(1250, 1550);
        let deadline = policy.redemption_deadline(ts, exp);
        assert_eq!(deadline, 1600);
        assert!(matches!(
            policy.validate_reply(ts, exp, &response, 1600),
            Err(Error::RedemptionTooLate {
                now: 1600,
                deadline: 1600
            })
        ));
        assert!(matches!(
            policy.validate_reply(ts, exp, &response, 2000),
            Err(Error::RedemptionTooLate {
                now: 2000,
                deadline: 1600
            })
        ));
    }

    /// The decision itself must be in time: stamped after the request's
    /// expiry (beyond skew) the response is worthless, however fast it is
    /// redeemed.
    #[test]
    fn reply_decided_after_the_window_is_refused() {
        let policy = Policy::default();
        let (ts, exp) = (1000, 1300);
        let skew = policy.max_clock_skew_secs;
        // Just inside the skew-extended window: accepted.
        let late = header(exp + skew, exp + skew + 300);
        assert!(
            policy
                .validate_reply(ts, exp, &late, exp + skew + 10)
                .is_ok()
        );
        // One second past it: refused.
        let too_late = header(exp + skew + 1, exp + skew + 301);
        assert!(matches!(
            policy.validate_reply(ts, exp, &too_late, exp + skew + 10),
            Err(Error::DecisionOutsideWindow { .. })
        ));
    }

    /// Clock skew, early direction: a phone clock running behind stamps
    /// the decision before the request existed; within skew that is in
    /// time, beyond it is not (and a future-dated decision beyond skew is
    /// refused outright).
    #[test]
    fn reply_clock_skew_both_directions() {
        let policy = Policy::default();
        let (ts, exp) = (1000, 1300);
        let skew = policy.max_clock_skew_secs;

        // Approver clock behind by `skew`: decision stamped at request
        // creation minus skew still counts as in time.
        let early = header(ts - skew, ts - skew + 300);
        assert!(policy.validate_reply(ts, exp, &early, 1100).is_ok());
        // Behind by more than skew: the decision predates the request.
        let too_early = header(ts - skew - 1, ts - skew + 299);
        assert!(matches!(
            policy.validate_reply(ts, exp, &too_early, 1100),
            Err(Error::DecisionOutsideWindow { .. })
        ));

        // Approver clock ahead: a decision stamped in the future beyond
        // skew is refused before the window check (clock sanity).
        let ahead = header(1100 + skew + 1, 1400 + skew + 1);
        assert!(matches!(
            policy.validate_reply(ts, exp, &ahead, 1100),
            Err(Error::ClockSkew(ts2)) if ts2 == 1100 + skew + 1
        ));
    }

    /// The response's own expiry no longer bounds redemption, but its TTL
    /// shape is still policy-checked.
    #[test]
    fn reply_ttl_shape_is_still_checked() {
        let policy = Policy::default();
        let (ts, exp) = (1000, 1300);
        // exp <= ts is nonsense.
        assert!(matches!(
            policy.validate_reply(ts, exp, &header(1250, 1250), 1400),
            Err(Error::Ttl)
        ));
        // A response claiming more than the max TTL is refused.
        assert!(matches!(
            policy.validate_reply(ts, exp, &header(1250, 1250 + policy.max_ttl_secs + 1), 1400),
            Err(Error::Ttl)
        ));
    }

    /// Ceremony requests (enroll_key, save) carry the longer TTL, and it
    /// stays inside the receiver's TTL ceiling.
    #[test]
    fn ceremony_policy_extends_the_request_ttl_within_the_cap() {
        let policy = Policy::default();
        let ceremony = policy.for_ceremony();
        assert!(ceremony.ttl_secs > policy.ttl_secs);
        assert!(ceremony.ttl_secs <= policy.max_ttl_secs);
        // The receiver side accepts a request sealed with it.
        let header = crate::message::Header {
            v: crate::message::VERSION,
            t: 3,
            n: "00".repeat(16),
            ts: 1000,
            exp: 1000 + ceremony.ttl_secs,
            skid: "a".repeat(16),
            rkid: "b".repeat(16),
            rid: "c".repeat(16),
        };
        assert!(
            ceremony
                .validate(&header, 1000 + ceremony.ttl_secs - 1)
                .is_ok()
        );
        // And the redemption bound scales with the actual request TTL.
        assert_eq!(
            policy.redemption_deadline(1000, 1000 + ceremony.ttl_secs),
            1000 + 2 * ceremony.ttl_secs
        );
    }
}
