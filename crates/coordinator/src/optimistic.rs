//! Optimistic acceptance: a result is provisionally accepted on
//! submission and becomes final when the challenge window closes
//! without a challenge. A challenge inside the window escalates to the
//! dispute game.
//!
//! This is the ~1x-overhead tier: no redundant execution unless someone
//! actually challenges. Its known weakness is the watcher problem —
//! nobody challenges if checking is unpaid — which the protocol answers
//! elsewhere (challenge bounty = slashed bond, protocol-funded random
//! audits). The state machine here is deliberately pure: the caller
//! decides whether the window is still open.

use crate::dispute::Verdict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Result submitted; window open.
    Awaiting,
    /// Window expired without challenge; the result is final.
    Accepted { hash: String },
    /// Challenged in time; the dispute game produced a verdict.
    Disputed { verdict: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    /// A bonded challenge arrives, with the counter-result's verdict
    /// already resolved by the dispute game.
    Challenge(&'a Verdict),
    /// The window closed with no challenge; carries the accepted hash.
    Expire(&'a str),
}

/// `window_open` is the caller's clock judgment: true while the
/// challenge window is still open.
pub fn transition(state: &State, event: &Event, window_open: bool) -> Result<State, String> {
    match (state, event) {
        (State::Awaiting, Event::Expire(hash)) => {
            if window_open {
                Err("window has not expired yet".into())
            } else {
                Ok(State::Accepted { hash: hash.to_string() })
            }
        }
        (State::Awaiting, Event::Challenge(verdict)) => {
            if !window_open {
                return Err("challenge arrived after the window closed".into());
            }
            Ok(State::Disputed { verdict: format!("{verdict:?}") })
        }
        (s, _) => Err(format!("terminal state {s:?} accepts no further events")),
    }
}

/// Convenience wrapper that fills in the accepted hash at expiry.
pub fn expire(state: &State, hash: &str) -> Result<State, String> {
    match state {
        State::Awaiting => Ok(State::Accepted { hash: hash.to_string() }),
        s => Err(format!("terminal state {s:?} accepts no further events")),
    }
}
