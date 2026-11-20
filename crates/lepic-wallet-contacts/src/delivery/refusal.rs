// SPDX-License-Identifier: Apache-2.0
//! What a mailbox's refusal of a post means for the outbox: whether the post may go again, and
//! after how long.
//!
//! A refusal for a rate limit, for want of room or for a busy mailbox is passing: the outbox
//! posts again after the mailbox's wait, never sooner, and on its back-off. A busy relay names
//! no wait, so the back-off alone applies. Any other refusal is final. Epicmail names
//! a rate limit by its code on mux/1; a full mailbox, and every refusal on a short connection,
//! name their case in the description alone, so the phrases the mailbox writes are matched
//! here, in one place, and only when the code does not decide.

use std::time::Duration;

use lepic_epicbox::{MuxCode, RelayErrorKind, retry_in};

use super::epicbox::RefusalCode;

/// The start of a rate limit's description, on mux/1 ("Rate limit exceeded.") and on a short
/// connection ("Rate limit exceeded; retry in {s} s.").
const RATE_LIMITED: &str = "Rate limit exceeded";

pub(crate) use lepic_epicbox::RETRY_IN;

/// The starts of the descriptions of refusals for want of room: the receiver's slot is full,
/// the sender has too many messages waiting for it, the mailbox's storage is full.
const NO_ROOM: [&str; 3] = [
    "Recipient mailbox is full",
    "Too many messages from this sender are waiting",
    "Relay storage is full",
];

/// The longest wait a refusal is taken at; a longer one is cut to this. The payment's cutoff
/// ends the row in any case.
const MAX_WAIT: Duration = Duration::from_secs(24 * 60 * 60);

/// What a refusal means for the post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The post may go again: the refusal was for a rate limit or for want of room.
    pub(crate) retryable: bool,
    /// The wait the mailbox asked for before the next post, from its frame or its description.
    pub(crate) retry_after: Option<Duration>,
}

/// Reads a refusal of `code`, with the mailbox's `description` and the wait its frame named.
/// The code decides where it names the case; the description decides for a code that covers
/// several cases, or none. A refusal that names a wait is passing whatever its code.
pub(crate) fn classify(
    code: Option<&RefusalCode>,
    description: Option<&str>,
    retry_after: Option<Duration>,
) -> Refusal {
    let text = description.map(str::trim_start).unwrap_or_default();
    let retry_after = retry_after
        .or_else(|| retry_in(text))
        .map(|wait| wait.min(MAX_WAIT));
    let by_text =
        || text.starts_with(RATE_LIMITED) || NO_ROOM.iter().any(|room| text.starts_with(room));
    let retryable = retry_after.is_some()
        || match code {
            Some(
                RefusalCode::Mux(MuxCode::RateLimited) | RefusalCode::Relay(RelayErrorKind::Busy),
            ) => true,
            Some(
                RefusalCode::Mux(MuxCode::PostRefused | MuxCode::Other(_))
                | RefusalCode::Relay(RelayErrorKind::InvalidRequest),
            )
            | None => by_text(),
            Some(_) => false,
        };
    Refusal {
        retryable,
        retry_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mux(code: MuxCode) -> Option<RefusalCode> {
        Some(RefusalCode::Mux(code))
    }

    fn relay() -> Option<RefusalCode> {
        Some(RefusalCode::Relay(RelayErrorKind::InvalidRequest))
    }

    #[test]
    fn a_rate_limit_on_mux_is_passing_with_its_wait() {
        let refusal = classify(
            mux(MuxCode::RateLimited).as_ref(),
            Some("Rate limit exceeded."),
            Some(Duration::from_secs(12)),
        );
        assert_eq!(
            refusal,
            Refusal {
                retryable: true,
                retry_after: Some(Duration::from_secs(12)),
            }
        );
        let bare = classify(mux(MuxCode::RateLimited).as_ref(), None, None);
        assert!(bare.retryable);
        assert_eq!(bare.retry_after, None);
    }

    #[test]
    fn a_rate_limit_on_a_short_connection_is_passing_with_the_wait_it_names() {
        let refusal = classify(
            relay().as_ref(),
            Some("Rate limit exceeded; retry in 45 s."),
            None,
        );
        assert_eq!(
            refusal,
            Refusal {
                retryable: true,
                retry_after: Some(Duration::from_secs(45)),
            }
        );
    }

    #[test]
    fn a_busy_relay_is_passing() {
        let refusal = classify(
            Some(RefusalCode::Relay(RelayErrorKind::Busy)).as_ref(),
            None,
            None,
        );
        assert_eq!(
            refusal,
            Refusal {
                retryable: true,
                retry_after: None,
            }
        );
    }

    #[test]
    fn a_full_slot_is_passing() {
        for code in [mux(MuxCode::PostRefused), relay(), None] {
            let refusal = classify(
                code.as_ref(),
                Some("Recipient mailbox is full; try again later."),
                None,
            );
            assert!(refusal.retryable, "{code:?}");
            assert_eq!(refusal.retry_after, None);
        }
    }

    #[test]
    fn too_many_waiting_from_one_sender_is_passing() {
        for code in [mux(MuxCode::PostRefused), relay()] {
            let refusal = classify(
                code.as_ref(),
                Some("Too many messages from this sender are waiting for the recipient."),
                None,
            );
            assert!(refusal.retryable, "{code:?}");
        }
    }

    #[test]
    fn a_full_store_is_passing() {
        for code in [mux(MuxCode::PostRefused), relay()] {
            let refusal = classify(
                code.as_ref(),
                Some("Relay storage is full; try again later."),
                None,
            );
            assert!(refusal.retryable, "{code:?}");
        }
    }

    #[test]
    fn other_refusals_are_final() {
        let finals = [
            (
                mux(MuxCode::PostRefused),
                Some("Address host is not allowed."),
            ),
            (mux(MuxCode::Internal), None),
            (mux(MuxCode::BadSignature), Some("Rate limit exceeded.")),
            (relay(), Some("Invalid request.")),
            (relay(), None),
            (
                Some(RefusalCode::Relay(RelayErrorKind::UnknownError)),
                Some("Internal error; try again."),
            ),
            (Some(RefusalCode::Cancelled), None),
            (None, None),
        ];
        for (code, description) in finals {
            let refusal = classify(code.as_ref(), description, None);
            assert!(!refusal.retryable, "{code:?} {description:?}");
            assert_eq!(refusal.retry_after, None);
        }
    }

    #[test]
    fn a_refusal_that_names_a_wait_is_passing_and_the_wait_is_bounded() {
        let refusal = classify(
            mux(MuxCode::PostRefused).as_ref(),
            None,
            Some(Duration::from_secs(10 * 24 * 60 * 60)),
        );
        assert!(refusal.retryable);
        assert_eq!(refusal.retry_after, Some(MAX_WAIT));
        let unread = classify(
            relay().as_ref(),
            Some("Rate limit exceeded; retry in s."),
            None,
        );
        assert!(unread.retryable);
        assert_eq!(unread.retry_after, None);
    }
}
