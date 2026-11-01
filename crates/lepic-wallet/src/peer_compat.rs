// SPDX-License-Identifier: Apache-2.0
//! What the software behind each Epicbox key showed it is, learned only from messages the user's
//! own actions caused, and the rules derived from it (ADR 0016).
//!
//! The store keeps dates and feature bits per key; nothing here is stored that can be derived.
//! A key is LEPIC while its last marked message is newer than its last unmarked one, and Epic
//! otherwise. A plain notice to a payments address needs the key LEPIC with a marked message in
//! the last [`NOTICE_WINDOW`], and the exchange the notice is about must itself have come marked:
//! a non-LEPIC listener never acknowledges a notice, and the relay drops its whole queue after a
//! few unacknowledged rounds.

use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use lepic_epicbox::EpicboxAddress;
use lepic_node::NodeApi;
use lepic_store::{PeerCompat, Repositories, StoreError, WalletStore};
use tracing::instrument;

use crate::error::WalletError;
use crate::inbox::{InboxError, relay_network};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// How recent the last marked message from a key must be for a plain notice to go to it, and
/// how long an unmarked one keeps a key from being fresh.
pub const NOTICE_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Feature bit 0: the LEPIC marker and notices, claimed by every marker.
pub const MARKER_BIT: u32 = 1;

/// The software behind a key, as its own messages showed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKind {
    /// Nothing learned, or forgotten.
    Unknown,
    /// Its last marked message is newer than its last unmarked one.
    Lepic,
    /// Any other wallet: its last slate came without the marker, or it sent an invoice back.
    Epic,
}

/// What is stored about a key and what follows from it at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerFacts {
    /// What is stored; `None` when nothing is.
    pub stored: Option<PeerCompat>,
    pub kind: PeerKind,
    /// LEPIC, with a marked message within [`NOTICE_WINDOW`]: a plain notice about an exchange
    /// whose own incoming slate was marked may go to the key.
    pub notices: bool,
    /// As `notices`, and no unmarked slate within [`NOTICE_WINDOW`]: what a message the user did
    /// not ask the peer for needs.
    pub fresh: bool,
}

fn within(time: Option<Timestamp>, now: Timestamp) -> bool {
    let window = SignedDuration::try_from(NOTICE_WINDOW).unwrap_or(SignedDuration::MAX);
    time.is_some_and(|time| now.duration_since(time) <= window)
}

impl PeerFacts {
    pub fn derive(stored: Option<PeerCompat>, now: Timestamp) -> Self {
        let kind = match stored {
            None => PeerKind::Unknown,
            Some(PeerCompat {
                last_marked_at: Some(marked),
                last_unmarked_at,
                ..
            }) if last_unmarked_at.is_none_or(|unmarked| marked > unmarked) => PeerKind::Lepic,
            Some(compat) if compat.last_seen().is_none() => PeerKind::Unknown,
            Some(_) => PeerKind::Epic,
        };
        let notices =
            kind == PeerKind::Lepic && within(stored.and_then(|row| row.last_marked_at), now);
        let fresh = notices && !within(stored.and_then(|row| row.last_unmarked_at), now);
        Self {
            stored,
            kind,
            notices,
            fresh,
        }
    }
}

/// The facts about `key` at `now`.
pub(crate) fn facts(
    repos: &dyn Repositories,
    key: &str,
    now: Timestamp,
) -> Result<PeerFacts, StoreError> {
    Ok(PeerFacts::derive(repos.peer_compat(key)?, now))
}

/// Records an authenticated message from `key` that carried the LEPIC marker, or a notice from
/// it this wallet accepted. `features` are the bits the marker claimed, `None` for a marker
/// that claims none, which is bit 0 alone. A claim without a bit takes the bit from what works.
pub(crate) fn record_marked(
    repos: &mut dyn Repositories,
    key: &str,
    now: Timestamp,
    features: Option<u32>,
) -> Result<(), StoreError> {
    let mut compat = repos.peer_compat(key)?.unwrap_or_default();
    compat.last_marked_at = Some(now);
    compat.claimed = features.map_or(MARKER_BIT, |bits| bits | MARKER_BIT);
    compat.features_at = features.map(|_| now);
    compat.works = (compat.works | MARKER_BIT) & compat.claimed;
    repos.put_peer_compat(key, &compat)
}

/// Records a slate from `key` over Epicbox without the LEPIC marker, or an invoice it sent back
/// unchanged. The feature bits stay: another install on the same key may still use them.
pub(crate) fn record_unmarked(
    repos: &mut dyn Repositories,
    key: &str,
    now: Timestamp,
) -> Result<(), StoreError> {
    let mut compat = repos.peer_compat(key)?.unwrap_or_default();
    compat.last_unmarked_at = Some(now);
    repos.put_peer_compat(key, &compat)
}

/// Records what the authenticated slate from `key` showed: marked or not.
pub(crate) fn record_slate(
    repos: &mut dyn Repositories,
    key: &str,
    now: Timestamp,
    marked: bool,
) -> Result<(), StoreError> {
    if marked {
        record_marked(repos, key, now, None)
    } else {
        record_unmarked(repos, key, now)
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// What this wallet learned about the software at `address` from its own messages over
    /// Epicbox, and what follows from it now. Matched on the key only. Reads only the store.
    ///
    /// Fails with [`InboxError::Address`] for an address that does not parse or is on the other
    /// network, and with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn peer_compat(&self, address: &str) -> Result<PeerFacts, InboxError> {
        let network = relay_network(self.config().network);
        let key = EpicboxAddress::parse_key(address, network)
            .map(|key| EpicboxAddress::key_text_of(&key, network))
            .map_err(InboxError::Address)?;
        let now = self.ports().clock.now();
        let session = self.session()?;
        Ok(session
            .store
            .read(|repos| Ok::<_, WalletError>(facts(repos, &key, now)?))?)
    }

    /// Deletes what is known of every key not heard from for `older_than`, and returns how many
    /// keys were forgotten. A forgotten key is unknown: it gets no notices until it is heard from
    /// again. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn forget_peers(&self, older_than: Duration) -> Result<usize, WalletError> {
        let now = self.ports().clock.now();
        let before = SignedDuration::try_from(older_than)
            .ok()
            .and_then(|age| now.checked_sub(age).ok())
            .unwrap_or(Timestamp::MIN);
        let session = self.session()?;
        let forgotten = session
            .store
            .write(|repos| Ok::<_, WalletError>(repos.forget_peers(before)?))?;
        tracing::debug!(count = forgotten, "peers forgotten");
        Ok(forgotten)
    }
}

// Tests may use plain arithmetic (docs/rules.md); clippy does not treat the helpers as tests.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use lepic_store::WalletStore;

    use super::*;

    const DAY: i64 = 24 * 60 * 60;

    fn at(day: i64) -> Option<Timestamp> {
        Some(Timestamp::from_second(1_790_000_000 + day * DAY).unwrap())
    }

    fn now() -> Timestamp {
        at(100).unwrap()
    }

    fn derive(marked: Option<i64>, unmarked: Option<i64>) -> PeerFacts {
        PeerFacts::derive(
            Some(PeerCompat {
                last_marked_at: marked.and_then(at),
                last_unmarked_at: unmarked.and_then(at),
                ..PeerCompat::default()
            }),
            now(),
        )
    }

    fn store() -> lepic_store::MemoryStore {
        lepic_store::MemoryStore::new(lepic_store::StoreKeys::from_bytes([1; 32], [2; 32]))
    }

    fn stored(store: &lepic_store::MemoryStore) -> PeerCompat {
        store
            .read(|repos| repos.peer_compat("key"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn a_marker_without_bits_claims_and_works_bit_zero_only() {
        let store = store();
        store
            .write(|repos| record_marked(repos, "key", now(), None))
            .unwrap();
        assert_eq!(
            stored(&store),
            PeerCompat {
                last_marked_at: Some(now()),
                claimed: MARKER_BIT,
                works: MARKER_BIT,
                ..PeerCompat::default()
            }
        );
    }

    #[test]
    fn a_claim_keeps_its_bits_and_the_time_and_a_later_claim_without_a_bit_drops_it() {
        let store = store();
        store
            .write(|repos| {
                record_marked(repos, "key", at(90).unwrap(), Some(0b110))?;
                let mut compat = repos.peer_compat("key")?.unwrap_or_default();
                compat.works |= 0b100;
                repos.put_peer_compat("key", &compat)
            })
            .unwrap();
        let first = stored(&store);
        assert_eq!(first.claimed, 0b111);
        assert_eq!(first.works, 0b101);
        assert_eq!(first.features_at, at(90));

        store
            .write(|repos| record_marked(repos, "key", now(), Some(0b010)))
            .unwrap();
        let later = stored(&store);
        assert_eq!(later.claimed, 0b011);
        assert_eq!(
            later.works, MARKER_BIT,
            "a bit no longer claimed stops working"
        );
        assert_eq!(later.features_at, Some(now()));
    }

    #[test]
    fn an_unmarked_slate_keeps_the_bits_and_turns_the_key_epic() {
        let store = store();
        store
            .write(|repos| {
                record_marked(repos, "key", at(90).unwrap(), Some(0b10))?;
                record_slate(repos, "key", now(), false)
            })
            .unwrap();
        let compat = stored(&store);
        assert_eq!((compat.claimed, compat.works), (0b11, MARKER_BIT));
        assert_eq!(compat.last_unmarked_at, Some(now()));
        assert_eq!(PeerFacts::derive(Some(compat), now()).kind, PeerKind::Epic);
    }

    #[test]
    fn nothing_stored_is_unknown_and_gets_nothing() {
        let facts = PeerFacts::derive(None, now());
        assert_eq!(facts.kind, PeerKind::Unknown);
        assert!(!facts.notices && !facts.fresh);
        assert_eq!(derive(None, None).kind, PeerKind::Unknown);
    }

    #[test]
    fn a_recent_marked_message_makes_a_fresh_lepic_key() {
        let facts = derive(Some(90), None);
        assert_eq!(facts.kind, PeerKind::Lepic);
        assert!(facts.notices && facts.fresh);
    }

    #[test]
    fn a_lepic_key_not_heard_from_in_thirty_days_gets_no_notice() {
        let facts = derive(Some(60), None);
        assert_eq!(facts.kind, PeerKind::Lepic);
        assert!(!facts.notices && !facts.fresh);
        assert!(derive(Some(70), None).notices, "exactly thirty days");
    }

    #[test]
    fn a_newer_unmarked_slate_makes_the_key_epic() {
        let facts = derive(Some(95), Some(96));
        assert_eq!(facts.kind, PeerKind::Epic);
        assert!(!facts.notices);
        assert_eq!(derive(Some(95), Some(95)).kind, PeerKind::Epic, "a tie");
        assert_eq!(derive(None, Some(1)).kind, PeerKind::Epic);
    }

    #[test]
    fn a_recent_unmarked_slate_keeps_a_lepic_key_from_being_fresh() {
        let facts = derive(Some(99), Some(80));
        assert_eq!(facts.kind, PeerKind::Lepic);
        assert!(facts.notices && !facts.fresh);
        assert!(derive(Some(99), Some(60)).fresh);
    }
}
