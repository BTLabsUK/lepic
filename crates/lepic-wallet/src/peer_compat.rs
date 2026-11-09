// SPDX-License-Identifier: Apache-2.0
//! What the software behind each peer key showed it is, learned only from messages the user's
//! own actions caused, and the rules derived from it (ADR 0016).
//!
//! The store keeps dates and feature bits per key; nothing here is stored that can be derived.
//! A key is LEPIC while its last marked message is newer than its last unmarked one, and Epic
//! otherwise. A plain notice to a payments address needs the key LEPIC with a marked message in
//! the last [`NOTICE_WINDOW`], and the exchange the notice is about must itself have come marked:
//! a non-LEPIC listener never acknowledges a notice, and the relay drops its whole queue after a
//! few unacknowledged rounds.

use std::sync::Arc;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use lepic_node::NodeApi;
use lepic_store::{PeerCompat, Repositories, StoreError, WalletStore};
use lepic_transport::method::{Method, SenderFacts};
use tracing::instrument;

use crate::error::WalletError;
use crate::inbox::InboxError;
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

/// What a marked message showed about the key its native slates are sealed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeKey {
    /// The marker's claim: the key when it claimed native slates with a valid key, `None` when
    /// it did not. It replaces the stored key, as a newer claim does.
    Marker(Option<[u8; 32]>),
    /// The message carried no marker claim of its own, as a notice or a native slate: the stored
    /// key stays.
    Kept,
}

/// What an authenticated slate from a key showed: marked, with the claim of its marker, or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shown {
    pub(crate) marked: bool,
    /// The bits the marker claimed; `None` for a marker that claims none.
    pub(crate) features: Option<u32>,
    pub(crate) native: NativeKey,
}

impl Shown {
    /// A slate without the marker.
    pub(crate) const UNMARKED: Self = Self {
        marked: false,
        features: None,
        native: NativeKey::Kept,
    };

    /// What `facts`, read off a slate's wire, show to a wallet whose `native_direct` is as
    /// given. A wallet that sends no native slates records no key, so its rows stay as they
    /// were before native slates over Epicbox.
    pub(crate) fn of(facts: &SenderFacts, native_direct: bool) -> Self {
        let key = crate::native_epicbox::claimed_key(facts.features, facts.reply_key)
            .filter(|_| native_direct);
        Self {
            marked: facts.marked,
            features: facts.features,
            native: NativeKey::Marker(key),
        }
    }

    /// The same facts, keeping the stored native key: for a key that is only shown LEPIC by
    /// another key's slate, or a slate that came native.
    pub(crate) const fn keeping_key(self) -> Self {
        Self {
            native: NativeKey::Kept,
            ..self
        }
    }

    /// The same marking, with no claim: what the slate shows about a key it did not come from.
    pub(crate) const fn unclaimed(self) -> Self {
        Self {
            marked: self.marked,
            features: None,
            native: NativeKey::Kept,
        }
    }
}

/// Records an authenticated message from `key` that carried the LEPIC marker, or a notice from
/// it this wallet accepted. `features` are the bits the marker claimed, `None` for a marker
/// that claims none, which is bit 0 alone. A claim without a bit takes the bit from what works.
/// `native` sets the key native slates go to, or keeps it.
pub(crate) fn record_marked(
    repos: &mut dyn Repositories,
    key: &str,
    now: Timestamp,
    features: Option<u32>,
    native: NativeKey,
) -> Result<(), StoreError> {
    let mut compat = repos.peer_compat(key)?.unwrap_or_default();
    compat.last_marked_at = Some(now);
    compat.claimed = features.map_or(MARKER_BIT, |bits| bits | MARKER_BIT);
    compat.features_at = features.map(|_| now);
    compat.works = (compat.works | MARKER_BIT) & compat.claimed;
    if let NativeKey::Marker(native_key) = native {
        compat.native_key = native_key;
    }
    repos.put_peer_compat(key, &compat)
}

/// Records a slate from `key` over Epicbox without the LEPIC marker, or an invoice it sent back
/// unchanged. The feature bits and the native key stay: another install on the same key may
/// still use them.
pub(crate) fn record_unmarked(
    repos: &mut dyn Repositories,
    key: &str,
    now: Timestamp,
) -> Result<(), StoreError> {
    let mut compat = repos.peer_compat(key)?.unwrap_or_default();
    compat.last_unmarked_at = Some(now);
    repos.put_peer_compat(key, &compat)
}

/// Records what the authenticated slate from `key` showed.
pub(crate) fn record_slate(
    repos: &mut dyn Repositories,
    key: &str,
    now: Timestamp,
    shown: Shown,
) -> Result<(), StoreError> {
    if shown.marked {
        record_marked(repos, key, now, shown.features, shown.native)
    } else {
        record_unmarked(repos, key, now)
    }
}

/// The key native slates to `key` are sealed to, when this wallet sends them there: the
/// wallet's `native_direct` is on, the key is LEPIC with a marked message within
/// [`NOTICE_WINDOW`], and its latest marked slate claimed native slates with a valid key
/// (RFC 0003 11.1).
pub(crate) fn native_key(facts: &PeerFacts, native_direct: bool) -> Option<[u8; 32]> {
    if !native_direct || !facts.notices {
        return None;
    }
    facts.stored.and_then(|row| row.native_key)
}

/// Records the `features` a pairing envelope of `key` claimed, once the pairing proved the
/// key: they replace the claim of the key's latest marked message, as a newer claim does.
pub fn record_claim(
    repos: &mut dyn Repositories,
    key: &str,
    now: Timestamp,
    features: u32,
) -> Result<(), StoreError> {
    let mut compat = repos.peer_compat(key)?.unwrap_or_default();
    compat.claimed = features | MARKER_BIT;
    compat.features_at = Some(now);
    compat.works &= compat.claimed;
    repos.put_peer_compat(key, &compat)
}

/// Records that the feature `bit` worked with `key`, or failed. Only a claimed bit starts
/// working; a failure clears it whatever was claimed. Silence is never a failure: callers
/// report only what a message showed.
pub fn record_works(
    repos: &mut dyn Repositories,
    key: &str,
    bit: u32,
    worked: bool,
) -> Result<(), StoreError> {
    let Some(mut compat) = repos.peer_compat(key)? else {
        return Ok(());
    };
    let before = compat.works;
    if worked {
        compat.works |= bit & compat.claimed;
    } else {
        compat.works &= !bit;
    }
    if compat.works != before {
        repos.put_peer_compat(key, &compat)?;
    }
    Ok(())
}

/// Fails with [`InboxError::NotHostFeature`] unless `bit` is one host bit (device forwarding or
/// the name service).
fn check_host_feature(bit: u32) -> Result<(), InboxError> {
    use lepic_transport::marker::features::HOST_FEATURES;
    if !bit.is_power_of_two() || bit & HOST_FEATURES == 0 {
        return Err(InboxError::NotHostFeature);
    }
    Ok(())
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// What this wallet learned about the software at `address` of `method` from its own
    /// messages, and what follows from it now. Matched on the key under `method` only. Reads
    /// only the store.
    ///
    /// Fails with [`InboxError::Address`] for an address `method` names no key with on the
    /// wallet's network, and with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn peer_compat(
        &self,
        method: &Arc<dyn Method>,
        address: &str,
    ) -> Result<PeerFacts, InboxError> {
        let key = method
            .peer_key(self.config().network, address)
            .map_err(|error| InboxError::Address(Box::new(error)))?;
        self.peer_compat_by_key(&key)
    }

    /// [`Self::peer_compat`] of the peer stored under `key`, as a method's
    /// [`Method::peer_key`] gives it. Reads only the store. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn peer_compat_by_key(&self, key: &str) -> Result<PeerFacts, InboxError> {
        let now = self.ports().clock.now();
        let session = self.session()?;
        Ok(session
            .store
            .read(|repos| Ok::<_, WalletError>(facts(repos, key, now)?))?)
    }

    /// Records what the host app learned of one of its own features with the key of `address`
    /// under `method`: that it worked, or that it failed. Only the host bits (device forwarding and the name
    /// service) are taken; a bit the key never claimed does not start working. Sends nothing.
    ///
    /// Fails with [`InboxError::Address`] for an address `method` names no key with on the
    /// wallet's network, with [`InboxError::NotHostFeature`] for any other bit than one host bit, and with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn peer_feature_result(
        &self,
        method: &Arc<dyn Method>,
        address: &str,
        bit: u32,
        worked: bool,
    ) -> Result<(), InboxError> {
        check_host_feature(bit)?;
        let key = method
            .peer_key(self.config().network, address)
            .map_err(|error| InboxError::Address(Box::new(error)))?;
        self.peer_feature_result_by_key(&key, bit, worked)
    }

    /// [`Self::peer_feature_result`] for the peer stored under `key`, as a method's
    /// [`Method::peer_key`] gives it.
    ///
    /// Fails with [`InboxError::NotHostFeature`] for any other bit than one host bit, and with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn peer_feature_result_by_key(
        &self,
        key: &str,
        bit: u32,
        worked: bool,
    ) -> Result<(), InboxError> {
        check_host_feature(bit)?;
        let session = self.session()?;
        Ok(session
            .store
            .write(|repos| Ok::<_, WalletError>(record_works(repos, key, bit, worked)?))?)
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
            .write(|repos| record_marked(repos, "key", now(), None, NativeKey::Kept))
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
                record_marked(repos, "key", at(90).unwrap(), Some(0b110), NativeKey::Kept)?;
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
            .write(|repos| record_marked(repos, "key", now(), Some(0b010), NativeKey::Kept))
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
                record_marked(repos, "key", at(90).unwrap(), Some(0b10), NativeKey::Kept)?;
                record_slate(repos, "key", now(), Shown::UNMARKED)
            })
            .unwrap();
        let compat = stored(&store);
        assert_eq!((compat.claimed, compat.works), (0b11, MARKER_BIT));
        assert_eq!(compat.last_unmarked_at, Some(now()));
        assert_eq!(PeerFacts::derive(Some(compat), now()).kind, PeerKind::Epic);
    }

    #[test]
    fn a_marked_slate_records_the_bits_its_marker_claims() {
        let store = store();
        store
            .write(|repos| {
                record_slate(
                    repos,
                    "key",
                    now(),
                    Shown {
                        marked: true,
                        features: Some(0b1010),
                        native: NativeKey::Kept,
                    },
                )
            })
            .unwrap();
        let compat = stored(&store);
        assert_eq!((compat.claimed, compat.works), (0b1011, MARKER_BIT));
        assert_eq!(compat.features_at, Some(now()));
    }

    #[test]
    fn a_claimed_bit_works_only_once_it_worked_and_stops_on_a_failure() {
        let store = store();
        store
            .write(|repos| {
                record_marked(repos, "key", now(), Some(0b1000), NativeKey::Kept)?;
                // Not claimed: never starts working.
                record_works(repos, "key", 0b0100, true)?;
                record_works(repos, "key", 0b1000, true)
            })
            .unwrap();
        assert_eq!(stored(&store).works, 0b1001);
        store
            .write(|repos| record_works(repos, "key", 0b1000, false))
            .unwrap();
        assert_eq!(stored(&store).works, MARKER_BIT);
    }

    #[test]
    fn silence_changes_nothing() {
        let store = store();
        store
            .write(|repos| {
                record_marked(repos, "key", at(10).unwrap(), Some(0b1000), NativeKey::Kept)?;
                record_works(repos, "key", 0b1000, true)
            })
            .unwrap();
        let before = stored(&store);
        // Ninety days later nothing more arrived: what is known stays as it was.
        assert_eq!(stored(&store), before);
        assert_eq!(PeerFacts::derive(Some(before), now()).kind, PeerKind::Lepic);
        assert_eq!(before.works, 0b1001);
    }

    #[test]
    fn a_pairing_claim_replaces_the_bits_and_drops_what_no_longer_works() {
        let store = store();
        store
            .write(|repos| {
                record_marked(repos, "key", at(90).unwrap(), Some(0b1010), NativeKey::Kept)?;
                record_works(repos, "key", 0b1000, true)?;
                record_claim(repos, "key", now(), 0b0010)
            })
            .unwrap();
        let compat = stored(&store);
        assert_eq!((compat.claimed, compat.works), (0b0011, MARKER_BIT));
        assert_eq!(compat.features_at, Some(now()));
        assert_eq!(
            compat.last_marked_at,
            at(90),
            "a claim is not a marked message"
        );
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

    /// A valid X25519 public key.
    fn native() -> [u8; 32] {
        *lepic_contact::EncSecretKey::from_bytes([9; 32])
            .public_key()
            .as_bytes()
    }

    fn claim(features: u32, reply: Option<[u8; 32]>) -> Shown {
        Shown::of(&SenderFacts::new(true, Some(features), reply), true)
    }

    fn eligible(store: &lepic_store::MemoryStore, at: Timestamp, native_direct: bool) -> bool {
        let facts = store.read(|repos| facts(repos, "key", at)).unwrap();
        native_key(&facts, native_direct).is_some()
    }

    #[test]
    fn a_marker_claiming_native_slates_with_a_valid_key_makes_the_key_eligible() {
        use lepic_transport::marker::features::NATIVE_SLATES;
        let store = store();
        let record = |shown: Shown| {
            store
                .write(|repos| record_slate(repos, "key", now(), shown))
                .unwrap();
        };
        record(claim(1 | NATIVE_SLATES, Some(native())));
        assert_eq!(stored(&store).native_key, Some(native()));
        assert!(eligible(&store, now(), true));
        assert!(!eligible(&store, now(), false), "native_direct off");

        // A notice or a native slate keeps the key; a newer marker without the claim drops it.
        store
            .write(|repos| record_marked(repos, "key", now(), None, NativeKey::Kept))
            .unwrap();
        assert!(eligible(&store, now(), true));
        record(claim(1, Some(native())));
        assert_eq!(stored(&store).native_key, None);
        assert!(!eligible(&store, now(), true));

        // A claim whose key is not a valid public key is no claim.
        record(claim(1 | NATIVE_SLATES, Some([0; 32])));
        assert_eq!(stored(&store).native_key, None);
        record(claim(1 | NATIVE_SLATES, None));
        assert_eq!(stored(&store).native_key, None);
    }

    #[test]
    fn a_key_not_lepic_lately_gets_no_native_slate_whatever_it_claimed() {
        use lepic_transport::marker::features::NATIVE_SLATES;
        let store = store();
        store
            .write(|repos| {
                record_slate(
                    repos,
                    "key",
                    at(90).unwrap(),
                    claim(1 | NATIVE_SLATES, Some(native())),
                )
            })
            .unwrap();
        assert!(eligible(&store, now(), true));
        // The marked message is older than thirty days.
        assert!(!eligible(&store, at(121).unwrap(), true));
        // A newer unmarked slate keeps the key but makes the peer Epic.
        store
            .write(|repos| record_slate(repos, "key", now(), Shown::UNMARKED))
            .unwrap();
        assert_eq!(stored(&store).native_key, Some(native()));
        assert!(!eligible(&store, now(), true));
    }

    #[test]
    fn a_wallet_without_native_direct_stores_the_row_it_stored_before() {
        use lepic_transport::marker::features::NATIVE_SLATES;
        let claiming = SenderFacts::new(true, Some(1 | NATIVE_SLATES), Some(native()));
        let store = store();
        store
            .write(|repos| record_slate(repos, "key", now(), Shown::of(&claiming, false)))
            .unwrap();
        let row = stored(&store);
        assert_eq!(row.native_key, None);
        // The row a build without native slates over Epicbox wrote for the same claim.
        let before = PeerCompat {
            last_marked_at: Some(now()),
            last_unmarked_at: None,
            features_at: Some(now()),
            claimed: 1 | NATIVE_SLATES,
            works: MARKER_BIT,
            native_key: None,
        };
        assert_eq!(row, before);
        // Version 1, 34 bytes, as before.
        let bytes = lepic_store::peer_vectors::record(&row).unwrap();
        assert_eq!(bytes, lepic_store::peer_vectors::record(&before).unwrap());
        assert_eq!((bytes.first(), bytes.len()), (Some(&1), 34));
    }
}
