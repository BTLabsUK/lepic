// SPDX-License-Identifier: Apache-2.0
//! The carrier: the shared mux/1 sessions that carry the watched mailboxes.
//!
//! A host hands the carrier the whole watch set. The carrier claims every live row's mailbox on
//! the contacts session of its relay, lets go of what left the set, and keeps which mailbox each
//! socket index stands for, so the router can name the row of every message a relay pushes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use futures_util::future::join_all;
use jiff::Timestamp;
use lepic_epicbox::sessions::{Owner, Placement, PushedConfig};
use lepic_epicbox::{
    MAX_MAILBOXES_PER_SOCKET, MuxError, MuxEvent, MuxOptions, MuxSession, MuxState, RelayEndpoint,
};
use lepic_primitives::error_chain::ErrorChain;
use lepic_store::{StoreError, WalletStore, WatchRow};
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use super::peer::PeerPoster;
use super::watch::{
    MailboxKeys, RelayWatch, SkipReason, Skipped, WatchError, WatchReport, Watched,
};
use crate::relay::{check_online, endpoint_for, host_text, mailbox_client};
use crate::{ContactError, ContactRelays};

/// Why the carrier did not take a watch set.
#[derive(Debug, Error)]
pub(crate) enum CarrierError {
    #[error(transparent)]
    Contact(#[from] ContactError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The session group of the contact mailboxes while the host has set none.
const DEFAULT_GROUP: &str = "contacts";

/// The contacts session setting while the host has set none: contact mail is always read from
/// mux/1 sessions.
fn default_config() -> PushedConfig {
    PushedConfig {
        group: DEFAULT_GROUP.to_owned(),
        options: MuxOptions::default(),
    }
}

/// The watched mailboxes of the contacts' mux/1 sessions, and the host's posters for `http`
/// and `tor` routes.
pub(crate) struct Carrier {
    relays: ContactRelays,
    http: Option<Arc<dyn PeerPoster>>,
    tor: Option<Arc<dyn PeerPoster>>,
    /// Taken by a watch for its whole pass, so two passes do not claim over each other.
    turn: tokio::sync::Mutex<()>,
    parts: Mutex<Vec<Part>>,
}

/// The watched mailboxes one socket carries.
#[derive(Clone)]
pub(crate) struct Part {
    /// The relay as `domain:port`.
    pub(crate) host: String,
    pub(super) session: Arc<MuxSession>,
    /// The mailbox at each of the socket's indexes.
    pub(crate) mailboxes: BTreeMap<usize, Arc<Watched>>,
    /// The session's events since the claim was set, shared by the clones of the part.
    pub(super) events: Arc<Mutex<broadcast::Receiver<MuxEvent>>>,
}

impl Part {
    /// The keys of the mailboxes another socket of the wallet took over from this one.
    pub(crate) fn taken_over(&self) -> BTreeSet<String> {
        self.session.replaced_keys()
    }
}

/// The live rows of one relay, each mailbox once.
struct RelaySet {
    endpoint: RelayEndpoint,
    /// The key text of each mailbox, by place in `mailboxes`.
    keys: Vec<String>,
    /// The same keys, for the repeat check.
    seen: BTreeSet<String>,
    mailboxes: Vec<Watched>,
    /// The onion of the first row that names one.
    onion: Option<String>,
}

impl Carrier {
    pub(crate) fn new(relays: ContactRelays) -> Self {
        Self {
            relays,
            http: None,
            tor: None,
            turn: tokio::sync::Mutex::new(()),
            parts: Mutex::new(Vec::new()),
        }
    }

    /// Posts `http` routes with `http` and `tor` routes with `tor`; a route without a poster
    /// has no carrier.
    pub(crate) fn with_posters(
        mut self,
        http: Option<Arc<dyn PeerPoster>>,
        tor: Option<Arc<dyn PeerPoster>>,
    ) -> Self {
        self.http = http;
        self.tor = tor;
        self
    }

    pub(crate) fn posters(&self) -> (Option<&dyn PeerPoster>, Option<&dyn PeerPoster>) {
        (self.http.as_deref(), self.tor.as_deref())
    }

    pub(crate) fn relays(&self) -> &ContactRelays {
        &self.relays
    }

    /// Makes the sessions carry exactly the live rows of `set`. A row whose `expires_at` is not
    /// later than `now` is not claimed, and the expired rows are removed from `store`. A row
    /// whose relay or key does not resolve is skipped. Mailboxes on relays that left the set, and the mailboxes of skipped
    /// rows, are released; another owner's claim on a shared socket stays. Each relay is
    /// reported on its own, so one relay's failure does not hide the others.
    ///
    /// Waits for every claim to be answered. A session answers at once while it has a socket or
    /// waits to reconnect, and holds a claim only while it opens and greets a socket, so the
    /// wait is bounded by one connection attempt per relay. A claim answered while no socket is
    /// up is attached when the socket comes back; it counts as watched.
    pub(super) async fn claim(
        &self,
        set: Vec<WatchRow>,
        keys: &impl MailboxKeys,
        store: &impl WalletStore,
        now: Timestamp,
    ) -> Result<WatchReport, CarrierError> {
        check_online(&self.relays)?;
        let config = self
            .relays
            .epicbox
            .pushed()
            .contacts()
            .unwrap_or_else(default_config);
        let _turn = self.turn.lock().await;
        let mut report = WatchReport::default();
        let (expired, live): (Vec<WatchRow>, Vec<WatchRow>) = set
            .into_iter()
            .partition(|row| row.expires_at.is_some_and(|at| at <= now));
        if !expired.is_empty() {
            report.expired = store.write(|repos| repos.remove_expired_watches(now))?;
        }
        let mut sets: BTreeMap<String, RelaySet> = BTreeMap::new();
        for row in live {
            let endpoint = match endpoint_for(&row.relay, &self.relays) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    report.skipped.push(Skipped {
                        row,
                        reason: SkipReason::Relay(error),
                    });
                    continue;
                }
            };
            let identity = match keys.identity(&row) {
                Ok(identity) => identity,
                Err(error) => {
                    report.skipped.push(Skipped {
                        row,
                        reason: error.into(),
                    });
                    continue;
                }
            };
            let key = identity.address().key_text();
            let relay = sets.entry(host_text(&endpoint)).or_insert(RelaySet {
                endpoint,
                keys: Vec::new(),
                seen: BTreeSet::new(),
                mailboxes: Vec::new(),
                onion: None,
            });
            if !relay.seen.insert(key.clone()) {
                report.skipped.push(Skipped {
                    row,
                    reason: SkipReason::Repeated,
                });
                continue;
            }
            if relay.onion.is_none() {
                relay.onion = keys.onion(&row);
            }
            relay.keys.push(key);
            relay.mailboxes.push(Watched { row, identity });
        }
        let kept: BTreeSet<String> = sets.keys().cloned().collect();
        let watched = join_all(
            sets.into_iter()
                .map(|(host, set)| self.watch_relay(&config, host, set)),
        )
        .await;
        self.relays
            .epicbox
            .pushed()
            .release_except(Owner::Contacts, &kept);
        let mut parts = Vec::new();
        for (relay, relay_parts) in watched {
            report.relays.push(relay);
            parts.extend(relay_parts);
        }
        *self.parts.lock().unwrap_or_else(PoisonError::into_inner) = parts;
        Ok(report)
    }

    /// Claims the mailboxes of `set` on the contacts session of `host`.
    async fn watch_relay(
        &self,
        config: &PushedConfig,
        host: String,
        set: RelaySet,
    ) -> (RelayWatch, Vec<Part>) {
        let pushed = self.relays.epicbox.pushed();
        let total = set.mailboxes.len();
        let failed = |host: String, error: WatchError| {
            warn!(peer_relay = %host, error = %ErrorChain(&error), "mailboxes not watched");
            RelayWatch {
                relay: host,
                mailboxes: total,
                watched: 0,
                error: Some(error),
            }
        };
        let placements = match pushed.place(
            &host,
            &config.group,
            Owner::Contacts,
            &set.keys,
            false,
            || {
                mailbox_client(&self.relays, set.endpoint.clone(), set.onion.as_deref())
                    .start_mux_queued(Vec::new(), config.options)
            },
        ) {
            Ok(placements) => placements,
            Err(error) => return (failed(host, WatchError::Session(error)), Vec::new()),
        };
        let by_key: BTreeMap<String, Arc<Watched>> = set
            .keys
            .into_iter()
            .zip(set.mailboxes.into_iter().map(Arc::new))
            .collect();
        let bound = placements
            .iter()
            .map(|placement| placement.session.mailbox_cap())
            .min()
            .unwrap_or(MAX_MAILBOXES_PER_SOCKET);
        let ended = placements
            .iter()
            .any(|placement| *placement.session.state().borrow() == MuxState::NotOffered);
        let claims = join_all(
            placements
                .into_iter()
                .map(|placement| claim(&host, placement, &by_key)),
        )
        .await;
        let mut parts = Vec::new();
        let mut refused = None;
        for claim in claims {
            match claim {
                Ok(part) => parts.push(part),
                Err(error) => {
                    refused.get_or_insert(error);
                }
            }
        }
        let watched: usize = parts.iter().map(|part| part.mailboxes.len()).sum();
        let left = total.saturating_sub(watched);
        let error = if watched == 0 && (ended || pushed.supports_push(&host) == Some(false)) {
            Some(WatchError::NoPush)
        } else if left > 0 {
            Some(WatchError::LeftOut {
                count: left,
                bound,
                source: refused,
            })
        } else {
            None
        };
        debug!(peer_relay = %host, count = watched, "mailboxes watched");
        match error {
            Some(error) => {
                let mut relay = failed(host, error);
                relay.watched = watched;
                (relay, parts)
            }
            None => (
                RelayWatch {
                    relay: host,
                    mailboxes: total,
                    watched,
                    error: None,
                },
                parts,
            ),
        }
    }

    /// A snapshot of the watched mailboxes, socket by socket.
    pub(crate) fn parts(&self) -> Vec<Part> {
        self.parts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Claims the mailboxes of `placement` as the contacts' whole claim on its socket. A socket that
/// has ended takes none.
async fn claim(
    host: &str,
    placement: Placement,
    by_key: &BTreeMap<String, Arc<Watched>>,
) -> Result<Part, MuxError> {
    let Placement { session, keys } = placement;
    if session.state().borrow().has_ended() {
        return Err(MuxError::Ended);
    }
    let mine: Vec<Arc<Watched>> = keys
        .iter()
        .filter_map(|key| by_key.get(key).cloned())
        .collect();
    let identities = mine
        .iter()
        .map(|watched| watched.identity.clone())
        .collect();
    // Subscribed before the claim, so the cancellations the relay pushes on attach are seen.
    let events = session.events();
    let claimed = session
        .set_claim(Owner::Contacts.as_str(), identities)
        .await
        .inspect_err(|error| {
            warn!(peer_relay = %host, error = %ErrorChain(error), "mux/1 claim not set");
        })?;
    Ok(Part {
        host: host.to_owned(),
        session,
        mailboxes: claimed.indexes.into_iter().zip(mine).collect(),
        events: Arc::new(Mutex::new(events)),
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::collections::HashSet;

    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_epicbox::{Identity, Network};
    use lepic_store::{MailClass, MemoryStore, Repositories, StoreKeys};

    use super::*;
    use crate::delivery::testing::{HOST, identity};
    use crate::delivery::testing::{Table, now, relays, row, wide_identity};

    fn store() -> MemoryStore {
        MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]))
    }

    fn keys(identities: &[Identity]) -> HashSet<String> {
        identities
            .iter()
            .map(|identity| identity.address().key_text())
            .collect()
    }

    #[tokio::test]
    async fn an_expired_row_is_not_attached_and_leaves_the_store() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, _) = relays(&relay, &classic, &[]);
        let carrier = Carrier::new(relays);
        let store = store();
        let old = row("k1", MailClass::Pairing, Some(999));
        let live = row("k2", MailClass::Contact, None);
        let later = row("k3", MailClass::Address, Some(1_001));
        store
            .write(|repos: &mut dyn Repositories| {
                repos.put_watch(&old)?;
                repos.put_watch(&live)?;
                repos.put_watch(&later)
            })
            .unwrap();
        let table = Table::default()
            .with("k1", identity(1))
            .with("k2", identity(2))
            .with("k3", identity(3));

        let set = vec![old.clone(), live.clone(), later.clone()];
        let report = carrier.claim(set, &table, &store, now()).await.unwrap();

        assert_eq!(report.expired, 1);
        assert_eq!(report.relays.len(), 1);
        assert_eq!(report.relays[0].relay, HOST);
        assert_eq!(report.relays[0].watched, 2);
        assert!(report.relays[0].error.is_none());
        assert_eq!(relay.attached(), keys(&[identity(2), identity(3)]));
        let parts = carrier.parts();
        assert_eq!(parts.len(), 1);
        let watched: Vec<&WatchRow> = parts[0]
            .mailboxes
            .values()
            .map(|watched| &watched.row)
            .collect();
        assert_eq!(watched, vec![&live, &later]);
        let rows = store
            .read(|repos: &dyn Repositories| repos.watch_set())
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(!rows.contains(&old));
    }

    #[tokio::test]
    async fn rows_that_do_not_resolve_are_skipped_and_the_others_watched() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, _) = relays(&relay, &classic, &[]);
        let carrier = Carrier::new(relays);
        let table = Table::default()
            .with("k1", identity(1))
            .with("same", identity(1))
            .with("k2", identity(2));
        let mut local = row("k2", MailClass::Contact, None);
        local.relay = "127.0.0.1:80".to_owned();
        let set = vec![
            row("k1", MailClass::Contact, None),
            row("unknown", MailClass::Contact, None),
            row("same", MailClass::Pairing, None),
            local.clone(),
        ];

        let report = carrier.claim(set, &table, &store(), now()).await.unwrap();

        assert_eq!(relay.attached(), keys(&[identity(1)]));
        assert_eq!(report.relays.len(), 1);
        assert_eq!(report.relays[0].watched, 1);
        let skipped: Vec<(&str, &SkipReason)> = report
            .skipped
            .iter()
            .map(|skipped| (skipped.row.key_ref.as_str(), &skipped.reason))
            .collect();
        assert_eq!(skipped.len(), 3);
        assert!(matches!(skipped[0], ("unknown", SkipReason::Unresolved(_))));
        assert!(matches!(skipped[1], ("same", SkipReason::Repeated)));
        assert!(matches!(
            skipped[2],
            ("k2", SkipReason::Relay(ContactError::RelayAddress))
        ));
        assert_eq!(report.skipped[2].row, local);
        assert_eq!(report.expired, 0);
    }

    #[tokio::test]
    async fn a_socket_carries_at_most_256_and_the_rest_is_reported() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, _) = relays(&relay, &classic, &[]);
        let carrier = Carrier::new(relays);
        let mut table = Table::default();
        let mut set = Vec::new();
        for n in 0..257u16 {
            let key_ref = format!("k{n}");
            table = table.with(&key_ref, wide_identity(n));
            set.push(row(&key_ref, MailClass::Contact, None));
        }
        let first: Vec<WatchRow> = set[..256].to_vec();
        let report = carrier.claim(first, &table, &store(), now()).await.unwrap();
        assert_eq!(report.relays[0].watched, 256);
        assert!(report.relays[0].error.is_none());
        assert_eq!(relay.sockets_made(), 1);

        // No second socket can be had: the relay stops offering mux/1 to new sockets.
        relay.offer_mux(false);
        let report = carrier.claim(set, &table, &store(), now()).await.unwrap();

        let watch = &report.relays[0];
        assert_eq!(watch.watched, 256);
        let Some(WatchError::LeftOut { count, bound, .. }) = &watch.error else {
            panic!("{:?}", watch.error);
        };
        assert_eq!((*count, *bound), (1, 256));
        assert!(watch.error.as_ref().unwrap().to_string().contains("256"));
        assert_eq!(relay.attached().len(), 256);
        assert_eq!(relay.sockets_made(), 2);
        assert_eq!(carrier.parts().len(), 1);
        assert_eq!(carrier.parts()[0].mailboxes.len(), 256);
    }

    #[tokio::test]
    async fn a_relay_without_mux_gets_its_own_error_and_nothing_is_attached() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.offer_mux(false);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, _) = relays(&relay, &classic, &[]);
        let carrier = Carrier::new(relays);
        let table = Table::default().with("k1", identity(1));

        for _ in 0..2 {
            let set = vec![row("k1", MailClass::Contact, None)];
            let report = carrier.claim(set, &table, &store(), now()).await.unwrap();
            assert_eq!(report.relays.len(), 1);
            assert_eq!(report.relays[0].watched, 0);
            assert!(matches!(report.relays[0].error, Some(WatchError::NoPush)));
        }

        assert!(relay.attached().is_empty());
        assert_eq!(relay.received("Attach"), 0);
        assert_eq!(relay.received("Subscribe"), 0);
        assert_eq!(classic.received("Subscribe"), 0);
        // The second pass knew the relay and opened no socket.
        assert_eq!(relay.sockets_made(), 1);
        assert!(carrier.parts().is_empty());
    }

    #[tokio::test]
    async fn a_smaller_set_releases_what_left_it_and_not_another_owners_claim() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, _) = relays(&relay, &classic, &[]);
        let carrier = Carrier::new(relays);
        let table = Table::default()
            .with("k1", identity(1))
            .with("k2", identity(2));
        let both = vec![
            row("k1", MailClass::Contact, None),
            row("k2", MailClass::Reply, None),
        ];
        carrier.claim(both, &table, &store(), now()).await.unwrap();
        let payments = carrier
            .relays()
            .epicbox
            .pushed()
            .get_or_start(HOST, "wallet", Owner::Payments, || Err(MuxError::NoRuntime))
            .unwrap();
        payments
            .set_claim(Owner::Payments.as_str(), vec![identity(9)])
            .await
            .unwrap();
        assert_eq!(
            relay.attached(),
            keys(&[identity(1), identity(2), identity(9)])
        );

        let one = vec![row("k1", MailClass::Contact, None)];
        carrier.claim(one, &table, &store(), now()).await.unwrap();
        relay
            .wait_until(|relay| relay.attached() == keys(&[identity(1), identity(9)]))
            .await;

        carrier
            .claim(Vec::new(), &table, &store(), now())
            .await
            .unwrap();
        relay
            .wait_until(|relay| relay.attached() == keys(&[identity(9)]))
            .await;
        assert!(carrier.parts().is_empty());
        assert_eq!(relay.sockets_made(), 1);
    }
}
