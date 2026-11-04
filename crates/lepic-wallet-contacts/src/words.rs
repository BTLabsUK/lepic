// SPDX-License-Identifier: Apache-2.0
//! Pairing words (RFC 0002 7.7): five SAS-table entries that find an invite posted to a
//! rendezvous mailbox on the meeting relays, for when there is nothing to scan or paste.

use std::time::Duration;

use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use lepic_contact::{Invite, PairingWords, SasSymbol, WORD_COUNT, WordsKey, WordsWindow};
use lepic_epicbox::{
    DrainLimits, Handled, Identity, MailboxContent, MailboxHandler, MailboxMessage,
};
use lepic_node::NodeApi;
use lepic_transport::transport::BoxFuture;
use tracing::{debug, info, instrument};

use super::keys::{contact_network, pairing_mailbox};
use super::relay::{check_online, mailbox_client};
use super::{ContactError, ContactRelays, LockedRng, new_id};
use crate::ContactBook;
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// An invite offered as words lasts this long (RFC 0002 7.1).
pub const WORDS_INVITE_EXPIRY: Duration = Duration::from_secs(10 * 60);

/// Once one relay took the words, how long the other posts may still take: a relay that hangs
/// does not hold the words back.
const WORDS_POST_GRACE: Duration = Duration::from_secs(5);

/// How long one relay may take to show its two rendezvous mailboxes when looking for words; a
/// healthy relay answers in about a second. The relays are asked at once.
const WORDS_DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

fn unix_seconds(time: jiff::Timestamp) -> u64 {
    u64::try_from(time.as_second()).unwrap_or(0)
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Draws five words for `invite`, stretches them for the current window, and posts the sealed
    /// invite to the rendezvous mailbox on every meeting relay, all at once: the other side
    /// looks on each of them, so the words work whatever relay this wallet uses and whichever
    /// meeting relay either network blocks. Returns the words as the user sees them once one
    /// relay took the invite and the others had [`WORDS_POST_GRACE`] more; when none did, the
    /// last relay's error.
    pub(crate) async fn post_invite_words(
        &self,
        relays: &ContactRelays,
        invite: &Invite,
    ) -> Result<[SasSymbol; WORD_COUNT], ContactError> {
        check_online(relays)?;
        let network = self.wallet.config().network;
        let words = {
            let mut rng = LockedRng(&mut **self.wallet.ports().rng.lock());
            let bytes = new_id(&mut rng);
            let mut five = [0u8; WORD_COUNT];
            for (slot, byte) in five.iter_mut().zip(bytes) {
                *slot = byte;
            }
            PairingWords::from_bytes(five)
        };
        let symbols = words
            .symbols()
            .map_err(|_| ContactError::Words(lepic_contact::WordsError::Unknown))?;
        let window = WordsWindow::at(unix_seconds(self.wallet.ports().clock.now()));
        let key = self
            .contact_work(move |_, _| {
                words
                    .stretch(contact_network(network), window)
                    .map_err(ContactError::Words)
            })
            .await?;
        let posted = key
            .seal_invite(
                invite,
                &mut LockedRng(&mut **self.wallet.ports().rng.lock()),
            )
            .map_err(ContactError::Words)?;
        let mut posts = Vec::with_capacity(relays.meeting.len());
        for relay in &relays.meeting {
            let (rendezvous, from) = pairing_mailbox(&key.mailbox_seed(), network, relay)?;
            let posted = &posted;
            posts.push(async move {
                let result = mailbox_client(relays, relay.clone(), None)
                    .post(&from, rendezvous.address(), posted)
                    .await;
                if let Err(error) = &result {
                    debug!(peer_relay = %relay.domain(), error = %lepic_primitives::error_chain::ErrorChain(error), "pairing words not posted");
                }
                result
            });
        }
        let mut pending: FuturesUnordered<_> = posts.into_iter().collect();
        let mut last = None;
        let mut offered = 0usize;
        let mut grace = None;
        loop {
            let next = match grace {
                None => pending.next().await,
                Some(deadline) => match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(next) => next,
                    // The posts still going are dropped; their relays simply hold no copy.
                    Err(_) => break,
                },
            };
            match next {
                None => break,
                Some(Ok(())) => {
                    offered = offered.saturating_add(1);
                    grace.get_or_insert_with(|| {
                        let now = tokio::time::Instant::now();
                        now.checked_add(WORDS_POST_GRACE).unwrap_or(now)
                    });
                }
                Some(Err(error)) => last = Some(error),
            }
        }
        match last {
            Some(error) if offered == 0 => Err(ContactError::Relay(error)),
            None if offered == 0 => Err(ContactError::WordsUnavailable),
            _ => {
                info!(relays = offered, "pairing words offered");
                Ok(symbols)
            }
        }
    }

    /// Finds the invite that pairing words name (RFC 0002 7.7): the words, typed as names or
    /// emoji, are stretched for the current and the previous window, and the two rendezvous
    /// mailboxes are drained on every meeting relay at once, each for at most
    /// [`WORDS_DRAIN_TIMEOUT`]. The first invite that opens wins and the drains still going are
    /// dropped; the message it came in is acknowledged, so nobody else finds that copy, and
    /// copies on other relays stay until they expire. Returns the invite as its
    /// `epiccash://pair/1/` link, for [`Wallet::pairing_preview`] and
    /// [`Wallet::pairing_accept`].
    ///
    /// Fails with [`ContactError::Words`] for words not in the table,
    /// [`ContactError::WordsNotFound`] when no meeting relay holds the invite,
    /// [`ContactError::Relay`] when not one meeting relay could be drained,
    /// [`ContactError::WordsUnavailable`] when there is no meeting relay, and
    /// [`ContactError::Offline`] or [`ContactError::EpicboxOff`] before connecting.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn pairing_find_words<T: AsRef<str>>(
        &self,
        relays: &ContactRelays,
        typed: &[T],
    ) -> Result<String, ContactError> {
        check_online(relays)?;
        self.check_contact_network(relays)?;
        let words = PairingWords::parse(typed).map_err(ContactError::Words)?;
        if relays.meeting.is_empty() {
            return Err(ContactError::WordsUnavailable);
        }
        let network = self.wallet.config().network;
        let now = unix_seconds(self.wallet.ports().clock.now());
        let keys = self
            .contact_work(move |_, _| {
                WordsWindow::to_try(now)
                    .map(|window| {
                        words
                            .stretch(contact_network(network), window)
                            .map_err(ContactError::Words)
                    })
                    .collect::<Result<Vec<WordsKey>, ContactError>>()
            })
            .await?;
        let mut drains = FuturesUnordered::new();
        for relay in &relays.meeting {
            let identities: Vec<Identity> = keys
                .iter()
                .map(|key| pairing_mailbox(&key.mailbox_seed(), network, relay).map(|(id, _)| id))
                .collect::<Result<_, _>>()?;
            let keys = &keys;
            drains.push(async move {
                let mut finder = Finder {
                    keys,
                    network: contact_network(network),
                    found: None,
                };
                let client = mailbox_client(relays, relay.clone(), None);
                let limits = DrainLimits {
                    timeout: WORDS_DRAIN_TIMEOUT,
                    ..client.limits()
                };
                let drained = client
                    .with_limits(limits)
                    .drain_once(&identities, &mut finder)
                    .await;
                (relay, drained, finder.found)
            });
        }
        // Words that no relay could be asked about are not "not found": the relays were not
        // reached, which the caller words differently.
        let mut reached = false;
        let mut failed = None;
        while let Some((relay, drained, found)) = drains.next().await {
            if let Some(invite) = found {
                info!(peer_relay = %relay.domain(), "invite found by pairing words");
                return Ok(invite.to_link());
            }
            match drained {
                Ok(_) => reached = true,
                Err(error) => {
                    debug!(peer_relay = %relay.domain(), error = %lepic_primitives::error_chain::ErrorChain(&error), "rendezvous drain failed");
                    failed = Some(error);
                }
            }
        }
        match failed {
            Some(error) if !reached => Err(ContactError::Relay(error)),
            _ => Err(ContactError::WordsNotFound),
        }
    }
}

/// Opens rendezvous messages with the stretched words; only the one that opens is acknowledged.
struct Finder<'a> {
    keys: &'a [WordsKey],
    network: lepic_contact::Network,
    found: Option<Invite>,
}

impl MailboxHandler for Finder<'_> {
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            if self.found.is_some() {
                return Handled::Later;
            }
            let Some(key) = self.keys.get(message.mailbox()) else {
                return Handled::Later;
            };
            let MailboxContent::Opened(received) = message.into_content() else {
                return Handled::Later;
            };
            let Ok(bytes) = key.open_invite(self.network, received.plaintext.expose_str()) else {
                return Handled::Later;
            };
            let bytes = zeroize::Zeroizing::new(bytes);
            match Invite::decode(&bytes, self.network) {
                Ok(invite) => {
                    self.found = Some(invite);
                    Handled::Stored
                }
                Err(_) => Handled::Later,
            }
        })
    }
}
