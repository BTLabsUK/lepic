//! Pairing words (RFC 0002 7.7): five SAS-table entries that find an invite posted to a
//! rendezvous mailbox on a built-in relay, for when there is nothing to scan or paste.

use std::time::Duration;

use lepic_contact::{Invite, PairingWords, SasSymbol, WORD_COUNT, WordsKey, WordsWindow};
use lepic_epicbox::{
    Handled, Identity, MailboxContent, MailboxHandler, MailboxMessage, RelayEndpoint,
};
use lepic_node::NodeApi;
use lepic_transport::transport::BoxFuture;
use tracing::{debug, info, instrument};

use super::keys::{contact_network, pairing_mailbox};
use super::relay::{check_online, mailbox_client};
use super::{ContactError, ContactRelays, LockedRng, new_id};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// An invite offered as words lasts this long (RFC 0002 7.1).
pub const WORDS_INVITE_EXPIRY: Duration = Duration::from_secs(10 * 60);

fn unix_seconds(time: jiff::Timestamp) -> u64 {
    u64::try_from(time.as_second()).unwrap_or(0)
}

/// Whether `relay` is one of the wallet's built-in relays, the only ones words are offered on.
pub(crate) fn built_in(relays: &ContactRelays, relay: &RelayEndpoint) -> bool {
    relays
        .built_in
        .iter()
        .any(|known| known.domain() == relay.domain() && known.port() == relay.port())
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Draws five words for `invite`, stretches them for the current window, and posts the sealed
    /// invite to the rendezvous mailbox on `home`. Returns the words as the user sees them.
    pub(crate) async fn post_invite_words(
        &self,
        relays: &ContactRelays,
        invite: &Invite,
        home: &RelayEndpoint,
    ) -> Result<[SasSymbol; WORD_COUNT], ContactError> {
        check_online(relays)?;
        let network = self.config().network;
        let words = {
            let mut rng = LockedRng(&mut **self.ports().rng.lock());
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
        let window = WordsWindow::at(unix_seconds(self.ports().clock.now()));
        let key = self
            .contact_work(move |_, _| {
                words
                    .stretch(contact_network(network), window)
                    .map_err(ContactError::Words)
            })
            .await?;
        let posted = key
            .seal_invite(invite, &mut LockedRng(&mut **self.ports().rng.lock()))
            .map_err(ContactError::Words)?;
        let (rendezvous, from) = pairing_mailbox(*key.mailbox_seed(), network, home)?;
        mailbox_client(relays, home.clone(), None)
            .post(&from, rendezvous.address(), &posted)
            .await
            .map_err(ContactError::Relay)?;
        info!("pairing words offered");
        Ok(symbols)
    }

    /// Finds the invite that pairing words name (RFC 0002 7.7): the words, typed as names or
    /// emoji, are stretched for the current and the previous window, and the two rendezvous
    /// mailboxes are drained on each built-in relay in order until one holds an invite that opens.
    /// That message is acknowledged, so nobody else finds it; others stay. Returns the invite as
    /// its `epiccash://pair/1/` link, for [`Wallet::pairing_preview`] and
    /// [`Wallet::pairing_accept`].
    ///
    /// Fails with [`ContactError::Words`] for words not in the table,
    /// [`ContactError::WordsNotFound`] when no built-in relay holds the invite, and
    /// [`ContactError::Offline`] or [`ContactError::EpicboxOff`] before connecting.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn pairing_find_words<T: AsRef<str>>(
        &self,
        relays: &ContactRelays,
        typed: &[T],
    ) -> Result<String, ContactError> {
        check_online(relays)?;
        self.check_contact_network(relays)?;
        let words = PairingWords::parse(typed).map_err(ContactError::Words)?;
        let network = self.config().network;
        let now = unix_seconds(self.ports().clock.now());
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
        for relay in &relays.built_in {
            let identities: Vec<Identity> = keys
                .iter()
                .map(|key| pairing_mailbox(*key.mailbox_seed(), network, relay).map(|(id, _)| id))
                .collect::<Result<_, _>>()?;
            let mut finder = Finder {
                keys: &keys,
                network: contact_network(network),
                found: None,
            };
            match mailbox_client(relays, relay.clone(), None)
                .drain_once(&identities, &mut finder)
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    debug!(error = %crate::inbox::ErrorChain(&error), "rendezvous drain failed");
                }
            }
            if let Some(invite) = finder.found {
                info!("invite found by pairing words");
                return Ok(invite.to_link());
            }
        }
        Err(ContactError::WordsNotFound)
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
