// SPDX-License-Identifier: Apache-2.0
//! The seal key each native endpoint showed to each account (EPICTX 5.15). The first native
//! exchange with an origin pins its key; a later exchange with the same key only moves the last
//! seen date, and another key is reported, never stored: the user forgets the pin to take it.

use jiff::Timestamp;
use lepic_contact::EncSecretKey;
use lepic_node::NodeApi;
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, PIN_KEY_LEN, PeerPin, Repositories, StoreError, WalletStore};
use tracing::instrument;

use crate::error::WalletError;
use crate::namespace::{self, SealKeyKind};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

// The account whose seal keys the listener sockets show.
const LISTENER_ACCOUNT: u32 = 0;

/// What [`Wallet::pin_peer`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// The origin had no pin; the key is pinned now.
    Pinned,
    /// The origin is pinned to this key; its last seen date moved.
    Seen,
    /// The origin is pinned to another key, which is kept as it was.
    Changed { pinned: [u8; PIN_KEY_LEN] },
}

/// Pins `seal_key` for `origin` under `account`, or moves the last seen date of the same pin,
/// or reports the key already pinned. Nothing is written for a changed key.
pub(crate) fn pin(
    repos: &mut dyn Repositories,
    account: AccountIndex,
    origin: &str,
    seal_key: [u8; PIN_KEY_LEN],
    now: Timestamp,
) -> Result<PinOutcome, StoreError> {
    let (outcome, first_seen) = match repos.peer_pin(account, origin)? {
        None => (PinOutcome::Pinned, now),
        Some(pin) if pin.seal_key == seal_key => (PinOutcome::Seen, pin.first_seen),
        Some(pin) => {
            return Ok(PinOutcome::Changed {
                pinned: pin.seal_key,
            });
        }
    };
    repos.put_peer_pin(&PeerPin {
        account,
        origin: origin.to_owned(),
        seal_key,
        first_seen,
        last_seen: now,
    })?;
    Ok(outcome)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The seal key of the listener socket of `kind` ([`SealKeyKind::Onion`] or
    /// [`SealKeyKind::Web`]): the key a native endpoint on that socket advertises and opens
    /// envelopes with. A listener serves the wallet, not one account, so the key is account 0's.
    /// Fails with [`WalletError::Locked`] while the wallet is locked.
    pub fn listener_seal_key(&self, kind: SealKeyKind) -> Result<EncSecretKey, WalletError> {
        let session = self.session()?;
        let network = match self.config().network {
            Network::Mainnet => lepic_contact::Network::Mainnet,
            Network::Floonet => lepic_contact::Network::Floonet,
        };
        namespace::seal_key(&session.seed, LISTENER_ACCOUNT, network, kind)
    }

    /// Every pin of `account`, in origin order. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name, account = %account))]
    pub fn peer_pins(&self, account: AccountIndex) -> Result<Vec<PeerPin>, WalletError> {
        let session = self.session()?;
        Ok(session.store.read(|repos| repos.peer_pins(account))?)
    }

    /// The pin of `account` for the normalised `origin`, if there is one. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name, account = %account))]
    pub fn peer_pin(
        &self,
        account: AccountIndex,
        origin: &str,
    ) -> Result<Option<PeerPin>, WalletError> {
        let session = self.session()?;
        Ok(session
            .store
            .read(|repos| repos.peer_pin(account, origin))?)
    }

    /// Pins the key `origin` showed in a native exchange that succeeded; see [`PinOutcome`].
    /// Fails with [`WalletError::Locked`], and with [`WalletError::Store`] for an origin the
    /// store does not keep.
    #[instrument(skip_all, fields(wallet = %self.config().name, account = %account))]
    pub fn pin_peer(
        &self,
        account: AccountIndex,
        origin: &str,
        seal_key: [u8; PIN_KEY_LEN],
    ) -> Result<PinOutcome, WalletError> {
        let now = self.ports().clock.now();
        let session = self.session()?;
        let outcome = session
            .store
            .write(|repos| pin(repos, account, origin, seal_key, now))?;
        tracing::debug!(?outcome, "peer pin checked");
        Ok(outcome)
    }

    /// Forgets the pin of `account` for `origin`, so the next native exchange with it pins the
    /// key it shows then. Returns whether there was a pin. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name, account = %account))]
    pub fn forget_peer_pin(
        &self,
        account: AccountIndex,
        origin: &str,
    ) -> Result<bool, WalletError> {
        let session = self.session()?;
        let forgotten = session
            .store
            .write(|repos| repos.forget_peer_pin(account, origin))?;
        tracing::info!(forgotten, "peer pin forgotten");
        Ok(forgotten)
    }
}

#[cfg(test)]
mod tests {
    use lepic_store::{MemoryStore, StoreKeys};

    use super::*;

    const ORIGIN: &str = "https://wallet.example:443";
    const ACCOUNT: AccountIndex = AccountIndex(0);

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(1_790_000_000_i64.saturating_add(second)).unwrap()
    }

    fn check(store: &MemoryStore, key: u8, now: i64) -> PinOutcome {
        store
            .write(|repos| pin(repos, ACCOUNT, ORIGIN, [key; PIN_KEY_LEN], at(now)))
            .unwrap()
    }

    #[test]
    fn the_first_key_is_pinned_and_a_later_one_is_reported_not_stored() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [2; 32]));
        assert_eq!(check(&store, 7, 1), PinOutcome::Pinned);
        assert_eq!(check(&store, 7, 5), PinOutcome::Seen);
        assert_eq!(
            check(&store, 8, 9),
            PinOutcome::Changed {
                pinned: [7; PIN_KEY_LEN]
            }
        );
        let stored = store
            .read(|repos| repos.peer_pin(ACCOUNT, ORIGIN))
            .unwrap()
            .unwrap();
        assert_eq!(stored.seal_key, [7; PIN_KEY_LEN]);
        assert_eq!((stored.first_seen, stored.last_seen), (at(1), at(5)));
        assert!(
            store
                .write(|repos| repos.forget_peer_pin(ACCOUNT, ORIGIN))
                .unwrap()
        );
        assert_eq!(check(&store, 8, 10), PinOutcome::Pinned);
    }
}
