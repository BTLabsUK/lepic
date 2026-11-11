// SPDX-License-Identifier: Apache-2.0
//! The serve API's event log and idempotency records, kept in the wallet's store. Events and
//! request records are stamped with the wallet's clock.

use jiff::Timestamp;
use lepic_node::NodeApi;
use lepic_store::{API_DIGEST_LEN, ApiEvent, ApiRequest, Repositories, StoreError, WalletStore};
use tracing::instrument;

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Appends an event of `kind` with JSON bytes `data`, stamped with the wallet's clock, and
    /// returns its id. Ids rise and are never reused, also after pruning. Fails with
    /// [`WalletError::Locked`], and with [`WalletError::Store`] for a kind or data the store
    /// does not keep (data above 1 MiB).
    #[instrument(skip_all, fields(wallet = %self.config().name, kind))]
    pub fn append_api_event(&self, kind: &str, data: &[u8]) -> Result<u64, WalletError> {
        let now = self.ports().clock.now();
        let session = self.session()?;
        Ok(session
            .store
            .write(|repos| repos.append_api_event(kind, now, data))?)
    }

    /// Up to `limit` events with id above `after`, oldest first. `kinds` empty means all; an
    /// entry matches a kind equal to it, or, ending in `.*`, every kind starting with the text
    /// before the `*`. Fails with [`WalletError::Locked`], and with [`WalletError::Store`] for a
    /// malformed pattern or a `limit` above 1000.
    #[instrument(skip_all, fields(wallet = %self.config().name, after, limit))]
    pub fn api_events_after(
        &self,
        after: u64,
        limit: usize,
        kinds: &[String],
    ) -> Result<Vec<ApiEvent>, WalletError> {
        let session = self.session()?;
        Ok(session
            .store
            .read(|repos| repos.api_events_after(after, limit, kinds))?)
    }

    /// The lowest and highest event id the log holds; `None` when empty. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn api_event_bounds(&self) -> Result<Option<(u64, u64)>, WalletError> {
        let session = self.session()?;
        Ok(session.store.read(|repos| repos.api_event_bounds())?)
    }

    /// The highest event id ever given, also after every event was pruned; 0 when none ever was.
    /// Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn api_event_last_id(&self) -> Result<u64, WalletError> {
        let session = self.session()?;
        Ok(session.store.read(|repos| repos.api_event_last_id())?)
    }

    /// Deletes the events created before `before` and returns how many. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn prune_api_events(&self, before: Timestamp) -> Result<u64, WalletError> {
        let session = self.session()?;
        let pruned = session
            .store
            .write(|repos| repos.prune_api_events(before))?;
        tracing::debug!(pruned, "api events pruned");
        Ok(pruned)
    }

    /// Records what the create `(scope, id)` was first called with, stamped with the wallet's
    /// clock. Fails with [`WalletError::Locked`], and with [`WalletError::Store`] holding
    /// [`StoreError::Duplicate`] if the pair is already recorded: read it with
    /// [`Wallet::api_request`] and compare the digest.
    #[instrument(skip_all, fields(wallet = %self.config().name, scope))]
    pub fn put_api_request(
        &self,
        scope: &str,
        id: &str,
        digest: [u8; API_DIGEST_LEN],
    ) -> Result<(), WalletError> {
        let request = ApiRequest {
            scope: scope.to_owned(),
            id: id.to_owned(),
            digest,
            created_at: self.ports().clock.now(),
        };
        let session = self.session()?;
        Ok(session
            .store
            .write(|repos| repos.put_api_request(&request))?)
    }

    /// The record of the create `(scope, id)`, if there is one. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name, scope))]
    pub fn api_request(&self, scope: &str, id: &str) -> Result<Option<ApiRequest>, WalletError> {
        let session = self.session()?;
        Ok(session.store.read(|repos| repos.api_request(scope, id))?)
    }

    /// Deletes the request records created before `before` and returns how many. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub fn prune_api_requests(&self, before: Timestamp) -> Result<u64, WalletError> {
        let session = self.session()?;
        let pruned = session
            .store
            .write(|repos| repos.prune_api_requests(before))?;
        tracing::debug!(pruned, "api requests pruned");
        Ok(pruned)
    }
}

#[cfg(test)]
mod tests {
    use lepic_store::{MemoryStore, StoreKeys};

    use super::*;

    // The wallet methods are thin; this checks the error the CLI maps for a reused id.
    #[test]
    fn a_reused_request_id_is_a_duplicate_store_error() {
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [2; 32]));
        let request = ApiRequest {
            scope: "payment".to_owned(),
            id: "a".to_owned(),
            digest: [1; API_DIGEST_LEN],
            created_at: Timestamp::from_second(1_790_000_000).unwrap(),
        };
        store
            .write(|repos| repos.put_api_request(&request))
            .unwrap();
        let error: WalletError = store
            .write(|repos| repos.put_api_request(&request))
            .map_err(WalletError::from)
            .unwrap_err();
        assert!(matches!(
            error,
            WalletError::Store(StoreError::Duplicate { .. })
        ));
    }
}
