// SPDX-License-Identifier: Apache-2.0
//! The outbox's fill: once per store, the posts that in-person records made before the outbox
//! owe, or made, are stored as outbox rows, so every post is read from and delivered by the
//! outbox. The store's migration to version 18 copies the contact posts.
//!
//! A marker in the settings, stored in the same write, keeps the fill from running again. A
//! record that already has outbox rows is left as it is.

use lepic_node::NodeApi;
use lepic_store::WalletStore;
use lepic_wallet::ports::{SecretVault, StoreOpener};
use tracing::info;

use crate::{ContactBook, ContactError, ContactRelays, in_person};

/// The setting that marks the store as filled, with the Unix second it was.
pub(crate) const FILLED_KEY: &str = "outbox.filled";

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Fills the outbox from the records made before it, once per store. Safe to call before
    /// every outbox run: a filled store is read and left.
    pub(crate) async fn outbox_fill(&self, relays: &ContactRelays) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let relays = relays.clone();
        let stored = self
            .contact_work(move |ports, _| {
                if session
                    .store
                    .read(|repos| repos.setting(FILLED_KEY))?
                    .is_some()
                {
                    return Ok(None);
                }
                let now = ports.clock.now();
                session.store.write(|repos| {
                    if repos.setting(FILLED_KEY)?.is_some() {
                        return Ok::<_, ContactError>(None);
                    }
                    let stored = in_person::fill_outbox(repos, network, &relays, now)?;
                    repos.put_setting(FILLED_KEY, &now.as_second().to_string())?;
                    Ok(Some(stored))
                })
            })
            .await?;
        if let Some(rows) = stored {
            info!(rows, "outbox filled from stored records");
        }
        Ok(())
    }
}
