// SPDX-License-Identifier: Apache-2.0
//! Watching the wallet's mailboxes again between cycles, so a relay pushes the answer to a
//! pairing made or answered, or the mail of a link issued or a payment posted, since the last
//! cycle as soon as it arrives.

use lepic_primitives::error_chain::ErrorChain;
use tracing::{debug, warn};

use lepic_node::NodeApi;
use lepic_wallet::ports::{SecretVault, StoreOpener};

use super::delivery::transport::Reach;
use super::relay::check_online;
use super::{ContactBook, ContactRelays};

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Has the push sessions watch the wallet's mailboxes as the records stand now, so a relay
    /// pushes the reply or confirm of a pairing made or answered since the last cycle, or the
    /// mail of a link or payment made since, instead of holding it until the next one. Every
    /// mailbox of the watch set is watched again, so one call covers all made since the last.
    /// Nothing is read and nothing fails: a mailbox left out is watched by the next cycle.
    ///
    /// Waits for the contact turn, so a cycle that derived its mailboxes before this pairing was
    /// stored cannot replace the watch afterwards. A running cycle holds that turn until it
    /// ends, so a host calls this after the pairing call has returned, off the caller's path.
    pub async fn claim_pushed(&self, relays: &ContactRelays) {
        if check_online(relays).is_err() {
            return;
        }
        let _turn = self.wallet.contact_turn().await;
        match self.watch_mailboxes(relays, Vec::new(), Reach::Claim).await {
            Ok((_, _, watch)) => {
                let count = watch
                    .relays
                    .iter()
                    .fold(0usize, |count, relay| count.saturating_add(relay.watched));
                debug!(count, "contact mailboxes watched again");
            }
            Err(error) => {
                warn!(error = %ErrorChain(&error), "contact mailboxes not watched again");
            }
        }
    }
}
