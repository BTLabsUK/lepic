// SPDX-License-Identifier: Apache-2.0
//! The open receipt caps that bound payments nobody asked for, on every transport that takes
//! them: [`WalletPolicy::max_open_receipts_per_sender`] per sender, where the transport names
//! one, and [`WalletPolicy::max_open_receipts`] in all. Each transport counts only its own open
//! receipts; payments taken at epic1 link mailboxes count apart, whatever transport carried them.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use lepic_node::NodeApi;
use lepic_slate::codec::WireSlate;
use lepic_store::{OpenReceipt, StoreError, TxDirection, TxId, WalletStore};
use lepic_transport::method::Method;
use lepic_transport::transport::TransportId;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::{ReceiveError, ReceiveRequest, Received, check_proposal};
use crate::wallet::Wallet;
use lepic_primitives::error_chain::ErrorChain;

/// Why a new S1 cannot be received under the caps.
#[derive(Debug)]
pub(crate) enum NoRoom {
    /// The sender has [`WalletPolicy::max_open_receipts_per_sender`] open.
    FromSender,
    /// At [`WalletPolicy::max_open_receipts`] and no open receipt could be cancelled.
    Full,
    /// At [`WalletPolicy::max_open_receipts`] and the node could not be asked whether one may be cancelled.
    Unchecked(WalletError),
    /// The wallet could not count or cancel open receipts.
    Wallet(WalletError),
    /// The wallet refuses payments nobody asked for
    /// ([`WalletPolicy::refuse_unsolicited_payments`]) and this slate id is new.
    Refused,
}

impl From<WalletError> for NoRoom {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}

type KeyOf<'a> = &'a (dyn Fn(&str) -> String + Sync);

/// The open receipts a cap counts.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Pool {
    /// Those received over the transport.
    Transport(TransportId),
    /// Those paid to an epic1 address of the wallet, taken at a link mailbox or not.
    Epic1(TransportId),
}

impl Pool {
    fn transport(self) -> TransportId {
        match self {
            Self::Transport(transport) | Self::Epic1(transport) => transport,
        }
    }
}

/// The sender of a new S1, for transports that name one: its key, and how the counterparty
/// stored with an open receipt maps to a key.
pub(crate) struct Sender<'a> {
    pub(crate) key: &'a str,
    pub(crate) key_of: KeyOf<'a>,
}

/// The sender key of each open receipt, by `key_of`.
fn sender_keys(open: &[OpenReceipt], key_of: KeyOf<'_>) -> Vec<Option<String>> {
    open.iter()
        .map(|receipt| receipt.counterparty.as_deref().map(key_of))
        .collect()
}

/// The open receipts `open`, oldest first, in the order they are given up at the cap: those of
/// the sender key with the most open receipts first, and each count oldest first.
fn eviction_order(open: &[OpenReceipt], key_of: KeyOf<'_>) -> Vec<TxId> {
    let keys = sender_keys(open, key_of);
    let mut counts: HashMap<&Option<String>, usize> = HashMap::new();
    for key in &keys {
        let count = counts.entry(key).or_default();
        *count = count.saturating_add(1);
    }
    let mut order: Vec<(usize, TxId)> = open
        .iter()
        .zip(&keys)
        .map(|(receipt, key)| (counts.get(key).copied().unwrap_or_default(), receipt.id))
        .collect();
    // Stable, so receipts with equal counts keep their age order.
    order.sort_by_key(|(count, _)| Reverse(*count));
    order.into_iter().map(|(_, id)| id).collect()
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// [`Wallet::receive`] of a payment nobody asked for, such as one a listener took: a new
    /// S1 is received only within the open receipt caps on `transport`, which names no sender,
    /// so only [`WalletPolicy::max_open_receipts`] applies. At that cap the wallet refreshes
    /// first, at most once a minute, so receipts already mined leave the count. With no sender
    /// to tell payments apart, no open receipt is cancelled to make room: a new S1 is refused
    /// until the count drops. An S1 received before is answered with its stored S2 whatever
    /// the count. Calls are served one at a time.
    ///
    /// Fails with [`ReceiveError::Refused`] for a new S1 when the wallet refuses payments
    /// nobody asked for ([`WalletPolicy::refuse_unsolicited_payments`]), and with
    /// [`ReceiveError::OpenReceipts`] at the cap; the sender can send the payment again later.
    /// Otherwise fails as [`Wallet::receive`] does; the slate is checked before the caps are.
    #[instrument(
        name = "receive_unsolicited",
        skip_all,
        fields(wallet = %self.config().name, transport = %method.id())
    )]
    pub async fn receive_unsolicited(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> Result<Received, ReceiveError> {
        let refuse = self.config().policy.refuse_unsolicited_payments;
        self.receive_capped(method, wire, request, Pool::Transport(method.id()), refuse)
            .await
    }

    /// [`Wallet::receive`] of a payment that came to an epic1 link mailbox, paid to the epic1
    /// address `request` names: received only within [`WalletPolicy::max_open_receipts`],
    /// counted over the open receipts paid to the wallet's epic1 addresses, as
    /// [`Wallet::receive_unsolicited`] receives within the cap of a transport. A link is a
    /// request the user made, so [`WalletPolicy::refuse_unsolicited_payments`] does not apply.
    ///
    /// Fails as [`Wallet::receive_unsolicited`] does, but never with [`ReceiveError::Refused`].
    #[instrument(
        name = "receive_at_link",
        skip_all,
        fields(wallet = %self.config().name, transport = %method.id())
    )]
    pub async fn receive_at_link(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> Result<Received, ReceiveError> {
        self.receive_capped(method, wire, request, Pool::Epic1(method.id()), false)
            .await
    }

    async fn receive_capped(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
        pool: Pool,
        refuse: bool,
    ) -> Result<Received, ReceiveError> {
        let slate = method
            .decode(self.config().network, wire)
            .map_err(ReceiveError::Decode)?;
        check_proposal(&slate)?;
        // Taken after the checks, so slates that are not payments never wait for it.
        let _turn = self.unsolicited_turn().await;
        let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
        match self.make_room(pool, slate_id, None, refuse).await {
            Ok(()) => {}
            Err(NoRoom::Wallet(error)) => return Err(ReceiveError::Wallet(error)),
            Err(NoRoom::Unchecked(error)) => return Err(ReceiveError::OpenReceipts(Some(error))),
            Err(NoRoom::FromSender | NoRoom::Full) => return Err(ReceiveError::OpenReceipts(None)),
            Err(NoRoom::Refused) => return Err(ReceiveError::Refused),
        }
        self.receive(method, wire, request).await
    }

    /// Checks the open receipt caps of `pool` before the new S1 `slate_id`, from `sender`
    /// when the transport names one, is received. A slate id received before passes, so its
    /// stored S2 is sent again. Over the sender's cap the S1 is refused; at the total cap room
    /// is made as [`WalletPolicy::max_open_receipts`] says, and only on a transport that names a sender:
    /// without one, the oldest receipt is as likely a real payment as not, so the S1 is
    /// refused instead. With `refuse`, a new S1 is refused before any count, as
    /// [`WalletPolicy::refuse_unsolicited_payments`] says.
    pub(crate) async fn make_room(
        &self,
        pool: Pool,
        slate_id: Uuid,
        sender: Option<Sender<'_>>,
        refuse: bool,
    ) -> Result<(), NoRoom> {
        let Some(mut open) = self
            .open_receipts_unless_known(pool, Some(slate_id))
            .await?
        else {
            return Ok(());
        };
        if refuse {
            return Err(NoRoom::Refused);
        }
        let no_key = |text: &str| text.to_owned();
        let key_of: KeyOf<'_> = sender.as_ref().map_or(&no_key, |s| s.key_of);
        let from_sender = |open: &[OpenReceipt]| {
            sender.as_ref().map_or(0, |sender| {
                sender_keys(open, key_of)
                    .iter()
                    .filter(|key| key.as_deref() == Some(sender.key))
                    .count()
            })
        };
        let policy = self.config().policy;
        let at_a_cap = |open: &[OpenReceipt]| {
            from_sender(open) >= policy.max_open_receipts_per_sender
                || open.len() >= policy.max_open_receipts
        };
        // An open receipt is one no refresh has seen confirmed yet, so some may already be
        // mined; a refresh confirms those before a cap refuses the S1 or a receipt is
        // cancelled.
        if at_a_cap(&open) && self.tip_refresh_due().await? {
            if let Err(error) = self.refresh().await {
                warn!(error = %ErrorChain(&error), "tip not refreshed");
            }
            open = self
                .open_receipts_unless_known(pool, None)
                .await?
                .unwrap_or_default();
        }
        if from_sender(&open) >= policy.max_open_receipts_per_sender {
            return Err(NoRoom::FromSender);
        }
        if open.len() < policy.max_open_receipts {
            return Ok(());
        }
        if sender.is_none() {
            return Err(NoRoom::Full);
        }
        for tx_id in eviction_order(&open, key_of) {
            match self.cancel(tx_id).await {
                Ok(()) => {
                    info!(tx_id = %tx_id, "open receipt cancelled to make room");
                    return Ok(());
                }
                Err(
                    error @ (WalletError::InPool(_)
                    | WalletError::OnChain(_)
                    | WalletError::ChangedDuringCancel(_)
                    | WalletError::Transition(_)
                    | WalletError::UnknownTransaction(_)),
                ) => {
                    debug!(tx_id = %tx_id, error = %ErrorChain(&error), "open receipt kept");
                }
                // Either says nothing of this receipt, only that the node cannot be asked.
                Err(error @ (WalletError::Node(_) | WalletError::Implausible(_))) => {
                    return Err(NoRoom::Unchecked(error));
                }
                Err(error) => return Err(NoRoom::Wallet(error)),
            }
        }
        Err(NoRoom::Full)
    }

    /// The open receipts of `pool`, oldest first, or `None` when `slate_id` was received
    /// before.
    async fn open_receipts_unless_known(
        &self,
        pool: Pool,
        slate_id: Option<Uuid>,
    ) -> Result<Option<Vec<OpenReceipt>>, WalletError> {
        let session = self.session()?;
        self.blocking(move |_, _| {
            Ok(session.store.read(|repos| {
                if let Some(slate_id) = slate_id
                    && repos
                        .transaction_by_slate(slate_id, TxDirection::Incoming)?
                        .is_some()
                {
                    return Ok::<_, StoreError>(None);
                }
                // A paired contact's receipts have caps of their own (RFC 0002 12.5).
                let mut open = Vec::new();
                for receipt in repos.open_receipts(pool.transport().as_str())? {
                    let epic1 = crate::epic1_index::index_of(repos, receipt.id)?.is_some();
                    if epic1 != matches!(pool, Pool::Epic1(_)) {
                        continue;
                    }
                    let contact = match repos.transaction(receipt.id)?.and_then(|tx| tx.slate_id) {
                        Some(slate) => crate::contact_link::slate_contact(repos, slate)?,
                        None => None,
                    };
                    if contact.is_none() {
                        open.push(receipt);
                    }
                }
                Ok(Some(open))
            })?)
        })
        .await
    }
}
