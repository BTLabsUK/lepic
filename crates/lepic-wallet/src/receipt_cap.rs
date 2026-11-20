// SPDX-License-Identifier: Apache-2.0
//! The open receipt caps that bound payments nobody asked for, on every transport that takes
//! them: [`WalletPolicy::max_open_receipts_per_sender`] per sender, where the transport names
//! one, and [`WalletPolicy::max_open_receipts`] in all. Each transport counts only its own open
//! receipts; payments taken at the delivery mailboxes of epic1 addresses count apart, whatever
//! transport carried them.
//!
//! The caps only refuse: a new S1 at a cap is refused with [`ReceiveError::OpenReceipts`] and
//! no receipt is ever cancelled to make room. An open receipt counts while it is younger than
//! [`DEFAULT_TTL_BLOCKS`], from the tip it was received at, and before its TTL cutoff when
//! that is nearer. An older one stays as it is and only leaves the count.

use std::sync::Arc;

use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_primitives::params::Network;
use lepic_slate::codec::WireSlate;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{OpenReceipt, Repositories, StoreError, TxDirection, TxId, WalletStore};
use lepic_transport::method::Method;
use lepic_transport::transport::TransportId;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::chain::{DEFAULT_TTL_BLOCKS, position};
use crate::codecs;
use crate::error::WalletError;
use crate::event::{Event, ReceiptCap, RefusedPayment, SlateId};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::{ReceiveError, ReceiveRequest, Received, check_proposal};
use crate::wallet::Wallet;
use lepic_primitives::error_chain::ErrorChain;

/// Why a new S1 cannot be received under the caps.
#[derive(Debug)]
pub(crate) enum NoRoom {
    /// The sender has [`WalletPolicy::max_open_receipts_per_sender`] open.
    FromSender,
    /// [`WalletPolicy::max_open_receipts`] are open.
    Full,
    /// The wallet could not count open receipts.
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
    /// Those paid to an epic1 address of the wallet, taken at its delivery mailbox or not.
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

/// How many of `open` came from `sender`, by its `key_of`.
fn from_sender(open: &[OpenReceipt], sender: &Sender<'_>) -> usize {
    open.iter()
        .filter(|receipt| {
            receipt
                .counterparty
                .as_deref()
                .map(sender.key_of)
                .as_deref()
                == Some(sender.key)
        })
        .count()
}

/// Whether the open receipt `tx_id` still counts against the caps at `tip`: while it is younger
/// than [`DEFAULT_TTL_BLOCKS`] from the tip it was received at, and before its TTL cutoff. One
/// with neither height, or with no tip known, counts.
fn counts_at(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tip: Option<Height>,
    tx_id: TxId,
    slate_id: Option<Uuid>,
) -> Result<bool, StoreError> {
    let Some(tip) = tip else {
        return Ok(true);
    };
    let aged = repos
        .tx_marks(tx_id)?
        .receive_seen_at
        .and_then(|seen| seen.checked_add_blocks(DEFAULT_TTL_BLOCKS).ok());
    let cutoff = match slate_id {
        Some(slate_id) => crate::refresh::ttl_cutoff(repos, codecs, tx_id, slate_id)?,
        None => None,
    };
    Ok([aged, cutoff].into_iter().flatten().all(|end| tip < end))
}

/// Whether the open receipt `tx_id`, of slate `slate_id`, still counts against the open
/// receipt caps of a wallet on `network`: while it is younger than [`DEFAULT_TTL_BLOCKS`]
/// from the tip it was received at, and before its TTL cutoff, both against the last tip a
/// refresh confirmed. One with neither height, or with no tip known, counts. For callers that
/// keep caps of their own over [`Repositories::open_receipts`], such as a contact's.
///
/// # Errors
///
/// Fails when the store cannot be read.
pub fn receipt_counts(
    repos: &dyn Repositories,
    network: Network,
    tx_id: TxId,
    slate_id: Option<Uuid>,
) -> Result<bool, StoreError> {
    let codecs = codecs::legacy(network.params().default_base_fee());
    counts_at(
        repos,
        &codecs,
        position(repos)?.confirmed_height(),
        tx_id,
        slate_id,
    )
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
    /// first, at most once a minute, so receipts already mined leave the count. No open
    /// receipt is cancelled to make room: a new S1 is refused until the count drops, as
    /// receipts confirm, end or age out of it (see the module docs). An S1 received before is
    /// answered with its stored S2 whatever the count. Calls are served one at a time.
    ///
    /// Fails with [`ReceiveError::Refused`] for a new S1 when the wallet refuses payments
    /// nobody asked for ([`WalletPolicy::refuse_unsolicited_payments`]), one to an epic1
    /// address as any other; with [`ReceiveError::OpenReceipts`] at the cap, and the sender
    /// can send the payment again later. Otherwise fails as [`Wallet::receive`] does; the
    /// slate is checked before the caps are.
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
        self.receive_capped(method, wire, request, Pool::Transport(method.id()), true)
            .await
    }

    /// [`Wallet::receive`] of a payment that came to the delivery mailbox of the epic1 address
    /// `request` names: received only within [`WalletPolicy::max_open_receipts`], counted over
    /// the open receipts paid to the wallet's epic1 addresses, as
    /// [`Wallet::receive_unsolicited`] receives within the cap of a transport. The caller
    /// applies [`WalletPolicy::refuse_unsolicited_payments`] first, so it can answer the payer.
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
        unasked: bool,
    ) -> Result<Received, ReceiveError> {
        let slate = method
            .decode(self.config().network, wire)
            .map_err(ReceiveError::Decode)?;
        check_proposal(&slate)?;
        let refuse = unasked && self.config().policy.refuse_unsolicited_payments;
        // Taken after the checks, so slates that are not payments never wait for it.
        let _turn = self.unsolicited_turn().await;
        let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
        match self.make_room(pool, slate_id, None, refuse).await {
            Ok(()) => {}
            Err(NoRoom::Wallet(error)) => return Err(ReceiveError::Wallet(error)),
            Err(NoRoom::FromSender | NoRoom::Full) => return Err(ReceiveError::OpenReceipts(None)),
            Err(NoRoom::Refused) => return Err(ReceiveError::Refused),
        }
        self.receive(method, wire, request).await
    }

    /// Checks the open receipt caps of `pool` before the new S1 `slate_id`, from `sender`
    /// when the transport names one, is received. A slate id received before passes, so its
    /// stored S2 is sent again. At a cap the wallet refreshes first, at most once a minute, so
    /// receipts already mined leave the count; then the S1 is refused. Nothing is cancelled to
    /// make room. With `refuse`, a new S1 is refused before any count, as
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
        let of_sender = |open: &[OpenReceipt]| {
            sender
                .as_ref()
                .map_or(0, |sender| from_sender(open, sender))
        };
        let policy = self.config().policy;
        let at_a_cap = |open: &[OpenReceipt]| {
            of_sender(open) >= policy.max_open_receipts_per_sender
                || open.len() >= policy.max_open_receipts
        };
        // An open receipt is one no refresh has seen confirmed yet, so some may already be
        // mined; a refresh confirms those before a cap refuses the S1.
        if at_a_cap(&open) && self.tip_refresh_due().await? {
            if let Err(error) = self.refresh().await {
                warn!(error = %ErrorChain(&error), "tip not refreshed");
            }
            open = self
                .open_receipts_unless_known(pool, None)
                .await?
                .unwrap_or_default();
        }
        let (refused, cap) = if of_sender(&open) >= policy.max_open_receipts_per_sender {
            (NoRoom::FromSender, ReceiptCap::PerSender)
        } else if open.len() >= policy.max_open_receipts {
            (NoRoom::Full, ReceiptCap::Total)
        } else {
            return Ok(());
        };
        // An epic1 payment reports the method it was taken by: `file` for one opened by hand
        // or taken at its delivery mailbox.
        let transport = pool.transport();
        info!(
            %slate_id,
            %transport,
            cap = cap.as_str(),
            open = open.len(),
            "payment refused at the open receipt cap"
        );
        self.emit(Event::PaymentRefused(RefusedPayment {
            slate_id: SlateId::from_bytes(*slate_id.as_bytes()),
            transport,
            sender: sender.map(|sender| sender.key.to_owned()),
            cap,
        }));
        Err(refused)
    }

    /// The open receipts of `pool` that count against its caps, oldest first, or `None` when
    /// `slate_id` was received before. The tip is the last one a refresh confirmed.
    async fn open_receipts_unless_known(
        &self,
        pool: Pool,
        slate_id: Option<Uuid>,
    ) -> Result<Option<Vec<OpenReceipt>>, WalletError> {
        let session = self.session()?;
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
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
                let tip = position(repos)?.confirmed_height();
                let mut open = Vec::new();
                for receipt in repos.open_receipts(pool.transport().as_str())? {
                    let epic1 = crate::epic1_index::index_of(repos, receipt.id)?.is_some();
                    if epic1 != matches!(pool, Pool::Epic1(_)) {
                        continue;
                    }
                    let slate = repos.transaction(receipt.id)?.and_then(|tx| tx.slate_id);
                    let contact = match slate {
                        Some(slate) => crate::contact_link::slate_contact(repos, slate)?,
                        None => None,
                    };
                    if contact.is_none() && counts_at(repos, &codecs, tip, receipt.id, slate)? {
                        open.push(receipt);
                    }
                }
                Ok(Some(open))
            })?)
        })
        .await
    }
}
