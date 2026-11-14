// SPDX-License-Identifier: Apache-2.0
//! The Epicbox inbox loop (ADR 0004): it takes each message the relay hands out to the engine
//! with [`Wallet::arrived`], records how it settled and acknowledges it.
//!
//! A message is acknowledged once its effect is stored, or once it was rejected for good and
//! the rejection is recorded, under its relay message id when the relay gave it one; a
//! transient failure leaves it unacknowledged, so the relay delivers it again. A held message
//! holds back everything behind it, because the relay delivers one message at a time. An answer
//! the engine gives back as [`lepic_wallet::inbox::Outcome::Requeue`] is posted back to the address for another
//! install of the wallet before it is acknowledged.
//!
//! - `source`: where messages come from, a socket subscription or a shared mux/1 session.
//! - `run`: the loop that settles them.
//! - `events`: the connection events the host hears.

mod events;
mod run;
mod source;

pub(super) use self::run::Run;
pub(super) use self::source::Source;

use std::sync::Arc;

use lepic_epicbox::{
    EpicboxAddress, EpicboxClient, Identity, ListenOptions, MailboxClient, MuxError, MuxOptions,
    MuxSession, MuxState, RELAY_RETENTION, Subscription, TRANSPORT_ID,
};
use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_transport::method::Method;
use lepic_wallet::event::{Connection, Event, TransportState, TransportStatus};
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet::{SecretVault, StoreOpener, Wallet};
use tracing::{debug, info, instrument, warn};

use self::events::{forward_mux_states, forward_states};
use self::source::Pushed;
use super::sessions::PAYMENTS_OWNER;
use super::{Epicbox, NATIVE_NOTICE_LENGTHS};

// The engine drops a notice longer than this, so the longest padding must fit.
const _: () = assert!(NATIVE_NOTICE_LENGTHS[2] <= lepic_wallet::notice::MAX_NOTICE_LEN);

impl Epicbox {
    /// Attaches `wallet`'s Epicbox identity, the address key of the default account at index 0
    /// as `epic-wallet` derives it, so that this method can send and receive for it, and
    /// returns the wallet's address at the relay. Attaching again replaces the identity. The
    /// key stays attached until [`Epicbox::detach`]; hosts detach when they lock.
    ///
    /// Fails with [`InboxError::Wallet`] carrying [`lepic_wallet::WalletError::Locked`], and
    /// with [`InboxError::NetworkMismatch`] when this method serves the other network.
    pub fn attach_wallet<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
    ) -> Result<EpicboxAddress, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        Ok(self.attached_client(wallet)?.address().clone())
    }

    fn attached_client<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
    ) -> Result<EpicboxClient, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        Ok(self.attach(self.identity(wallet)?))
    }

    /// Connects to the relay once, handles every pending message for `wallet` and disconnects:
    /// the mode for background work on mobile. Attaches the wallet's identity first, as
    /// [`Epicbox::attach_wallet`] does. Slates that arrive are taken and answered over this
    /// method.
    ///
    /// Stops at the first message that fails for a transient reason, such as the node being
    /// unreachable, and leaves it and everything behind it on the relay for the next drain.
    /// A slate the node's tip says has expired is such a message until a refresh stores a
    /// confirmed height at or past its cutoff; the drain makes one refresh itself before it
    /// holds one. A reply or an expired slate is not held past the bound the engine's inbox
    /// docs give. Fails with [`InboxError::Subscription`] when the relay connection fails;
    /// whatever was handled until then stays handled. Fails as [`Epicbox::attach_wallet`]
    /// does.
    #[instrument(skip_all, fields(wallet = %wallet.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn drain<N, S, V>(&self, wallet: &Wallet<N, S, V>) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let client = self.inbox_client(wallet).await?;
        let subscription = client
            .drain()
            .map_err(|error| InboxError::Subscription(Box::new(error)))?;
        let method: Arc<dyn Method> = Arc::new(self.clone());
        self.run_inbox(wallet, method, &subscription, None).await
    }

    /// Holds a relay connection and handles messages for `wallet` as they arrive, until
    /// `handle` is stopped: the mode while the app is in the foreground. Reconnects on its own
    /// after the relay drops. Emits [`Event::Transport`] as the connection changes, and
    /// attaches the wallet's identity first, as [`Epicbox::attach_wallet`] does.
    ///
    /// A message that fails for a transient reason is tried again with backoff, and nothing
    /// behind it is delivered until it settles. A slate the node's tip says has expired settles
    /// once a refresh stores a confirmed height at or past its cutoff; the listen refreshes the
    /// tip itself before it holds one, at most once a minute. A reply or an expired slate is not
    /// held past the bound the engine's inbox docs give. Fails as [`Epicbox::drain`] does
    /// before it connects.
    #[instrument(skip_all, fields(wallet = %wallet.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn listen<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        handle: &ListenHandle,
    ) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let client = self.inbox_client(wallet).await?;
        let subscription = client
            .listen_with(ListenOptions {
                held_rounds: wallet.config().policy.listener_held_rounds,
                challenge_rounds: wallet.config().policy.listener_challenge_rounds,
            })
            .map_err(|error| InboxError::Subscription(Box::new(error)))?;
        let method: Arc<dyn Method> = Arc::new(self.clone());
        self.run_inbox(wallet, method, &subscription, Some(handle))
            .await
    }

    /// Like [`Epicbox::listen`], but reads the wallet's mail from a mux/1 session on this
    /// transport's relay that other consumers share: the session of `group` in
    /// [`Epicbox::pushed`], opened on the first call and kept while another owner uses it. The
    /// wallet's mailbox is the payments claim of that session.
    ///
    /// A message is handled, held, requeued and acknowledged as [`Epicbox::listen`] does it. The
    /// connection events differ: [`TransportState::Disconnected`] follows a session that is
    /// waiting to reconnect. When the relay does not offer mux/1, this falls back to
    /// [`Epicbox::listen`] with its own socket, so the host needs no second code path. Fails as
    /// [`Epicbox::listen`] does.
    #[instrument(skip_all, fields(wallet = %wallet.config().name, transport = TRANSPORT_ID.as_str(), group))]
    pub async fn listen_via<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        handle: &ListenHandle,
        group: &str,
        options: MuxOptions,
    ) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        self.inbox_client(wallet).await?;
        let identity = self.identity(wallet)?;
        let client = MailboxClient::new(self.settings().clone(), self.connector());
        let session = match self.payments_session(&client, group, options) {
            Ok(session) => session,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "mux/1 session not started, listening on a socket");
                return self.listen(wallet, handle).await;
            }
        };
        let outcome = tokio::select! {
            biased;
            outcome = self.listen_on_session(wallet, handle, &session, identity, &client) => outcome,
            never = forward_mux_states(wallet, &session, Connection::Listener) => match never {},
        };
        self.pushed().release(PAYMENTS_OWNER);
        let not_offered = *session.state().borrow() == MuxState::NotOffered;
        if (matches!(outcome, Ok(None)) || not_offered) && !handle.is_stopped() {
            info!("relay does not offer mux/1, listening on a socket");
            return self.listen(wallet, handle).await;
        }
        wallet.emit(Event::Transport(TransportStatus {
            transport: TRANSPORT_ID,
            connection: Connection::Listener,
            state: TransportState::Stopped,
        }));
        outcome.map(Option::unwrap_or_default)
    }

    /// The shared session of `group` on this transport's relay, started with `client` if there
    /// is none, with the payments listener added to its owners.
    fn payments_session(
        &self,
        client: &MailboxClient,
        group: &str,
        options: MuxOptions,
    ) -> Result<Arc<MuxSession>, MuxError> {
        let endpoint = &self.settings().endpoint;
        let relay = format!("{}:{}", endpoint.domain(), endpoint.port());
        self.pushed()
            .get_or_start(&relay, group, PAYMENTS_OWNER, || {
                client.start_mux_queued(Vec::new(), options)
            })
    }

    /// Claims the payments mailbox on `session` and consumes it until `handle` is stopped.
    /// Returns `None` when the relay refuses the claim, so the caller can listen on a socket.
    async fn listen_on_session<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        handle: &ListenHandle,
        session: &Arc<MuxSession>,
        identity: Identity,
        client: &MailboxClient,
    ) -> Result<Option<InboxSummary>, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let claimed = tokio::select! {
            biased;
            () = handle.stopped() => return Ok(Some(InboxSummary::default())),
            claimed = claim_payments_mailbox(session, &identity) => claimed,
        };
        let Some(index) = claimed else {
            return Ok(None);
        };
        let pushed = Pushed::new(Arc::clone(session), index, identity, client.clone());
        let method: Arc<dyn Method> = Arc::new(self.clone());
        Run::new(
            wallet,
            method,
            Source::Pushed(&pushed),
            self.settings().backoff,
        )
        .listening(Some(handle))
        .consume()
        .await
        .map(Some)
    }

    /// The attached client for a drain or a listen, after pruning the relay inbox. Pruning runs
    /// before the subscription starts, so the host sees every connection state.
    async fn inbox_client<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
    ) -> Result<EpicboxClient, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let client = self.attached_client(wallet)?;
        wallet.prune_arrivals(RELAY_RETENTION).await;
        Ok(client)
    }

    /// Consumes the subscription and stops it, while its connection state goes out as events.
    async fn run_inbox<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        method: Arc<dyn Method>,
        subscription: &Subscription,
        listen: Option<&ListenHandle>,
    ) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let run = Run::new(
            wallet,
            method,
            Source::Socket(subscription),
            self.settings().backoff,
        )
        .listening(listen);
        let consume = async {
            let consumed = run.consume().await;
            // A failed connection explains a failed consume better than the consume does.
            subscription
                .stop()
                .await
                .map_err(|error| InboxError::Subscription(Box::new(error)))?;
            consumed
        };
        let connection = match listen {
            Some(_) => Connection::Listener,
            None => Connection::PaymentsDrain,
        };
        let (result, ()) = tokio::join!(consume, forward_states(wallet, subscription, connection));
        result
    }
}

/// The index of the payments mailbox in `session`, once the relay applies the claim of
/// `identity`; `None` when it refuses it.
async fn claim_payments_mailbox(session: &MuxSession, identity: &Identity) -> Option<usize> {
    match session
        .set_claim(PAYMENTS_OWNER, vec![identity.clone()])
        .await
    {
        Ok(claimed) => claimed.indexes.first().copied(),
        Err(error) => {
            debug!(error = %ErrorChain(&error), "mux/1 claim refused");
            None
        }
    }
}
