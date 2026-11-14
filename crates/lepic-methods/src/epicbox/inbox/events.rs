// SPDX-License-Identifier: Apache-2.0
//! Connection events of a drain or a listen: how the state of a relay connection becomes
//! [`Event::Transport`] and [`Event::TransportDisconnected`] for the host.

use std::convert::Infallible;

use lepic_epicbox::{ConnectionState, MuxSession, MuxState, Subscription, TRANSPORT_ID};
use lepic_node::NodeApi;
use lepic_wallet::event::{
    Connection, Event, TransportDisconnect, TransportState, TransportStatus,
};
use lepic_wallet::{SecretVault, StoreOpener, Wallet};

/// The reason given when the relay client has no better one for a lost connection.
const CONNECTION_ENDED: &str = "connection ended";

fn transport_state(state: ConnectionState) -> TransportState {
    match state {
        ConnectionState::Connecting { .. } => TransportState::Connecting,
        ConnectionState::Subscribed => TransportState::Connected,
        ConnectionState::Stopped | ConnectionState::Drained => TransportState::Stopped,
        _ => TransportState::Disconnected,
    }
}

fn emit_status<N, S, V>(wallet: &Wallet<N, S, V>, connection: Connection, state: TransportState)
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    wallet.emit(Event::Transport(TransportStatus {
        transport: TRANSPORT_ID,
        connection,
        state,
    }));
}

fn emit_disconnect<N, S, V>(
    wallet: &Wallet<N, S, V>,
    connection: Connection,
    reason: String,
    retry_in: Option<std::time::Duration>,
) where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    wallet.emit(Event::TransportDisconnected(TransportDisconnect {
        transport: TRANSPORT_ID,
        connection,
        reason,
        retry_in,
    }));
}

/// Emits the connection events of `subscription` until it has ended. Each change of the mapped
/// state is one event; a lost connection also reports why and when the client tries again.
pub(super) async fn forward_states<N, S, V>(
    wallet: &Wallet<N, S, V>,
    subscription: &Subscription,
    connection: Connection,
) where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    let mut states = subscription.state();
    let mut last = None;
    loop {
        let state = *states.borrow_and_update();
        let mapped = transport_state(state);
        if last != Some(mapped) {
            last = Some(mapped);
            emit_status(wallet, connection, mapped);
            if mapped == TransportState::Disconnected {
                let disconnect = subscription.last_disconnect();
                let reason = disconnect
                    .as_ref()
                    .map_or_else(|| CONNECTION_ENDED.to_owned(), |d| d.reason.clone());
                emit_disconnect(
                    wallet,
                    connection,
                    reason,
                    disconnect.map(|disconnect| disconnect.retry_in),
                );
            }
        }
        if state.has_ended() || states.changed().await.is_err() {
            return;
        }
    }
}

/// Emits the connection events of a mux/1 session while the returned future is polled; it never
/// completes, so a caller can race it against the work the session serves. A relay that does
/// not offer mux/1 emits nothing: the listener goes on over a socket and reports that one.
pub(super) async fn forward_mux_states<N, S, V>(
    wallet: &Wallet<N, S, V>,
    session: &MuxSession,
    connection: Connection,
) -> Infallible
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    forward_until_ended(wallet, session, connection).await;
    std::future::pending().await
}

async fn forward_until_ended<N, S, V>(
    wallet: &Wallet<N, S, V>,
    session: &MuxSession,
    connection: Connection,
) where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    let mut states = session.state();
    let mut last = None;
    loop {
        let state = *states.borrow_and_update();
        let mapped = match state {
            MuxState::Connecting { .. } => TransportState::Connecting,
            MuxState::Attached => TransportState::Connected,
            MuxState::NotOffered => return,
            MuxState::Stopped => TransportState::Stopped,
            _ => TransportState::Disconnected,
        };
        if last != Some(mapped) {
            last = Some(mapped);
            emit_status(wallet, connection, mapped);
            if let MuxState::Waiting { delay, .. } = state {
                emit_disconnect(wallet, connection, CONNECTION_ENDED.to_owned(), Some(delay));
            }
        }
        if state.has_ended() || states.changed().await.is_err() {
            return;
        }
    }
}
