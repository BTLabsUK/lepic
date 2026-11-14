// SPDX-License-Identifier: Apache-2.0
//! The task that owns a subscription: it connects, reconnects with backoff in `listen` mode,
//! and records how the subscription ended.

use std::pin::pin;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::client::{CancelToken, ClientContext, ClientError};
use crate::frame::RelayMessageId;
use crate::session::{Connection, Greeting};

use super::inbox::Shared;
use super::session::Session;
use super::{Carry, ConnectionState, Disconnect, Mode};

pub(super) struct Command {
    pub(super) msg_id: RelayMessageId,
    pub(super) reply: oneshot::Sender<Result<(), ClientError>>,
}

/// How a subscription ended without an error.
pub(super) enum End {
    Stopped,
    Drained,
}

pub(super) struct Manager {
    pub(super) context: Arc<ClientContext>,
    pub(super) shared: Arc<Shared>,
    pub(super) commands: mpsc::UnboundedReceiver<Command>,
    pub(super) mode: Mode,
    /// A listener moves to a fresh socket after this many rounds with a message held. `None`
    /// keeps the socket. Never applies to a drain.
    pub(super) held_rounds: Option<u32>,
    /// A listener leaves a socket that sent no challenge for this many challenge intervals.
    /// `None` keeps the socket. Never applies to a drain.
    pub(super) challenge_rounds: Option<u32>,
    /// Set for a drain that hands its connection on.
    pub(super) carry: Option<Carry>,
    pub(super) cancel: CancelToken,
}

impl Manager {
    pub(super) async fn run(mut self) -> Result<(), ClientError> {
        let outcome = self.connect_loop().await;
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            let _ = command.reply.send(Err(ClientError::Ended));
        }
        let state = match &outcome {
            Ok(End::Stopped) => ConnectionState::Stopped,
            Ok(End::Drained) => ConnectionState::Drained,
            Err(_) => ConnectionState::Failed,
        };
        self.shared.update(|inbox| inbox.expecting = false);
        self.shared.set_state(state);
        match outcome {
            Ok(End::Stopped) => {
                info!("epicbox stopped");
                Ok(())
            }
            Ok(End::Drained) => {
                info!("epicbox drained");
                Ok(())
            }
            Err(error) => {
                warn!(error = %ErrorChain(&error), "epicbox subscription failed");
                Err(error)
            }
        }
    }

    pub(super) async fn connect_loop(&mut self) -> Result<End, ClientError> {
        let mut attempt: u32 = 0;
        loop {
            attempt = attempt.saturating_add(1);
            info!(
                attempt,
                relay = %self.context.settings.endpoint.domain(),
                "epicbox connecting"
            );
            self.shared
                .set_state(ConnectionState::Connecting { attempt });
            let cancel = self.cancel.clone();
            let opened = tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(End::Stopped),
                opened = self.open() => opened,
            };
            let failure = match opened {
                Ok((connection, greeting)) => {
                    let session = Session::new(self, connection, greeting);
                    match session.run(&mut attempt).await {
                        Ok(end) => return Ok(end),
                        Err(error) => error,
                    }
                }
                Err(error) => error,
            };
            self.shared.update(|inbox| inbox.expecting = false);
            if self.mode == Mode::Drain {
                return Err(failure);
            }
            let delay = self
                .context
                .settings
                .backoff
                .delay(attempt.max(1), getrandom::u32().unwrap_or(u32::MAX));
            let reason = ErrorChain(&failure).to_string();
            let retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            warn!(attempt, retry_in_ms, error = %reason, "epicbox disconnected, retrying");
            *self
                .shared
                .disconnect
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Disconnect {
                reason,
                retry_in: delay,
            });
            self.shared
                .set_state(ConnectionState::Waiting { attempt, delay });
            if self.wait(delay).await {
                return Ok(End::Stopped);
            }
        }
    }

    pub(super) async fn open(&mut self) -> Result<(Connection, Greeting), ClientError> {
        if let Some(handed) = self.carry.as_mut().and_then(|carry| carry.incoming.take()) {
            self.shared
                .update(|inbox| inbox.relay_version = handed.greeting.version);
            return Ok((handed.connection, handed.greeting));
        }
        let settings = &self.context.settings;
        let mut connection = Connection::open(
            self.context.connector.as_ref(),
            &settings.endpoint,
            settings.connect_timeout,
        )
        .await?;
        let greeting = connection.greet(self.mode.wallet_mode(), settings).await?;
        self.shared
            .update(|inbox| inbox.relay_version = greeting.version);
        Ok((connection, greeting))
    }

    /// Sleeps for `delay` while refusing acknowledgements, which need a connection. Returns
    /// whether the subscription was stopped.
    pub(super) async fn wait(&mut self, delay: Duration) -> bool {
        let mut nap = pin!(sleep(delay));
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return true,
                () = &mut nap => return false,
                Some(command) = self.commands.recv() => {
                    let _ = command.reply.send(Err(ClientError::NotConnected));
                }
            }
        }
    }
}
