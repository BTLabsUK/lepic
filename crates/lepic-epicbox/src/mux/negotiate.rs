// SPDX-License-Identifier: Apache-2.0
//! The mux/1 greeting: ask for the extension and read whether the relay offers it.

use lepic_primitives::error_chain::ErrorChain;
use tokio::time::timeout_at;
use tracing::{debug, warn};

use crate::client::{Awaiting, ClientError, ClientSettings};
use crate::frame::{CANCEL_FORM_EXTENSION, ClientFrame, FrameError, WalletMode};
use crate::mux_frame::{
    ATTACH_HOST_EXTENSION, MuxChallenge, MuxCode, MuxLimits, MuxRelayFrame, OkFrame,
    TXCANCEL_EXTENSION,
};
use crate::session::{Connection, deadline_after};

use super::manager::Manager;

pub(super) enum Refusal {
    NotOffered,
    /// The relay answered the greeting with an `Error` (other than a rate limit).
    Rejected(ClientError),
    /// The greeting got no answer in time.
    Silent(ClientError),
    Failed(ClientError),
}

pub(super) struct Negotiated {
    pub(super) challenge: MuxChallenge,
    pub(super) limits: MuxLimits,
    /// The relay listed `txcancel/1`: cancel fields and frames may be used on this socket.
    pub(super) cancel: bool,
    /// The relay echoed the cancel-form extension: cancels are signed over the
    /// domain-separated text.
    pub(super) cancel_form: bool,
    /// The relay listed the host-bound attach extension: attach signatures name this host,
    /// the mailbox's name as the wallet dialled it, lowercase and without a port.
    pub(super) attach_host: Option<String>,
}

impl Manager {
    /// Asks for mux/1 and reads the relay's answer. The first `Challenge` a relay may send is
    /// ignored: only the challenge of the `Ok` is signed.
    pub(super) async fn negotiate(
        &self,
        connection: &mut Connection,
    ) -> Result<Negotiated, Refusal> {
        let host = dialled_host(self.settings.endpoint.domain().as_str());
        Self::accept(greet(connection, &self.settings).await?, host)
    }

    fn accept(ok: OkFrame, host: String) -> Result<Negotiated, Refusal> {
        if !ok.offers_mux() {
            return Err(Refusal::NotOffered);
        }
        match ok.challenge {
            Some(challenge) => Ok(Negotiated {
                challenge,
                limits: ok.limits,
                cancel: ok.ext.iter().any(|ext| ext == TXCANCEL_EXTENSION),
                cancel_form: ok.ext.iter().any(|ext| ext == CANCEL_FORM_EXTENSION),
                attach_host: ok
                    .ext
                    .iter()
                    .any(|ext| ext == ATTACH_HOST_EXTENSION)
                    .then_some(host),
            }),
            None => Err(Refusal::Failed(ClientError::Frame(
                FrameError::MuxChallenge,
            ))),
        }
    }
}

/// The host an attach signature names: the mailbox's domain as dialled, in lower case, without
/// the trailing dot of an absolute name. The endpoint keeps the port apart.
pub(super) fn dialled_host(domain: &str) -> String {
    let host = domain.to_ascii_lowercase();
    match host.strip_suffix('.') {
        Some(stripped) => stripped.to_owned(),
        None => host,
    }
}

/// Sends the greeting that asks for mux/1 and reads the relay's `Ok`, whether or not it offers
/// the extension. Frames before the answer are ignored.
pub(super) async fn greet(
    connection: &mut Connection,
    settings: &ClientSettings,
) -> Result<OkFrame, Refusal> {
    let timed_out = || {
        Refusal::Silent(ClientError::Timeout {
            awaiting: Awaiting::Answer,
        })
    };
    let deadline = deadline_after(settings.response_timeout);
    let details =
        ClientFrame::client_details_with_mux(&settings.wallet_version, WalletMode::Listener)
            .to_json()
            .map_err(|error| Refusal::Failed(ClientError::Frame(error)))?;
    timeout_at(deadline, connection.send_text(details))
        .await
        .map_err(|_| timed_out())?
        .map_err(Refusal::Failed)?;
    loop {
        let text = timeout_at(deadline, connection.receive_text())
            .await
            .map_err(|_| timed_out())?
            .map_err(Refusal::Failed)?;
        match MuxRelayFrame::from_json(&text) {
            Ok(MuxRelayFrame::Ok(ok)) => return Ok(ok),
            Ok(MuxRelayFrame::Error(error)) => {
                let refusal = ClientError::Relay { kind: error.kind };
                return Err(if error.code == Some(MuxCode::RateLimited) {
                    Refusal::Failed(refusal)
                } else {
                    Refusal::Rejected(refusal)
                });
            }
            Ok(_) => debug!("epicbox frame ignored during mux negotiation"),
            Err(FrameError::MuxChallenge) => {
                warn!("epicbox relay sent a mux challenge of the wrong shape");
                return Err(Refusal::Failed(ClientError::Frame(
                    FrameError::MuxChallenge,
                )));
            }
            Err(error) => {
                debug!(error = %ErrorChain(&error), "epicbox frame ignored during mux negotiation");
            }
        }
    }
}
