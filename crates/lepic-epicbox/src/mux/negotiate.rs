// SPDX-License-Identifier: Apache-2.0
//! The mux/1 greeting: ask for the extension and read whether the relay offers it.

use lepic_primitives::error_chain::ErrorChain;
use tokio::time::timeout_at;
use tracing::{debug, warn};

use crate::client::{Awaiting, ClientError};
use crate::frame::{ClientFrame, FrameError, WalletMode};
use crate::mux_frame::{MuxChallenge, MuxCode, MuxLimits, MuxRelayFrame, OkFrame};
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
}

impl Manager {
    /// Asks for mux/1 and reads the relay's answer. The first `Challenge` a relay may send is
    /// ignored: only the challenge of the `Ok` is signed.
    pub(super) async fn negotiate(
        &self,
        connection: &mut Connection,
    ) -> Result<Negotiated, Refusal> {
        let timed_out = || {
            Refusal::Silent(ClientError::Timeout {
                awaiting: Awaiting::Answer,
            })
        };
        let deadline = deadline_after(self.settings.response_timeout);
        let details = ClientFrame::client_details_with_mux(
            &self.settings.wallet_version,
            WalletMode::Listener,
        )
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
                Ok(MuxRelayFrame::Ok(ok)) => return Self::accept(ok),
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

    fn accept(ok: OkFrame) -> Result<Negotiated, Refusal> {
        if !ok.offers_mux() {
            return Err(Refusal::NotOffered);
        }
        match ok.challenge {
            Some(challenge) => Ok(Negotiated {
                challenge,
                limits: ok.limits,
            }),
            None => Err(Refusal::Failed(ClientError::Frame(
                FrameError::MuxChallenge,
            ))),
        }
    }
}
