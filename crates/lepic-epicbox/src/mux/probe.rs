// SPDX-License-Identifier: Apache-2.0
//! A one-off check of a mailbox the user may add: does it open over TLS, answer the greeting, and
//! offer mux/1. The probe reports; the host decides what to do with the result.

use lepic_primitives::error_chain::ErrorChain;

use crate::client::ClientSettings;
use crate::session::{Connection, Connector};

use super::negotiate::{Refusal, greet};

/// The result of one step of a probe.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeStep {
    Passed,
    /// The step failed, with why.
    Failed(String),
    /// An earlier step failed, so this one was not tried.
    NotReached,
}

impl ProbeStep {
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// What a probe of one mailbox found.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MailboxProbe {
    /// The connection, its TLS handshake and the websocket upgrade.
    pub tls: ProbeStep,
    /// The mailbox answered the greeting with `Ok`.
    pub greeting: ProbeStep,
    /// The `Ok` offered mux/1, which the wallet reads by.
    pub push: ProbeStep,
}

impl MailboxProbe {
    /// Every step passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.tls.passed() && self.greeting.passed() && self.push.passed()
    }
}

fn failed(error: &(dyn std::error::Error + 'static)) -> ProbeStep {
    ProbeStep::Failed(ErrorChain(error).to_string())
}

/// Opens one connection to `settings.endpoint`, greets it as a mux/1 listener and closes it.
/// Nothing is attached, posted or stored.
pub async fn probe_mailbox(settings: &ClientSettings, connector: &dyn Connector) -> MailboxProbe {
    let mut connection =
        match Connection::open(connector, &settings.endpoint, settings.connect_timeout).await {
            Ok(connection) => connection,
            Err(error) => {
                return MailboxProbe {
                    tls: failed(&error),
                    greeting: ProbeStep::NotReached,
                    push: ProbeStep::NotReached,
                };
            }
        };
    let greeted = greet(&mut connection, settings).await;
    connection.close().await;
    let (greeting, push) = match greeted {
        Ok(ok) if ok.offers_mux() => (ProbeStep::Passed, ProbeStep::Passed),
        Ok(_) | Err(Refusal::NotOffered) => (
            ProbeStep::Passed,
            ProbeStep::Failed("the mailbox does not offer mux/1".to_owned()),
        ),
        Err(Refusal::Rejected(error) | Refusal::Silent(error) | Refusal::Failed(error)) => {
            (failed(&error), ProbeStep::NotReached)
        }
    };
    MailboxProbe {
        tls: ProbeStep::Passed,
        greeting,
        push,
    }
}
