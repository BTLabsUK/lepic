// SPDX-License-Identifier: Apache-2.0
//! The mailbox list native mail goes to. The app keeps the list: its shipped mailboxes in its
//! own configuration and the user's changes in its settings. The session holds it in memory
//! from [`Session::mailbox_set`] and hands each change back for the app to store.

use lepic_epicbox::{MailboxProbe as EngineProbe, ProbeStep, RelayEndpoint, probe_mailbox};
use lepic_wallet_contacts::{
    MAX_MAILBOXES, MailboxList, MailboxListError, MailboxOrigin as EngineOrigin, MailboxStatus,
    mailbox_host, parse_mailbox,
};

use super::{Session, invalid, lock};
use crate::api::error::WalletError;
use crate::api::types::{
    ContactRelayMode, MailboxAdded, MailboxChanges, MailboxOrigin, MailboxProbe, MailboxProbeStep,
    MailboxRemoved, MailboxView,
};

impl Session {
    /// Sets the list from the app's shipped mailboxes and the user's changes to them; it
    /// replaces the one held, for running sessions too. Nothing changes when it is refused.
    pub(crate) fn mailbox_set(
        &self,
        shipped: &[String],
        added: &[String],
        removed: &[String],
    ) -> Result<(), WalletError> {
        let list = MailboxList::new(hosts(shipped)?, hosts(added)?, hosts(removed)?)?;
        if named(&list) > MAX_MAILBOXES {
            return Err(MailboxListError::Full.into());
        }
        *lock(&self.mailboxes) = Some(list);
        Ok(())
    }

    /// The list in use with each mailbox's origin and health: before [`Self::mailbox_set`], the
    /// wallet's own Epicbox relay alone.
    pub(crate) fn mailbox_list(&self) -> Result<Vec<MailboxView>, WalletError> {
        let relays = self.contact_relays(ContactRelayMode::Online)?;
        Ok(relays
            .list()
            .iter()
            .zip(relays.mailbox_status())
            .map(|(endpoint, status)| view(mailbox_host(endpoint), status))
            .collect())
    }

    /// Tests `host`, then adds it when the test passed or `anyway` is given.
    pub(crate) async fn mailbox_add(
        &self,
        host: &str,
        anyway: bool,
    ) -> Result<MailboxAdded, WalletError> {
        let endpoint = parse_mailbox(host)?;
        self.with_list(|_| Ok(()))?;
        let probe = self.mailbox_probe_of(&endpoint).await?;
        self.with_list(|list| {
            let added = if probe.passed || anyway {
                list.add(endpoint)?
            } else {
                false
            };
            Ok(MailboxAdded {
                added,
                probe,
                changes: changes(list),
            })
        })
    }

    /// Takes `host` out of the list: a shipped mailbox is marked removed, an added one goes.
    pub(crate) fn mailbox_remove(&self, host: &str) -> Result<MailboxRemoved, WalletError> {
        let endpoint = parse_mailbox(host)?;
        self.with_list(|list| {
            let removed = list.remove(&endpoint)?;
            Ok(MailboxRemoved {
                removed,
                changes: changes(list),
            })
        })
    }

    /// One test of `host` over the wallet's relay route; changes nothing.
    pub(crate) async fn mailbox_probe(&self, host: &str) -> Result<MailboxProbe, WalletError> {
        let endpoint = parse_mailbox(host)?;
        self.mailbox_probe_of(&endpoint).await
    }

    async fn mailbox_probe_of(
        &self,
        endpoint: &RelayEndpoint,
    ) -> Result<MailboxProbe, WalletError> {
        let epicbox = self.epicbox()?;
        let mut settings = epicbox.settings().clone();
        settings.endpoint = endpoint.clone();
        let probe = probe_mailbox(&settings, epicbox.connector().as_ref()).await;
        Ok(probe_view(mailbox_host(endpoint), &probe))
    }

    /// Runs `change` on the list held; a change it refuses leaves the list as it was.
    fn with_list<T>(
        &self,
        change: impl FnOnce(&mut MailboxList) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let mut held = lock(&self.mailboxes);
        let list = held
            .as_mut()
            .ok_or_else(|| invalid("no mailbox list is set: call mailbox_set first"))?;
        let mut changed = list.clone();
        let answer = change(&mut changed)?;
        *list = changed;
        Ok(answer)
    }
}

/// Each of `hosts` as a mailbox; the first that is not one is named in the error.
fn hosts(hosts: &[String]) -> Result<Vec<RelayEndpoint>, WalletError> {
    if hosts.len() > MAX_MAILBOXES {
        return Err(MailboxListError::Full.into());
    }
    hosts
        .iter()
        .map(|host| {
            parse_mailbox(host).map_err(|error| {
                let mut error = WalletError::from(error);
                error.message = format!("{host}: {}", error.message);
                error
            })
        })
        .collect()
}

/// How many mailboxes `list` names, counting those past [`MAX_MAILBOXES`] that its listing
/// leaves out.
fn named(list: &MailboxList) -> usize {
    let removed: Vec<String> = list.removed().iter().map(mailbox_host).collect();
    let shipped = list
        .shipped()
        .iter()
        .map(mailbox_host)
        .filter(|host| !removed.contains(host));
    let mut named: Vec<String> = Vec::new();
    for host in shipped.chain(list.added().iter().map(mailbox_host)) {
        if !named.contains(&host) {
            named.push(host);
        }
    }
    named.len()
}

fn changes(list: &MailboxList) -> MailboxChanges {
    MailboxChanges {
        added: list.added().iter().map(mailbox_host).collect(),
        removed: list.removed().iter().map(mailbox_host).collect(),
    }
}

fn view(host: String, status: MailboxStatus) -> MailboxView {
    let origin = match status.origin {
        EngineOrigin::Added => MailboxOrigin::Added,
        EngineOrigin::Shipped => MailboxOrigin::Shipped,
    };
    let last_success_at_ms = status
        .last_success
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_millis()).ok());
    MailboxView {
        host,
        origin,
        push: status.push,
        no_mux: status.no_mux,
        last_success_at_ms,
        failures: status.failures,
        last_error: status.last_error,
    }
}

fn probe_view(host: String, probe: &EngineProbe) -> MailboxProbe {
    MailboxProbe {
        host,
        tls: step(&probe.tls),
        greeting: step(&probe.greeting),
        push: step(&probe.push),
        failure: [&probe.tls, &probe.greeting, &probe.push]
            .into_iter()
            .find_map(|step| match step {
                ProbeStep::Failed(reason) => Some(reason.clone()),
                _ => None,
            }),
        passed: probe.passed(),
    }
}

fn step(step: &ProbeStep) -> MailboxProbeStep {
    match step {
        ProbeStep::Passed => MailboxProbeStep::Passed,
        ProbeStep::Failed(_) => MailboxProbeStep::Failed,
        _ => MailboxProbeStep::NotReached,
    }
}
