// SPDX-License-Identifier: Apache-2.0
//! The wallet's one mailbox list (ADR 0065): the mailboxes shipped with the host's release, plus
//! those the user added, minus the shipped ones the user removed. The host stores only what was
//! added and removed, so a release that changes the shipped part reaches every install.

use std::time::SystemTime;

use lepic_epicbox::{Domain, RelayEndpoint, Security};
use lepic_transport::host_rule::{self, HostClass};
use thiserror::Error;

use super::ContactRelays;
use super::delivery::carrier::Carrier;
use super::delivery::transport::Transport;
use super::relay::parse_host;

/// The most mailboxes a list holds.
pub const MAX_MAILBOXES: usize = 16;

/// Name endings that only a private network resolves: a mailbox there reaches no other device.
const PRIVATE_SUFFIXES: [&str; 5] = ["internal", "lan", "home.arpa", "intranet", "corp"];

/// Where a mailbox of the list comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxOrigin {
    /// Shipped with the host's release.
    Shipped,
    /// Added by the user.
    Added,
}

/// One mailbox of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedMailbox {
    pub endpoint: RelayEndpoint,
    pub origin: MailboxOrigin,
}

/// Why the mailbox list refused a change.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MailboxListError {
    #[error("a mailbox is a domain name with an optional non-zero port")]
    NotAName,
    /// The host is this device, an address, or a name only a private network resolves: no
    /// other device would reach mail posted there.
    #[error("the mailbox is not a public name on the internet")]
    NotPublic,
    #[error("the list already holds {MAX_MAILBOXES} mailboxes")]
    Full,
    #[error("the last mailbox of the list cannot be removed")]
    Last,
    /// The shipped list and the user's changes leave no mailbox.
    #[error("the mailbox list is empty")]
    Empty,
}

/// Whether `a` and `b` are one mailbox: their domains match in any case and their ports are
/// equal, so a host given with and without its default port is one mailbox.
pub(crate) fn same_mailbox(a: &RelayEndpoint, b: &RelayEndpoint) -> bool {
    a.domain() == b.domain() && a.port() == b.port()
}

/// The mailbox `host`, `domain[:port]`, reached over TLS. Refused for anything that is not a
/// public name on the internet: an address, this device, or a private network's name.
pub fn parse_mailbox(host: &str) -> Result<RelayEndpoint, MailboxListError> {
    let (domain, port) =
        parse_host(&host.trim().to_ascii_lowercase()).map_err(|_| MailboxListError::NotAName)?;
    if port == Some(0) {
        return Err(MailboxListError::NotAName);
    }
    let endpoint = RelayEndpoint::new(domain, port, Security::Tls);
    check_public(&endpoint)?;
    Ok(endpoint)
}

/// Refuses an endpoint that is not TLS to a public name.
pub(crate) fn check_public(endpoint: &RelayEndpoint) -> Result<(), MailboxListError> {
    if endpoint.security() != Security::Tls || !is_public_name(endpoint.domain()) {
        return Err(MailboxListError::NotPublic);
    }
    Ok(())
}

/// Whether `domain` is a name that resolves on the internet: not an address, not this device,
/// not a single label and not under a private suffix.
fn is_public_name(domain: &Domain) -> bool {
    let name = domain.as_str().trim_end_matches('.').to_ascii_lowercase();
    if name
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !name.contains('.')
    {
        return false;
    }
    if PRIVATE_SUFFIXES
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
    {
        return false;
    }
    matches!(host_rule::classify_name(&name), Ok(HostClass::Public))
}

/// The list: shipped, added and removed, as the host stores the last two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxList {
    shipped: Vec<RelayEndpoint>,
    added: Vec<RelayEndpoint>,
    removed: Vec<RelayEndpoint>,
}

impl MailboxList {
    /// The list of `shipped` with the user's `added` and `removed`. The shipped mailboxes are the
    /// host's own and are taken as given; an added one the host stored is taken as given too.
    /// A removed mailbox that is not shipped is kept, so it stays removed if a release ships it.
    ///
    /// Fails with [`MailboxListError::Empty`] when nothing is left.
    pub fn new(
        shipped: Vec<RelayEndpoint>,
        added: Vec<RelayEndpoint>,
        removed: Vec<RelayEndpoint>,
    ) -> Result<Self, MailboxListError> {
        let list = Self {
            shipped,
            added,
            removed,
        };
        if list.listed().is_empty() {
            return Err(MailboxListError::Empty);
        }
        Ok(list)
    }

    /// `endpoint` as the one shipped mailbox.
    pub(crate) fn of_one(endpoint: RelayEndpoint) -> Self {
        Self {
            shipped: vec![endpoint],
            added: Vec::new(),
            removed: Vec::new(),
        }
    }

    /// The shipped mailboxes only.
    pub fn shipped_only(shipped: Vec<RelayEndpoint>) -> Result<Self, MailboxListError> {
        Self::new(shipped, Vec::new(), Vec::new())
    }

    /// The mailboxes, shipped ones first in their order, then added ones in the order they were
    /// added. A mailbox named twice is listed once, where it first appears; past
    /// [`MAX_MAILBOXES`] the rest are left out.
    pub fn listed(&self) -> Vec<ListedMailbox> {
        let shipped = self
            .shipped
            .iter()
            .filter(|endpoint| !self.removed.iter().any(|gone| same_mailbox(gone, endpoint)))
            .map(|endpoint| (endpoint, MailboxOrigin::Shipped));
        let added = self
            .added
            .iter()
            .map(|endpoint| (endpoint, MailboxOrigin::Added));
        let mut listed: Vec<ListedMailbox> = Vec::new();
        for (endpoint, origin) in shipped.chain(added) {
            if listed.len() == MAX_MAILBOXES {
                break;
            }
            if !listed
                .iter()
                .any(|known| same_mailbox(&known.endpoint, endpoint))
            {
                listed.push(ListedMailbox {
                    endpoint: endpoint.clone(),
                    origin,
                });
            }
        }
        listed
    }

    /// The endpoints of [`MailboxList::listed`].
    pub fn endpoints(&self) -> Vec<RelayEndpoint> {
        self.listed()
            .into_iter()
            .map(|listed| listed.endpoint)
            .collect()
    }

    /// Whether `endpoint` is one of the listed mailboxes.
    pub fn contains(&self, endpoint: &RelayEndpoint) -> bool {
        self.listed()
            .iter()
            .any(|listed| same_mailbox(&listed.endpoint, endpoint))
    }

    /// Whether any shipped mailbox is still listed.
    pub fn holds_shipped(&self) -> bool {
        self.listed()
            .iter()
            .any(|listed| listed.origin == MailboxOrigin::Shipped)
    }

    pub fn shipped(&self) -> &[RelayEndpoint] {
        &self.shipped
    }

    /// What the host stores as added.
    pub fn added(&self) -> &[RelayEndpoint] {
        &self.added
    }

    /// What the host stores as removed.
    pub fn removed(&self) -> &[RelayEndpoint] {
        &self.removed
    }

    /// Adds `endpoint`, which must be TLS to a public name ([`parse_mailbox`] gives one). A
    /// removed shipped mailbox comes back as shipped. `Ok(false)` when it is already listed.
    pub fn add(&mut self, endpoint: RelayEndpoint) -> Result<bool, MailboxListError> {
        check_public(&endpoint)?;
        if self.contains(&endpoint) {
            return Ok(false);
        }
        if self.listed().len() >= MAX_MAILBOXES {
            return Err(MailboxListError::Full);
        }
        let was_removed = self.removed.len();
        self.removed.retain(|gone| !same_mailbox(gone, &endpoint));
        let shipped = self
            .shipped
            .iter()
            .any(|known| same_mailbox(known, &endpoint));
        if !(shipped && self.removed.len() < was_removed) {
            self.added.push(endpoint);
        }
        Ok(true)
    }

    /// Removes `endpoint`. `Ok(false)` when it is not listed; refused for the last one.
    pub fn remove(&mut self, endpoint: &RelayEndpoint) -> Result<bool, MailboxListError> {
        let listed = self.listed();
        if !listed
            .iter()
            .any(|known| same_mailbox(&known.endpoint, endpoint))
        {
            return Ok(false);
        }
        if listed.len() <= 1 {
            return Err(MailboxListError::Last);
        }
        self.added.retain(|known| !same_mailbox(known, endpoint));
        if let Some(shipped) = self
            .shipped
            .iter()
            .find(|known| same_mailbox(known, endpoint))
        {
            self.removed.push(shipped.clone());
        }
        Ok(true)
    }
}

/// One mailbox of the list as the host shows it, with its health as the sessions of this
/// process last saw it. Health is shown, never used to drop a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MailboxStatus {
    /// The mailbox, `domain:port`.
    pub host: String,
    pub origin: MailboxOrigin,
    /// Whether the mailbox offered push (mux/1) at its last greeting; `None` before any answer.
    pub push: Option<bool>,
    /// The mailbox is known to lack mux/1 (see `MailboxHealth::no_mux`): not unreachable, and
    /// never picked for a native post, since the wallet has no other way to read it.
    pub no_mux: bool,
    /// When a socket last attached to it; `None` when none has yet.
    pub last_success: Option<SystemTime>,
    /// Sockets lost since the last success.
    pub failures: u32,
    pub last_error: Option<String>,
}

impl ContactRelays {
    /// Each mailbox of the list, in its order, with its origin and health. Opens no connection.
    pub fn mailbox_status(&self) -> Vec<MailboxStatus> {
        Carrier::new(self.clone()).status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::host_text;

    fn tls(host: &str) -> RelayEndpoint {
        parse_mailbox(host).unwrap()
    }

    fn hosts(list: &MailboxList) -> Vec<String> {
        list.endpoints().iter().map(host_text).collect()
    }

    fn shipped() -> Vec<RelayEndpoint> {
        vec![tls("a.example"), tls("b.example")]
    }

    #[test]
    fn the_list_is_shipped_minus_removed_then_added() {
        let list = MailboxList::new(
            shipped(),
            vec![tls("c.example:5443")],
            vec![tls("a.example")],
        )
        .unwrap();
        assert_eq!(hosts(&list), ["b.example:443", "c.example:5443"]);
        assert_eq!(
            list.listed()
                .iter()
                .map(|listed| listed.origin)
                .collect::<Vec<_>>(),
            [MailboxOrigin::Shipped, MailboxOrigin::Added]
        );
    }

    #[test]
    fn stored_changes_follow_a_changed_shipped_list() {
        let added = vec![tls("mine.example")];
        let removed = vec![tls("a.example")];
        let before = MailboxList::new(shipped(), added.clone(), removed.clone()).unwrap();
        assert_eq!(hosts(&before), ["b.example:443", "mine.example:443"]);

        let next_release = vec![tls("a.example"), tls("d.example"), tls("e.example")];
        let after = MailboxList::new(next_release, added, removed).unwrap();
        assert_eq!(
            hosts(&after),
            ["d.example:443", "e.example:443", "mine.example:443"]
        );
    }

    #[test]
    fn a_mailbox_named_twice_is_listed_once() {
        let list = MailboxList::new(
            shipped(),
            vec![
                RelayEndpoint::new(
                    Domain::parse("A.EXAMPLE").unwrap(),
                    Some(443),
                    Security::Tls,
                ),
                tls("c.example"),
                tls("C.example:443"),
            ],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            hosts(&list),
            ["a.example:443", "b.example:443", "c.example:443"]
        );
    }

    #[test]
    fn the_list_holds_at_most_sixteen() {
        let added = (0..20).map(|n| tls(&format!("m{n}.example"))).collect();
        let mut list = MailboxList::new(shipped(), added, Vec::new()).unwrap();
        assert_eq!(list.listed().len(), MAX_MAILBOXES);
        assert_eq!(hosts(&list)[0], "a.example:443");
        assert_eq!(
            list.add(tls("one.more.example")),
            Err(MailboxListError::Full)
        );
    }

    #[test]
    fn adding_back_a_removed_shipped_mailbox_lists_it_as_shipped() {
        let mut list = MailboxList::shipped_only(shipped()).unwrap();
        assert_eq!(list.remove(&tls("a.example")), Ok(true));
        assert_eq!(list.removed(), [tls("a.example")]);

        assert_eq!(list.add(tls("A.example")), Ok(true));
        assert!(list.removed().is_empty());
        assert!(list.added().is_empty());
        assert_eq!(hosts(&list), ["a.example:443", "b.example:443"]);
    }

    #[test]
    fn add_and_remove_repeat_safely() {
        let mut list = MailboxList::shipped_only(shipped()).unwrap();
        assert_eq!(list.add(tls("c.example")), Ok(true));
        assert_eq!(list.add(tls("c.example")), Ok(false));
        assert_eq!(list.added(), [tls("c.example")]);
        assert_eq!(list.remove(&tls("c.example")), Ok(true));
        assert_eq!(list.remove(&tls("c.example")), Ok(false));
        assert!(list.added().is_empty());
        assert!(list.removed().is_empty());
    }

    #[test]
    fn the_last_mailbox_cannot_be_removed() {
        let mut list = MailboxList::shipped_only(vec![tls("a.example")]).unwrap();
        assert_eq!(list.remove(&tls("a.example")), Err(MailboxListError::Last));
        assert_eq!(hosts(&list), ["a.example:443"]);
    }

    #[test]
    fn a_list_with_nothing_left_is_refused() {
        assert_eq!(
            MailboxList::new(vec![tls("a.example")], Vec::new(), vec![tls("a.example")]),
            Err(MailboxListError::Empty)
        );
        assert_eq!(
            MailboxList::shipped_only(Vec::new()),
            Err(MailboxListError::Empty)
        );
    }

    #[test]
    fn only_a_public_name_is_a_mailbox() {
        for host in ["mail.example", "relay2.test:5443", "A.Example"] {
            assert!(parse_mailbox(host).is_ok(), "{host}");
        }
        for host in [
            "127.0.0.1",
            "192.168.1.10",
            "203.0.113.7",
            "localhost",
            "box.localhost",
            "printer.local",
            "nas.lan",
            "box.home.arpa",
            "svc.internal",
            "intranet",
            "router",
        ] {
            assert_eq!(
                parse_mailbox(host),
                Err(MailboxListError::NotPublic),
                "{host}"
            );
        }
        for host in ["", "mail.example:0", "mail.example:x", "mail_box.example"] {
            assert_eq!(
                parse_mailbox(host),
                Err(MailboxListError::NotAName),
                "{host}"
            );
        }
    }

    #[test]
    fn a_plain_endpoint_is_not_added() {
        let mut list = MailboxList::shipped_only(shipped()).unwrap();
        let plain = RelayEndpoint::new(Domain::parse("c.example").unwrap(), None, Security::Plain);
        assert_eq!(list.add(plain), Err(MailboxListError::NotPublic));
    }
}
