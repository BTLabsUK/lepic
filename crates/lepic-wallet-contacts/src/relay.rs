// SPDX-License-Identifier: Apache-2.0
//! Reaching home relays: their endpoints and the mailbox clients that read them over mux/1
//! and post to them (RFC 0002 8.2).

use lepic_epicbox::tunnel::DialTarget;
use lepic_epicbox::{Domain, EpicboxAddress, MailboxClient, RelayEndpoint, Security};

use super::in_person::known_endpoint;
use super::{ContactError, ContactRelays, RelayMode};

/// Refuses before anything connects when the user chose Offline.
pub(crate) fn check_online(relays: &ContactRelays) -> Result<(), ContactError> {
    match relays.mode {
        RelayMode::Online => Ok(()),
        RelayMode::Offline => Err(ContactError::Offline),
    }
}

/// `domain:port` of an endpoint, as invites and records name a home relay.
pub(crate) fn host_text(endpoint: &RelayEndpoint) -> String {
    format!("{}:{}", endpoint.domain(), endpoint.port())
}

/// The endpoint of the mailbox `host`, `domain[:port]`. A mailbox of the list is reached as the
/// list names it; any other over TLS, which a mailbox on the internet needs, and only by a name
/// on a port other than 0: a contact never makes the wallet dial an address, its own device or
/// its network.
pub(crate) fn endpoint_for(
    host: &str,
    relays: &ContactRelays,
) -> Result<RelayEndpoint, ContactError> {
    let (domain, port) = parse_host(host)?;
    if let Some(known) = known_endpoint(relays, &domain, port) {
        return Ok(known);
    }
    if port == Some(0) || !is_relay_name(&domain) {
        return Err(ContactError::RelayAddress);
    }
    Ok(RelayEndpoint::new(domain, port, Security::Tls))
}

/// Whether `domain` names a host on the internet: not an IPv4 address and not this device.
fn is_relay_name(domain: &Domain) -> bool {
    let name = domain.as_str().trim_end_matches('.').to_ascii_lowercase();
    !(name.parse::<std::net::Ipv4Addr>().is_ok()
        || name == "localhost"
        || name.ends_with(".localhost")
        || name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.'))
}

/// The domain and optional port of `host`, `domain[:port]`.
pub(crate) fn parse_host(host: &str) -> Result<(Domain, Option<u16>), ContactError> {
    let (domain, port) = match host.rsplit_once(':') {
        Some((domain, port)) => (
            domain,
            Some(
                port.parse::<u16>()
                    .map_err(|_| ContactError::RelayAddress)?,
            ),
        ),
        None => (host, None),
    };
    let domain = Domain::parse(domain).map_err(|_| ContactError::RelayAddress)?;
    Ok((domain, port))
}

/// `domain` of a mailbox on the TLS default port, `domain:port` of any other: how the host app
/// and the watch rows name a mailbox.
pub fn mailbox_host(endpoint: &RelayEndpoint) -> String {
    if endpoint.port() == lepic_epicbox::DEFAULT_PORT {
        endpoint.domain().to_string()
    } else {
        host_text(endpoint)
    }
}

/// The endpoint a mailbox address names: its domain and port.
pub(crate) fn endpoint_of_address(
    address: &EpicboxAddress,
    relays: &ContactRelays,
) -> Result<RelayEndpoint, ContactError> {
    let host = match address.port() {
        Some(port) => format!("{}:{port}", address.domain()),
        None => address.domain().to_string(),
    };
    endpoint_for(&host, relays)
}

/// A client for mux/1 sessions and posts on `endpoint`, through the wallet's connector, dialing
/// `onion` when relay traffic goes through tor and the relay has no onion route.
pub(crate) fn mailbox_client(
    relays: &ContactRelays,
    endpoint: RelayEndpoint,
    onion: Option<&str>,
) -> MailboxClient {
    let mut settings = relays.epicbox.settings().clone();
    let port = endpoint.port();
    settings.endpoint = endpoint;
    let client = MailboxClient::new(settings, relays.epicbox.connector());
    match onion {
        Some(onion) => client.with_onion(DialTarget {
            host: onion.to_owned(),
            port,
        }),
        None => client,
    }
}

#[cfg(test)]
mod tests {
    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_epicbox::sessions::Owner;
    use lepic_epicbox::{MuxOptions, Network};

    use super::*;
    use crate::delivery::testing::{HOST, relays, until};
    use crate::mailboxes::{MailboxList, MailboxOrigin};

    fn tls(domain: &str, port: Option<u16>) -> RelayEndpoint {
        RelayEndpoint::new(Domain::parse(domain).unwrap(), port, Security::Tls)
    }

    fn hosts(list: &[RelayEndpoint]) -> Vec<String> {
        list.iter().map(host_text).collect()
    }

    /// Test relays whose list is `relay.test:80` then `added`.
    fn listed(relay: &MuxMockRelay, added: Vec<RelayEndpoint>) -> ContactRelays {
        let (relays, _) = relays(relay, &MockRelay::new(Network::Mainnet), &[]);
        let shipped = vec![relays.epicbox.settings().endpoint.clone()];
        let list = MailboxList::new(shipped, added, Vec::new()).unwrap();
        relays.with_mailboxes(list)
    }

    /// A socket of the payments on the first mailbox, started as the delivery layer starts one.
    fn start_first_session(relays: &ContactRelays) {
        let endpoint = relays.list()[0].clone();
        relays
            .epicbox
            .pushed()
            .get_or_start(HOST, "wallet", Owner::Payments, || {
                mailbox_client(relays, endpoint, None)
                    .start_mux_queued(Vec::new(), MuxOptions::default())
            })
            .unwrap();
    }

    fn pushes(relays: &ContactRelays) -> Vec<(String, MailboxOrigin, Option<bool>)> {
        relays
            .mailbox_status()
            .into_iter()
            .map(|status| (status.host, status.origin, status.push))
            .collect()
    }

    #[tokio::test]
    async fn a_host_reaches_the_first_listed_mailbox_of_its_name() {
        let relays = listed(
            &MuxMockRelay::new(Network::Mainnet),
            vec![tls("relay.test", Some(5443)), tls("b.test", None)],
        );

        assert_eq!(
            endpoint_for("relay.test", &relays).unwrap(),
            relays.list()[0]
        );
        assert_eq!(
            endpoint_for("relay.test:5443", &relays).unwrap(),
            relays.list()[1]
        );
        assert_eq!(
            endpoint_for("b.test:443", &relays).unwrap(),
            relays.list()[2]
        );
        assert_eq!(
            hosts(&relays.list()),
            ["relay.test:80", "relay.test:5443", "b.test:443"]
        );
    }

    #[tokio::test]
    async fn a_mailbox_without_mux_is_listed_with_its_health() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.offer_mux(false);
        let relays = listed(&relay, vec![tls("far.test", None)]);

        start_first_session(&relays);
        until(|| relays.epicbox.pushed().supports_push(HOST).is_some()).await;

        assert_eq!(
            pushes(&relays),
            [
                (HOST.to_owned(), MailboxOrigin::Shipped, Some(false)),
                ("far.test:443".to_owned(), MailboxOrigin::Added, None),
            ]
        );
        // One that answered without mux/1 is shown as such, not as unreachable; one never
        // asked is not.
        let status = relays.mailbox_status();
        assert_eq!(
            (status[0].no_mux, status[0].failures, &status[0].last_error),
            (true, 0, &None)
        );
        let far = &status[1];
        assert!(!far.no_mux);
        assert_eq!(
            (far.last_success, far.failures, &far.last_error),
            (None, 0, &None)
        );
        // The added mailbox was never dialled to find out.
        assert_eq!(relay.sockets_made(), 1);
    }

    #[tokio::test]
    async fn a_mailbox_offering_mux_keeps_its_health_after_its_socket_is_gone() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let relays = listed(&relay, Vec::new());

        start_first_session(&relays);
        until(|| relays.mailbox_status()[0].last_success.is_some()).await;
        assert_eq!(relays.mailbox_status()[0].push, Some(true));
        assert!(!relays.mailbox_status()[0].no_mux);
        relays.epicbox.pushed().release(Owner::Payments);

        assert_eq!(relays.mailbox_status()[0].push, Some(true));
        assert!(relays.mailbox_status()[0].last_success.is_some());
    }

    #[tokio::test]
    async fn no_mailbox_greeted_is_not_known() {
        let relays = listed(
            &MuxMockRelay::new(Network::Mainnet),
            vec![tls("far.test", None)],
        );

        assert_eq!(
            pushes(&relays),
            [
                (HOST.to_owned(), MailboxOrigin::Shipped, None),
                ("far.test:443".to_owned(), MailboxOrigin::Added, None),
            ]
        );
    }

    #[test]
    fn only_a_name_on_the_internet_is_a_contacts_relay() {
        for host in [
            "epicbox.example",
            "relay2.test",
            "1password.example",
            "a1.b2",
        ] {
            assert!(is_relay_name(&Domain::parse(host).unwrap()), "{host}");
        }
        for host in [
            "192.0.2.1",
            "198.51.100.1",
            "127.0.0.1",
            "203.0.113.7",
            "1.2.3",
            "localhost",
            "LOCALHOST",
            "relay.localhost",
        ] {
            assert!(!is_relay_name(&Domain::parse(host).unwrap()), "{host}");
        }
    }
}
