// SPDX-License-Identifier: Apache-2.0
//! Reaching home relays: their endpoints, one-off mailbox clients, and posts (RFC 0002 8.2).

use lepic_contact::armor;
use lepic_epicbox::tunnel::DialTarget;
use lepic_epicbox::{Domain, EpicboxAddress, Identity, MailboxClient, RelayEndpoint, Security};

use super::{ContactError, ContactRelays, RelayMode};

/// Refuses before anything connects when the user chose Offline or switched Epicbox off.
pub(crate) fn check_online(relays: &ContactRelays) -> Result<(), ContactError> {
    match relays.mode {
        RelayMode::Online => Ok(()),
        RelayMode::Offline => Err(ContactError::Offline),
        RelayMode::EpicboxOff => Err(ContactError::EpicboxOff),
    }
}

/// `domain:port` of an endpoint, as invites and records name a home relay.
pub(crate) fn host_text(endpoint: &RelayEndpoint) -> String {
    format!("{}:{}", endpoint.domain(), endpoint.port())
}

/// The endpoint of the home relay `host`, `domain[:port]`. A relay the wallet knows, its own or
/// a meeting relay, is reached as the wallet reaches it; any other over TLS, which a relay on the
/// internet needs, and only by a name on a port other than 0: a contact never makes the wallet
/// dial an address, its own device or its network.
pub(crate) fn endpoint_for(
    host: &str,
    relays: &ContactRelays,
) -> Result<RelayEndpoint, ContactError> {
    let (domain, port) = parse_host(host)?;
    let ours = &relays.epicbox.settings().endpoint;
    let known = std::iter::once(ours)
        .chain(relays.meeting.iter())
        .find(|known| known.domain() == &domain && port.is_none_or(|port| port == known.port()));
    if let Some(known) = known {
        return Ok(known.clone());
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
fn parse_host(host: &str) -> Result<(Domain, Option<u16>), ContactError> {
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

/// How many meeting relays one call may name: each costs a connection while words are offered
/// or looked for.
pub const MAX_MEETING_RELAYS: usize = 16;

/// The meeting relays `hosts` name, each `domain[:port]` reached over TLS, lowercased, without
/// repeats, in the order given.
///
/// Fails with [`ContactError::RelayAddress`] for a host that is not a domain with an optional
/// non-zero port or for more than [`MAX_MEETING_RELAYS`] hosts, and with
/// [`ContactError::WordsUnavailable`] for none.
pub fn meeting_relays<T: AsRef<str>>(hosts: &[T]) -> Result<Vec<RelayEndpoint>, ContactError> {
    if hosts.is_empty() {
        return Err(ContactError::WordsUnavailable);
    }
    if hosts.len() > MAX_MEETING_RELAYS {
        return Err(ContactError::RelayAddress);
    }
    let mut endpoints: Vec<RelayEndpoint> = Vec::with_capacity(hosts.len());
    for host in hosts {
        let (domain, port) = parse_host(&host.as_ref().trim().to_ascii_lowercase())?;
        if port == Some(0) {
            return Err(ContactError::RelayAddress);
        }
        let endpoint = RelayEndpoint::new(domain, port, Security::Tls);
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    Ok(endpoints)
}

/// `domain` of a relay on the TLS default port, `domain:port` of any other: how the host app
/// names a meeting relay.
pub fn meeting_host(endpoint: &RelayEndpoint) -> String {
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

/// A client for one-off drains and posts on `endpoint`, through the wallet's connector, dialing
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

/// Posts the armored `envelope` from `from` to `to`, on the relay `to` names.
pub(crate) async fn post_envelope(
    relays: &ContactRelays,
    from: &Identity,
    to: &EpicboxAddress,
    onion: Option<&str>,
    envelope: &[u8],
) -> Result<(), ContactError> {
    check_online(relays)?;
    let endpoint = endpoint_of_address(to, relays)?;
    mailbox_client(relays, endpoint, onion)
        .post(from, to, &armor(envelope))
        .await
        .map_err(ContactError::Relay)
}

#[cfg(test)]
mod tests {
    use super::*;

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
