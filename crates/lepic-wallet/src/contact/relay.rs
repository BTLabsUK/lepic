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
/// a built-in one, is reached as the wallet reaches it; any other over TLS, which a relay on the
/// internet needs.
pub(crate) fn endpoint_for(
    host: &str,
    relays: &ContactRelays,
) -> Result<RelayEndpoint, ContactError> {
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
    let candidate = RelayEndpoint::new(domain.clone(), port, Security::Tls);
    let ours = &relays.epicbox.settings().endpoint;
    let known = std::iter::once(ours)
        .chain(relays.built_in.iter())
        .find(|known| known.domain() == &domain && port.is_none_or(|port| port == known.port()));
    Ok(known.cloned().unwrap_or(candidate))
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
/// `onion` when relay traffic goes through tor and the relay has no built-in onion.
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
