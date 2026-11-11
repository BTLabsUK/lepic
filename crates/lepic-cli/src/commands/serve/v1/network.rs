// SPDX-License-Identifier: Apache-2.0
//! The relay, peers and profile: `/relay`, `/peers`, `/profile`.

use std::collections::BTreeMap;

use hyper::StatusCode;
use lepic_store::{AccountIndex, OutboxStatus, WalletStore as _};
use lepic_wallet_contacts::WalletContacts as _;
use serde::Deserialize;

use super::super::Service;
use super::contacts::{OWN_NAME, own_name, problem_at, read, relays, write};
use super::Reply;
use crate::api::list::{ListQuery, Order, Page};
use crate::api::model::{Peer, Profile, Relay};
use crate::api::{Context, Problem, Request, no_content, ok, response};
use crate::cli::MAX_DRAIN_DAYS;
use crate::commands::peer::to_hex;
use crate::exit::CliError;
use crate::host::Host;
use crate::output::Report;
use crate::profile::{describe, parse_names};

/// Peers belong to the default account.
const ACCOUNT: AccountIndex = AccountIndex(0);

/// The relay this wallet moved its contacts to; the configured relay until it moved.
const HOME_RELAY: &str = "api.home_relay";
/// The profile bits set through the API; the configured profile until they were set.
const PROFILE: &str = "api.profile";

fn problem(error: lepic_wallet_contacts::ContactError) -> Problem {
    problem_at(error, "/host")
}

// ----------------------------------------------------------------------------------------------
// Relay

/// The relay, for `GET /relay` and the `relay.updated` event.
pub(super) async fn relay_object<H: Host>(service: &Service<'_, H>) -> Result<Relay, Problem> {
    let host = match read(service, HOME_RELAY)? {
        Some(host) => host,
        None => service.settings.relay.url(),
    };
    let address = service
        .held
        .epicbox
        .attach_wallet(&service.held.wallet)
        .map_err(CliError::from)?
        .to_string();
    let session = service.held.wallet.session().map_err(CliError::from)?;
    let (waiting, previous) = session
        .store
        .read(|repos| {
            let waiting = repos.outbox(OutboxStatus::Pending)?.len();
            let mut previous = BTreeMap::new();
            for record in repos.contacts()? {
                let Some(mailbox) = repos.contact_mailbox(record.contact_id)? else {
                    continue;
                };
                if let Some(old) = mailbox.previous {
                    let until = previous.entry(old.relay).or_insert(old.until);
                    *until = (*until).max(old.until);
                }
            }
            Ok((waiting, previous))
        })
        .map_err(|error: lepic_store::StoreError| Problem::from(CliError::from(error)))?;
    let now = jiff::Timestamp::now();
    let draining = previous
        .into_iter()
        .filter(|(_, until)| *until > now)
        .map(|(host, until)| (host, until.to_string()))
        .collect();
    Ok(Relay::new(
        host,
        service.epicbox.get().unwrap_or("connecting"),
        address,
        u64::try_from(waiting).unwrap_or(u64::MAX),
        draining,
    ))
}

pub(super) async fn get_relay<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    ok(&relay_object(service).await?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveBody {
    host: String,
    drain_days: Option<i64>,
}

pub(super) async fn move_relay<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: MoveBody = request.json()?;
    let host = body.host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(Problem::invalid("/host", "the name of a relay"));
    }
    let days = u16::try_from(body.drain_days.unwrap_or(0))
        .ok()
        .filter(|days| i64::from(*days) <= MAX_DRAIN_DAYS)
        .ok_or_else(|| Problem::invalid("/drain_days", "0 to 365"))?;
    let drain = std::time::Duration::from_secs(24 * 60 * 60).saturating_mul(u32::from(days));
    service
        .held
        .wallet
        .contact_book()
        .contacts_move_home(&relays(service), &host, drain)
        .await
        .map_err(problem)?;
    write(service, HOME_RELAY, &host)?;
    ok(&relay_object(service).await?)
}

// ----------------------------------------------------------------------------------------------
// Peers

pub(super) async fn list_peers<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let list = ListQuery::parse(request.query())?;
    let mut pins = service
        .held
        .wallet
        .peer_pins(ACCOUNT)
        .map_err(CliError::from)?;
    pins.sort_by(|left, right| left.origin.cmp(&right.origin));
    let items: Vec<Peer> = pins
        .into_iter()
        .map(|pin| Peer {
            origin: pin.origin,
            key: to_hex(&pin.seal_key),
            first_seen_at: pin.first_seen.to_string(),
            last_seen_at: pin.last_seen.to_string(),
        })
        .collect();
    ok(&Page::of(items, &list, Order::Ascending, |peer| {
        peer.origin.clone()
    }))
}

pub(super) async fn delete_peer<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let given = request.param("origin")?;
    let origin = lepic_methods::http::Origin::parse(given)
        .map_err(|_| Problem::not_found("no such peer"))?
        .to_string();
    let forgotten = service
        .held
        .wallet
        .forget_peer_pin(ACCOUNT, &origin)
        .map_err(CliError::from)?;
    if !forgotten {
        return Err(Problem::not_found("no such peer"));
    }
    no_content()
}

// ----------------------------------------------------------------------------------------------
// Profile

/// The profile bits this wallet tells its contacts.
fn profile_bits<H: Host>(service: &Service<'_, H>) -> Result<u16, Problem> {
    Ok(read(service, PROFILE)?
        .and_then(|text| text.parse().ok())
        .unwrap_or(service.settings.profile))
}

fn profile_object<H: Host>(service: &Service<'_, H>) -> Result<Profile, Problem> {
    let (names, _) = describe(u32::from(profile_bits(service)?));
    let domain = service.settings.domain.clone();
    let domain_proof = match &domain {
        Some(_) => match crate::commands::profile::domain_document(
            &service.held,
            service.settings,
            &[],
        ) {
            Ok(Report::ProfileDomainDocument(file)) => Some(file.document),
            _ => None,
        },
        None => None,
    };
    Ok(Profile {
        name: Some(own_name(service)?),
        flags: names.into_iter().map(str::to_owned).collect(),
        domain,
        domain_proof,
    })
}

pub(super) async fn get_profile<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    ok(&profile_object(service)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileBody {
    name: Option<String>,
    flags: Option<Vec<String>>,
    domain: Option<String>,
}

pub(super) async fn update_profile<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: ProfileBody = request.json()?;
    let bits = match &body.flags {
        Some(flags) => Some(
            parse_names(&flags.join(","))
                .ok_or_else(|| Problem::invalid("/flags", "no-payments or automated"))?,
        ),
        None => None,
    };
    if let Some(domain) = &body.domain {
        let current = service.settings.domain.as_deref().unwrap_or_default();
        if domain.trim() != current {
            return Err(Problem::conflict(
                "domain_fixed",
                "the domain is set in the wallet's configuration, not through the api",
            ));
        }
    }
    let book = service.held.wallet.contact_book();
    let relays = relays(service);
    if let Some(name) = &body.name {
        book.contacts_set_own_name(&relays, name)
            .await
            .map_err(|error| problem_at(error, "/name"))?;
        write(service, OWN_NAME, name)?;
    }
    if let Some(bits) = bits {
        book.contacts_set_own_profile(&relays, bits)
            .await
            .map_err(|error| problem_at(error, "/flags"))?;
        write(service, PROFILE, &bits.to_string())?;
    }
    ok(&profile_object(service)?)
}

pub(super) async fn domain_file<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let mut hosts = Vec::new();
    if let Some(relay) = request.query().get("relay") {
        let relay = relay.trim().to_ascii_lowercase();
        if relay.is_empty() {
            return Err(Problem::invalid("/relay", "the name of a relay"));
        }
        hosts.push(relay);
    }
    if service.settings.domain.is_none() {
        return Err(Problem::not_found("no domain is configured"));
    }
    match crate::commands::profile::domain_document(&service.held, service.settings, &hosts)? {
        Report::ProfileDomainDocument(file) => {
            Ok(response(StatusCode::OK, "text/plain", file.document.into()))
        }
        _ => Err(Problem::not_found("no domain file")),
    }
}
