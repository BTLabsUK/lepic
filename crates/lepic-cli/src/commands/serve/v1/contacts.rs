// SPDX-License-Identifier: Apache-2.0
//! Contacts and pairing: `/contacts`, `/pair-requests`, `/payloads`, `/quarantine`.
//!
//! A contact is a paired wallet or a pairing on its way; the wallet lists them apart, and this
//! module lists them together. The wallet keeps a few things the API shows nowhere else, so
//! serve keeps them beside the contact in the wallet's settings, under `api.`: the link of an
//! invite or a reply to hand over, a relay move the user refused, the name this wallet gives
//! itself, and the id a caller chose for a create.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_store::{AccountIndex, ContactId, WalletStore as _};
use lepic_wallet_contacts::{
    AcceptRequest, ContactError, ContactKind, ContactRelays, ContactView, InviteExpiry,
    InviteRequest, KeyCheckStart, KeysDecision, MAX_APP_PAYLOAD_LEN, PairingClass,
    PairingEndReason, PairingRole, PairingStatus, PayloadId, PendingPairingView, RelayMode,
    SasDecision, WalletContacts as _,
};
use serde::Deserialize;
use serde_json::json;

use super::super::Service;
use super::events::{self, Change};
use super::{Reply, begin};
use crate::api::list::{ListQuery, Order, Page, number_key};
use crate::api::model::{Contact, ContactKeys, ContactsBackup, ImportResult, PairRequest};
use crate::api::model::{Payload, Quarantined};
use crate::api::{Category, Context, Problem, Request, created, idempotency, no_content, ok};
use crate::cli::DEFAULT_CONTACT_NAME;
use crate::commands::contact::{contact_id, to_hex};
use crate::exit::CliError;
use crate::host::Host;

/// Contacts belong to the default account.
const ACCOUNT: AccountIndex = AccountIndex(0);

const STATES: [&str; 5] = ["waiting", "paired", "verified", "keys_changed", "ended"];
const CLASSES: [&str; 2] = ["standard", "private"];

/// The name this wallet gives itself in a card.
pub(super) const OWN_NAME: &str = "api.own_name";
const LINK_PREFIX: &str = "api.invite_link.";
const REFUSED_PREFIX: &str = "api.refused_relay.";
const CREATED_PREFIX: &str = "api.contact_id.";
const LABEL_PREFIX: &str = "api.label.";

/// The longest label the wallet takes, in bytes.
const LABEL_MAX: usize = 48;

/// The id of `contact` in the API: its 32 hex digits.
pub(super) fn api_id(id: ContactId) -> String {
    id.to_string()
}

// ----------------------------------------------------------------------------------------------
// Settings

pub(super) fn read<H: Host>(
    service: &Service<'_, H>,
    key: &str,
) -> Result<Option<String>, Problem> {
    let session = service.held.wallet.session().map_err(CliError::from)?;
    session
        .store
        .read(|repos| repos.setting(key))
        .map_err(|error| Problem::from(CliError::from(error)))
}

pub(super) fn write<H: Host>(
    service: &Service<'_, H>,
    key: &str,
    value: &str,
) -> Result<(), Problem> {
    let session = service.held.wallet.session().map_err(CliError::from)?;
    session
        .store
        .write(|repos| repos.put_setting(key, value))
        .map_err(|error| Problem::from(CliError::from(error)))
}

pub(super) fn forget<H: Host>(service: &Service<'_, H>, key: &str) -> Result<(), Problem> {
    let session = service.held.wallet.session().map_err(CliError::from)?;
    session
        .store
        .write(|repos| repos.delete_setting(key))
        .map_err(|error| Problem::from(CliError::from(error)))
}

fn with_prefix<H: Host>(
    service: &Service<'_, H>,
    prefix: &str,
) -> Result<HashMap<String, String>, Problem> {
    let session = service.held.wallet.session().map_err(CliError::from)?;
    let rows = session
        .store
        .read(|repos| repos.settings_with_prefix(prefix))
        .map_err(|error| Problem::from(CliError::from(error)))?;
    Ok(rows
        .into_iter()
        .filter_map(|(key, value)| {
            key.strip_prefix(prefix)
                .map(|rest| (rest.to_owned(), value))
        })
        .collect())
}

/// What serve keeps beside the contacts.
struct Extras {
    links: HashMap<String, String>,
    refused: HashMap<String, String>,
    labels: HashMap<String, String>,
}

fn extras<H: Host>(service: &Service<'_, H>) -> Result<Extras, Problem> {
    Ok(Extras {
        links: with_prefix(service, LINK_PREFIX)?,
        refused: with_prefix(service, REFUSED_PREFIX)?,
        labels: with_prefix(service, LABEL_PREFIX)?,
    })
}

/// Forgets what serve kept for the contact `id`.
fn forget_extras<H: Host>(service: &Service<'_, H>, id: &str) -> Result<(), Problem> {
    forget(service, &format!("{LINK_PREFIX}{id}"))?;
    forget(service, &format!("{LABEL_PREFIX}{id}"))?;
    forget(service, &format!("{REFUSED_PREFIX}{id}"))
}

/// The name this wallet gives itself in a card.
pub(super) fn own_name<H: Host>(service: &Service<'_, H>) -> Result<String, Problem> {
    Ok(read(service, OWN_NAME)?.unwrap_or_else(|| DEFAULT_CONTACT_NAME.to_owned()))
}

/// The relays the wallet's contact calls use.
pub(super) fn relays<H: Host>(service: &Service<'_, H>) -> ContactRelays {
    ContactRelays::new((*service.held.epicbox).clone(), RelayMode::Online)
        .with_meeting(service.settings.servers.meeting_relays.clone())
}

// ----------------------------------------------------------------------------------------------
// Errors

/// The problem a contact call's error is. `param` names the request field a rejected input
/// came in.
pub(super) fn problem_at(error: ContactError, param: &str) -> Problem {
    match error {
        ContactError::UnknownContact => Problem::not_found("no such contact"),
        ContactError::UnknownPairing => Problem::not_found("no such pairing or request"),
        ContactError::InviteExpired => Problem::conflict("invite_expired", "the invite expired"),
        ContactError::AlreadyPaired => {
            Problem::conflict("already_paired", "already paired with this wallet")
        }
        ContactError::Ended => Problem::conflict("contact_ended", "the pairing ended"),
        ContactError::NotVerified => Problem::conflict(
            "not_verified",
            "the contact is not verified; compare the words first",
        ),
        ContactError::Waiting => Problem::conflict(
            "contact_waiting",
            "the pairing waits for the contact's wallet",
        ),
        ContactError::KeyCheckRefused => Problem::conflict(
            "key_check_refused",
            "no key check is allowed for these pairings now",
        ),
        ContactError::PairingInProgress => Problem::conflict(
            "pairing_in_progress",
            "a pairing with this wallet is in progress",
        ),
        ContactError::Crossed => {
            Problem::conflict("pairing_crossed", "a crossed pairing with this wallet wins")
        }
        ContactError::RelayMoveNotRequested => Problem::conflict(
            "relay_changed",
            "the contact asked for no move to this relay",
        ),
        ContactError::WrongClass => Problem::conflict(
            "wrong_class",
            "this does not apply to a pairing of this class",
        ),
        ContactError::InviteDismissed => {
            Problem::conflict("invite_dismissed", "this pairing request was dismissed")
        }
        ContactError::OtherAddress => Problem::of(
            Category::Rejected,
            "other_address",
            "the pairing proves another address than the one that asked",
        ),
        ContactError::AddressProofMissing => Problem::of(
            Category::Rejected,
            "address_proof_missing",
            "the pairing proves no address",
        ),
        ContactError::PeerNotProven => Problem::of(
            Category::Rejected,
            "peer_not_proven",
            "the wallet is not proven to take pairing requests",
        ),
        ContactError::NoFreeSlot => Problem::of(
            Category::Rejected,
            "no_free_slot",
            "the wallet has no free pairing slot",
        ),
        ContactError::Name(_) => Problem::invalid(param, "not a name a contact card can carry"),
        ContactError::RelayAddress => Problem::invalid(param, "not the name of a relay"),
        ContactError::Decode(_) | ContactError::Words(_) | ContactError::WordsNotFound => {
            Problem::invalid(param, "not a pairing invite this wallet can read")
        }
        ContactError::TooLarge { max } => {
            Problem::invalid(param, format!("larger than {max} bytes"))
        }
        other => Problem::from(CliError::from(other)),
    }
}

fn problem(error: ContactError) -> Problem {
    problem_at(error, "/label")
}

// ----------------------------------------------------------------------------------------------
// Objects

fn state_name(status: PairingStatus) -> &'static str {
    match status {
        PairingStatus::Waiting => "waiting",
        PairingStatus::Paired => "paired",
        PairingStatus::Verified => "verified",
        PairingStatus::KeysChanged => "keys_changed",
        PairingStatus::Ended => "ended",
    }
}

fn reason_name(reason: PairingEndReason) -> &'static str {
    match reason {
        PairingEndReason::Mismatch => "mismatch",
        PairingEndReason::PeerMismatch => "their_mismatch",
        PairingEndReason::Unpaired => "unpaired",
        PairingEndReason::NeverFinished => "never_finished",
    }
}

/// The contact the wallet's `view` shows.
fn contact_of(view: &ContactView, class: &str, extras: &Extras) -> Contact {
    let id = api_id(view.contact_id);
    let label = labeled(&view.label, extras, &id);
    let refused = extras.refused.get(&id).cloned();
    let requested = view
        .requested_relay
        .clone()
        .filter(|host| Some(host) != refused.as_ref());
    let words = (view.verified_at.is_none() && view.status == PairingStatus::Paired)
        .then_some(view.sas.as_ref())
        .flatten()
        .map(|symbols| {
            symbols
                .iter()
                .map(|symbol| symbol.name.to_owned())
                .collect()
        });
    let contact = Contact {
        id,
        class: class.to_owned(),
        state: state_name(view.status).to_owned(),
        ended_reason: view
            .ended_reason
            .map(|reason| reason_name(reason).to_owned()),
        label,
        claimed_name: view.claimed_name.clone(),
        verify_words: words,
        allow_invoices: view.allow_invoices,
        seal: matches!(view.seal, lepic_store::SealMode::On),
        home_relay: view.home_relay.clone().unwrap_or_default(),
        requested_relay: requested,
        refused_relay: refused,
        profile: None,
        features: None,
        pairing: None,
        last_heard_at: view.peer_heard_at.map(|at| at.to_string()),
        verified_at: view.verified_at.map(|at| at.to_string()),
        ended_at: view.ended_at.map(|at| at.to_string()),
        created_at: view.created_at.to_string(),
    };
    if view.peer_heard_at.is_some() {
        let (names, _) = crate::profile::describe(view.peer_profile);
        contact
            .with_profile(
                names.into_iter().map(str::to_owned).collect(),
                view.peer_domain.clone(),
                false,
            )
            .with_features(view.native_slates)
    } else {
        contact
    }
}

/// The label of contact `id`: the wallet's, or else the one given while the pairing was still
/// on its way (the wallet takes labels of paired contacts only).
fn labeled(label: &str, extras: &Extras, id: &str) -> String {
    if label.is_empty() {
        extras.labels.get(id).cloned().unwrap_or_default()
    } else {
        label.to_owned()
    }
}

/// Gives contact `contact` its label `label`, in the wallet once it is paired and here before.
async fn set_label<H: Host>(
    service: &Service<'_, H>,
    contact: ContactId,
    label: String,
) -> Result<(), Problem> {
    let id = api_id(contact);
    match service
        .held
        .wallet
        .contact_book()
        .contact_set_label(contact, label.clone())
        .await
    {
        Ok(()) => forget(service, &format!("{LABEL_PREFIX}{id}")),
        Err(ContactError::UnknownContact) => write(service, &format!("{LABEL_PREFIX}{id}"), &label),
        Err(error) => Err(problem_at(error, "/label")),
    }
}

/// The contact a pairing in progress shows.
fn pending_of(view: &PendingPairingView, extras: &Extras) -> Contact {
    let id = api_id(view.contact_id);
    let label = labeled(&view.label, extras, &id);
    let method = match (view.role, view.expect_address.is_some()) {
        (PairingRole::Invitee, _) => "accept",
        (PairingRole::Inviter, false) => "invite",
        (PairingRole::Inviter, true) => "request",
    };
    let link = extras.links.get(&id).cloned();
    Contact {
        id,
        class: "standard".to_owned(),
        state: "waiting".to_owned(),
        ended_reason: None,
        label,
        claimed_name: (view.role == PairingRole::Invitee).then(|| view.invite_name.clone()),
        verify_words: None,
        allow_invoices: false,
        seal: false,
        home_relay: view.home_relay.clone(),
        requested_relay: None,
        refused_relay: None,
        profile: None,
        features: None,
        pairing: None,
        last_heard_at: None,
        verified_at: None,
        ended_at: None,
        created_at: view.created_at.to_string(),
    }
    .with_pairing(method, link, Some(view.expires_at.to_string()))
}

/// The key of a contact in a list: its creation second, then its id.
fn list_key(contact: &Contact, created: jiff::Timestamp) -> String {
    format!(
        "{}{}",
        number_key(u64::try_from(created.as_second()).unwrap_or(0)),
        contact.id
    )
}

/// Every contact and pairing, oldest first, each with its list key.
async fn listing<H: Host>(service: &Service<'_, H>) -> Result<Vec<(String, Contact)>, Problem> {
    let book = service.held.wallet.contact_book();
    let extras = extras(service)?;
    // Pairings in progress are read first: one that completes in between is then still found
    // in the paired list read after them. A contact seen twice is listed as paired.
    let mut all: Vec<(String, Contact)> = Vec::new();
    for view in book.private_pairings().await.map_err(problem)? {
        let contact = contact_of(&view, "private", &extras);
        all.push((list_key(&contact, view.created_at), contact));
    }
    for view in book.pairings_pending().await.map_err(problem)? {
        let contact = pending_of(&view, &extras);
        all.push((list_key(&contact, view.created_at), contact));
    }
    for view in book.contacts().await.map_err(problem)? {
        let contact = contact_of(&view, "standard", &extras);
        all.retain(|(_, seen)| seen.id != contact.id);
        all.push((list_key(&contact, view.created_at), contact));
    }
    all.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(all)
}

/// The contact with API id `id`, if the wallet has it.
pub(super) async fn object<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<Contact>, Problem> {
    let Ok(parsed) = contact_id(id) else {
        return Ok(None);
    };
    let wanted = api_id(parsed);
    Ok(listing(service)
        .await?
        .into_iter()
        .map(|(_, contact)| contact)
        .find(|contact| contact.id == wanted))
}

/// The contact of the path, or 404.
async fn existing<H: Host>(
    service: &Service<'_, H>,
    request: &Request,
) -> Result<Contact, Problem> {
    let id = request.param("id")?;
    object(service, id)
        .await?
        .ok_or_else(|| Problem::not_found("no such contact").with_contact(id))
}

/// The id of the path as the wallet knows it, or 404.
fn path_id(request: &Request) -> Result<ContactId, Problem> {
    let id = request.param("id")?;
    contact_id(id).map_err(|_| Problem::not_found("no such contact").with_contact(id))
}

/// The pairing request with API id `id`.
fn request_key(text: &str) -> Option<[u8; lepic_store::INVITE_ID_LEN]> {
    let text = text.trim();
    let mut id = [0u8; lepic_store::INVITE_ID_LEN];
    if text.len() != id.len().checked_mul(2)? || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(id)
}

fn pair_request_of(view: &lepic_wallet_contacts::PairRequestView) -> PairRequest {
    PairRequest {
        id: to_hex(&view.request_id),
        from_address: view.from_address.clone(),
        claimed_name: Some(view.claimed_name.clone()).filter(|name| !name.is_empty()),
        received_at: view.received_at.to_string(),
        expires_at: view.expires_at.to_string(),
    }
}

pub(super) async fn pair_request_object<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<PairRequest>, Problem> {
    let Some(key) = request_key(id) else {
        return Ok(None);
    };
    Ok(service
        .held
        .wallet
        .contact_book()
        .pairing_requests()
        .await
        .map_err(problem)?
        .iter()
        .find(|view| view.request_id == key)
        .map(pair_request_of))
}

fn payload_of(kept: &lepic_wallet_contacts::ContactPayload) -> Payload {
    Payload {
        id: kept.id.to_string(),
        contact_id: api_id(kept.contact_id),
        size: u64::try_from(kept.payload.len()).unwrap_or(u64::MAX),
        received_at: kept.received_at.to_string(),
        data_base64: STANDARD.encode(&kept.payload),
    }
}

pub(super) async fn payload_object<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<Payload>, Problem> {
    let Some(wanted) = PayloadId::parse(id.trim()) else {
        return Ok(None);
    };
    Ok(service
        .held
        .wallet
        .contact_book()
        .contact_payloads()
        .await
        .map_err(problem)?
        .iter()
        .find(|kept| kept.id == wanted)
        .map(payload_of))
}

fn quarantined_of(kept: &lepic_wallet_contacts::QuarantinedMessage) -> Quarantined {
    Quarantined {
        id: kept.id.clone(),
        contact_id: Some(api_id(kept.contact_id)),
        reason: kept.reason.name().to_owned(),
        size: kept.size,
        attempts: kept.attempts,
        first_seen_at: kept.first_seen.to_string(),
    }
}

pub(super) async fn quarantined_object<H: Host>(
    service: &Service<'_, H>,
    id: &str,
) -> Result<Option<Quarantined>, Problem> {
    Ok(service
        .held
        .wallet
        .contact_book()
        .contact_quarantine()
        .await
        .map_err(problem)?
        .iter()
        .find(|kept| kept.id == id)
        .map(quarantined_of))
}

// ----------------------------------------------------------------------------------------------
// Contacts

pub(super) async fn list<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let query = request.query();
    let list = ListQuery::parse(query)?;
    let state = query.get("state");
    if let Some(state) = state
        && !STATES.contains(&state)
    {
        return Err(Problem::invalid("/state", "not a contact state"));
    }
    let class = query.get("class");
    if let Some(class) = class
        && !CLASSES.contains(&class)
    {
        return Err(Problem::invalid("/class", "not a contact class"));
    }
    let items: Vec<(String, Contact)> = listing(service)
        .await?
        .into_iter()
        .filter(|(_, contact)| {
            state.is_none_or(|state| contact.state == state)
                && class.is_none_or(|class| contact.class == class)
        })
        .collect();
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page
            .items
            .into_iter()
            .map(|(_, contact)| contact)
            .collect::<Vec<_>>(),
        next_cursor: page.next_cursor,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    method: String,
    id: Option<String>,
    label: Option<String>,
    class: Option<String>,
    invite: Option<String>,
    address: Option<String>,
    expires_in: Option<String>,
    deliver: Option<bool>,
}

/// Checks a label the way the wallet does, before anything is made.
fn check_label(label: &str, param: &str) -> Result<(), Problem> {
    if label.len() > LABEL_MAX || label.chars().any(char::is_control) {
        return Err(Problem::invalid(
            param,
            "at most 48 bytes, without control characters",
        ));
    }
    Ok(())
}

/// The contact a caller's `id` made, if it still exists.
async fn made<H: Host>(service: &Service<'_, H>, caller: &str) -> Result<Option<Contact>, Problem> {
    match read(service, &format!("{CREATED_PREFIX}{caller}"))? {
        Some(id) => object(service, &id).await,
        None => Ok(None),
    }
}

/// Starts the pairing a create asks for. Returns its contact id and the link to hand over, if
/// there is one.
async fn start_pairing<H: Host>(
    service: &Service<'_, H>,
    body: &CreateBody,
    class: PairingClass,
    expiry: InviteExpiry,
) -> Result<(ContactId, Option<String>), Problem> {
    let book = service.held.wallet.contact_book();
    let relays = relays(service);
    let name = own_name(service)?;
    Ok(match body.method.as_str() {
        "invite" => {
            let offer = book
                .pairing_invite(
                    &relays,
                    InviteRequest {
                        account: ACCOUNT,
                        name,
                        kind: ContactKind::Person,
                        expiry,
                        home_relay: None,
                        class,
                        expect_address: None,
                    },
                )
                .await
                .map_err(|error| problem_at(error, "/label"))?;
            (offer.contact_id, Some(offer.link))
        }
        "accept" => {
            let by_hand = body.deliver == Some(false);
            let outcome = book
                .pairing_accept(
                    &relays,
                    AcceptRequest {
                        link: body.invite.clone().unwrap_or_default(),
                        account: ACCOUNT,
                        name,
                        by_hand,
                        class,
                        expect_address: None,
                    },
                )
                .await
                .map_err(|error| problem_at(error, "/invite"))?;
            (outcome.contact_id, by_hand.then_some(outcome.reply_link))
        }
        _ => {
            service
                .held
                .epicbox
                .attach_wallet(&service.held.wallet)
                .map_err(CliError::from)?;
            let offer = book
                .pairing_request_send(
                    &relays,
                    ACCOUNT,
                    body.address.as_deref().unwrap_or_default().trim(),
                    &name,
                )
                .await
                .map_err(|error| problem_at(error, "/address"))?;
            (offer.contact_id, Some(offer.link))
        }
    })
}

pub(super) async fn create<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    context: &Context,
) -> Reply {
    let body: CreateBody = request.json()?;
    let method = body.method.as_str();
    if !["invite", "accept", "request"].contains(&method) {
        return Err(Problem::invalid("/method", "invite, accept or request"));
    }
    let class = match body.class.as_deref() {
        None | Some("standard") => PairingClass::Contact,
        Some("private") => PairingClass::Private,
        Some(_) => return Err(Problem::invalid("/class", "standard or private")),
    };
    if let Some(label) = &body.label {
        check_label(label, "/label")?;
    }
    let expiry = match body.expires_in.as_deref() {
        None | Some("24h") => InviteExpiry::OneDay,
        Some("1h") => InviteExpiry::OneHour,
        Some("7d") => InviteExpiry::SevenDays,
        Some(_) => return Err(Problem::invalid("/expires_in", "1h, 24h or 7d")),
    };
    match method {
        "accept"
            if body
                .invite
                .as_deref()
                .is_none_or(|text| text.trim().is_empty()) =>
        {
            return Err(Problem::invalid("/invite", "an accept needs the invite"));
        }
        "request"
            if body
                .address
                .as_deref()
                .is_none_or(|text| text.trim().is_empty()) =>
        {
            return Err(Problem::invalid("/address", "a request needs the address"));
        }
        "request" if class == PairingClass::Private => {
            return Err(Problem::invalid(
                "/class",
                "a request makes a standard contact",
            ));
        }
        _ => {}
    }
    let create = match &body.id {
        Some(id) => {
            if id.is_empty() || id.len() > 128 {
                return Err(Problem::invalid("/id", "1 to 128 bytes"));
            }
            Some(begin(
                service,
                context,
                idempotency::CONTACT,
                id,
                &json!({
                    "method": body.method,
                    "label": body.label,
                    "class": body.class,
                    "invite": body.invite,
                    "address": body.address,
                    "expires_in": body.expires_in,
                    "deliver": body.deliver,
                }),
            )?)
        }
        None => None,
    };
    if let (Some(create), Some(caller)) = (&create, &body.id)
        && create.repeat
        && let Some(existing) = made(service, caller).await?
    {
        return ok(&existing);
    }

    let (new_id, link) = start_pairing(service, &body, class, expiry).await?;
    let id = api_id(new_id);
    if let Some(link) = link {
        write(service, &format!("{LINK_PREFIX}{id}"), &link)?;
    }
    if let Some(caller) = &body.id {
        write(service, &format!("{CREATED_PREFIX}{caller}"), &id)?;
    }
    if let Some(label) = body.label.as_deref().filter(|label| !label.is_empty()) {
        set_label(service, new_id, label.to_owned()).await?;
    }
    events::contact(service, &id, Change::Created).await;
    let contact = object(service, &id)
        .await?
        .ok_or_else(|| Problem::not_found("no such contact").with_contact(&id))?;
    created(&contact)
}

pub(super) async fn get<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    ok(&existing(service, &request).await?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateBody {
    label: Option<String>,
    allow_invoices: Option<bool>,
    seal: Option<bool>,
}

pub(super) async fn update<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: UpdateBody = request.json()?;
    let before = existing(service, &request).await?;
    let id = path_id(&request)?;
    if let Some(label) = &body.label {
        check_label(label, "/label")?;
    }
    let book = service.held.wallet.contact_book();
    if let Some(label) = body.label {
        set_label(service, id, label).await?;
        events::contact(service, &before.id, Change::Updated(&["label"])).await;
    }
    if let Some(seal) = body.seal {
        book.contact_set_seal(id, seal).await.map_err(problem)?;
        events::contact(service, &before.id, Change::Updated(&["seal"])).await;
    }
    if let Some(allow) = body.allow_invoices {
        book.contact_set_allow_invoices(id, allow)
            .await
            .map_err(problem)?;
        book.contacts_outbox_deliver(&relays(service))
            .await
            .map_err(problem)?;
        events::contact(service, &before.id, Change::Updated(&["allow_invoices"])).await;
    }
    ok(&existing(service, &request).await?)
}

pub(super) async fn delete<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let notify = request.query().flag("notify")?.unwrap_or(true);
    let before = existing(service, &request).await?;
    let id = path_id(&request)?;
    let book = service.held.wallet.contact_book();
    let removed = if notify {
        book.contact_unpair(&relays(service), id).await
    } else {
        book.contact_remove(id).await
    }
    .map_err(problem)?;
    if !removed {
        return Err(Problem::not_found("no such contact").with_contact(&before.id));
    }
    forget_extras(service, &before.id)?;
    events::contact_removed(service, &before.id, &before);
    no_content()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyBody {
    result: String,
}

pub(super) async fn verify<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: VerifyBody = request.json()?;
    let decision = match body.result.as_str() {
        "match" => SasDecision::Match,
        "mismatch" => SasDecision::Mismatch,
        "skip" => SasDecision::Skip,
        _ => return Err(Problem::invalid("/result", "match, mismatch or skip")),
    };
    let mut before = existing(service, &request).await?;
    let id = path_id(&request)?;
    service
        .held
        .wallet
        .contact_book()
        .pairing_sas(&relays(service), id, decision)
        .await
        .map_err(problem)?;
    if decision == SasDecision::Mismatch {
        // The wallet removes a pairing that does not match; the answer shows how it ended.
        forget_extras(service, &before.id)?;
        before.state = "ended".to_owned();
        before.ended_reason = Some("mismatch".to_owned());
        before.ended_at = Some(jiff::Timestamp::now().to_string());
        before.verify_words = None;
        events::contact_removed(service, &before.id, &before);
        return ok(&before);
    }
    events::contact(service, &before.id, Change::State(None)).await;
    ok(&existing(service, &request).await?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckBody {
    previous_contact_id: Option<String>,
}

pub(super) async fn check<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: CheckBody = request.json()?;
    let before = existing(service, &request).await?;
    let id = path_id(&request)?;
    let book = service.held.wallet.contact_book();
    let relays = relays(service);
    match &body.previous_contact_id {
        Some(previous) => {
            let old = contact_id(previous)
                .map_err(|_| Problem::invalid("/previous_contact_id", "not a contact id"))?;
            let started = book
                .contact_key_check(&relays, id, old)
                .await
                .map_err(problem)?;
            if started == KeyCheckStart::KeysChanged {
                events::contact(service, &before.id, Change::State(None)).await;
            }
        }
        None => book.contact_check(&relays, id).await.map_err(problem)?,
    }
    ok(&existing(service, &request).await?)
}

pub(super) async fn resolve_keys<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: ContactKeys = request.json()?;
    let decision = match body.keep.as_str() {
        "old" => KeysDecision::KeepOld,
        "new" => KeysDecision::UseNew,
        _ => return Err(Problem::invalid("/use", "old or new")),
    };
    let before = existing(service, &request).await?;
    let id = path_id(&request)?;
    service
        .held
        .wallet
        .contact_book()
        .contact_keys_resolve(id, decision)
        .await
        .map_err(|error| match error {
            // The contact exists (checked above) but has no changed keys to decide on.
            ContactError::UnknownContact => Problem::conflict(
                "keys_not_changed",
                "the contact's keys did not change; there is nothing to decide",
            )
            .with_contact(&before.id),
            other => problem_at(other, "/use"),
        })?;
    if decision == KeysDecision::KeepOld {
        // Keeping the old keys drops the new pairing.
        forget_extras(service, &before.id)?;
        events::contact_removed(service, &before.id, &before);
        return ok(&before);
    }
    events::contact(service, &before.id, Change::State(None)).await;
    ok(&existing(service, &request).await?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveBody {
    host: String,
    accept: Option<bool>,
}

pub(super) async fn move_contact<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: MoveBody = request.json()?;
    let before = existing(service, &request).await?;
    let id = path_id(&request)?;
    let host = body.host.trim().to_ascii_lowercase();
    let current = before
        .requested_relay
        .as_deref()
        .map(str::to_ascii_lowercase);
    if current.as_deref() != Some(host.as_str()) {
        return Err(Problem::conflict(
            "relay_changed",
            "the contact's requested relay is not the one given; nothing moved",
        )
        .with_contact(&before.id));
    }
    if body.accept.unwrap_or(true) {
        service
            .held
            .wallet
            .contact_book()
            .apply_relay_move(id, &host)
            .await
            .map_err(problem)?;
        forget(service, &format!("{REFUSED_PREFIX}{}", before.id))?;
        events::contact(
            service,
            &before.id,
            Change::Updated(&["home_relay", "requested_relay"]),
        )
        .await;
    } else {
        // The wallet keeps no refusal of its own and tells nobody.
        write(service, &format!("{REFUSED_PREFIX}{}", before.id), &host)?;
        events::contact(
            service,
            &before.id,
            Change::Updated(&["requested_relay", "refused_relay"]),
        )
        .await;
    }
    ok(&existing(service, &request).await?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadBody {
    data_base64: String,
}

pub(super) async fn send_payload<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: PayloadBody = request.json()?;
    let before = existing(service, &request).await?;
    let id = path_id(&request)?;
    let bytes = STANDARD
        .decode(body.data_base64.trim())
        .map_err(|_| Problem::invalid("/data_base64", "not base64"))?;
    if bytes.len() > MAX_APP_PAYLOAD_LEN {
        return Err(Problem::invalid(
            "/data_base64",
            format!("larger than {MAX_APP_PAYLOAD_LEN} bytes"),
        ));
    }
    service
        .held
        .wallet
        .contact_book()
        .contact_post_payload(&relays(service), id, bytes)
        .await
        .map_err(|error| problem_at(error, "/data_base64"))
        .map_err(|problem| problem.with_contact(&before.id))?;
    no_content()
}

pub(super) async fn export<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    let document = service
        .held
        .wallet
        .contact_book()
        .contacts_export()
        .await
        .map_err(problem)?;
    ok(&ContactsBackup { document })
}

/// A refused backup is the caller's document (400), or a cap the wallet has reached (409).
fn import_problem(error: ContactError) -> Problem {
    use lepic_store::StoreError;
    use lepic_wallet::WalletError;
    match error {
        ContactError::Wallet(WalletError::Store(
            StoreError::Corrupt { .. }
            | StoreError::UnsupportedBackup { .. }
            | StoreError::BackupOfOtherNetwork,
        )) => Problem::invalid("/document", "not a contacts backup this wallet can read"),
        ContactError::Wallet(WalletError::Store(StoreError::ContactCapReached { .. })) => {
            Problem::conflict(
                "contact_cap_reached",
                "the wallet holds as many contacts as it may",
            )
        }
        other => problem_at(other, "/document"),
    }
}

pub(super) async fn import<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: ContactsBackup = request.json()?;
    let summary = service
        .held
        .wallet
        .contact_book()
        .contacts_import(body.document)
        .await
        .map_err(import_problem)?;
    ok(&ImportResult {
        imported: u32::try_from(summary.imported).unwrap_or(u32::MAX),
    })
}

// ----------------------------------------------------------------------------------------------
// Pair requests

pub(super) async fn list_pair_requests<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let list = ListQuery::parse(request.query())?;
    let mut views = service
        .held
        .wallet
        .contact_book()
        .pairing_requests()
        .await
        .map_err(problem)?;
    views.sort_by_key(|view| (view.received_at, view.request_id));
    let items: Vec<(String, PairRequest)> = views
        .iter()
        .map(|view| {
            let object = pair_request_of(view);
            let key = format!(
                "{}{}",
                number_key(u64::try_from(view.received_at.as_second()).unwrap_or(0)),
                object.id
            );
            (key, object)
        })
        .collect();
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page
            .items
            .into_iter()
            .map(|(_, object)| object)
            .collect::<Vec<_>>(),
        next_cursor: page.next_cursor,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptRequestBody {
    label: Option<String>,
}

pub(super) async fn accept_pair_request<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: AcceptRequestBody = request.json()?;
    if let Some(label) = &body.label {
        check_label(label, "/label")?;
    }
    let text = request.param("id")?;
    let key = request_key(text).ok_or_else(|| Problem::not_found("no such pair request"))?;
    let book = service.held.wallet.contact_book();
    let pending = book
        .pairing_requests()
        .await
        .map_err(problem)?
        .into_iter()
        .find(|view| view.request_id == key)
        .ok_or_else(|| Problem::not_found("no such pair request"))?;
    let outcome = book
        .pairing_accept(
            &relays(service),
            AcceptRequest {
                link: pending.invite_link,
                account: ACCOUNT,
                name: own_name(service)?,
                by_hand: false,
                class: PairingClass::Contact,
                expect_address: Some(pending.from_address),
            },
        )
        .await
        .map_err(problem)?;
    let id = api_id(outcome.contact_id);
    if let Some(label) = body.label.filter(|label| !label.is_empty()) {
        set_label(service, outcome.contact_id, label).await?;
    }
    events::contact(service, &id, Change::Created).await;
    let contact = object(service, &id)
        .await?
        .ok_or_else(|| Problem::not_found("no such contact").with_contact(&id))?;
    ok(&contact)
}

pub(super) async fn delete_pair_request<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let key = request_key(request.param("id")?)
        .ok_or_else(|| Problem::not_found("no such pair request"))?;
    service
        .held
        .wallet
        .contact_book()
        .pairing_request_dismiss(key)
        .await
        .map_err(problem)?;
    no_content()
}

// ----------------------------------------------------------------------------------------------
// Payloads

pub(super) async fn list_payloads<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let list = ListQuery::parse(request.query())?;
    let mut kept = service
        .held
        .wallet
        .contact_book()
        .contact_payloads()
        .await
        .map_err(problem)?;
    kept.sort_by_key(|payload| (payload.received_at, payload.id.to_string()));
    let items: Vec<(String, Payload)> = kept
        .iter()
        .map(|payload| {
            let object = payload_of(payload);
            let key = format!(
                "{}{}",
                number_key(u64::try_from(payload.received_at.as_second()).unwrap_or(0)),
                object.id
            );
            (key, object)
        })
        .collect();
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page
            .items
            .into_iter()
            .map(|(_, object)| object)
            .collect::<Vec<_>>(),
        next_cursor: page.next_cursor,
    })
}

pub(super) async fn delete_payload<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let id = PayloadId::parse(request.param("id")?.trim())
        .ok_or_else(|| Problem::not_found("no such payload"))?;
    let removed = service
        .held
        .wallet
        .contact_book()
        .contact_payloads_ack(&[id])
        .await
        .map_err(problem)?;
    if removed == 0 {
        return Err(Problem::not_found("no such payload"));
    }
    no_content()
}

// ----------------------------------------------------------------------------------------------
// Quarantine

pub(super) async fn list_quarantine<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let list = ListQuery::parse(request.query())?;
    let mut kept = service
        .held
        .wallet
        .contact_book()
        .contact_quarantine()
        .await
        .map_err(problem)?;
    kept.sort_by(|left, right| (left.first_seen, &left.id).cmp(&(right.first_seen, &right.id)));
    let items: Vec<(String, Quarantined)> = kept
        .iter()
        .map(|message| {
            let key = format!(
                "{}{}",
                number_key(u64::try_from(message.first_seen.as_second()).unwrap_or(0)),
                message.id
            );
            (key, quarantined_of(message))
        })
        .collect();
    let page = Page::of(items, &list, Order::Ascending, |(key, _)| key.clone());
    ok(&Page {
        items: page
            .items
            .into_iter()
            .map(|(_, object)| object)
            .collect::<Vec<_>>(),
        next_cursor: page.next_cursor,
    })
}

pub(super) async fn retry_quarantined<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let id = request.param("id")?;
    let Some(before) = quarantined_object(service, id).await? else {
        return Err(Problem::not_found("no such quarantined message"));
    };
    service
        .held
        .wallet
        .contact_book()
        .contact_quarantine_retry(&relays(service), Some(id))
        .await
        .map_err(problem)?;
    // A message that was handled has left quarantine: the answer then is the entry as it was.
    ok(&quarantined_object(service, id).await?.unwrap_or(before))
}

pub(super) async fn delete_quarantined<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let removed = service
        .held
        .wallet
        .contact_book()
        .contact_quarantine_discard(request.param("id")?)
        .await
        .map_err(problem)?;
    if !removed {
        return Err(Problem::not_found("no such quarantined message"));
    }
    no_content()
}
