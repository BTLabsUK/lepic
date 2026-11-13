// SPDX-License-Identifier: Apache-2.0
//! The event log: `GET /events` as a page or a stream, and what fills it.
//!
//! Each entry is a change to one object with a snapshot of the object after it (proposal §7).
//! The [`writer`] turns the engine's events into entries; a handler that changes an object
//! itself records it with the same functions ([`payment`], [`contact`], ...). Both compare the
//! new snapshot with the last one this serve wrote for the object, so a change reported twice is
//! written once and `changed` names the fields that differ. After a restart there is no last
//! snapshot: the entry then follows the [`Change`] the caller names.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::StreamBody;
use hyper::StatusCode;
use hyper::body::{Bytes, Frame};
use hyper::header::{self, HeaderValue};
use jiff::SignedDuration;
use lepic_node::NodeApi;
use lepic_store::{AccountIndex, ApiEvent, ContactId, TxId};
use lepic_wallet::event::{Connection, Event as EngineEvent, PairingFailure, SlateId};
use serde_json::{Map, Value, json};
use tokio::sync::{Notify, broadcast, watch};
use tokio::time::MissedTickBehavior;

use super::super::{Opened, Service};
use super::{Reply, contacts, network, payments, wallet};
use crate::api::model::Event;
use crate::api::{
    Body, Context, InFlight, ListQuery, Order, Page, Problem, Request, keep_alive_frame, list, ok,
    sse_frame,
};
use crate::exit::CliError;
use crate::host::Host;

/// How long the log keeps an event, and the store an idempotency record.
const KEEP: SignedDuration = SignedDuration::from_hours(30 * 24);
/// How often the writer prunes the log.
const PRUNE_EVERY: Duration = Duration::from_secs(60 * 60);
/// How often an idle stream sends a comment.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// The least time between two `wallet.progress` entries, but for the last of a run.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);
/// How many events a stream reads from the store at once.
const STREAM_BATCH: usize = 100;
/// How many snapshots the log remembers before it forgets them all.
const MAX_SEEN: usize = 10_000;

/// The log's state in serve: the newest id, for streams to wait on, and the last snapshot
/// written of each object.
pub(in super::super) struct Log {
    newest: watch::Sender<u64>,
    seen: RefCell<HashMap<String, Value>>,
    progress_at: Cell<Option<Instant>>,
    refreshed: Notify,
}

impl Log {
    /// The log of a wallet whose newest event id is `newest`.
    pub(in super::super) fn new(newest: u64) -> Self {
        Self {
            newest: watch::Sender::new(newest),
            seen: RefCell::default(),
            progress_at: Cell::new(None),
            refreshed: Notify::new(),
        }
    }

    /// Told after each wallet refresh, so the writer checks the confirmations it reached.
    pub(in super::super) const fn refreshed(&self) -> &Notify {
        &self.refreshed
    }
}

/// Fills `seen` from logged events, oldest first: the newest `data.object` of each payment and
/// contact. A key already in the map is replaced; a new one is added while the map is below
/// [`MAX_SEEN`].
fn fill_seen<'a>(
    seen: &mut HashMap<String, Value>,
    events: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) {
    for (kind, data) in events {
        let resource = match kind.split_once('.') {
            Some(("payment", _)) => "payment",
            Some(("contact", rest)) if rest != "removed" => "contact",
            _ => continue,
        };
        let Ok(Value::Object(mut data)) = serde_json::from_slice::<Value>(data) else {
            continue;
        };
        let Some(object) = data.remove("object") else {
            continue;
        };
        let Some(id) = object.get("id").and_then(Value::as_str) else {
            continue;
        };
        let key = key(resource, id);
        if seen.contains_key(&key) || seen.len() < MAX_SEEN {
            seen.insert(key, object);
        }
    }
}

/// Reads the snapshots clients last saw from the event log into the log's memory, so the first
/// change after a restart is compared with them.
fn load_seen<H: Host>(service: &Service<'_, H>) {
    let kinds = ["payment.*".to_owned(), "contact.*".to_owned()];
    let mut after = 0;
    let mut seen = service.log.seen.borrow_mut();
    loop {
        let batch = match service.held.wallet.api_events_after(
            after,
            lepic_store::MAX_API_EVENTS_PER_READ,
            &kinds,
        ) {
            Ok(batch) => batch,
            Err(error) => {
                tracing::warn!(
                    error = %lepic_telemetry::ErrorChain(&error),
                    "the api log was not read at start"
                );
                return;
            }
        };
        let Some(last) = batch.last().map(|event| event.id) else {
            return;
        };
        fill_seen(
            &mut seen,
            batch
                .iter()
                .map(|event| (event.kind.as_str(), event.data.as_slice())),
        );
        after = last;
    }
}

/// What a change is when the log has no earlier snapshot of the object to compare with.
pub(super) enum Change {
    /// The object is new: `<resource>.created`.
    Created,
    /// Its state changed: `<resource>.state_changed`, with `reason` when the caller knows it,
    /// else the object's own (`state_reason`, `ended_reason`).
    State(Option<String>),
    /// Other fields changed: `<resource>.updated` with these in `changed`.
    Updated(&'static [&'static str]),
}

/// Records the payment with slate id `id` as it is now.
pub(super) async fn payment<H: Host>(service: &Service<'_, H>, id: &str, change: Change) {
    match payments::object(service, id).await {
        Ok(Some(object)) => record(service, "payment", id, to_value(&object), change),
        Ok(None) => gone(service, "payment", id, change),
        Err(problem) => skipped(&problem),
    }
}

async fn payment_of_tx<H: Host>(service: &Service<'_, H>, tx: TxId, change: Change) {
    match payments::object_of_tx(service, tx).await {
        Ok(Some(object)) => {
            let id = object.id.clone();
            record(service, "payment", &id, to_value(&object), change);
        }
        Ok(None) => {}
        Err(problem) => skipped(&problem),
    }
}

/// Records the contact `id` as it is now.
pub(super) async fn contact<H: Host>(service: &Service<'_, H>, id: &str, change: Change) {
    match contacts::object(service, id).await {
        Ok(Some(object)) => record(service, "contact", id, to_value(&object), change),
        Ok(None) => gone(service, "contact", id, change),
        Err(problem) => skipped(&problem),
    }
}

/// Records that the user removed the contact `object`.
pub(super) fn contact_removed<H: Host>(
    service: &Service<'_, H>,
    id: &str,
    object: &impl serde::Serialize,
) {
    service.log.seen.borrow_mut().remove(&key("contact", id));
    append(
        service,
        "contact.removed",
        &json!({ "object": to_value(object) }),
    );
}

async fn account<H: Host>(service: &Service<'_, H>, index: AccountIndex) {
    match wallet::account_object(service, index).await {
        Ok(Some(object)) => {
            let object = to_value(&object);
            let key = key("account", &index.0.to_string());
            if remember(service, &key, &object).as_ref() != Some(&object) {
                append(
                    service,
                    "account.balance_changed",
                    &json!({ "object": object }),
                );
            }
        }
        Ok(None) => {}
        Err(problem) => skipped(&problem),
    }
}

async fn relay<H: Host>(service: &Service<'_, H>, extra: Map<String, Value>) {
    match network::relay_object(service).await {
        Ok(object) => {
            let mut data = extra;
            data.insert("object".to_owned(), to_value(&object));
            append(service, "relay.updated", &Value::Object(data));
        }
        Err(problem) => skipped(&problem),
    }
}

async fn progress<H: Host>(service: &Service<'_, H>, height: u64, target: u64) {
    let now = Instant::now();
    let recent = service
        .log
        .progress_at
        .get()
        .is_some_and(|at| now.saturating_duration_since(at) < PROGRESS_EVERY);
    if recent && height < target {
        return;
    }
    service.log.progress_at.set(Some(now));
    match wallet::wallet_object(service).await {
        Ok(object) => append(
            service,
            "wallet.progress",
            &json!({ "object": to_value(&object), "height": height, "target_height": target }),
        ),
        Err(problem) => skipped(&problem),
    }
}

fn to_value(object: &impl serde::Serialize) -> Value {
    serde_json::to_value(object).unwrap_or(Value::Null)
}

fn key(resource: &str, id: &str) -> String {
    format!("{resource}:{id}")
}

/// Stores `object` as the last snapshot of `key` and returns the one before.
fn remember<H: Host>(service: &Service<'_, H>, key: &str, object: &Value) -> Option<Value> {
    let mut seen = service.log.seen.borrow_mut();
    if seen.len() >= MAX_SEEN && !seen.contains_key(key) {
        seen.clear();
    }
    seen.insert(key.to_owned(), object.clone())
}

fn record<H: Host>(
    service: &Service<'_, H>,
    resource: &str,
    id: &str,
    object: Value,
    change: Change,
) {
    let previous = remember(service, &key(resource, id), &object);
    if let Some((kind, data)) = entry(resource, previous.as_ref(), object, change) {
        append(service, &kind, &data);
    }
}

/// The entry for a change of an object of `resource` from `previous` to `object`; `None` when
/// nothing a client sees changed.
fn entry(
    resource: &str,
    previous: Option<&Value>,
    object: Value,
    change: Change,
) -> Option<(String, Value)> {
    let state = object.get("state").cloned();
    let own_reason = object
        .get("state_reason")
        .or_else(|| object.get("ended_reason"))
        .cloned();
    let reason = |given: Option<String>| given.map(Value::String).or(own_reason.clone());
    let mut data = Map::new();
    let kind = match previous {
        Some(previous) => {
            let before = previous.get("state");
            if before != state.as_ref() {
                insert(&mut data, "from_state", before.cloned());
                insert(&mut data, "to_state", state);
                let given = match change {
                    Change::State(reason) => reason,
                    Change::Created | Change::Updated(_) => None,
                };
                insert(&mut data, "reason", reason(given));
                "state_changed"
            } else {
                let changed = changed_fields(previous, &object);
                if changed.is_empty() {
                    return None;
                }
                data.insert("changed".to_owned(), json!(changed));
                "updated"
            }
        }
        None => match change {
            Change::Created => "created",
            Change::State(given) => {
                insert(&mut data, "to_state", state);
                insert(&mut data, "reason", reason(given));
                "state_changed"
            }
            Change::Updated(fields) => {
                // Never `changed: []`: without a snapshot and without fields, say nothing.
                if !fields.is_empty() {
                    data.insert("changed".to_owned(), json!(fields));
                }
                "updated"
            }
        },
    };
    data.insert("object".to_owned(), object);
    Some((format!("{resource}.{kind}"), Value::Object(data)))
}

fn insert(data: &mut Map<String, Value>, name: &str, value: Option<Value>) {
    if let Some(value) = value {
        data.insert(name.to_owned(), value);
    }
}

/// The top-level fields that differ between two snapshots, but `updated_at`.
fn changed_fields(before: &Value, after: &Value) -> Vec<String> {
    let empty = Map::new();
    let before = before.as_object().unwrap_or(&empty);
    let after = after.as_object().unwrap_or(&empty);
    let mut changed: Vec<String> = before
        .keys()
        .chain(after.keys())
        .filter(|name| name.as_str() != "updated_at" && before.get(*name) != after.get(*name))
        .cloned()
        .collect();
    changed.sort();
    changed.dedup();
    changed
}

/// An object the wallet no longer holds: its last snapshot, if this serve wrote one, ends in
/// the state the change names.
fn gone<H: Host>(service: &Service<'_, H>, resource: &str, id: &str, change: Change) {
    let previous = service.log.seen.borrow_mut().remove(&key(resource, id));
    let Change::State(reason) = change else {
        return;
    };
    let mut data = Map::new();
    data.insert(format!("{resource}_id"), Value::String(id.to_owned()));
    if let Some(previous) = previous {
        insert(&mut data, "from_state", previous.get("state").cloned());
        data.insert("object".to_owned(), previous);
    }
    insert(&mut data, "reason", reason.map(Value::String));
    append(
        service,
        &format!("{resource}.state_changed"),
        &Value::Object(data),
    );
}

fn skipped(problem: &Problem) {
    tracing::warn!(code = problem.code(), "an api event was not written");
}

/// Appends an entry and wakes the streams.
fn append<H: Host>(service: &Service<'_, H>, kind: &str, data: &Value) {
    let bytes = serde_json::to_vec(data).unwrap_or_default();
    match service.held.wallet.append_api_event(kind, &bytes) {
        Ok(id) => {
            service.log.newest.send_replace(id);
        }
        Err(error) => {
            tracing::warn!(
                error = %lepic_telemetry::ErrorChain(&error),
                kind,
                "an api event was not written"
            );
        }
    }
}

/// Writes the engine's events to the log for as long as serve runs, and prunes it.
pub(in super::super) async fn writer<H: Host>(service: &Service<'_, H>) -> Infallible {
    let mut events = service.held.wallet.subscribe();
    load_seen(service);
    let mut prune = tokio::time::interval(PRUNE_EVERY);
    prune.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = prune.tick() => prune_log(service),
            () = service.log.refreshed.notified() => confirmations(service).await,
            event = events.recv() => match event {
                Ok(event) => engine(service, &event).await,
                Err(broadcast::error::RecvError::Lagged(count)) => append(
                    service,
                    "events.skipped",
                    &json!({ "count": count, "reason": "lagged" }),
                ),
                Err(broadcast::error::RecvError::Closed) => {
                    return std::future::pending().await;
                }
            },
        }
    }
}

/// Logs `payment.confirmations_reached` for each payment that reached `payment_confirmations`
/// since the last check.
async fn confirmations<H: Host>(service: &Service<'_, H>) {
    let needed = service.settings.payment_confirmations;
    match payments::view::reached(service, needed).await {
        Ok(reached) => {
            for payment in reached {
                let data = json!({ "object": to_value(&payment) });
                append(service, "payment.confirmations_reached", &data);
            }
        }
        Err(error) => skipped(&Problem::from(error)),
    }
}

fn prune_log<H: Host>(service: &Service<'_, H>) {
    let wallet = &service.held.wallet;
    let Ok(before) = wallet.ports().clock.now().checked_sub(KEEP) else {
        return;
    };
    let pruned = wallet
        .prune_api_events(before)
        .and_then(|_| wallet.prune_api_requests(before));
    if let Err(error) = pruned {
        tracing::warn!(error = %lepic_telemetry::ErrorChain(&error), "pruning the api log failed");
    }
}

/// The reason string of a `contact.state_changed` entry for a pairing that failed. One arm per
/// variant and no catch-all: a new variant does not compile until it is named here and in
/// `docs/api/README.md`.
fn failure_reason(failure: PairingFailure) -> &'static str {
    match failure {
        PairingFailure::ChangedOnTheWay => "changed_on_the_way",
        PairingFailure::KindDiffers => "kind_differs",
        PairingFailure::Expired => "expired",
        PairingFailure::NotConfirmed => "not_confirmed",
        PairingFailure::Refused(_) => "refused",
        PairingFailure::OtherAddress => "other_address",
        PairingFailure::AddressProofMissing => "address_proof_missing",
        PairingFailure::Crossed => "crossed",
    }
}

fn slate(id: SlateId) -> String {
    id.to_string()
}

fn contact_id(id: ContactId) -> String {
    contacts::api_id(id)
}

/// Writes the entries one engine event stands for (`mapping.md` §3).
#[allow(clippy::too_many_lines)] // One arm per engine event.
async fn engine<H: Host>(service: &Service<'_, H>, event: &EngineEvent) {
    use Change::{Created, State, Updated};
    use EngineEvent as E;
    let s = service;
    match event {
        E::Balance(balance) => account(s, balance.account).await,
        E::Transaction(change) => payment_of_tx(s, change.tx_id, State(None)).await,
        E::Received(received) => payment(s, &slate(received.slate_id), Created).await,
        E::SelfSent(sent) => payment_of_tx(s, sent.tx_id, Created).await,
        E::AnsweredAgain(again) => {
            payment(s, &slate(again.slate_id), Updated(&["answers"])).await;
        }
        E::ReplyUndelivered(reply) => {
            payment(s, &slate(reply.slate_id), Updated(&["delivery"])).await;
        }
        E::Sync(sync) => progress(s, sync.height.value(), sync.target.value()).await,
        E::Transport(status)
            if status.transport == lepic_epicbox::TRANSPORT_ID
                && status.connection == Connection::Listener =>
        {
            relay(
                s,
                Map::from_iter([("changed".to_owned(), json!(["connection"]))]),
            )
            .await;
        }
        E::TransportDisconnected(gone)
            if gone.transport == lepic_epicbox::TRANSPORT_ID
                && gone.connection == Connection::Listener =>
        {
            let data = Map::from_iter([
                ("changed".to_owned(), json!(["connection"])),
                ("reason".to_owned(), Value::String(gone.reason.clone())),
            ]);
            relay(s, data).await;
        }
        E::HomeRelayUnreachable(unreachable) => {
            let data = Map::from_iter([
                ("reason".to_owned(), json!("home_unreachable")),
                ("host".to_owned(), Value::String(unreachable.relay.clone())),
            ]);
            relay(s, data).await;
        }
        E::InvoiceParked(parked) => payment(s, &slate(parked.slate_id), Created).await,
        E::InvoiceFinalized(done) => payment(s, &slate(done.slate_id), State(None)).await,
        E::InvoiceExpired(expired) => {
            payment(
                s,
                &slate(expired.slate_id),
                State(Some("expired".to_owned())),
            )
            .await;
        }
        E::InvoicePosted(posted) => payment(s, &slate(posted.slate_id), State(None)).await,
        E::InvoiceDeclined(declined) => {
            payment(
                s,
                &slate(declined.slate_id),
                State(Some("by_them".to_owned())),
            )
            .await;
        }
        E::InvoiceWithdrawn(withdrawn) => {
            payment(
                s,
                &slate(withdrawn.slate_id),
                State(Some("by_them".to_owned())),
            )
            .await;
        }
        E::InvoiceBounced(bounced) => {
            payment(s, &slate(bounced.slate_id), Updated(&["delivery"])).await;
        }
        E::UnknownSlate(unknown) => append(
            s,
            "slate.unmatched",
            &json!({
                "reason": "unknown_slate",
                "slate_id": slate(unknown.slate_id),
                "stage": unknown.stage.as_str(),
                "sender": unknown.sender,
            }),
        ),
        E::NoticeUnmatched(unmatched) => append(
            s,
            "slate.unmatched",
            &json!({
                "reason": "notice",
                "slate_id": slate(unmatched.notice.slate_id),
                "sender": unmatched.sender,
            }),
        ),
        E::ReceiveSuperseded(superseded) => {
            let reason = State(Some("superseded".to_owned()));
            payment(s, &slate(superseded.slate_id), reason).await;
        }
        E::PaymentPosted(notice) => {
            payment(s, &slate(notice.slate_id), Updated(&["their_notices"])).await;
        }
        E::PaymentCancelled(notice) => {
            payment(s, &slate(notice.slate_id), Updated(&["their_notices"])).await;
        }
        E::PaymentDeclined(notice) => {
            payment(s, &slate(notice.slate_id), Updated(&["their_notices"])).await;
        }
        E::PairingReplied(pairing) | E::PairingConfirmed(pairing) => {
            contact(s, &contact_id(pairing.contact_id), State(None)).await;
        }
        E::PairingFailed(failed) => {
            let reason = failure_reason(failed.reason).to_owned();
            contact(s, &contact_id(failed.contact_id), State(Some(reason))).await;
        }
        E::PairingRequested(request) => {
            let id = crate::commands::contact::to_hex(&request.request_id);
            match contacts::pair_request_object(s, &id).await {
                Ok(Some(object)) => append(
                    s,
                    "pair_request.received",
                    &json!({ "object": to_value(&object) }),
                ),
                Ok(None) => {}
                Err(problem) => skipped(&problem),
            }
        }
        E::ContactUpdated(update) => {
            contact(s, &contact_id(update.contact_id), Updated(&[])).await;
        }
        E::ContactRelayMoveRequested(moved) => {
            contact(
                s,
                &contact_id(moved.contact_id),
                Updated(&["requested_relay"]),
            )
            .await;
        }
        E::ContactKeysRestored(keys) | E::ContactKeysChanged(keys) => {
            contact(s, &contact_id(keys.contact_id), State(None)).await;
        }
        E::ContactUnpaired(unpaired) => {
            let reason = State(Some("unpaired".to_owned()));
            contact(s, &contact_id(unpaired.contact_id), reason).await;
        }
        E::InvoiceFromContact(invoice) => payment(s, &slate(invoice.slate_id), Created).await,
        E::WithdrawalFromContact(sent) | E::SealedReceived(sent) => {
            payment(s, &slate(sent.slate_id), Created).await;
        }
        E::SealedUnopenable(unopenable) => append(
            s,
            "quarantine.added",
            &json!({
                "reason": "unopenable",
                "contact_id": contact_id(unopenable.contact_id),
            }),
        ),
        E::OutboxDelivered(outbox) | E::OutboxStuck(outbox) => {
            payment(s, &slate(outbox.slate_id), Updated(&["delivery"])).await;
        }
        E::ContactPaymentFinalized(done) => {
            payment(s, &slate(done.slate_id), State(None)).await;
        }
        E::ContactPayload(sent) => append(
            s,
            "payload.received",
            &json!({ "contact_id": contact_id(sent.contact_id) }),
        ),
        E::ContactPayloadsParked(parked) => append(
            s,
            "payload.received",
            &json!({ "contact_id": contact_id(parked.contact_id), "reason": "parked" }),
        ),
        E::NotPosted(refused) => {
            payment(
                s,
                &slate(refused.slate_id),
                State(Some(refused.reason.clone())),
            )
            .await;
        }
        E::InPersonAnswer(answer) => {
            payment(s, &slate(answer.slate_id), Updated(&["answers"])).await;
        }
        _ => {}
    }
}

/// The `types` filter: a comma list of types, `payment.*` style wildcards allowed.
fn types(request: &Request) -> Result<Vec<String>, Problem> {
    let Some(types) = request.query().get("types") else {
        return Ok(Vec::new());
    };
    let invalid = || Problem::invalid("/types", "types: a comma list of event types");
    let types: Vec<String> = types.split(',').map(str::to_owned).collect();
    if types.len() > lepic_store::MAX_API_KIND_PATTERNS {
        return Err(invalid());
    }
    for kind in &types {
        let name = kind.strip_suffix(".*").unwrap_or(kind);
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte == b'.');
        if !valid {
            return Err(invalid());
        }
    }
    Ok(types)
}

fn event(stored: ApiEvent) -> Event {
    Event {
        id: stored.id,
        kind: stored.kind,
        created_at: stored.created_at.to_string(),
        data: serde_json::from_slice(&stored.data).unwrap_or(Value::Null),
    }
}

/// `events.skipped` before the first event after `after`, when the log no longer holds the
/// events between: its id is the last one it stands for.
fn skipped_since<N: NodeApi + 'static>(
    opened: &Opened<N>,
    after: u64,
) -> Result<Option<Event>, CliError> {
    let wallet = &opened.wallet;
    let first_kept = match wallet.api_event_bounds()? {
        Some((lowest, _)) => lowest,
        None => wallet.api_event_last_id()?.saturating_add(1),
    };
    let last_lost = first_kept.saturating_sub(1);
    Ok((after < last_lost).then(|| Event {
        id: last_lost,
        kind: "events.skipped".to_owned(),
        created_at: wallet.ports().clock.now().to_string(),
        data: json!({ "count": last_lost.saturating_sub(after), "reason": "pruned" }),
    }))
}

pub(super) async fn list<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    context: &Context,
) -> Reply {
    let kinds = types(&request)?;
    let after = request.query().parsed::<u64>("after")?;
    let streams = request
        .header(header::ACCEPT.as_str())
        .is_some_and(|accept| accept.contains("text/event-stream"));
    if streams {
        let resume =
            match request.header("last-event-id") {
                Some(id) => Some(id.trim().parse::<u64>().map_err(|_| {
                    Problem::invalid("/Last-Event-ID", "Last-Event-ID: an event id")
                })?),
                None => after,
            };
        return stream(service, &request, context, kinds, resume);
    }
    let query = ListQuery::parse(request.query())?;
    let after = after.unwrap_or(0);
    let start = match &query.after {
        Some(cursor) => cursor
            .parse::<u64>()
            .map_err(|_| Problem::bad_request("invalid_cursor", "the cursor is not valid"))?
            .max(after),
        None => after,
    };
    let opened = &*service.held;
    let mut items = Vec::new();
    if query.after.is_none() {
        items.extend(skipped_since(opened, start)?);
    }
    let read = query
        .limit
        .saturating_add(1)
        .min(lepic_store::MAX_API_EVENTS_PER_READ);
    let stored = opened
        .wallet
        .api_events_after(start, read, &kinds)
        .map_err(CliError::from)?;
    items.extend(stored.into_iter().map(event));
    ok(&Page::of(items, &query, Order::Ascending, |event| {
        list::number_key(event.id)
    }))
}

/// A live stream of the events after `resume`, or after the newest when there is none.
fn stream<H: Host>(
    service: &Service<'_, H>,
    request: &Request,
    context: &Context,
    kinds: Vec<String>,
    resume: Option<u64>,
) -> Reply {
    let opened = Arc::clone(&service.held);
    let newest = service.log.newest.subscribe();
    let after = resume.unwrap_or_else(|| *newest.borrow());
    let mut pending = VecDeque::new();
    if let Some(skipped) = skipped_since(&opened, after)? {
        pending.push_back(frame(&skipped));
    }
    let start = tokio::time::Instant::now()
        .checked_add(KEEP_ALIVE)
        .unwrap_or_else(tokio::time::Instant::now);
    let mut keep_alive = tokio::time::interval_at(start, KEEP_ALIVE);
    keep_alive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let live = Live {
        opened,
        newest,
        closing: request.closing(),
        kinds,
        after,
        pending,
        keep_alive,
        _in_flight: context.in_flight(),
    };
    let frames = futures_util::stream::unfold(live, |mut live| async move {
        let frame = live.next().await?;
        Some((Ok::<_, Infallible>(Frame::data(frame)), live))
    });
    let body: Body = Box::pin(StreamBody::new(frames));
    let mut response = hyper::Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn frame(event: &Event) -> Bytes {
    let data = serde_json::to_string(event).unwrap_or_default();
    sse_frame(event.id, &event.kind, &data)
}

/// A stream's state.
struct Live<N: NodeApi + 'static> {
    opened: Arc<Opened<N>>,
    newest: watch::Receiver<u64>,
    closing: watch::Receiver<bool>,
    kinds: Vec<String>,
    /// The id of the last event sent, or the one the stream started after.
    after: u64,
    pending: VecDeque<Bytes>,
    keep_alive: tokio::time::Interval,
    _in_flight: InFlight,
}

impl<N: NodeApi + 'static> Live<N> {
    /// The next frame; `None` ends the stream: the connection closes, serve stops, or the log
    /// cannot be read.
    async fn next(&mut self) -> Option<Bytes> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Some(frame);
            }
            if *self.closing.borrow() {
                return None;
            }
            self.newest.borrow_and_update();
            let read = self
                .opened
                .wallet
                .api_events_after(self.after, STREAM_BATCH, &self.kinds);
            match read {
                Ok(batch) if !batch.is_empty() => {
                    for stored in batch {
                        self.after = stored.id;
                        self.pending.push_back(frame(&event(stored)));
                    }
                    continue;
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(&error),
                        "an event stream ended: the log cannot be read"
                    );
                    return None;
                }
            }
            tokio::select! {
                changed = self.newest.changed() => changed.ok()?,
                changed = self.closing.changed() => changed.ok()?,
                _ = self.keep_alive.tick() => return Some(keep_alive_frame()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn payment(state: &str, amount: &str) -> Value {
        json!({ "id": "p", "state": state, "amount": amount, "updated_at": "x" })
    }

    #[test]
    fn a_first_snapshot_follows_the_change_named() {
        let (kind, data) = entry("payment", None, payment("posted", "1"), Change::Created).unwrap();
        assert_eq!(kind, "payment.created");
        assert_eq!(data["object"]["state"], "posted");
        let (kind, data) = entry(
            "payment",
            None,
            payment("cancelled", "1"),
            Change::State(Some("by_them".into())),
        )
        .unwrap();
        assert_eq!(kind, "payment.state_changed");
        assert_eq!(data["to_state"], "cancelled");
        assert_eq!(data["reason"], "by_them");
        assert!(data.get("from_state").is_none());
    }

    #[test]
    fn a_later_snapshot_is_compared_with_the_last() {
        let before = payment("awaiting_answer", "1");
        let (kind, data) = entry(
            "payment",
            Some(&before),
            payment("finalized", "1"),
            Change::Updated(&[]),
        )
        .unwrap();
        assert_eq!(kind, "payment.state_changed");
        assert_eq!(data["from_state"], "awaiting_answer");
        assert_eq!(data["to_state"], "finalized");
        let mut later = payment("awaiting_answer", "2");
        later["updated_at"] = json!("y");
        let (kind, data) = entry("payment", Some(&before), later, Change::State(None)).unwrap();
        assert_eq!(kind, "payment.updated");
        assert_eq!(data["changed"], json!(["amount"]));
        let mut same = payment("awaiting_answer", "1");
        same["updated_at"] = json!("z");
        assert!(entry("payment", Some(&before), same, Change::Created).is_none());
    }

    #[test]
    fn an_update_without_a_snapshot_or_fields_names_no_changed() {
        let (kind, data) =
            entry("contact", None, json!({ "id": "c" }), Change::Updated(&[])).unwrap();
        assert_eq!(kind, "contact.updated");
        assert!(data.get("changed").is_none(), "{data}");
        let (_, data) = entry(
            "contact",
            None,
            json!({ "id": "c" }),
            Change::Updated(&["requested_relay"]),
        )
        .unwrap();
        assert_eq!(data["changed"], json!(["requested_relay"]));
    }

    #[test]
    fn a_state_change_without_a_snapshot_has_no_from_state() {
        let (_, data) =
            entry("payment", None, payment("posted", "1"), Change::State(None)).unwrap();
        assert_eq!(data["to_state"], "posted");
        assert!(data.get("from_state").is_none());
    }

    #[test]
    fn the_snapshots_are_filled_from_the_newest_logged_objects() {
        let first = br#"{"object":{"id":"p","state":"awaiting_answer"}}"#;
        let second = br#"{"object":{"id":"p","state":"finalized"},"from_state":"awaiting_answer"}"#;
        let contact = br#"{"object":{"id":"c","state":"paired"}}"#;
        let removed = br#"{"object":{"id":"gone","state":"paired"}}"#;
        let other = br#"{"object":{"id":"a"}}"#;
        let mut seen = HashMap::new();
        fill_seen(
            &mut seen,
            [
                ("payment.created", first.as_slice()),
                ("payment.state_changed", second.as_slice()),
                ("contact.created", contact.as_slice()),
                ("contact.removed", removed.as_slice()),
                ("account.balance_changed", other.as_slice()),
                ("payment.updated", b"not json".as_slice()),
            ],
        );
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!(seen["payment:p"]["state"], "finalized");
        assert_eq!(seen["contact:c"]["state"], "paired");
        let before = seen["payment:p"].clone();
        assert!(
            entry(
                "payment",
                Some(&before),
                before.clone(),
                Change::State(None)
            )
            .is_none()
        );
    }

    #[test]
    fn a_failure_reason_is_a_fixed_snake_case_string() {
        assert_eq!(
            failure_reason(PairingFailure::ChangedOnTheWay),
            "changed_on_the_way"
        );
        assert_eq!(
            failure_reason(PairingFailure::AddressProofMissing),
            "address_proof_missing"
        );
        assert_eq!(
            failure_reason(PairingFailure::Refused(
                lepic_wallet_contacts::Refusal::Expired
            )),
            "refused"
        );
    }
}
