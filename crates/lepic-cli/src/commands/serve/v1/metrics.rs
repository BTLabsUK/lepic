// SPDX-License-Identifier: Apache-2.0
//! `GET /metrics`: the facts serve holds, in the Prometheus text format. It reads the store and
//! what serve noted since it started, and asks no node or mailbox.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use hyper::StatusCode;
use hyper::body::Bytes;

use super::super::Service;
use super::{Reply, mailboxes, payments, wallet};
use crate::api::metrics::{CONTENT_TYPE, Exposition, Kind, Sample};
use crate::api::model::{Mailbox, OpenPayments};
use crate::api::{Context, Problem, Request, response};
use crate::exit::CliError;
use crate::host::Host;

/// What serve counts for the metrics since it started: nothing is stored.
#[derive(Default)]
pub(in crate::commands::serve) struct Counters {
    created: Cell<u64>,
    errors: RefCell<BTreeMap<&'static str, u64>>,
}

impl Counters {
    /// Counts the answer of a payment create: made (201), or an error by its category. An answer
    /// for a repeat of an earlier create (200) is neither.
    pub(super) fn created(&self, reply: &Reply) {
        match reply {
            Ok(answer) if answer.status() == StatusCode::CREATED => {
                self.created.set(self.created.get().saturating_add(1));
            }
            Ok(_) => {}
            Err(problem) => {
                let mut errors = self.errors.borrow_mut();
                let count = errors.entry(problem.category().name()).or_default();
                *count = count.saturating_add(1);
            }
        }
    }
}

pub(super) async fn get<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    if !service.metrics {
        return Err(Problem::not_found(
            "the metrics are off; start serve with --metrics",
        ));
    }
    let text = exposition(service).await?;
    Ok(response(
        StatusCode::OK,
        CONTENT_TYPE,
        Bytes::from(text.into_bytes()),
    ))
}

fn seconds(text: &str) -> Option<u64> {
    let at: jiff::Timestamp = text.parse().ok()?;
    u64::try_from(at.as_second()).ok()
}

/// What the families are made of, read once for a scrape.
struct Facts {
    balances: Vec<Sample>,
    open: OpenPayments,
    queued: u64,
    stuck: u64,
    wallet_height: u64,
    mailboxes: Vec<Mailbox>,
    refresh_failures: u64,
    refreshed_at: Option<jiff::Timestamp>,
    node_height: Option<u64>,
    created: u64,
    create_errors: Vec<Sample>,
}

async fn exposition<H: Host>(service: &Service<'_, H>) -> Result<String, Problem> {
    let facts = gather(service).await?;
    let mut out = Exposition::new();
    wallet_families(&mut out, &facts);
    delivery_families(&mut out, &facts);
    mailbox_families(&mut out, &facts);
    out.family(
        "lepic_payments_created_total",
        Kind::Counter,
        "Payments and invoices created through the API since serve started.",
        vec![Sample::bare(facts.created)],
    );
    out.family(
        "lepic_payment_create_errors_total",
        Kind::Counter,
        "Payment creates the API answered with an error since serve started, by error category.",
        facts.create_errors,
    );
    Ok(out.finish())
}

async fn gather<H: Host>(service: &Service<'_, H>) -> Result<Facts, Problem> {
    let wallet = &service.held.wallet;
    let mut balances = Vec::new();
    for account in wallet.accounts().map_err(CliError::from)? {
        let balance = wallet.balance(account.index).map_err(CliError::from)?;
        for (state, amount) in [
            ("spendable", balance.spendable),
            ("confirming", balance.awaiting_confirmation),
            ("pending", balance.awaiting_finalization),
            ("locked", balance.locked),
            ("maturing", balance.immature),
        ] {
            balances.push(Sample::labelled(
                [("account", account.label.as_str()), ("state", state)],
                amount.value(),
            ));
        }
    }
    let open = payments::view::status(service)?.open;
    let deliveries = payments::view::open_deliveries(service).await?;
    let wallet_height = wallet::wallet_object(service).await?.height;
    let mailboxes = mailboxes::listed(service).await?.mailboxes;
    let (refresh_failures, refreshed_at, node_height) = {
        let maintenance = service.maintenance.borrow();
        (
            maintenance.refresh.failures_total,
            maintenance.refresh.succeeded_at,
            maintenance.tip.map(|tip| tip.height.value()),
        )
    };
    let create_errors = service
        .counters
        .errors
        .borrow()
        .iter()
        .map(|(category, n)| Sample::labelled([("category", category)], *n))
        .collect();
    Ok(Facts {
        balances,
        open,
        queued: deliveries.queued,
        stuck: deliveries.stuck,
        wallet_height,
        mailboxes,
        refresh_failures,
        refreshed_at,
        node_height,
        created: service.counters.created.get(),
        create_errors,
    })
}

fn wallet_families(out: &mut Exposition, facts: &Facts) {
    out.family(
        "lepic_balance",
        Kind::Gauge,
        "Balance of an account in the wallet's base unit (1e-8 EPIC), by state.",
        facts.balances.clone(),
    );
    out.family(
        "lepic_wallet_height",
        Kind::Gauge,
        "Block height the wallet has scanned to; the lowest of its accounts.",
        vec![Sample::bare(facts.wallet_height)],
    );
    out.family(
        "lepic_node_height",
        Kind::Gauge,
        "Block height of the node's tip as the last refresh saw it; no sample before the first.",
        facts.node_height.map(Sample::bare).into_iter().collect(),
    );
    out.family(
        "lepic_refresh_failures_total",
        Kind::Counter,
        "Wallet refreshes that failed since serve started.",
        vec![Sample::bare(facts.refresh_failures)],
    );
    out.family(
        "lepic_refresh_last_success_timestamp_seconds",
        Kind::Gauge,
        "Unix time of the last wallet refresh that worked; no sample before the first.",
        facts
            .refreshed_at
            .and_then(|at| u64::try_from(at.as_second()).ok())
            .map(Sample::bare)
            .into_iter()
            .collect(),
    );
}

fn delivery_families(out: &mut Exposition, facts: &Facts) {
    let open = &facts.open;
    out.family(
        "lepic_payments",
        Kind::Gauge,
        "Payments that are not over, by state.",
        [
            ("needs_approval", open.needs_approval),
            ("awaiting_answer", open.awaiting_answer),
            ("finalized", open.finalized),
            ("posted", open.posted),
        ]
        .map(|(state, n)| Sample::labelled([("state", state)], n))
        .into(),
    );
    out.family(
        "lepic_payments_stuck",
        Kind::Gauge,
        "Payments that are not over whose delivery is marked stuck or is uncertain or failed, as GET /payments shows it.",
        vec![Sample::bare(facts.stuck)],
    );
    out.family(
        "lepic_outbox_queue_depth",
        Kind::Gauge,
        "Payments that are not over whose delivery is queued, as GET /payments shows it.",
        vec![Sample::bare(facts.queued)],
    );
}

fn mailbox_families(out: &mut Exposition, facts: &Facts) {
    let each = |value: &dyn Fn(&Mailbox) -> Option<u64>| -> Vec<Sample> {
        facts
            .mailboxes
            .iter()
            .filter_map(|m| Some(Sample::labelled([("mailbox", m.host.as_str())], value(m)?)))
            .collect()
    };
    out.family(
        "lepic_mailbox_failures",
        Kind::Gauge,
        "Sessions to the mailbox lost since its last success.",
        each(&|m| Some(u64::from(m.failures))),
    );
    out.family(
        "lepic_mailbox_last_success_timestamp_seconds",
        Kind::Gauge,
        "Unix time a session last attached to the mailbox; no sample before the first.",
        each(&|m| seconds(m.last_success_at.as_deref()?)),
    );
    out.family(
        "lepic_mailbox_push_offered",
        Kind::Gauge,
        "1 when the mailbox offered push (mux/1) at its last greeting, 0 when it did not; no \
         sample before it answered.",
        each(&|m| Some(u64::from(m.push?))),
    );
    out.family(
        "lepic_mailbox_no_mux",
        Kind::Gauge,
        "1 when the mailbox is known to lack mux/1, so the wallet neither reads nor posts to it.",
        each(&|m| Some(u64::from(m.no_mux))),
    );
}
