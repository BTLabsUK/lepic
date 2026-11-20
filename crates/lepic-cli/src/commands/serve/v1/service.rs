// SPDX-License-Identifier: Apache-2.0
//! The service: `GET /status` and `GET /openapi.json`.

use std::sync::PoisonError;

use hyper::StatusCode;
use hyper::body::Bytes;
use lepic_epicbox::MuxState;
use lepic_methods::http::CoinbaseAccess;
use lepic_wallet::boost::Poller;
use lepic_wallet::error_text::node_text;

use super::super::{Service, TaskStatus};
use super::Reply;
use crate::api::model::{
    Boost, EpicboxListener, EpicboxRelay, HttpListener, Listeners, NodeStatus, OwnerTls, Requests,
    Status, Task,
};
use crate::api::{Context, Request, VERSION, ok, response, spec};
use crate::host::Host;

pub(super) async fn get_status<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    context: &Context,
) -> Reply {
    let payments = super::payments::view::status(service)?;
    let requests = context.requests();
    let maintenance = service.maintenance.borrow();
    ok(&Status {
        version: VERSION.to_owned(),
        uptime_s: service.started.elapsed().as_secs(),
        listeners: Listeners {
            epicbox: EpicboxListener {
                state: service.epicbox.get().map(str::to_owned),
                relays: relays(service),
            },
            http: service.http.map(|http| {
                let counts = http.report();
                HttpListener {
                    port: counts.port,
                    exposure: counts.exposure.to_owned(),
                    received: counts.received,
                    repeated: counts.repeated,
                    refused: counts.refused,
                    coinbase: match http.coinbase {
                        CoinbaseAccess::Off => "off",
                        CoinbaseAccess::LocalOnly => "local",
                        CoinbaseAccess::Remote => "remote",
                    }
                    .to_owned(),
                }
            }),
        },
        node: NodeStatus {
            tip_height: maintenance.tip.map(|tip| tip.height.value()),
            tip_changed_at: maintenance.tip.map(|tip| tip.changed_at.to_string()),
        },
        payments,
        owner_tls: service.owner_tls.map(|tls| OwnerTls {
            address: tls.address.to_string(),
            fingerprint: tls.fingerprint.to_string(),
        }),
        refresh: task(&maintenance.refresh, service, Poller::Node),
        collect: task(&maintenance.collect, service, Poller::Relays),
        requests: Requests {
            served: requests.served,
            in_flight: requests.in_flight,
            refused: requests.refused,
        },
    })
}

/// The push sessions as they are now, with what this serve saw of each.
fn relays<H: Host>(service: &Service<'_, H>) -> Vec<EpicboxRelay> {
    let pushed = service.held.epicbox.pushed();
    let seen = service
        .relays
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let infos = pushed.infos();
    // The listener lets go of a session the relay refused and listens on a plain socket, so the
    // registry no longer lists it; the relay's health record is kept past that. A live session
    // of the relay wins over the record.
    let not_offered: Vec<EpicboxRelay> = pushed
        .health()
        .into_iter()
        .filter(|(relay, health)| {
            health.push == Some(false) && !infos.iter().any(|info| &info.relay == relay)
        })
        .map(|(relay, health)| EpicboxRelay {
            host: relay,
            group: health.group,
            state: "not_offered".to_owned(),
            push: Some(false),
            last_error: None,
            connected_since: None,
            last_mail_at: None,
        })
        .collect();
    infos
        .into_iter()
        .map(|info| {
            let saw = seen
                .get(&(info.relay.clone(), info.group.clone()))
                .copied()
                .unwrap_or_default();
            EpicboxRelay {
                push: pushed.supports_push(&info.relay),
                state: match info.state {
                    MuxState::Connecting { .. } => "connecting",
                    MuxState::Attached => "attached",
                    MuxState::NotOffered => "not_offered",
                    MuxState::Stopped => "stopped",
                    // Waiting, and any state added later: not attached, and it retries.
                    _ => "waiting",
                }
                .to_owned(),
                last_error: info.last_error.as_deref().map(node_text),
                connected_since: saw.connected_since.map(|at| at.to_string()),
                last_mail_at: saw.last_mail_at.map(|at| at.to_string()),
                host: info.relay,
                group: info.group,
            }
        })
        .chain(not_offered)
        .collect()
}

fn task<H: Host>(status: &TaskStatus, service: &Service<'_, H>, poller: Poller) -> Task {
    Task {
        failures: status.failures,
        last_success_at: status.succeeded_at.map(|at| at.to_string()),
        last_error: status.error.clone(),
        boost: service.held.wallet.boosts().window(poller).map(Boost::of),
    }
}

/// The contract serve answers: `docs/api/openapi.json` as built in.
#[allow(clippy::unused_async)] // Every handler is async.
pub(super) async fn get_open_api<H: Host>(
    _service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    Ok(response(
        StatusCode::OK,
        "application/json",
        Bytes::from_static(spec::DOCUMENT.as_bytes()),
    ))
}
