// SPDX-License-Identifier: Apache-2.0
//! The service: `GET /status` and `GET /openapi.json`.

use hyper::StatusCode;
use hyper::body::Bytes;
use lepic_methods::http::CoinbaseAccess;

use super::super::{Service, TaskStatus};
use super::Reply;
use crate::api::model::{
    EpicboxListener, HttpListener, Listeners, OwnerTls, Requests, Status, Task,
};
use crate::api::{Context, Request, VERSION, ok, response, spec};
use crate::host::Host;

pub(super) async fn get_status<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    context: &Context,
) -> Reply {
    let requests = context.requests();
    let maintenance = service.maintenance.borrow();
    ok(&Status {
        version: VERSION.to_owned(),
        uptime_s: service.started.elapsed().as_secs(),
        listeners: Listeners {
            epicbox: EpicboxListener {
                state: service.epicbox.get().map(str::to_owned),
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
        owner_tls: service.owner_tls.map(|tls| OwnerTls {
            address: tls.address.to_string(),
            fingerprint: tls.fingerprint.to_string(),
        }),
        refresh: task(&maintenance.refresh),
        collect: task(&maintenance.collect),
        requests: Requests {
            served: requests.served,
            in_flight: requests.in_flight,
            refused: requests.refused,
        },
    })
}

fn task(status: &TaskStatus) -> Task {
    Task {
        failures: status.failures,
        last_success_at: status.succeeded_at.map(|at| at.to_string()),
        last_error: status.error.clone(),
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
