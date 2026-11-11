// SPDX-License-Identifier: Apache-2.0
//! Server-sent events for `GET /api/v1/events` with `Accept: text/event-stream`, and the engine
//! events serve reads for its own state.

use hyper::body::Bytes;
use lepic_wallet::event::{Connection, Event, TransportState};

/// One event as an SSE frame: `id:` its sequence number, `event:` its type, `data:` its JSON on
/// one line.
pub(crate) fn sse_frame(id: u64, kind: &str, data: &str) -> Bytes {
    // JSON from serde_json has no raw line breaks, so one `data:` line holds it.
    Bytes::from(format!("id: {id}\nevent: {kind}\ndata: {data}\n\n"))
}

/// The comment line that keeps an idle stream open.
pub(crate) fn keep_alive_frame() -> Bytes {
    Bytes::from_static(b": keepalive\n\n")
}

const fn transport_state(state: TransportState) -> Option<&'static str> {
    match state {
        TransportState::Connecting => Some("connecting"),
        TransportState::Connected => Some("connected"),
        TransportState::Disconnected => Some("disconnected"),
        TransportState::Stopped => Some("stopped"),
        _ => None,
    }
}

/// The state of the Epicbox listener that `event` reports, if it reports one.
pub(crate) fn epicbox_state(event: &Event) -> Option<&'static str> {
    match event {
        Event::Transport(status)
            if status.transport == lepic_epicbox::TRANSPORT_ID
                && status.connection == Connection::Listener =>
        {
            transport_state(status.state)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_names_the_id_type_and_data() {
        assert_eq!(
            sse_frame(7, "payment.created", r#"{"a":1}"#),
            Bytes::from_static(b"id: 7\nevent: payment.created\ndata: {\"a\":1}\n\n")
        );
    }
}
