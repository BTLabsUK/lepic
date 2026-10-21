//! The HTTP method as a transport (ADR 0003, ADR 0017): its format policy, the client as its
//! outbound side, and the receivers' answers as its inbound side.
//!
//! Over HTTP the receiver answers `receive_tx` with its S2 in the same exchange. The outbound
//! side keeps that answer, keyed by slate id, until the caller finalizes it; nothing else is
//! ever handed out inbound.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::validate::check_size;
use lepic_transport::error::TransportError;
use lepic_transport::policy::{Encoding, FormatPolicy};
use lepic_transport::transport::{
    AckToken, BoxFuture, Destination, Envelope, Inbound, Outbound, Transport, TransportId,
};
use serde::Deserialize;
use tracing::debug;

use crate::client::ForeignClient;
use crate::error::ClientError;
use crate::url::{ForeignUrl, PlainHttp};

/// The transport id of the HTTP method, stored with its transactions.
pub const TRANSPORT_ID: TransportId = TransportId::new("http");

// Answers waiting to be finalized. Each send takes its own at once, so more than a handful
// means callers stopped taking them; the oldest is dropped and its sender can send again.
const MAX_HELD_REPLIES: usize = 64;

/// The policy `epic-wallet` `v4.1.0` speaks over HTTP: V3 and V2 accepted, detected by shape
/// with V3 tried first; a new slate in the V2 shape every listener since 3.0 takes; a reply in
/// the shape it answers.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpPolicy;

impl HttpPolicy {
    const ACCEPTED: [CodecId; 2] = [LEGACY_V3_JSON, LEGACY_V2_JSON];
}

impl FormatPolicy for HttpPolicy {
    fn accepted(&self) -> &[CodecId] {
        &Self::ACCEPTED
    }

    fn for_new_slate(&self, _slate: &Slate, _context: &EncodeContext) -> Encoding {
        Encoding {
            codec: LEGACY_V2_JSON,
            legacy_header: None,
        }
    }

    fn for_reply(&self, slate: &Slate, context: &EncodeContext) -> Encoding {
        match slate.origin() {
            Some(origin) if Self::ACCEPTED.contains(&origin.codec()) => Encoding {
                codec: origin.codec(),
                legacy_header: origin.legacy_header(),
            },
            _ => self.for_new_slate(slate, context),
        }
    }

    fn decode(&self, codecs: &CodecRegistry, wire: &WireSlate) -> Result<Slate, DecodeError> {
        check_size(wire)?;
        Self::ACCEPTED
            .iter()
            .filter_map(|&id| codecs.get(id))
            .find(|codec| codec.detect(wire))
            .ok_or(DecodeError::UnknownFormat)?
            .decode(wire)
    }
}

/// The HTTP method. Clones share the client and the held answers.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: ForeignClient,
    held: Arc<Mutex<VecDeque<Held>>>,
}

#[derive(Debug)]
struct Held {
    slate_id: String,
    wire: WireSlate,
}

impl HttpTransport {
    pub fn new(client: ForeignClient) -> Self {
        Self {
            client,
            held: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// The receiver's answer to the slate with `slate_id`, removed from the held answers.
    pub fn take_reply(&self, slate_id: &str) -> Option<WireSlate> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let position = held
            .iter()
            .position(|reply| reply.slate_id.eq_ignore_ascii_case(slate_id))?;
        held.remove(position).map(|reply| reply.wire)
    }

    fn hold(&self, slate_id: String, wire: WireSlate) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|reply| !reply.slate_id.eq_ignore_ascii_case(&slate_id));
        if held.len() >= MAX_HELD_REPLIES {
            held.pop_front();
        }
        held.push_back(Held { slate_id, wire });
    }

    async fn post(&self, to: &Destination, wire: &WireSlate) -> Result<(), ClientError> {
        // The caller checked the destination with the user's plain-HTTP choice when it was
        // typed; what reaches the transport is already consented to.
        let url = ForeignUrl::parse(to.as_str(), PlainHttp::Allowed)?;
        let version = self.client.check_version(&url).await?;
        if !version.v2 {
            return Err(ClientError::NoCommonVersion);
        }
        let reply = self.client.receive_tx(&url, wire).await?;
        let slate_id =
            slate_id_of(&reply).ok_or(ClientError::Rpc(crate::error::RpcError::Malformed))?;
        debug!(%slate_id, "answer received");
        self.hold(slate_id, reply);
        Ok(())
    }
}

#[derive(Deserialize)]
struct IdOnly {
    id: String,
}

/// The `id` both legacy shapes carry at the top, read without decoding the slate.
fn slate_id_of(wire: &WireSlate) -> Option<String> {
    let text = wire.as_text()?;
    let IdOnly { id } = serde_json::from_str(text).ok()?;
    (id.len() <= 64).then_some(id)
}

impl Outbound for HttpTransport {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.post(to, wire)
                .await
                .map_err(|error| TransportError::Backend {
                    transport: TRANSPORT_ID,
                    source: Box::new(error),
                })
        })
    }
}

impl Inbound for HttpTransport {
    /// Held answers, oldest first. Acknowledging is a no-op: an answer leaves the queue when
    /// it is handed out.
    fn next_envelope(&self) -> BoxFuture<'_, Result<Option<Envelope>, TransportError>> {
        Box::pin(async move {
            let next = self
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front();
            Ok(next.map(|reply| Envelope::new(AckToken::new(reply.slate_id), None, reply.wire)))
        })
    }

    fn acknowledge<'a>(
        &'a self,
        _token: &'a AckToken,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async { Ok(()) })
    }
}

impl Transport for HttpTransport {
    fn id(&self) -> TransportId {
        TRANSPORT_ID
    }

    fn policy(&self) -> &dyn FormatPolicy {
        &HttpPolicy
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }

    fn inbound(&self) -> Option<&dyn Inbound> {
        Some(self)
    }
}
