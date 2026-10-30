// SPDX-License-Identifier: Apache-2.0
//! The HTTP method as a transport (ADR 0003, ADR 0017): its format policy and the client as its
//! outbound side. It has no inbound side: payments to this wallet reach the listener.
//!
//! Over HTTP the receiver answers `receive_tx` with its S2 in the same exchange. The outbound
//! side keeps that answer, keyed by the id of the slate it answers, until the caller takes it
//! with [`HttpTransport::take_reply`] to finalize it.

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
    BoxFuture, Destination, Inbound, Outbound, Transport, TransportId,
};
use serde::Deserialize;
use tracing::debug;

use crate::client::ForeignClient;
use crate::error::{ClientError, RpcError};
use crate::url::{ForeignUrl, PlainHttp};

/// The transport id of the HTTP method, stored with its transactions.
pub const TRANSPORT_ID: TransportId = TransportId::new("http");

// Answers waiting to be finalized. Each send takes its own at once, so more than a handful
// means callers stopped taking them; the oldest is dropped and its sender can send again.
const MAX_HELD_REPLIES: usize = 64;

/// The policy `epic-wallet` `v4.1.0` speaks over HTTP: V3 and V2 accepted, detected by shape
/// with V3 tried first; a new slate in the V2 shape every listener since 3.0 takes, or in the
/// V3 shape when it asks for a payment proof, which V2 cannot carry, as `epic-wallet` sends it
/// to a listener that takes V3; a reply in the shape it answers.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpPolicy;

impl HttpPolicy {
    const ACCEPTED: [CodecId; 2] = [LEGACY_V3_JSON, LEGACY_V2_JSON];
}

impl FormatPolicy for HttpPolicy {
    fn accepted(&self) -> &[CodecId] {
        &Self::ACCEPTED
    }

    fn for_new_slate(&self, slate: &Slate, _context: &EncodeContext) -> Encoding {
        let codec = if slate.payment_proof().is_some() {
            LEGACY_V3_JSON
        } else {
            LEGACY_V2_JSON
        };
        Encoding {
            codec,
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

    /// Sends `wire` and holds the answer under its slate id. An answer for another slate is
    /// refused as malformed and not held.
    async fn post(&self, to: &Destination, wire: &WireSlate) -> Result<(), ClientError> {
        // The caller checked the destination with the user's plain-HTTP choice when it was
        // typed; what reaches the transport is already consented to.
        let url = ForeignUrl::parse(to.as_str(), PlainHttp::Allowed)?;
        let slate_id = slate_id_of(wire).ok_or(ClientError::Rpc(RpcError::NotJson))?;
        let version = self.client.check_version(&url).await?;
        let shared = if version_of(wire) == Some(3) {
            version.v3
        } else {
            version.v2
        };
        if !shared {
            return Err(ClientError::NoCommonVersion);
        }
        let reply = self.client.receive_tx(&url, wire).await?;
        if !slate_id_of(&reply).is_some_and(|answered| answered.eq_ignore_ascii_case(&slate_id)) {
            return Err(ClientError::Rpc(RpcError::Malformed));
        }
        debug!(%slate_id, "answer received");
        self.hold(slate_id, reply);
        Ok(())
    }
}

#[derive(Deserialize)]
struct IdOnly {
    id: String,
}

#[derive(Deserialize)]
struct VersionOnly {
    version_info: VersionInfoOnly,
}

#[derive(Deserialize)]
struct VersionInfoOnly {
    version: u64,
}

/// The `version_info.version` both legacy shapes carry, read without decoding the slate.
fn version_of(wire: &WireSlate) -> Option<u64> {
    let VersionOnly { version_info } = serde_json::from_str(wire.as_text()?).ok()?;
    Some(version_info.version)
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
        None
    }
}
