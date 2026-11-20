// SPDX-License-Identifier: Apache-2.0
//! The handler a listener's `/api/v1/inbox` route answers with (EPICTX 5.15): a
//! payment sealed to one of the wallet's epic1 addresses, received as the foreign API receives
//! a slate, with its S2 sealed to the reply key the envelope carries.

use std::sync::Arc;
use std::time::Duration;

use lepic_contact::{
    EncPublicKey, Hint, HintRule, KeyClass, SealedEnvelope, TxContent, TxKey, TxOpened, seal_tx,
};
use lepic_methods::http::{Busy, RouteRequest, RouteResponse, SocketRoute};
use lepic_methods::http::{Host, Refusal};
use lepic_peer::{
    HandlerFuture, PEER_PATH, PeerEndpoint, PeerRefusal, ProblemCode, SlateHandler,
    problem_response,
};
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::stage::Stage;
use lepic_store::AccountIndex;
use lepic_transport::method::Method;
use lepic_transport::transport::BoxFuture;
use lepic_wallet::ports::SharedRng;
use lepic_wallet::{Epic1AccountKeys, ProofKey, ReceiveRequest};
use tracing::{info, warn};

use super::keys::contact_network;
use super::native::{decode_native, native_body, v3_of_native};
use super::{ContactError, LockedRng};

/// The seal keys of a wallet's epic1 addresses, for a listener that takes payments sealed to
/// them ([`DirectHandler::with_epic1`]).
pub trait Epic1Keys: Send + Sync {
    /// [`lepic_wallet::Wallet::epic1_trial_keys_all`]; none when the wallet cannot give them.
    fn epic1_keys(&self) -> BoxFuture<'_, Vec<Epic1AccountKeys>>;
}

/// The handler of a listener socket's `/api/v1/inbox`: opens an envelope with a zero hint with
/// the seal keys of the wallet's epic1 addresses ([`DirectHandler::with_epic1`]), receives the
/// S1 in it through `host` into the address's account as the foreign API does, and seals the
/// S2 to the reply key the envelope carries. An envelope that names its sender, or a slate
/// that asks for a payment proof, is refused; without epic1 keys every envelope is.
pub struct DirectHandler<H: Host> {
    host: Arc<H>,
    method: Arc<dyn Method>,
    network: Network,
    rng: SharedRng,
    epic1: Option<Arc<dyn Epic1Keys>>,
}

/// `envelope` tried with the epic1 seal key of each of `accounts` in turn, on the blocking
/// pool: a zero hint does not tell which account's address it was sealed to, and each key tried
/// is an X25519 operation. Returns the account and its label of the first key that opens.
pub(crate) async fn trial_open_accounts(
    envelope: Vec<u8>,
    network: lepic_contact::Network,
    accounts: Vec<Epic1AccountKeys>,
) -> Option<(AccountIndex, String, TxOpened)> {
    tokio::task::spawn_blocking(move || {
        let sealed = SealedEnvelope::decode(&envelope, network).ok()?;
        accounts.into_iter().find_map(|account| {
            let opened = sealed.open_tx(&account.key, KeyClass::Epic1).ok()?;
            Some((account.account, account.label, opened))
        })
    })
    .await
    .ok()
    .flatten()
}

/// The S1 of an envelope a listener took, the key its answer is sealed to, and the epic1
/// address it was sealed to.
struct Proposal {
    wire: WireSlate,
    reply_key: EncPublicKey,
    /// The label of the account whose address it was sealed to.
    epic1: String,
}

impl<H: Host> DirectHandler<H> {
    /// A handler receiving over `method`, as the socket's foreign API does. `rng` draws the
    /// reply envelopes' keys.
    pub fn new(host: Arc<H>, method: Arc<dyn Method>, network: Network, rng: SharedRng) -> Self {
        Self {
            host,
            method,
            network,
            rng,
            epic1: None,
        }
    }

    /// The handler, also taking payments sealed to the epic1 addresses whose keys `keys` gives.
    #[must_use]
    pub fn with_epic1(mut self, keys: Arc<dyn Epic1Keys>) -> Self {
        self.epic1 = Some(keys);
        self
    }

    /// `envelope`, with a zero hint, opened with the seal key of an epic1 address, with the
    /// label of the address's account.
    async fn open(&self, envelope: &[u8]) -> Result<(TxOpened, String), PeerRefusal> {
        let sealed = SealedEnvelope::decode(envelope, contact_network(self.network))
            .map_err(|_| PeerRefusal::UnsupportedFormat)?;
        let Some(source) = &self.epic1 else {
            return Err(PeerRefusal::Refused);
        };
        if sealed.hint() != Hint::from_bytes([0; 8]) {
            return Err(PeerRefusal::Refused);
        }
        let accounts = source.epic1_keys().await;
        let found = trial_open_accounts(envelope.to_vec(), contact_network(self.network), accounts)
            .await
            .ok_or(PeerRefusal::Refused)?;
        let (account, label, opened) = found;
        // A payment to an epic1 is anonymous.
        if opened.sender.is_some() {
            return Err(PeerRefusal::Refused);
        }
        info!(account = account.0, "payment opened at an epic1 address");
        Ok((opened, label))
    }

    /// The S1 in `envelope`, the key its answer is sealed to, and the epic1 address it came to.
    async fn proposal(&self, envelope: &[u8]) -> Result<Proposal, PeerRefusal> {
        let (opened, epic1) = self.open(envelope).await?;
        let reply_key = opened.content.reply_key.ok_or(PeerRefusal::Refused)?;
        // An invoice, or any stage but a proposal, is not taken here.
        let slate = decode_native(self.network, &opened.content.body)
            .filter(|slate| slate.stage() == Stage::S1)
            .ok_or(PeerRefusal::Refused)?;
        let v3 = v3_of_native(self.network, slate, None).ok_or(PeerRefusal::Refused)?;
        let text = String::from_utf8(v3).map_err(|_| PeerRefusal::Refused)?;
        Ok(Proposal {
            wire: WireSlate::text(MediaType::JSON, text),
            reply_key,
            epic1,
        })
    }

    /// `reply`, the S2 the engine stored, as `lepic.v1` sealed to `reply_key`.
    fn sealed_reply(
        &self,
        reply: &WireSlate,
        reply_key: &EncPublicKey,
    ) -> Result<Vec<u8>, ContactError> {
        let body = native_body(self.network, reply.as_bytes())?;
        seal_tx(
            contact_network(self.network),
            reply_key,
            TxKey::Seal(HintRule::ReplyKey),
            &TxContent::new(body),
            None,
            &mut LockedRng(&mut **self.rng.lock()),
        )
        .map_err(ContactError::Encode)
    }
}

impl<H: Host> SlateHandler for DirectHandler<H> {
    /// The envelope's header and fields decode for this network; nothing is opened.
    fn check(&self, envelope: &[u8]) -> Result<(), PeerRefusal> {
        SealedEnvelope::decode(envelope, contact_network(self.network))
            .map(|_| ())
            .map_err(|_| PeerRefusal::UnsupportedFormat)
    }

    fn receive(&self, envelope: Vec<u8>) -> HandlerFuture<'_> {
        Box::pin(async move {
            let Proposal {
                wire,
                reply_key,
                epic1,
            } = match self.proposal(&envelope).await {
                Ok(proposal) => proposal,
                Err(refusal) => {
                    self.host.refused(Refusal::Rejected);
                    return Err(refusal);
                }
            };
            let request = ReceiveRequest {
                account: Some(epic1),
                proof_key: ProofKey::Epic1 { index: 0 },
                ..ReceiveRequest::default()
            };
            let received = match self.host.receive(&self.method, &wire, request).await {
                Ok(received) => received,
                Err(refusal) => {
                    self.host.refused(refusal);
                    return Err(match refusal {
                        Refusal::Unavailable | Refusal::OpenReceipts => PeerRefusal::NotReady {
                            retry_after: NOT_READY_RETRY,
                        },
                        _ => PeerRefusal::Refused,
                    });
                }
            };
            match self.sealed_reply(&received.reply, &reply_key) {
                Ok(sealed) => {
                    self.host.received(&received);
                    Ok(sealed)
                }
                Err(error) => {
                    // Stored, and answered again to a repeat once sealing works.
                    warn!(error = %error, "native answer not sealed");
                    self.host.refused(Refusal::Unavailable);
                    Err(PeerRefusal::NotReady {
                        retry_after: NOT_READY_RETRY,
                    })
                }
            }
        })
    }
}

/// How long a sender is asked to wait when the wallet cannot take a payment now.
const NOT_READY_RETRY: Duration = Duration::from_secs(30);

/// The `/api/v1/inbox` route of a listener socket: a `POST` of an envelope, answered by a
/// [`SlateHandler`] such as a [`DirectHandler`].
pub struct InboxRoute(PeerEndpoint);

impl InboxRoute {
    pub fn new(handler: Arc<dyn SlateHandler>) -> Self {
        Self(PeerEndpoint::new(handler))
    }
}

impl SocketRoute for InboxRoute {
    fn serves(&self, path: &str) -> bool {
        path == PEER_PATH
    }

    fn read(
        &self,
        request: RouteRequest,
        body_timeout: Duration,
    ) -> BoxFuture<'_, Result<Vec<u8>, Box<RouteResponse>>> {
        Box::pin(self.0.read(request, body_timeout))
    }

    fn take(&self, body: Vec<u8>) -> BoxFuture<'_, (RouteResponse, bool)> {
        Box::pin(async move {
            let answer = self.0.receive(body).await;
            (answer.response, answer.received)
        })
    }

    fn busy(&self, why: Busy, retry_after: Duration) -> RouteResponse {
        let code = match why {
            Busy::OverBudget => ProblemCode::RateLimited,
            Busy::TimedOut => ProblemCode::NotReady,
        };
        problem_response(code, Some(retry_after))
    }
}

/// A dialer that opens each connection of a [`lepic_peer::PeerClient`] through `tor`, on a
/// circuit of its own, waiting at most `connect_timeout` for it.
#[cfg(feature = "tor")]
pub fn onion_dialer(
    tor: lepic_methods::tor::Tor,
    connect_timeout: Duration,
) -> Arc<dyn lepic_peer::PeerDialer> {
    Arc::new(OnionDialer {
        tor,
        connect_timeout,
    })
}

#[cfg(feature = "tor")]
struct OnionDialer {
    tor: lepic_methods::tor::Tor,
    connect_timeout: Duration,
}

#[cfg(feature = "tor")]
impl lepic_peer::PeerDialer for OnionDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> lepic_peer::PeerDialFuture<'a> {
        Box::pin(async move {
            let stream = self.tor.open(host, port, self.connect_timeout).await?;
            Ok(Box::new(stream) as Box<dyn lepic_peer::PeerStream>)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use lepic_methods::http::{ClientSettings, Http, RpcClient, webpki_tls_config};
    use lepic_wallet::Received;
    use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};

    use lepic_contact::EncSecretKey;

    use super::*;

    /// A source of the same byte.
    struct FixedRng;

    impl rand_core::TryRng for FixedRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(7)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(7)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(7);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for FixedRng {}

    /// A host that counts what reaches it and takes nothing.
    #[derive(Default)]
    struct Counting {
        receives: AtomicU32,
        refusals: AtomicU32,
    }

    impl Host for Counting {
        fn receive(
            &self,
            _method: &Arc<dyn Method>,
            _wire: &WireSlate,
            _request: ReceiveRequest,
        ) -> BoxFuture<'_, Result<Received, Refusal>> {
            self.receives.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(Refusal::Rejected) })
        }

        fn build_coinbase(
            &self,
            _request: CoinbaseRequest,
        ) -> BoxFuture<'_, Result<Coinbase, Refusal>> {
            Box::pin(async { Err(Refusal::Unavailable) })
        }

        fn received(&self, _received: &Received) {}

        fn refused(&self, _refusal: Refusal) {
            self.refusals.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The V3 JSON of the floonet `slates_native` vector `name`.
    fn vector_v3(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/../../testdata/vectors/slates_native/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let vector: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        vector["inputs"]["v3_json"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn http() -> Arc<dyn Method> {
        let settings = ClientSettings {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
            max_response_bytes: 1024,
        };
        Arc::new(Http::new(RpcClient::new(
            settings,
            webpki_tls_config().unwrap(),
        )))
    }

    /// The answer of a handler with the epic1 address of `key` to `body` sealed to it with a
    /// reply key, and its host.
    fn answer(body: Vec<u8>) -> (Result<Vec<u8>, PeerRefusal>, Arc<Counting>) {
        let key = EncSecretKey::from_bytes([3; 32]);
        let host = Arc::new(Counting::default());
        let handler = DirectHandler::new(
            Arc::clone(&host),
            http(),
            Network::Floonet,
            SharedRng::new(FixedRng),
        )
        .with_epic1(Arc::new(OneAddress(key.clone())));
        let content = TxContent {
            reply_key: Some(EncSecretKey::from_bytes([5; 32]).public_key()),
            ..TxContent::new(body)
        };
        let envelope = seal_tx(
            contact_network(Network::Floonet),
            &key.public_key(),
            TxKey::Epic1,
            &content,
            None,
            &mut FixedRng,
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        (runtime.block_on(handler.receive(envelope)), host)
    }

    #[test]
    fn only_an_envelope_for_this_network_passes_the_check() {
        let key = EncSecretKey::from_bytes([3; 32]);
        let host = Arc::new(Counting::default());
        let handler = DirectHandler::new(
            Arc::clone(&host),
            http(),
            Network::Floonet,
            SharedRng::new(FixedRng),
        )
        .with_epic1(Arc::new(OneAddress(key.clone())));
        let sealed = |network| {
            seal_tx(
                contact_network(network),
                &key.public_key(),
                TxKey::Epic1,
                &TxContent::new(b"slate".to_vec()),
                None,
                &mut FixedRng,
            )
            .unwrap()
        };
        assert_eq!(handler.check(&sealed(Network::Floonet)), Ok(()));
        for envelope in [
            sealed(Network::Mainnet),
            b"not an envelope".to_vec(),
            Vec::new(),
        ] {
            assert_eq!(
                handler.check(&envelope),
                Err(PeerRefusal::UnsupportedFormat)
            );
        }
        assert_eq!(host.receives.load(Ordering::Relaxed), 0);
        assert_eq!(host.refusals.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_invoice_is_refused_before_the_wallet_sees_it() {
        let body = native_body(
            Network::Floonet,
            &vector_v3("invoice_file_plain_i1_floonet"),
        )
        .unwrap();
        assert!(
            decode_native(Network::Floonet, &body).is_some_and(|slate| slate.stage() == Stage::I1)
        );
        let (answer, host) = answer(body);
        assert!(matches!(answer, Err(PeerRefusal::Refused)));
        assert_eq!(host.receives.load(Ordering::Relaxed), 0);
        assert_eq!(host.refusals.load(Ordering::Relaxed), 1);
    }

    /// The epic1 seal key of one account, `key`.
    struct OneAddress(EncSecretKey);

    impl Epic1Keys for OneAddress {
        fn epic1_keys(&self) -> BoxFuture<'_, Vec<Epic1AccountKeys>> {
            let keys = vec![Epic1AccountKeys {
                account: AccountIndex(0),
                label: "default".to_owned(),
                key: self.0.clone(),
            }];
            Box::pin(async move { keys })
        }
    }

    /// The answer of a listener with `epic1` keys, or none, to an S1 sealed to `recipient` as
    /// `kind`, and how many slates reached its host.
    fn answer_sealed(
        epic1: Option<EncSecretKey>,
        recipient: &EncSecretKey,
        kind: TxKey<'_>,
    ) -> (Result<Vec<u8>, PeerRefusal>, u32) {
        let host = Arc::new(Counting::default());
        let mut handler = DirectHandler::new(
            Arc::clone(&host),
            http(),
            Network::Floonet,
            SharedRng::new(FixedRng),
        );
        if let Some(key) = epic1 {
            handler = handler.with_epic1(Arc::new(OneAddress(key)));
        }
        let body = native_body(Network::Floonet, &vector_v3("send_file_plain_s1_floonet")).unwrap();
        let content = TxContent {
            reply_key: Some(EncSecretKey::from_bytes([5; 32]).public_key()),
            ..TxContent::new(body)
        };
        let envelope = seal_tx(
            contact_network(Network::Floonet),
            &recipient.public_key(),
            kind,
            &content,
            None,
            &mut FixedRng,
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let answer = runtime.block_on(handler.receive(envelope));
        (answer, host.receives.load(Ordering::Relaxed))
    }

    #[test]
    fn a_listener_without_epic1_keys_answers_an_epic1_payment_as_one_it_cannot_open() {
        let epic1 = EncSecretKey::from_bytes([9; 32]);
        let other = EncSecretKey::from_bytes([11; 32]);
        let (to_epic1, reached) = answer_sealed(None, &epic1, TxKey::Epic1);
        assert!(matches!(to_epic1, Err(PeerRefusal::Refused)));
        assert_eq!(reached, 0);
        let (to_nobody, reached) = answer_sealed(None, &other, TxKey::Listener);
        assert!(matches!(to_nobody, Err(PeerRefusal::Refused)));
        assert_eq!(reached, 0);
        // With the keys, the same payment reaches the wallet; an envelope sealed to a
        // listener's key does not.
        let (_, reached) = answer_sealed(Some(epic1.clone()), &epic1, TxKey::Epic1);
        assert_eq!(reached, 1);
        let (to_listener, reached) = answer_sealed(Some(epic1.clone()), &epic1, TxKey::Listener);
        assert!(matches!(to_listener, Err(PeerRefusal::Refused)));
        assert_eq!(reached, 0);
    }

    #[test]
    fn a_proposal_reaches_the_wallet() {
        let body = native_body(Network::Floonet, &vector_v3("send_file_plain_s1_floonet")).unwrap();
        let (answer, host) = answer(body);
        // The counting host takes nothing; the refusal is its own.
        assert!(matches!(answer, Err(PeerRefusal::Refused)));
        assert_eq!(host.receives.load(Ordering::Relaxed), 1);
    }
}
