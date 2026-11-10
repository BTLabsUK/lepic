// SPDX-License-Identifier: Apache-2.0
//! Native slates to a listener's endpoint (ADR 0052, EPICTX 5.15 and 6.2): the send that picks
//! the dialect of an HTTP or Tor address, and the handler a listener's `/v1/peer/slates` route
//! answers with.
//!
//! A send goes native only when the host sets
//! [`lepic_wallet::config::WalletConfig::native_direct`], the caller did not ask for the legacy
//! dialect, and the listener's `check_version` answer advertises an endpoint. The advertised key
//! must be the one pinned for the sending account and the listener's origin; the first native
//! exchange that succeeds pins it. Once an origin is pinned, a send to it that cannot go native
//! stops with an error: it never falls back to the legacy dialect by itself.
//!
//! The S1 goes out as `lepic.v1` in an anonymous type `0A` envelope sealed to the advertised
//! key, carrying the slate's reply key; the listener seals its S2 to that reply key. The
//! transaction is stored as for a legacy send, so a native exchange that fails leaves it for
//! a resend or a cancel.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lepic_contact::{
    EncPublicKey, EncSecretKey, Hint, HintRule, KeyClass, SealedEnvelope, TxContent, TxKey,
    TxOpened, seal_tx,
};
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_methods::http::{
    Advert, DirectPeer, Host, OriginError, PeerClientError, Probe, ProbeError, Refusal,
};
use lepic_node::NodeApi;
use lepic_peer::{HandlerFuture, PeerRefusal, SlateHandler};
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::error::DecodeError as SlateDecodeError;
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, PIN_KEY_LEN, TxId, WalletStore};
use lepic_transport::codecs::legacy as legacy_codecs;
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::method::{Carries, EncodeContext, Encoded, Method, SenderFacts, Sending};
use lepic_transport::policy::{Encoding, FormatPolicy, encode_with};
use lepic_transport::transport::{
    BoxFuture, Destination, Exchange, Inbound, Outbound, Transport, TransportId,
};
use lepic_wallet::epic1_index::trial_open;
use lepic_wallet::ports::{SecretVault, SharedRng, StoreOpener};
use lepic_wallet::send::{Delivery, SendError, SendRequest, SentSlate};
use lepic_wallet::{
    Epic1AccountKeys, PinOutcome, ProofKey, ReceiveRequest, SlateFormat, WalletError,
};
use thiserror::Error;
use tracing::{info, instrument, warn};

use super::keys::contact_network;
use super::native::{decode_native, native_body, v3_of_native};
use super::{ContactError, LockedRng};
use crate::ContactBook;

/// How a slate went to a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// `lepic.v1` in an envelope through the listener's `/v1/peer/slates`.
    Native,
    /// A V2 or V3 JSON slate through the foreign API, as every wallet speaks it.
    Legacy,
}

impl Dialect {
    /// The name a report gives the dialect: `native` or `legacy`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Legacy => "legacy",
        }
    }
}

/// A send or resend to a listener that went out.
#[derive(Debug, Clone)]
pub struct DirectSent<T> {
    /// What the engine's send returned.
    pub sent: T,
    pub dialect: Dialect,
    /// The S2 a native exchange brought back, as V3 JSON ready for
    /// [`lepic_wallet::Wallet::finalize`]. `None` for the legacy dialect, whose answer stays
    /// with the method.
    pub reply: Option<WireSlate>,
}

/// Why a send to a listener did not go out, or did not come back.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DirectError {
    #[error(transparent)]
    Wallet(#[from] WalletError),
    /// The legacy send, or the storing of the native one, failed as [`SendError`] says.
    #[error(transparent)]
    Send(SendError),
    /// The listener of a pinned origin could not be asked for its endpoint. Nothing was stored.
    #[error("the endpoint of {origin} could not be read")]
    Probe {
        origin: String,
        #[source]
        source: ProbeError,
    },
    /// The origin is pinned and its listener advertises no endpoint. Nothing was stored; a send
    /// in the legacy dialect has to be asked for.
    #[error("{origin} is pinned but advertises no native endpoint")]
    PinnedNoAdvert { origin: String },
    /// The origin advertises another key than the pinned one. Nothing was stored; forgetting
    /// the pin takes the new key at the next exchange.
    #[error("{origin} shows another key than the pinned one")]
    PinChanged {
        origin: String,
        pinned: [u8; PIN_KEY_LEN],
        shown: [u8; PIN_KEY_LEN],
    },
    /// The listener is on this device and a native send never posts there. Nothing was
    /// stored; a send in the legacy dialect has to be asked for.
    #[error("{origin} is on this device, which a native send does not reach")]
    ThisDevice { origin: String },
    /// The transaction was stored and the native exchange failed. It waits for a resend or a
    /// cancel; nothing went through the legacy dialect.
    #[error("transaction {tx_id} is stored and its native exchange failed")]
    Native {
        tx_id: TxId,
        slate_id: SlateId,
        #[source]
        source: NativeFailure,
    },
}

/// What failed in a native exchange.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NativeFailure {
    /// The endpoint refused, could not be reached, or answered with something other than an
    /// envelope.
    #[error(transparent)]
    Post(#[from] PeerClientError),
    /// The advertised path or address is not one an envelope can be posted to.
    #[error("the endpoint cannot be reached at its address")]
    Target(#[source] OriginError),
    /// The advertised key is not a key an envelope can be sealed to.
    #[error("the advertised key cannot be sealed to")]
    Key,
    /// The slate could not be put in an envelope.
    #[error("the slate could not be sealed")]
    Seal(#[source] ContactError),
    /// The reply did not open with the slate's reply key, or holds no answer to the slate.
    #[error("the reply is not an answer to this slate")]
    Reply,
}

/// The dialect a send to a listener takes.
enum Route {
    Legacy,
    Native(Box<(Probe, Advert)>),
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Sends `request` to the listener at `to` over `method`, the HTTP or Tor method `peer`
    /// reaches the listener's native endpoint for. `legacy` asks for the legacy dialect whatever
    /// the listener advertises; the send is then [`lepic_wallet::Wallet::send`] as before.
    ///
    /// Fails, with nothing stored, with [`DirectError::PinnedNoAdvert`],
    /// [`DirectError::PinChanged`] or [`DirectError::Probe`] for a pinned origin,
    /// [`DirectError::ThisDevice`] for a native endpoint on this device, and with
    /// [`DirectError::Send`] as the engine's send fails. A native exchange that fails after the
    /// transaction was stored is [`DirectError::Native`].
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name, transport = %method.id()))]
    pub async fn direct_send(
        &self,
        peer: &dyn DirectPeer,
        method: &Arc<dyn Method>,
        request: SendRequest,
        to: Destination,
        legacy: bool,
    ) -> Result<DirectSent<SentSlate>, DirectError> {
        let account = request.account;
        let delivery = Delivery::Deliver { to: to.clone() };
        let (probe, advert) = match self.route(peer, account, &to, legacy).await? {
            Route::Legacy => {
                let sent = self
                    .wallet
                    .send(method, request, delivery)
                    .await
                    .map_err(DirectError::Send)?;
                return Ok(legacy_sent(sent));
            }
            Route::Native(native) => *native,
        };
        let capture = Arc::new(Capture::new(Arc::clone(method)));
        let carrier: Arc<dyn Method> = capture.clone();
        let sent = self
            .wallet
            .send(&carrier, request, delivery)
            .await
            .map_err(DirectError::Send)?;
        let reply = self
            .native_exchange(
                peer,
                account,
                &probe,
                &advert,
                capture.take(),
                sent.slate_id,
            )
            .await
            .map_err(|source| DirectError::Native {
                tx_id: sent.tx_id,
                slate_id: sent.slate_id,
                source,
            })?;
        Ok(DirectSent {
            sent,
            dialect: Dialect::Native,
            reply: Some(reply),
        })
    }

    /// Sends the stored S1 of `tx_id` again to the listener at `to`, choosing the dialect as
    /// [`Self::direct_send`] does for the transaction's account. Fails as
    /// [`lepic_wallet::Wallet::resend`] and [`Self::direct_send`] do.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name, transport = %method.id(), tx_id = %tx_id))]
    pub async fn direct_resend(
        &self,
        peer: &dyn DirectPeer,
        method: &Arc<dyn Method>,
        tx_id: TxId,
        to: Destination,
        legacy: bool,
    ) -> Result<DirectSent<SlateFormat>, DirectError> {
        let session = self.wallet.session()?;
        let entry = session
            .store
            .read(|repos| repos.transaction(tx_id))
            .map_err(WalletError::from)?
            .ok_or(WalletError::UnknownTransaction(tx_id))?;
        let delivery = Delivery::Deliver { to: to.clone() };
        let (probe, advert) = match self.route(peer, entry.account, &to, legacy).await? {
            Route::Legacy => {
                let format = self
                    .wallet
                    .resend(method, tx_id, delivery)
                    .await
                    .map_err(DirectError::Send)?;
                return Ok(legacy_sent(format));
            }
            Route::Native(native) => *native,
        };
        let capture = Arc::new(Capture::new(Arc::clone(method)));
        let carrier: Arc<dyn Method> = capture.clone();
        let format = self
            .wallet
            .resend(&carrier, tx_id, delivery)
            .await
            .map_err(DirectError::Send)?;
        let wire = capture.take();
        // A resend delivers the S1 of a send in state `sent`, which always has a slate id.
        let slate_id = entry
            .slate_id
            .map(|id| SlateId::from_bytes(*id.as_bytes()))
            .ok_or(WalletError::UnknownTransaction(tx_id))?;
        let reply = self
            .native_exchange(peer, entry.account, &probe, &advert, wire, slate_id)
            .await
            .map_err(|source| DirectError::Native {
                tx_id,
                slate_id,
                source,
            })?;
        Ok(DirectSent {
            sent: format,
            dialect: Dialect::Native,
            reply: Some(reply),
        })
    }

    /// The dialect of a send from `account` to `to`, under the rules of the module.
    async fn route(
        &self,
        peer: &dyn DirectPeer,
        account: AccountIndex,
        to: &Destination,
        legacy: bool,
    ) -> Result<Route, DirectError> {
        if legacy || !self.wallet.config().native_direct {
            return Ok(Route::Legacy);
        }
        // An address with no origin names no listener a pin is kept for; the legacy send
        // reports it as it always did.
        let Ok(origin) = peer.origin(to) else {
            return Ok(Route::Legacy);
        };
        let origin = origin.to_string();
        let pinned = self.wallet.peer_pin(account, &origin)?;
        let probe = match peer.probe(to).await {
            Ok(probe) => probe,
            Err(source) if pinned.is_some() => return Err(DirectError::Probe { origin, source }),
            // Without a pin the send goes on as a legacy send, which meets the same failure
            // and reports it as it always did.
            Err(_) => return Ok(Route::Legacy),
        };
        match (probe.advert().cloned(), pinned) {
            (None, None) => Ok(Route::Legacy),
            (None, Some(_)) => Err(DirectError::PinnedNoAdvert { origin }),
            (Some(advert), Some(pin)) if pin.seal_key != advert.seal => {
                Err(DirectError::PinChanged {
                    origin,
                    pinned: pin.seal_key,
                    shown: advert.seal,
                })
            }
            // The probe may reach a listener on this device; the post never does, and it is
            // known now, before the send stores anything.
            (Some(_), _) if peer.reaches_this_device(probe.origin()) => {
                Err(DirectError::ThisDevice { origin })
            }
            (Some(advert), _) => Ok(Route::Native(Box::new((probe, advert)))),
        }
    }

    /// Seals the stored S1 `wire` to the advertised key, posts it, and opens the S2 the
    /// endpoint answers with, completed from the stored S1. Pins the key once the answer is in.
    async fn native_exchange(
        &self,
        peer: &dyn DirectPeer,
        account: AccountIndex,
        probe: &Probe,
        advert: &Advert,
        wire: Option<WireSlate>,
        slate_id: SlateId,
    ) -> Result<WireSlate, NativeFailure> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let wire = wire.ok_or(NativeFailure::Reply)?;
        let body = native_body(network, wire.as_bytes()).map_err(NativeFailure::Seal)?;
        let reply_key = self
            .reply_secret(account, slate_id)
            .map_err(NativeFailure::Seal)?;
        let recipient = EncPublicKey::from_bytes(advert.seal).map_err(|_| NativeFailure::Key)?;
        let content = TxContent {
            reply_key: Some(reply_key.public_key()),
            ..TxContent::new(body)
        };
        let envelope = seal_tx(
            net,
            &recipient,
            TxKey::Listener,
            &content,
            None,
            &mut LockedRng(&mut **self.wallet.ports().rng.lock()),
        )
        .map_err(|source| NativeFailure::Seal(ContactError::Encode(source)))?;
        let target = probe.target(advert).map_err(NativeFailure::Target)?;
        let answer = peer.post(&target, &envelope).await?;
        let opened = SealedEnvelope::decode(&answer, net)
            .and_then(|sealed| sealed.open_tx(&reply_key, KeyClass::Seal))
            .map_err(|_| NativeFailure::Reply)?;
        let answers_this = decode_native(network, &opened.content.body)
            .is_some_and(|slate| slate.stage() == Stage::S2 && slate.id() == slate_id);
        if !answers_this {
            return Err(NativeFailure::Reply);
        }
        let v3 = self
            .v3_of_native(&opened.content.body)
            .await
            .map_err(NativeFailure::Seal)?
            .ok_or(NativeFailure::Reply)?;
        let reply = String::from_utf8(v3).map_err(|_| NativeFailure::Reply)?;
        let origin = probe.origin().to_string();
        match self.wallet.pin_peer(account, &origin, advert.seal) {
            Ok(PinOutcome::Pinned) => info!(origin = %origin, "native endpoint pinned"),
            Ok(PinOutcome::Seen) => {}
            // Checked before the post; another key now is a pin made by a concurrent send.
            Ok(PinOutcome::Changed { .. }) => {
                warn!(origin = %origin, "native endpoint pinned to another key meanwhile");
            }
            Err(error) => warn!(origin = %origin, error = %error, "native endpoint not pinned"),
        }
        Ok(WireSlate::text(MediaType::JSON, reply))
    }

    /// The one-time reply key of the slate `slate_id` this wallet starts in `account`.
    fn reply_secret(
        &self,
        account: AccountIndex,
        slate_id: SlateId,
    ) -> Result<EncSecretKey, ContactError> {
        let session = self.wallet.session()?;
        let root = crate::key_schedule::contact_root(
            &session.keychain,
            &lepic_wallet::account::parent_key_id(account)?,
            self.wallet.config().network,
        )
        .map_err(ContactError::Keys)?;
        let reply = root
            .reply_key(*slate_id.as_bytes())
            .map_err(ContactError::Keys)?;
        Ok(EncSecretKey::from_bytes(*reply.expose_x25519_secret()))
    }
}

fn legacy_sent<T>(sent: T) -> DirectSent<T> {
    DirectSent {
        sent,
        dialect: Dialect::Legacy,
        reply: None,
    }
}

/// A method that keeps the wire slate it is given instead of delivering it, so the engine
/// stores a send as it would for `inner` and the slate leaves natively. Everything but the
/// format of the S1 is `inner`'s.
struct Capture {
    inner: Arc<dyn Method>,
    wire: Mutex<Option<WireSlate>>,
}

impl Capture {
    fn new(inner: Arc<dyn Method>) -> Self {
        Self {
            inner,
            wire: Mutex::new(None),
        }
    }

    fn take(&self) -> Option<WireSlate> {
        self.wire
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl Outbound for Capture {
    fn deliver<'a>(
        &'a self,
        _to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        *self.wire.lock().unwrap_or_else(PoisonError::into_inner) = Some(wire.clone());
        Box::pin(async { Ok(()) })
    }
}

impl Transport for Capture {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    fn policy(&self) -> &dyn FormatPolicy {
        self.inner.policy()
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }

    fn inbound(&self) -> Option<&dyn Inbound> {
        self.inner.inbound()
    }

    fn exchange(&self) -> Option<&dyn Exchange> {
        self.inner.exchange()
    }
}

impl Method for Capture {
    fn carries(&self) -> Carries {
        self.inner.carries()
    }

    fn decode(&self, network: Network, wire: &WireSlate) -> Result<Slate, SlateDecodeError> {
        self.inner.decode(network, wire)
    }

    fn sender_facts(&self, wire: &WireSlate) -> SenderFacts {
        self.inner.sender_facts(wire)
    }

    /// The S1 is kept as V3 JSON, which holds everything `lepic.v1` carries, payment proofs
    /// included, whatever `inner` writes for the legacy dialect.
    fn encode_new(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
    ) -> Result<Encoded, FormatError> {
        let codecs = legacy_codecs(sending.network.params().default_base_fee());
        let encoding = Encoding {
            codec: LEGACY_V3_JSON,
            legacy_header: None,
        };
        Ok(Encoded {
            wire: encode_with(&codecs, encoding, slate, context)?,
            codec: LEGACY_V3_JSON,
        })
    }

    fn encode_reply(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
        from: &SenderFacts,
    ) -> Result<Encoded, FormatError> {
        self.inner.encode_reply(slate, context, sending, from)
    }

    fn notice_lengths(&self) -> &'static [usize] {
        self.inner.notice_lengths()
    }

    fn peer_key(&self, network: Network, address: &str) -> Result<String, TransportError> {
        self.inner.peer_key(network, address)
    }

    fn same_payee(&self, network: Network, to: &Destination, allowed: &str) -> bool {
        self.inner.same_payee(network, to, allowed)
    }

    fn delivery_is_permanent(&self, error: &TransportError) -> bool {
        self.inner.delivery_is_permanent(error)
    }
}

/// The seal keys of a wallet's epic1 addresses, for a listener that takes payments sealed to
/// them ([`DirectHandler::with_epic1`]).
pub trait Epic1Keys: Send + Sync {
    /// [`lepic_wallet::Wallet::epic1_trial_keys_all`]; none when the wallet cannot give them.
    fn epic1_keys(&self) -> BoxFuture<'_, Vec<Epic1AccountKeys>>;
}

/// The handler of a listener socket's `/v1/peer/slates`: opens an envelope with the socket's
/// seal key, receives the S1 in it through `host` as the foreign API does, and seals the S2 to
/// the reply key the envelope carries.
///
/// With [`DirectHandler::with_epic1`], an envelope with a zero hint that the socket's key does
/// not open is tried with the seal keys of the wallet's epic1 addresses. One that opens is
/// received into the address's account and signed with the address's proof key.
pub struct DirectHandler<H: Host> {
    host: Arc<H>,
    method: Arc<dyn Method>,
    proof_key: ProofKey,
    key: EncSecretKey,
    network: Network,
    rng: SharedRng,
    epic1: Option<Arc<dyn Epic1Keys>>,
}

/// `envelope` tried with the epic1 seal keys of `accounts`, each account in its own trial order,
/// on the blocking pool: an account can have many addresses, and each key tried is an X25519
/// operation. Returns the account, its label and the address index of the first key that opens.
pub(crate) async fn trial_open_accounts(
    envelope: Vec<u8>,
    network: lepic_contact::Network,
    accounts: Vec<Epic1AccountKeys>,
) -> Option<(AccountIndex, String, u32, TxOpened)> {
    tokio::task::spawn_blocking(move || {
        let sealed = SealedEnvelope::decode(&envelope, network).ok()?;
        accounts.into_iter().find_map(|account| {
            trial_open(&account.keys, |key| {
                sealed.open_tx(key, KeyClass::Epic1).ok()
            })
            .map(|(index, opened)| (account.account, account.label, index, opened))
        })
    })
    .await
    .ok()
    .flatten()
}

/// The S1 of an envelope a listener took, the key its answer is sealed to, and the epic1
/// address it was sealed to, if any.
struct Proposal {
    wire: WireSlate,
    reply_key: EncPublicKey,
    /// The account label and address index.
    epic1: Option<(String, u32)>,
}

impl<H: Host> DirectHandler<H> {
    /// A handler for the socket whose seal key is `key` ([`lepic_wallet::Wallet::
    /// listener_seal_key`]), receiving over `method` and signing payment proofs with
    /// `proof_key`, as the socket's foreign API does. `rng` draws the reply envelopes' keys.
    pub fn new(
        host: Arc<H>,
        method: Arc<dyn Method>,
        proof_key: ProofKey,
        key: EncSecretKey,
        network: Network,
        rng: SharedRng,
    ) -> Self {
        Self {
            host,
            method,
            proof_key,
            key,
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

    /// `envelope` opened with the socket's key or, for a zero hint, with the seal key of an
    /// epic1 address, with the account label and index of the address.
    async fn open(
        &self,
        envelope: &[u8],
    ) -> Result<(TxOpened, Option<(String, u32)>), PeerRefusal> {
        let sealed = SealedEnvelope::decode(envelope, contact_network(self.network))
            .map_err(|_| PeerRefusal::UnsupportedFormat)?;
        if let Ok(opened) = sealed.open_tx(&self.key, KeyClass::Listener) {
            return Ok((opened, None));
        }
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
        let (account, label, index, opened) = found;
        // A payment to an epic1 is anonymous.
        if opened.sender.is_some() {
            return Err(PeerRefusal::Refused);
        }
        info!(
            account = account.0,
            index, "payment opened at an epic1 address"
        );
        Ok((opened, Some((label, index))))
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
            let request = match epic1 {
                Some((label, index)) => ReceiveRequest {
                    account: Some(label),
                    proof_key: ProofKey::Epic1 { index },
                    ..ReceiveRequest::default()
                },
                None => ReceiveRequest {
                    proof_key: self.proof_key,
                    ..ReceiveRequest::default()
                },
            };
            let received = match self.host.receive(&self.method, &wire, request).await {
                Ok(received) => received,
                Err(refusal) => {
                    self.host.refused(refusal);
                    return Err(match refusal {
                        Refusal::Unavailable => PeerRefusal::NotReady {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use lepic_methods::http::{ClientSettings, Http, RpcClient, webpki_tls_config};
    use lepic_wallet::Received;
    use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};

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

    /// The handler's answer to `body` sealed to its key with a reply key, and its host.
    fn answer(body: Vec<u8>) -> (Result<Vec<u8>, PeerRefusal>, Arc<Counting>) {
        let key = EncSecretKey::from_bytes([3; 32]);
        let host = Arc::new(Counting::default());
        let handler = DirectHandler::new(
            Arc::clone(&host),
            http(),
            ProofKey::Payments,
            key.clone(),
            Network::Floonet,
            SharedRng::new(FixedRng),
        );
        let content = TxContent {
            reply_key: Some(EncSecretKey::from_bytes([5; 32]).public_key()),
            ..TxContent::new(body)
        };
        let envelope = seal_tx(
            contact_network(Network::Floonet),
            &key.public_key(),
            TxKey::Listener,
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

    #[test]
    fn a_proposal_reaches_the_wallet() {
        let body = native_body(Network::Floonet, &vector_v3("send_file_plain_s1_floonet")).unwrap();
        let (answer, host) = answer(body);
        // The counting host takes nothing; the refusal is its own.
        assert!(matches!(answer, Err(PeerRefusal::Refused)));
        assert_eq!(host.receives.load(Ordering::Relaxed), 1);
    }
}
