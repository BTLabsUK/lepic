// SPDX-License-Identifier: Apache-2.0
//! Native slates over Epicbox (RFC 0003 11.1): what the payments address claims in its marker,
//! and the seal key its native slates open with.
//!
//! With [`crate::WalletConfig::native_direct`] on, every marked slate this wallet sends over
//! Epicbox claims [`NATIVE_SLATES`] and carries, in the marker's `reply`, the public key of the
//! payments address's seal key of kind 03 ([`SealKeyKind::Epicbox`]). That key is not the
//! epic1's (kind 00), so the payments address and the epic1 address are not linkable. With it
//! off, the marker claims no native slates and carries no seal key.

use jiff::Timestamp;
use lepic_contact::{
    EncPublicKey, EncSecretKey, Hint, KeyClass, SealedEnvelope, TxContent, TxKey, armor_tx,
    dearmor, seal_tx,
};
use lepic_keychain::{Keychain, Seed};
use lepic_legacy_slate::marker::v3::MarkedV3JsonCodec;
use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::stage::Stage;
use lepic_store::{Repositories, SlateStage, StoreError, StoredSlate, TxDirection, TxState};
use lepic_transport::marker::features::NATIVE_SLATES;
use lepic_transport::method::{Method, Sending};
use lepic_transport::transport::{Destination, Envelope};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

use crate::config::WalletConfig;
use crate::error::WalletError;
use crate::extension::{NativeSlates, ReplyKeys};
use crate::namespace::{self, SealKeyKind};
use crate::peer_compat;
use crate::ports::SharedRng;

/// The account whose address is the payments address.
const PAYMENTS_ACCOUNT: u32 = 0;

/// What the marker of a slate this wallet sends over Epicbox claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Claim {
    /// The feature bits of the marker's `f`.
    pub(crate) features: u32,
    /// The public seal key of the marker's `reply`, when the wallet takes native slates there.
    pub(crate) seal_key: Option<[u8; 32]>,
}

impl Claim {
    /// A claim of `features` alone, the marker of a wallet that takes no native slates over
    /// Epicbox.
    pub(crate) const fn plain(features: u32) -> Self {
        Self {
            features,
            seal_key: None,
        }
    }

    /// The claim of the wallet of `seed` under `config`. A seal key that does not derive is
    /// logged and the wallet claims no native slates.
    pub(crate) fn of(config: &WalletConfig, seed: &Seed) -> Self {
        let features = config.claimed_features();
        if !config.native_direct {
            return Self::plain(features);
        }
        match payments_seal_key(seed, config.network) {
            Ok(secret) => Self {
                features: features | NATIVE_SLATES,
                seal_key: Some(*secret.public_key().as_bytes()),
            },
            Err(error) => {
                warn!(%error, "no epicbox seal key, claiming no native slates");
                Self::plain(features)
            }
        }
    }

    /// What a method encoding a slate on `network` needs, with this claim.
    pub(crate) fn sending(&self, network: Network, reply_key: Option<[u8; 32]>) -> Sending {
        let sending = Sending::new(network, self.features, reply_key);
        match self.seal_key {
            Some(key) => sending.with_seal_key(key),
            None => sending,
        }
    }
}

/// The seal key of kind 03 of the payments address on `network`: native slates sent to it over
/// Epicbox open with it.
pub(crate) fn payments_seal_key(
    seed: &Seed,
    network: Network,
) -> Result<EncSecretKey, WalletError> {
    namespace::seal_key(
        seed,
        PAYMENTS_ACCOUNT,
        contact_network(network),
        SealKeyKind::Epicbox,
    )
}

/// The network of the seal layer for `network`.
pub(crate) const fn contact_network(network: Network) -> lepic_contact::Network {
    match network {
        Network::Mainnet => lepic_contact::Network::Mainnet,
        Network::Floonet => lepic_contact::Network::Floonet,
    }
}

/// The key a marker's `reply` names when its `f` claims [`NATIVE_SLATES`], if it is a valid
/// X25519 public key.
pub(crate) fn claimed_key(features: Option<u32>, reply: Option<[u8; 32]>) -> Option<[u8; 32]> {
    let features = features?;
    if features & NATIVE_SLATES == 0 {
        return None;
    }
    let key = reply?;
    EncPublicKey::from_bytes(key).ok().map(|_| key)
}

/// How a slate went out over a method or to a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlateFormat {
    /// As the method's legacy JSON: V2 or V3, marked or not; to a contact, sealed V3.
    #[default]
    Legacy,
    /// As a `lepic.v1` slate in a type `0A` envelope, armored `BEGINEPICTX.`: anonymous over
    /// Epicbox, signed to a contact.
    Native,
}

impl SlateFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Native => "native",
        }
    }
}

/// What sealing a native slate over Epicbox takes besides the slate.
pub(crate) struct Sealing<'a> {
    pub(crate) network: Network,
    pub(crate) slates: &'a dyn NativeSlates,
    pub(crate) rng: &'a SharedRng,
}

impl Sealing<'_> {
    /// `v3`, a slate as V3 JSON, as a native slate sealed to `recipient` under `key`, armored
    /// `BEGINEPICTX.`, with `reply_key` as its tag 03. `None`, logged, when the slate has no
    /// native body or the envelope cannot carry it.
    pub(crate) fn seal(
        &self,
        v3: &[u8],
        recipient: &EncPublicKey,
        key: TxKey<'_>,
        reply_key: Option<EncPublicKey>,
        features: u32,
    ) -> Option<WireSlate> {
        let Some(body) = self.slates.body(self.network, v3) else {
            warn!("slate has no native body, sent as legacy json");
            return None;
        };
        let mut content = TxContent::new(body);
        content.reply_key = reply_key;
        content.features = Some(features);
        // The store is taken before the generator, as everywhere.
        let sealed = seal_tx(
            contact_network(self.network),
            recipient,
            key,
            &content,
            None,
            &mut *self.rng.lock(),
        );
        match sealed {
            Ok(envelope) => Some(WireSlate::text(MediaType::JSON, armor_tx(&envelope))),
            Err(error) => {
                warn!(%error, "native slate not sealed, sent as legacy json");
                None
            }
        }
    }
}

/// The S1 `slate` for `to` as a native slate, when the wallet sends one there: `native_direct`
/// is on, the payments address claims native slates, the slate carries a reply key for its
/// answer, and `to`'s key is LEPIC lately with a claim of a valid key (RFC 0003 11.1). `None`
/// otherwise, and the S1 goes as legacy JSON.
#[allow(clippy::too_many_arguments)]
pub(crate) fn native_s1(
    repos: &dyn Repositories,
    method: &dyn Method,
    sealing: &Sealing<'_>,
    claim: &Claim,
    native_direct: bool,
    now: Timestamp,
    to: &Destination,
    slate: &Slate,
    context: &EncodeContext,
    reply_key: Option<[u8; 32]>,
) -> Result<Option<WireSlate>, StoreError> {
    if !native_direct || slate.stage() != Stage::S1 || claim.seal_key.is_none() {
        return Ok(None);
    }
    let Some(reply_key) = reply_key.and_then(|key| EncPublicKey::from_bytes(key).ok()) else {
        return Ok(None);
    };
    let Ok(peer) = method.peer_key(sealing.network, to.as_str()) else {
        return Ok(None);
    };
    let facts = peer_compat::facts(repos, &peer, now)?;
    let Some(recipient) = peer_compat::native_key(&facts, native_direct)
        .and_then(|key| EncPublicKey::from_bytes(key).ok())
    else {
        return Ok(None);
    };
    let base_fee = sealing.network.params().default_base_fee();
    let Ok(v3) = V3JsonCodec::new(base_fee).encode(slate, context) else {
        return Ok(None);
    };
    Ok(sealing.seal(
        v3.as_bytes(),
        &recipient,
        TxKey::Epicbox,
        Some(reply_key),
        claim.features,
    ))
}

/// Whether `wire` is a native slate as it comes over Epicbox.
pub(crate) fn is_native(wire: &WireSlate) -> bool {
    wire.as_text()
        .is_some_and(|text| text.trim_start().starts_with(TX_ARMOR))
}

/// The armor header of a native slate.
const TX_ARMOR: &str = "BEGINEPICTX.";

/// Why a native slate that came over Epicbox is refused, with nothing stored (RFC 0003 6.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NativeRefusal {
    #[error("native slate armor or envelope is malformed")]
    Malformed,
    #[error("native slate does not open")]
    CannotOpen,
    #[error("native slate holds no slate this address takes")]
    NotASlate,
    #[error("native invoice refused at the payments address")]
    Invoice,
    #[error("native slate gives no key for its answer")]
    NoReplyKey,
    #[error("native slates are not read by this build")]
    NotInstalled,
}

/// A native slate that came over Epicbox, opened.
pub(crate) struct Arrived {
    /// The envelope with the slate as marked V3 JSON, as the engine receives and finalizes it.
    pub(crate) envelope: Envelope,
    /// The key the answer to an S1 is sealed to, its tag 03.
    pub(crate) reply_key: Option<EncPublicKey>,
}

/// What opening a native slate takes.
pub(crate) struct Opening<'a> {
    pub(crate) network: Network,
    pub(crate) seed: &'a Seed,
    pub(crate) keychain: &'a Keychain,
    pub(crate) slates: &'a dyn NativeSlates,
    pub(crate) reply_keys: Option<&'a dyn ReplyKeys>,
}

impl Opening<'_> {
    /// Opens the native slate of `envelope`: an S1 sealed to the payments address's seal key of
    /// kind 03, or the S2 answering a send of this wallet, sealed to that send's reply key and
    /// completed from its stored S1. Anything else is refused; only a store failure is an
    /// error.
    pub(crate) fn open(
        &self,
        repos: &dyn Repositories,
        envelope: &Envelope,
    ) -> Result<Result<Arrived, NativeRefusal>, StoreError> {
        let Some(text) = envelope.wire().as_text() else {
            return Ok(Err(NativeRefusal::Malformed));
        };
        let bytes = match dearmor(text) {
            Ok(bytes) if text.trim_start().starts_with(TX_ARMOR) => bytes,
            _ => return Ok(Err(NativeRefusal::Malformed)),
        };
        let Ok(sealed) = SealedEnvelope::decode(&bytes, contact_network(self.network)) else {
            return Ok(Err(NativeRefusal::Malformed));
        };
        let (opened, request) = if *sealed.hint().as_bytes() == [0; 8] {
            let Ok(key) = payments_seal_key(self.seed, self.network) else {
                return Ok(Err(NativeRefusal::CannotOpen));
            };
            (sealed.open_tx(&key, KeyClass::Epicbox), None)
        } else {
            let Some((key, request)) = self.reply_opening(repos, &sealed)? else {
                return Ok(Err(NativeRefusal::CannotOpen));
            };
            (sealed.open_tx(&key, KeyClass::Seal), Some(request))
        };
        let Ok(opened) = opened else {
            return Ok(Err(NativeRefusal::CannotOpen));
        };
        Ok(self.arrived(envelope, &opened.content, request.as_ref()))
    }

    /// The opened `content` as the engine takes it: an S1 with a reply key, or the S2 of
    /// `request`.
    fn arrived(
        &self,
        envelope: &Envelope,
        content: &TxContent,
        request: Option<&StoredSlate>,
    ) -> Result<Arrived, NativeRefusal> {
        let v3 = self
            .slates
            .v3(
                self.network,
                &content.body,
                request.map(|request| request.bytes.as_slice()),
            )
            .ok_or(NativeRefusal::NotASlate)?;
        let base_fee = self.network.params().default_base_fee();
        let slate = V3JsonCodec::new(base_fee)
            .decode(&WireSlate::binary(MediaType::JSON, v3))
            .map_err(|_| NativeRefusal::NotASlate)?;
        let expected = if request.is_some() {
            Stage::S2
        } else {
            Stage::S1
        };
        if slate.stage() == Stage::I1 {
            return Err(NativeRefusal::Invoice);
        }
        let same_slate = request
            .is_none_or(|request| Uuid::from_bytes(*slate.id().as_bytes()) == request.slate_id);
        if slate.stage() != expected || !same_slate {
            return Err(NativeRefusal::NotASlate);
        }
        if expected == Stage::S1 && content.reply_key.is_none() {
            return Err(NativeRefusal::NoReplyKey);
        }
        let codec = MarkedV3JsonCodec::new(V3JsonCodec::new(base_fee));
        let codec = match content.features {
            Some(features) => codec.with_features(features),
            None => codec,
        };
        let context = EncodeContext {
            block_header_version: self.network.params().block_header_version(slate.height()),
        };
        let wire = codec
            .encode(&slate, &context)
            .map_err(|_| NativeRefusal::NotASlate)?;
        Ok(Arrived {
            envelope: Envelope::new(
                envelope.ack_token().clone(),
                envelope.reply_to().cloned(),
                wire,
            ),
            reply_key: content.reply_key,
        })
    }

    /// The reply key of a send waiting for its answer whose hint `sealed` carries, with the
    /// send's stored S1.
    fn reply_opening(
        &self,
        repos: &dyn Repositories,
        sealed: &SealedEnvelope<'_>,
    ) -> Result<Option<(EncSecretKey, StoredSlate)>, StoreError> {
        let Some(reply_keys) = self.reply_keys else {
            return Ok(None);
        };
        for account in repos.accounts()? {
            for stored in repos.transactions(account.index)? {
                let entry = &stored.entry;
                let waiting =
                    (entry.direction, entry.state) == (TxDirection::Outgoing, TxState::Sent);
                let Some(slate_id) = entry.slate_id.filter(|_| waiting) else {
                    continue;
                };
                let Some(key) = reply_keys.reply_secret_key(
                    self.keychain,
                    self.network,
                    account.index,
                    *slate_id.as_bytes(),
                ) else {
                    continue;
                };
                if Hint::reply(&key.public_key(), sealed.enc()) != sealed.hint() {
                    continue;
                }
                return Ok(repos
                    .slate(slate_id, SlateStage::Standard1)?
                    .map(|request| (key, request)));
            }
        }
        Ok(None)
    }
}
