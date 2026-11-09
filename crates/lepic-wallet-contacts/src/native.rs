// SPDX-License-Identifier: Apache-2.0
//! Native slates between paired contacts (RFC 0003, ADR 0052 step 6): `lepic.v1` in a type `0A`
//! envelope through the contacts' mailboxes.
//!
//! The engine keeps storing V3 JSON; the format changes only at the edge. A slate goes native
//! when the host sets [`lepic_wallet::config::WalletConfig::native_direct`] and the contact's
//! pairing features claim [`NATIVE_SLATES`], and never through a private pairing; an answer
//! takes the format of its request. A native proposal carries no inputs or outputs and a native
//! answer leaves out the initiator's message, so an answer is completed from the request this
//! wallet stored before the engine sees it.

use lepic_contact::{
    ContactCard, Content, DecodeError, EncSecretKey, KeyClass, MessageType, Opened, SealedEnvelope,
    SigningKey, TxContent, TxKey, TxOpened, VerifyingKey, armor, armor_tx, seal_tx,
};
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_native_slate::{NativeSlate, Tail};
use lepic_primitives::params::Network;
use lepic_slate::codec::{EncodeContext, MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{ContactRecord, SlateStage, WalletStore};
use lepic_transport::marker::features::NATIVE_SLATES;
use lepic_wallet::receive::legacy_codecs;

use lepic_node::NodeApi;
use lepic_wallet::ports::{SecretVault, StoreOpener};
use uuid::Uuid;

use super::{ContactError, LockedRng};
use crate::ContactBook;

/// Whether a new slate to the contact of `record` goes native: the host sends native slates and
/// the contact claims to take them, through a base pairing.
pub(crate) fn wants_native(native_direct: bool, record: &ContactRecord) -> bool {
    native_direct
        && record.facts.peer_features & NATIVE_SLATES != 0
        && !super::private::is_private(record)
}

/// The `lepic.v1` bytes of a slate stored as V3 JSON.
fn native_body(network: Network, v3: &[u8]) -> Result<Vec<u8>, ContactError> {
    let slate = legacy_codecs(network)
        .map_err(ContactError::Receive)?
        .decode(&WireSlate::binary(MediaType::JSON, v3.to_vec()))
        .map_err(|_| ContactError::NotASlate)?;
    let native = NativeSlate::new(slate, Tail::empty()).map_err(|_| ContactError::NotASlate)?;
    Ok(native.encode(network))
}

/// The armored text of a slate envelope: `BEGINEPICTX.` for a native one, `BEGINEPICSEALED.`
/// for a V3 one, which every LEPIC build reads (RFC 0003 5.11).
pub(crate) fn armor_slate(envelope: &[u8], native: bool) -> String {
    if native {
        armor_tx(envelope)
    } else {
        armor(envelope)
    }
}

/// `content`, a slate as V3 JSON, sealed to `card` as `lepic.v1` in a type `0A` envelope and
/// signed. A body over [`lepic_contact::MAX_BODY_LEN`] is [`ContactError::Encode`] with
/// [`lepic_contact::EncodeError::BodyTooLarge`] (RFC 0003 5.17).
pub(crate) fn seal_native(
    network: Network,
    card: &ContactCard,
    content: Content,
    signer: &SigningKey,
    rng: &mut LockedRng<'_>,
) -> Result<Vec<u8>, ContactError> {
    let tx = TxContent {
        body: native_body(network, &content.body)?,
        reply_key: content.reply_key,
        reply_mailbox: None,
        purpose: content.purpose,
        reference: content.reference,
        expires: content.expires,
        card: content.card,
        sent_at: content.sent_at,
        address_proof: content.address_proof,
        features: content.features,
        domain: content.domain,
    };
    seal_tx(
        super::keys::contact_network(network),
        card.enc_key(),
        TxKey::Seal(card.hint_rule()),
        &tx,
        Some(signer),
        rng,
    )
    .map_err(ContactError::Encode)
}

fn opened_of(opened: TxOpened) -> Opened {
    let content = opened.content;
    Opened {
        content: Content {
            kind: MessageType::Slate,
            body: content.body,
            reply_key: content.reply_key,
            purpose: content.purpose,
            reference: content.reference,
            expires: content.expires,
            card: content.card,
            sent_at: content.sent_at,
            address_proof: content.address_proof,
            features: content.features,
            domain: content.domain,
        },
        sender: opened.sender,
    }
}

/// Opens a base envelope with `key`, of type `0A` as well as the types of RFC 0002. The flag
/// says the body is a `lepic.v1` slate.
pub(crate) fn open_any(
    sealed: &SealedEnvelope<'_>,
    key: &EncSecretKey,
) -> Result<(Opened, bool), DecodeError> {
    match sealed.open(key) {
        Ok(opened) => Ok((opened, false)),
        // The types of RFC 0002 do not include 0A; only then is it tried as a native slate.
        Err(DecodeError::Malformed(_)) => sealed
            .open_tx(key, KeyClass::Seal)
            .map(|opened| (opened_of(opened), true)),
        Err(error) => Err(error),
    }
}

/// [`open_any`] for an envelope that must not be signed by another key than `expected`, as
/// [`SealedEnvelope::open_from`] opens one.
pub(crate) fn open_any_from(
    sealed: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    expected: &VerifyingKey,
) -> Result<(Opened, bool), DecodeError> {
    let (opened, native) = open_any(sealed, key)?;
    if opened
        .sender
        .as_ref()
        .is_some_and(|sender| sender != expected)
    {
        return Err(DecodeError::KeyChanged);
    }
    Ok((opened, native))
}

/// A `lepic.v1` body decoded for `network`, refused when its tail holds a record a slate inside
/// an envelope never carries (RFC 0003 5.10).
pub(crate) fn decode_native(network: Network, body: &[u8]) -> Option<Slate> {
    let (slate, tail) = NativeSlate::decode(network, body).ok()?.into_parts();
    if tail.reply_key().is_some() || tail.reply_mailbox().is_some() {
        return None;
    }
    Some(slate)
}

/// The V3 JSON of a native slate: a proposal as it came, an answer completed from `request`,
/// the stored V3 JSON of the proposal it answers. The answer takes the request's inputs and
/// outputs and the initiator's message; an entry the answer repeats must be identical to the
/// stored one. `None` when the answer does not fit its request.
pub(crate) fn v3_of_native(
    network: Network,
    slate: Slate,
    request: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let codecs = legacy_codecs(network).ok()?;
    let slate = match (slate.stage(), request) {
        (Stage::S1 | Stage::I1, None) => slate,
        (Stage::S2 | Stage::I2, Some(request)) => {
            let request = codecs
                .decode(&WireSlate::binary(MediaType::JSON, request.to_vec()))
                .ok()?;
            completed(slate, &request)?
        }
        _ => return None,
    };
    let context = EncodeContext {
        block_header_version: network.params().block_header_version(slate.height()),
    };
    let wire = codecs.encode(LEGACY_V3_JSON, &slate, &context)?.ok()?;
    Some(wire.as_bytes().to_vec())
}

/// `answer` with the body and the initiator's message of `request`.
fn completed(answer: Slate, request: &Slate) -> Option<Slate> {
    let initiator = answer.flow().initiator();
    let message = request.participant(initiator)?.message.clone();
    let mut parts = answer.into_parts();
    let mut inputs = request.inputs().to_vec();
    for input in parts.inputs {
        match inputs
            .iter()
            .find(|held| held.commitment == input.commitment)
        {
            Some(held) if *held != input => return None,
            Some(_) => {}
            None => inputs.push(input),
        }
    }
    let mut outputs = request.outputs().to_vec();
    for output in parts.outputs {
        match outputs
            .iter()
            .find(|held| held.commitment == output.commitment)
        {
            Some(held) if *held != output => return None,
            Some(_) => {}
            None => outputs.push(output),
        }
    }
    parts.inputs = inputs;
    parts.outputs = outputs;
    let participant = match initiator {
        Role::Sender => parts.sender.as_mut(),
        Role::Receiver => parts.receiver.as_mut(),
    }?;
    participant.message = message;
    // The request's version info, which the stored stages of the slate share.
    parts.origin = request.origin().copied();
    Slate::from_parts(parts).ok()
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The V3 JSON of a `lepic.v1` body that came in an envelope, an answer completed from the
    /// request this wallet stored under its slate id. `None` for a body that does not decode,
    /// or an answer to no stored request or one it does not fit.
    pub(crate) async fn v3_of_native(&self, body: &[u8]) -> Result<Option<Vec<u8>>, ContactError> {
        let network = self.wallet.config().network;
        let Some(slate) = decode_native(network, body) else {
            return Ok(None);
        };
        let request_stage = match slate.stage() {
            Stage::S2 => SlateStage::Standard1,
            Stage::I2 => SlateStage::Invoice1,
            _ => return Ok(v3_of_native(network, slate, None)),
        };
        let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
        let session = self.wallet.session()?;
        let request = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.slate(slate_id, request_stage))?)
            })
            .await?;
        Ok(request.and_then(|request: lepic_store::StoredSlate| {
            v3_of_native(network, slate, Some(&request.bytes))
        }))
    }
}

#[cfg(test)]
mod tests {
    use lepic_contact::{
        Capabilities, CardFields, ContactKind, ContactName, EncodeError, HintKey, MAX_BODY_LEN,
        MailboxAddress,
    };
    use lepic_crypto::Commitment;
    use lepic_native_slate::{OutputView, SlateView};

    use super::*;

    /// A source of the same byte, enough for a seal that fails before it draws.
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

    /// The floonet S2 of the `slates_native` vectors with `extra` more outputs, as V3 JSON.
    fn s2_with_outputs(extra: usize) -> Vec<u8> {
        let text =
            include_str!("../../../testdata/vectors/slates_native/send_file_plain_s2_floonet.json");
        let vector: serde_json::Value = serde_json::from_str(text).unwrap();
        let mut view: SlateView =
            serde_json::from_value(vector["expected"]["view"].clone()).unwrap();
        let proof = view.outputs[0].proof.clone();
        // A fee the outputs pay for.
        view.fee = "1000000000".to_owned();
        // Commitments on the curve, each one new to the slate.
        let commitments = (0u16..)
            .map(|n| {
                let mut bytes = [0u8; 33];
                bytes[0] = 0x08;
                bytes[1..3].copy_from_slice(&n.to_be_bytes());
                bytes
            })
            .filter_map(|bytes| Commitment::from_bytes(&bytes).ok())
            .map(|commitment| {
                commitment
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .filter(|commitment| {
                view.outputs
                    .iter()
                    .all(|held| held.commitment != *commitment)
            })
            .take(extra)
            .collect::<Vec<_>>();
        view.outputs
            .extend(commitments.into_iter().map(|commitment| OutputView {
                features: "plain".to_owned(),
                commitment,
                proof: proof.clone(),
            }));
        let (network, native) = view.into_native().unwrap();
        let (slate, _) = native.into_parts();
        let context = EncodeContext {
            block_header_version: network.params().block_header_version(slate.height()),
        };
        legacy_codecs(network)
            .unwrap()
            .encode(LEGACY_V3_JSON, &slate, &context)
            .unwrap()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn card(signing: &SigningKey) -> ContactCard {
        let fields = CardFields {
            kind: ContactKind::Person,
            name: ContactName::new("Anna").unwrap(),
            enc_key: EncSecretKey::from_bytes([3; 32]).public_key(),
            sig_key: signing.verifying_key(),
            hint_key: HintKey::from_bytes([3; 32]),
            mailbox: MailboxAddress::new(
                "es7Rq2XGuB2GAqa4CqLwBPeZVsSnktXTQtCbdNuf9nvYv7bATYwM@relay.test:80",
            )
            .unwrap(),
            payments_address: None,
            home_onion: None,
            caps: Capabilities::default(),
            max_envelope_version: 1,
            seq: 1,
        };
        ContactCard::sign(lepic_contact::Network::Floonet, fields, signing).unwrap()
    }

    /// A slate whose `lepic.v1` bytes exceed an envelope body is refused before it is sealed,
    /// with the limit and the length it found.
    #[test]
    fn a_native_slate_over_the_body_limit_is_refused() {
        let signing = SigningKey::from_bytes(&[3; 32]);
        let card = card(&signing);
        let seal = |v3: Vec<u8>| {
            seal_native(
                Network::Floonet,
                &card,
                Content::new(MessageType::Slate, v3),
                &signing,
                &mut LockedRng(&mut FixedRng),
            )
        };
        let fits = s2_with_outputs(80);
        assert!(native_body(Network::Floonet, &fits).unwrap().len() <= MAX_BODY_LEN);
        assert!(seal(fits).is_ok());

        let large = s2_with_outputs(100);
        let found = native_body(Network::Floonet, &large).unwrap().len();
        assert!(found > MAX_BODY_LEN);
        assert!(matches!(
            seal(large),
            Err(ContactError::Encode(EncodeError::BodyTooLarge { limit, found: got }))
                if limit == MAX_BODY_LEN && got == found
        ));
    }

    /// The V3 JSON of the `slates_native` vector `name` with `inputs` and `outputs` more
    /// entries, as LEPIC encodes it, with a fee that pays for them.
    fn vector_with(name: &str, inputs: usize, outputs: usize) -> Vec<u8> {
        let path = format!(
            "{}/../../testdata/vectors/slates_native/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let vector: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut slate: serde_json::Value =
            serde_json::from_str(vector["inputs"]["v3_json"].as_str().unwrap()).unwrap();
        if inputs > 0 || outputs > 0 {
            let body = &mut slate["tx"]["body"];
            let proof = body["outputs"][0]["proof"].clone();
            let held = |entries: &serde_json::Value| -> Vec<String> {
                entries
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| entry["commit"].as_str().unwrap().to_owned())
                    .collect()
            };
            let mut taken = held(&body["inputs"]);
            taken.extend(held(&body["outputs"]));
            let mut fresh = (0u16..)
                .map(|n| {
                    let mut bytes = [0u8; 33];
                    bytes[0] = 0x09;
                    bytes[1..3].copy_from_slice(&n.to_be_bytes());
                    bytes
                })
                .filter_map(|bytes| Commitment::from_bytes(&bytes).ok())
                .map(|commitment| {
                    commitment
                        .as_bytes()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                })
                .filter(|commitment| !taken.contains(commitment));
            for commit in fresh.by_ref().take(inputs) {
                body["inputs"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({ "features": "Plain", "commit": commit }));
            }
            for commit in fresh.take(outputs) {
                body["outputs"].as_array_mut().unwrap().push(
                    serde_json::json!({ "features": "Plain", "commit": commit, "proof": proof }),
                );
            }
            for kernel in body["kernels"].as_array_mut().unwrap() {
                kernel["fee"] = serde_json::json!("100000000000");
            }
            slate["fee"] = serde_json::json!("100000000000");
        }
        let decoded = legacy_codecs(Network::Floonet)
            .unwrap()
            .decode(&WireSlate::binary(
                MediaType::JSON,
                serde_json::to_vec(&slate).unwrap(),
            ))
            .unwrap();
        let context = EncodeContext {
            block_header_version: Network::Floonet
                .params()
                .block_header_version(decoded.height()),
        };
        legacy_codecs(Network::Floonet)
            .unwrap()
            .encode(LEGACY_V3_JSON, &decoded, &context)
            .unwrap()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// Prints, for slates of each stage, the `lepic.v1` and V3 JSON lengths and the length of
    /// each sealed, signed contact envelope (type `01` with V3, type `0A` with `lepic.v1`, both
    /// padded), and the armored text of the `0A` one. Run with `--nocapture` to see the table.
    #[test]
    fn sizes_of_native_and_v3_slate_envelopes() {
        let signing = SigningKey::from_bytes(&[3; 32]);
        let card = card(&signing);
        let rows = [
            ("S1 plain", "send_file_plain_s1_floonet", 0, 0),
            ("S1 with proof", "send_file_payment_proof_s1_floonet", 0, 0),
            (
                "S1 three change outputs",
                "send_file_three_change_outputs_s1_floonet",
                0,
                0,
            ),
            ("S1 +9 inputs", "send_file_plain_input_s1_floonet", 9, 0),
            ("S1 +99 inputs", "send_file_plain_input_s1_floonet", 99, 0),
            ("S2 plain", "send_file_plain_s2_floonet", 0, 0),
            ("S2 with proof", "send_file_payment_proof_s2_floonet", 0, 0),
            ("S2 +99 inputs", "send_file_plain_input_s2_floonet", 99, 0),
            ("I1 plain", "invoice_file_plain_i1_floonet", 0, 0),
            ("I1 with messages", "invoice_file_messages_i1_floonet", 0, 0),
            ("I2 plain", "invoice_file_plain_i2_floonet", 0, 0),
            ("I2 +9 inputs", "invoice_file_plain_i2_floonet", 9, 0),
            ("I2 +99 inputs", "invoice_file_plain_i2_floonet", 99, 0),
            (
                "I2 +9 inputs +2 outputs",
                "invoice_file_plain_i2_floonet",
                9,
                2,
            ),
        ];
        println!(
            "| Slate | inputs/outputs (V3) | lepic.v1 | V3 JSON | 01 envelope | 0A envelope | 0A text |"
        );
        println!("|---|---|---|---|---|---|---|");
        for (label, name, inputs, outputs) in rows {
            let v3 = vector_with(name, inputs, outputs);
            let slate: serde_json::Value = serde_json::from_slice(&v3).unwrap();
            let counts = |key: &str| slate["tx"]["body"][key].as_array().unwrap().len();
            let native = native_body(Network::Floonet, &v3).unwrap();
            let mut content = Content::new(MessageType::Slate, v3.clone());
            content.sent_at = Some(1_800_000_000);
            // A request carries the key its answer is sealed to.
            if label.starts_with("S1") || label.starts_with("I1") {
                content.reply_key = Some(EncSecretKey::from_bytes([5; 32]).public_key());
            }
            let v3_envelope = lepic_contact::seal(
                lepic_contact::Network::Floonet,
                card.enc_key(),
                card.hint_rule(),
                &content,
                Some(&signing),
                &mut FixedRng,
            )
            .unwrap();
            let native_envelope = seal_native(
                Network::Floonet,
                &card,
                content,
                &signing,
                &mut LockedRng(&mut FixedRng),
            )
            .unwrap();
            let text = armor_slate(&native_envelope, true);
            println!(
                "| {label} | {}/{} | {} | {} | {} | {} | {} |",
                counts("inputs"),
                counts("outputs"),
                native.len(),
                v3.len(),
                v3_envelope.len(),
                native_envelope.len(),
                text.len(),
            );
            assert!(native.len() < v3.len());
            assert!(native_envelope.len() < v3_envelope.len());
        }
    }
}
