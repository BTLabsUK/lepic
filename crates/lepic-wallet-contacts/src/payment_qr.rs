// SPDX-License-Identifier: Apache-2.0
//! Payment files as QR codes: a slate file's text as `lepic.v1` bytes for the binary
//! `ur:epic-slate` payload, and those bytes as slate text again
//! (`docs/compat/ur-epic-slate.md`). Needs no wallet.
//!
//! `lepic.v1` leaves out the body of a proposal and the initiator's message in an answer, so a
//! slate read from such a code is smaller than the file it came from. The engine takes the
//! slate text as it takes any slate file: the receiver or payer answers from the proposal's
//! numbers, and the initiator puts its own inputs, change and message back from what it stored
//! when it finalizes.

use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_native_slate::{NativeSlate, Tail};
use lepic_primitives::params::Network;
use lepic_slate::codec::{EncodeContext, MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::origin::WireOrigin;
use lepic_wallet::receive::legacy_codecs;

/// Why `lepic.v1` bytes are not the slate of a payment file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PaymentQrRefusal {
    /// The slate carries a reply key or mailbox: an in-person code, read by the in-person flow.
    #[error("the code is an in-person code, not a payment file")]
    InPerson,
    /// The bytes do not decode as a `lepic.v1` slate, or its V3 text cannot be written.
    #[error("the code holds no slate")]
    Malformed,
}

/// The `lepic.v1` bytes of the V2 or V3 slate text `json` on `network`, with an empty tail.
/// `None` when the legacy codecs do not read the text or `lepic.v1` cannot carry the slate:
/// a range proof that is not a single bulletproof, a block header version other than the one
/// the fork table gives the slate's height, or bytes that would not read back, such as a
/// message over the `lepic.v1` limit. The caller writes the text then.
pub fn payment_qr_native(network: Network, json: &str) -> Option<Vec<u8>> {
    let slate = legacy_codecs(network)
        .ok()?
        .decode(&WireSlate::text(MediaType::JSON, json.to_owned()))
        .ok()?;
    let header = header_version(network, &slate);
    if slate
        .origin()
        .and_then(WireOrigin::legacy_header)
        .is_some_and(|legacy| legacy.block_header_version != header)
    {
        return None;
    }
    let bytes = NativeSlate::new(slate, Tail::empty()).ok()?.encode(network);
    NativeSlate::decode(network, &bytes).ok()?;
    Some(bytes)
}

/// The V3 slate text of the `lepic.v1` bytes of a payment file, on the network its header
/// names: a slate for another network reads, for the wallet to refuse as it refuses that file.
pub fn payment_qr_text(bytes: &[u8]) -> Result<String, PaymentQrRefusal> {
    let (network, native) =
        NativeSlate::decode_any(bytes).map_err(|_| PaymentQrRefusal::Malformed)?;
    let (slate, tail) = native.into_parts();
    if is_in_person(&tail) {
        return Err(PaymentQrRefusal::InPerson);
    }
    v3_text(network, &slate).ok_or(PaymentQrRefusal::Malformed)
}

/// Whether `bytes` is the `lepic.v1` slate of a payment file: a slate that decodes and carries
/// no reply key or mailbox. The in-person flow leaves such a code to the payment-file reader.
pub fn is_payment_qr_native(bytes: &[u8]) -> bool {
    NativeSlate::decode_any(bytes).is_ok_and(|(_, native)| !is_in_person(native.tail()))
}

/// An in-person code carries where its answer goes.
fn is_in_person(tail: &Tail) -> bool {
    tail.reply_key().is_some() || tail.reply_mailbox().is_some()
}

/// The block header version the fork table of `network` gives the height of `slate`.
fn header_version(network: Network, slate: &Slate) -> u16 {
    network.params().block_header_version(slate.height())
}

/// `slate` as V3 JSON, with the block header version the fork table gives its height.
fn v3_text(network: Network, slate: &Slate) -> Option<String> {
    let context = EncodeContext {
        block_header_version: header_version(network, slate),
    };
    let wire = legacy_codecs(network)
        .ok()?
        .encode(LEGACY_V3_JSON, slate, &context)?
        .ok()?;
    String::from_utf8(wire.as_bytes().to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use lepic_native_slate::ReplyKey;
    use lepic_slate::model::SlateParts;

    use super::*;

    fn vector(name: &str) -> String {
        let path = format!(
            "{}/../../testdata/vectors/slates/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        vector["expected"]["json"].as_str().unwrap().to_owned()
    }

    fn read(network: Network, json: &str) -> Slate {
        legacy_codecs(network)
            .unwrap()
            .decode(&WireSlate::text(MediaType::JSON, json.to_owned()))
            .unwrap()
    }

    fn parts(slate: Slate) -> SlateParts {
        slate.with_origin(None).into_parts()
    }

    /// What `lepic.v1` keeps of `json`: the slate as the code's reader gets it.
    fn kept(json: &str) -> SlateParts {
        let slate = read(Network::Floonet, json);
        parts(
            NativeSlate::new(slate, Tail::empty())
                .unwrap()
                .into_parts()
                .0,
        )
    }

    #[test]
    fn every_stage_reads_back_as_v3_text_of_what_the_code_keeps() {
        for name in [
            "send_file_plain_s1_file",
            "send_file_messages_s2_file",
            "send_file_plain_s3_file",
            "send_file_ttl_payment_proof_messages_s3_v2",
            "invoice_file_messages_i1_file",
            "invoice_file_messages_i2_file",
            "invoice_file_plain_i3_v2",
        ] {
            let json = vector(name);
            let bytes = payment_qr_native(Network::Floonet, &json).unwrap();
            assert!(bytes.len() < json.len() / 2, "{name}");
            assert!(is_payment_qr_native(&bytes), "{name}");
            let text = payment_qr_text(&bytes).unwrap();
            assert!(text.contains("\"version_info\""), "{name}: {text}");
            assert_eq!(parts(read(Network::Floonet, &text)), kept(&json), "{name}");
        }
    }

    #[test]
    fn a_finalized_slate_reads_back_whole() {
        let json = vector("send_file_plain_s3_file");
        let text = payment_qr_text(&payment_qr_native(Network::Floonet, &json).unwrap()).unwrap();
        assert_eq!(
            parts(read(Network::Floonet, &text)),
            parts(read(Network::Floonet, &json))
        );
    }

    #[test]
    fn a_code_reads_on_the_network_it_names() {
        let json = vector("send_file_plain_s1_file");
        let bytes = payment_qr_native(Network::Mainnet, &json).unwrap();
        assert_eq!(NativeSlate::decode_any(&bytes).unwrap().0, Network::Mainnet);
        assert_eq!(
            parts(read(Network::Mainnet, &payment_qr_text(&bytes).unwrap())),
            kept(&json)
        );
    }

    #[test]
    fn in_person_codes_and_other_bytes_are_refused() {
        let slate = read(Network::Floonet, &vector("send_file_plain_s1_file"));
        let tail = Tail::new(Some(ReplyKey::from_bytes([7; 32])), None, Vec::new()).unwrap();
        let in_person = NativeSlate::new(slate, tail)
            .unwrap()
            .encode(Network::Floonet);
        assert_eq!(payment_qr_text(&in_person), Err(PaymentQrRefusal::InPerson));
        assert!(!is_payment_qr_native(&in_person));
        assert_eq!(payment_qr_text(b"{}"), Err(PaymentQrRefusal::Malformed));
        assert!(!is_payment_qr_native(b"{}"));
    }

    #[test]
    fn text_the_legacy_codecs_do_not_read_has_no_bytes() {
        assert_eq!(payment_qr_native(Network::Floonet, r#"{"a":"1"}"#), None);
        assert_eq!(payment_qr_native(Network::Floonet, "slate"), None);
    }
}
