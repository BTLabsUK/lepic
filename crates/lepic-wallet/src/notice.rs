// SPDX-License-Identifier: Apache-2.0
//! LEPIC notices over Epicbox (ADR 0016): short advisory messages between LEPIC wallets about an
//! invoice or a payment, which are not slates.
//!
//! A notice is the JSON object `{"lepic":1,"type":<kind>,"slate_id":<uuid>}`, with the kernel
//! `excess` added for `posted`, at most [`MAX_NOTICE_LEN`] bytes. This wallet pads every notice
//! it writes to [`PADDED_NOTICE_LEN`] with a `pad` key, which readers ignore as they ignore
//! every unknown key, so that its size does not tell one kind from another. A stock `epic-wallet` listener
//! processes only V2 and V3 slates, so a notice goes only to a peer whose own messages proved
//! it runs LEPIC. A notice never moves funds or unlocks anything, and is taken
//! only from the recorded counterparty of its slate.

use lepic_crypto::Commitment;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::SlateId;
use lepic_slate::validate::check_size;
use serde::{Deserialize, Serialize};

/// The notice format version this wallet writes and reads.
pub const NOTICE_VERSION: u64 = 1;

/// The longest notice accepted, in bytes.
pub const MAX_NOTICE_LEN: usize = 512;

/// The length of every notice this wallet writes, in bytes: under [`MAX_NOTICE_LEN`], so that a
/// later version can add a key and still be read by this one.
pub const PADDED_NOTICE_LEN: usize = 256;
const _: () = assert!(PADDED_NOTICE_LEN <= MAX_NOTICE_LEN);

const PAD: char = '0';

const DECLINED: &str = "declined";
const WITHDRAWN: &str = "withdrawn";
const POSTED: &str = "posted";
const CANCELLED: &str = "cancelled";
const UNPAIRED: &str = "unpaired";

/// What a notice says about its invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    /// The payer declined the invoice; sent to the issuer.
    Declined,
    /// The issuer cancelled the invoice or let it expire; sent to the payer.
    Withdrawn,
    /// The issuer pushed the paid invoice to its node, with this kernel excess; sent to the
    /// payer.
    Posted { excess: Commitment },
    /// The sender cancelled an ordinary payment the receiver had answered; sent to the
    /// receiver.
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice {
    pub slate_id: SlateId,
    pub kind: NoticeKind,
}

/// What a decrypted Epicbox payload is, as far as notices are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    /// Not notice-shaped: decode it as a slate.
    Slate,
    Notice(Notice),
    /// A notice of a version or type this wallet does not know, which it ignores.
    Unknown,
    /// Notice-shaped and longer than [`MAX_NOTICE_LEN`].
    Oversize,
    /// A known notice type with missing or invalid fields.
    Malformed,
}

/// The one key that tells a notice from a slate: a number under `lepic`. A slate this wallet
/// writes carries an object there, and a stock slate carries nothing.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    lepic: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Fields {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    slate_id: Option<String>,
    #[serde(default)]
    excess: Option<String>,
}

#[derive(Serialize)]
struct Written {
    lepic: u64,
    #[serde(rename = "type")]
    kind: &'static str,
    slate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    excess: Option<String>,
    pad: String,
}

/// Classifies a decrypted payload. Bounded: anything over the slate size bound, binary, or not
/// a JSON object is left to the slate decoder, and only a payload of at most
/// [`MAX_NOTICE_LEN`] bytes is read as a notice.
pub fn classify(wire: &WireSlate) -> Payload {
    if check_size(wire).is_err() {
        return Payload::Slate;
    }
    match wire.as_text() {
        Some(text) => classify_text(text),
        None => Payload::Slate,
    }
}

/// [`classify`] for text, the entry point for fuzzing.
pub fn classify_text(text: &str) -> Payload {
    if !text.trim_start().starts_with('{') {
        return Payload::Slate;
    }
    let Ok(probe) = serde_json::from_str::<Probe>(text) else {
        return Payload::Slate;
    };
    let Some(serde_json::Value::Number(version)) = probe.lepic else {
        return Payload::Slate;
    };
    if text.len() > MAX_NOTICE_LEN {
        return Payload::Oversize;
    }
    if version.as_u64() != Some(NOTICE_VERSION) {
        return Payload::Unknown;
    }
    let Ok(fields) = serde_json::from_str::<Fields>(text) else {
        return Payload::Malformed;
    };
    let kind = match fields.kind.as_str() {
        DECLINED => NoticeKind::Declined,
        WITHDRAWN => NoticeKind::Withdrawn,
        CANCELLED => NoticeKind::Cancelled,
        POSTED => match fields.excess.as_deref().map(Commitment::from_hex) {
            Some(Ok(excess)) => NoticeKind::Posted { excess },
            _ => return Payload::Malformed,
        },
        _ => return Payload::Unknown,
    };
    match fields.slate_id.as_deref().map(SlateId::parse) {
        Some(Ok(slate_id)) => Payload::Notice(Notice { slate_id, kind }),
        _ => Payload::Malformed,
    }
}

impl Notice {
    /// The notice as it goes over Epicbox.
    pub fn encode(&self) -> WireSlate {
        let (kind, excess) = match self.kind {
            NoticeKind::Declined => (DECLINED, None),
            NoticeKind::Withdrawn => (WITHDRAWN, None),
            NoticeKind::Posted { excess } => (POSTED, Some(excess.to_hex())),
            NoticeKind::Cancelled => (CANCELLED, None),
        };
        let mut written = Written {
            lepic: NOTICE_VERSION,
            kind,
            slate_id: self.slate_id.to_string(),
            excess,
            pad: String::new(),
        };
        // A struct of strings and a number always serializes, and each pad character adds one
        // byte, as it needs no escaping.
        let unpadded = serde_json::to_string(&written).unwrap_or_default();
        written.pad =
            std::iter::repeat_n(PAD, PADDED_NOTICE_LEN.saturating_sub(unpadded.len())).collect();
        let text = serde_json::to_string(&written).unwrap_or(unpadded);
        WireSlate::text(MediaType::JSON, text)
    }
}

#[derive(Serialize)]
struct WrittenUnpaired {
    lepic: u64,
    #[serde(rename = "type")]
    kind: &'static str,
    pad: String,
}

/// The notice a wallet seals to a paired contact when it removes their pairing (RFC 0002 7.6):
/// `{"lepic":1,"type":"unpaired"}`, padded as every notice. It is about the pairing, not a
/// slate, so [`classify_text`] reads it as [`Payload::Unknown`], which a wallet that does not
/// know it ignores; [`is_unpaired`] reads it.
pub fn unpaired_notice() -> String {
    let mut written = WrittenUnpaired {
        lepic: NOTICE_VERSION,
        kind: UNPAIRED,
        pad: String::new(),
    };
    let unpadded = serde_json::to_string(&written).unwrap_or_default();
    written.pad =
        std::iter::repeat_n(PAD, PADDED_NOTICE_LEN.saturating_sub(unpadded.len())).collect();
    serde_json::to_string(&written).unwrap_or(unpadded)
}

/// Whether `text` is the notice [`unpaired_notice`] writes, of this notice version and at most
/// [`MAX_NOTICE_LEN`] bytes.
pub fn is_unpaired(text: &str) -> bool {
    if text.len() > MAX_NOTICE_LEN || !text.trim_start().starts_with('{') {
        return false;
    }
    let version = serde_json::from_str::<Probe>(text)
        .ok()
        .and_then(|probe| probe.lepic)
        .and_then(|version| version.as_u64());
    version == Some(NOTICE_VERSION)
        && serde_json::from_str::<Fields>(text).is_ok_and(|fields| fields.kind == UNPAIRED)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use proptest::prelude::*;

    use super::*;

    const SLATE_ID: &str = "0436430c-2b02-624c-2032-570501212b00";

    fn slate_id() -> SlateId {
        SlateId::parse(SLATE_ID).unwrap()
    }

    fn excess() -> Commitment {
        Commitment::commit_value(1).unwrap()
    }

    fn text(notice: Notice) -> String {
        notice.encode().as_text().unwrap().to_owned()
    }

    /// The notice as written, up to its padding.
    fn unpadded(notice: Notice) -> String {
        let text = text(notice);
        let (head, pad) = text.split_once(r#","pad":""#).unwrap();
        assert!(pad.trim_end_matches(['"', '}']).chars().all(|c| c == PAD));
        format!("{head}}}")
    }

    fn every_kind() -> [Notice; 4] {
        [
            NoticeKind::Declined,
            NoticeKind::Withdrawn,
            NoticeKind::Posted { excess: excess() },
            NoticeKind::Cancelled,
        ]
        .map(|kind| Notice {
            slate_id: slate_id(),
            kind,
        })
    }

    #[test]
    fn notices_are_written_with_the_version_first() {
        insta::assert_snapshot!(
            every_kind().map(unpadded).join("\n"),
            @r#"
        {"lepic":1,"type":"declined","slate_id":"0436430c-2b02-624c-2032-570501212b00"}
        {"lepic":1,"type":"withdrawn","slate_id":"0436430c-2b02-624c-2032-570501212b00"}
        {"lepic":1,"type":"posted","slate_id":"0436430c-2b02-624c-2032-570501212b00","excess":"0950929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"}
        {"lepic":1,"type":"cancelled","slate_id":"0436430c-2b02-624c-2032-570501212b00"}
        "#
        );
    }

    #[test]
    fn every_kind_is_written_at_one_length_and_reads_back() {
        for notice in every_kind() {
            assert_eq!(text(notice).len(), PADDED_NOTICE_LEN, "{notice:?}");
            assert_eq!(classify(&notice.encode()), Payload::Notice(notice));
        }
    }

    #[test]
    fn slates_and_other_payloads_are_left_to_the_slate_decoder() {
        for payload in [
            "",
            "not json",
            "[1]",
            "{",
            r#"{"id":"x","lepic":{"version":1}}"#,
            r#"{"id":"x"}"#,
            r#"{"lepic":"1","type":"declined"}"#,
            r#"{"lepic":true}"#,
            r#"{"lepic":null}"#,
        ] {
            assert_eq!(classify_text(payload), Payload::Slate, "{payload}");
        }
        assert_eq!(
            classify(&WireSlate::binary(MediaType::JSON, vec![b'{'])),
            Payload::Slate
        );
    }

    #[test]
    fn unknown_versions_and_types_are_unknown() {
        for payload in [
            format!(r#"{{"lepic":2,"type":"declined","slate_id":"{SLATE_ID}"}}"#),
            format!(r#"{{"lepic":0,"type":"declined","slate_id":"{SLATE_ID}"}}"#),
            format!(r#"{{"lepic":1.5,"type":"declined","slate_id":"{SLATE_ID}"}}"#),
            format!(r#"{{"lepic":1,"type":"thanks","slate_id":"{SLATE_ID}"}}"#),
            r#"{"lepic":1,"type":"thanks"}"#.to_owned(),
        ] {
            assert_eq!(classify_text(&payload), Payload::Unknown, "{payload}");
        }
    }

    #[test]
    fn known_types_with_bad_fields_are_malformed() {
        for payload in [
            r#"{"lepic":1}"#.to_owned(),
            r#"{"lepic":1,"type":"declined"}"#.to_owned(),
            r#"{"lepic":1,"type":"declined","slate_id":"nope"}"#.to_owned(),
            r#"{"lepic":1,"type":"cancelled"}"#.to_owned(),
            r#"{"lepic":1,"type":"cancelled","slate_id":7}"#.to_owned(),
            format!(r#"{{"lepic":1,"type":"posted","slate_id":"{SLATE_ID}"}}"#),
            format!(r#"{{"lepic":1,"type":"posted","slate_id":"{SLATE_ID}","excess":"00"}}"#),
            format!(
                r#"{{"lepic":1,"type":"declined","type":"withdrawn","slate_id":"{SLATE_ID}"}}"#
            ),
        ] {
            assert_eq!(classify_text(&payload), Payload::Malformed, "{payload}");
        }
    }

    #[test]
    fn a_notice_over_the_bound_is_oversize_whatever_it_says() {
        let padding = "a".repeat(MAX_NOTICE_LEN);
        let payload =
            format!(r#"{{"lepic":1,"type":"declined","slate_id":"{SLATE_ID}","pad":"{padding}"}}"#);
        assert_eq!(classify_text(&payload), Payload::Oversize);
        let payload = format!(r#"{{"lepic":7,"pad":"{padding}"}}"#);
        assert_eq!(classify_text(&payload), Payload::Oversize);
    }

    /// A reader that knows only the kinds before `cancelled`, as an older LEPIC build does:
    /// what it makes of a `cancelled` notice.
    fn classify_without_cancelled(text: &str) -> Payload {
        match classify_text(text) {
            Payload::Notice(Notice {
                kind: NoticeKind::Cancelled,
                ..
            }) => Payload::Unknown,
            other => other,
        }
    }

    #[test]
    fn a_cancelled_notice_is_a_notice_to_readers_that_do_not_know_it() {
        let notice = Notice {
            slate_id: slate_id(),
            kind: NoticeKind::Cancelled,
        };
        let text = text(notice);
        // The probe reads it as a notice, never as a slate, so an older reader that does not
        // know the type ignores it rather than decoding it as one.
        assert_ne!(classify_text(&text), Payload::Slate);
        assert_eq!(classify_without_cancelled(&text), Payload::Unknown);
        assert!(!is_unpaired(&text));
    }

    #[test]
    fn a_cancelled_notice_with_an_excess_still_reads_as_cancelled() {
        let payload =
            format!(r#"{{"lepic":1,"type":"cancelled","slate_id":"{SLATE_ID}","excess":"zz"}}"#);
        assert_eq!(
            classify_text(&payload),
            Payload::Notice(Notice {
                slate_id: slate_id(),
                kind: NoticeKind::Cancelled,
            })
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let payload =
            format!(r#"{{"lepic":1,"type":"withdrawn","slate_id":"{SLATE_ID}","note":"x"}}"#);
        assert_eq!(
            classify_text(&payload),
            Payload::Notice(Notice {
                slate_id: slate_id(),
                kind: NoticeKind::Withdrawn,
            })
        );
    }

    fn any_notice() -> impl Strategy<Value = Notice> {
        let kind = prop_oneof![
            Just(NoticeKind::Declined),
            Just(NoticeKind::Withdrawn),
            Just(NoticeKind::Posted { excess: excess() }),
            Just(NoticeKind::Cancelled),
        ];
        (any::<[u8; 16]>(), kind).prop_map(|(bytes, kind)| Notice {
            slate_id: SlateId::from_bytes(bytes),
            kind,
        })
    }

    #[test]
    fn the_unpaired_notice_is_padded_and_unknown_to_the_invoice_classifier() {
        let text = unpaired_notice();
        assert_eq!(text.len(), PADDED_NOTICE_LEN);
        assert!(text.starts_with(r#"{"lepic":1,"type":"unpaired","pad":"0"#));
        assert!(is_unpaired(&text));
        // A wallet that knows only the invoice notices ignores it.
        assert_eq!(classify_text(&text), Payload::Unknown);
    }

    #[test]
    fn only_the_unpaired_notice_reads_as_one() {
        for payload in [
            r#"{"lepic":2,"type":"unpaired"}"#.to_owned(),
            r#"{"lepic":1,"type":"declined"}"#.to_owned(),
            r#"{"lepic":1}"#.to_owned(),
            r#"{"type":"unpaired"}"#.to_owned(),
            "unpaired".to_owned(),
            format!(
                r#"{{"lepic":1,"type":"unpaired","pad":"{}"}}"#,
                "0".repeat(MAX_NOTICE_LEN)
            ),
        ] {
            assert!(!is_unpaired(&payload), "{payload}");
        }
        for notice in every_kind() {
            assert!(!is_unpaired(&text(notice)));
        }
    }

    proptest! {
        #[test]
        fn every_notice_reads_back_as_written(notice in any_notice()) {
            prop_assert_eq!(classify(&notice.encode()), Payload::Notice(notice));
        }

        #[test]
        fn classifying_any_text_never_panics(text in ".{0,600}") {
            let _ = classify_text(&text);
        }
    }
}
