// SPDX-License-Identifier: Apache-2.0
//! LEPIC notices (ADR 0016, ADR 0067): short advisory messages between LEPIC wallets about a
//! payment, an invoice or a pairing, which are not slates. This module is the one kind set and
//! the one codec of them all.
//!
//! A notice is the JSON object `{"lepic":1,"type":<kind>}`, with `slate_id` for a notice about
//! a slate, the kernel `excess` for `posted`, an optional `reason` for `declined` and the SAS
//! hash `sas` for `pair-match` and `pair-mismatch`, at most [`MAX_NOTICE_LEN`] bytes. A notice
//! to a pairing is padded with a `pad` key, which readers ignore as they ignore every unknown
//! key, to one of the lengths its caller gives, so that its size tells neither one kind from
//! another nor a notice from a payment. A notice sealed to an epic1 key is unpadded: its
//! envelope pads it. A notice never moves funds, changes a transaction or unlocks anything.
//!
//! The host's kind, `app`, is not JSON: its bytes, which LEPIC does not read, go under its id
//! as the app payload message type of a pairing, as they always have.

use lepic_crypto::{Commitment, hex};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::SlateId;
use lepic_slate::validate::check_size;
use lepic_store::VERDICT_LEN;
use serde::{Deserialize, Serialize};

/// The notice format version this wallet writes and reads.
pub const NOTICE_VERSION: u64 = 1;

/// The longest notice accepted, in bytes.
pub const MAX_NOTICE_LEN: usize = 8 * 1024;

const PAD: char = '0';

/// One of `lengths`, a method's notice lengths, drawn with `rng`; `0` when there are none.
pub fn notice_length<R: rand_core::Rng + ?Sized>(lengths: &[usize], rng: &mut R) -> usize {
    let at = usize::try_from(rng.next_u32())
        .unwrap_or(0)
        .checked_rem(lengths.len())
        .unwrap_or(0);
    lengths.get(at).copied().unwrap_or(0)
}

/// The JSON object `object` with a last `pad` key of zeros that makes it `length` bytes, or the
/// next of `lengths` it fits; an object longer than all of them is unpadded. The pad characters
/// need no escaping, so each adds one byte.
pub fn pad_object(object: &str, lengths: &[usize], length: usize) -> String {
    const OVERHEAD: usize = r#","pad":"""#.len();
    let Some(head) = object.strip_suffix('}') else {
        return object.to_owned();
    };
    let empty = head.trim_end().ends_with('{');
    let overhead = if empty {
        OVERHEAD.saturating_sub(1)
    } else {
        OVERHEAD
    };
    let needed = object.len().saturating_add(overhead);
    let target = std::iter::once(length)
        .chain(lengths.iter().copied())
        .find(|target| *target >= needed);
    let Some(target) = target else {
        return object.to_owned();
    };
    let zeros: String = std::iter::repeat_n(PAD, target.saturating_sub(needed)).collect();
    let comma = if empty { "" } else { "," };
    format!(r#"{head}{comma}"pad":"{zeros}"}}"#)
}

const DECLINED: &str = "declined";
const WITHDRAWN: &str = "withdrawn";
const POSTED: &str = "posted";
const CANCELLED: &str = "cancelled";
const PAIR_FINISHED: &str = "pair-finished";
const PAIR_MATCH: &str = "pair-match";
const PAIR_MISMATCH: &str = "pair-mismatch";
const UNPAIRED: &str = "unpaired";
const APP: &str = "app";

const REASON_DECLINED: &str = "declined";

/// Why a payee refused a payment, written beside a `declined` it seals to a payment's reply key.
/// A reader that does not know the reason ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The payee refuses unsolicited payments, or the payment asked for what it cannot give.
    Declined,
}

/// A notice: every kind a LEPIC wallet sends or takes, about a slate, about a pairing, or for
/// the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// The sender of `slate_id` pushed it to its node with this kernel excess.
    Posted {
        slate_id: SlateId,
        excess: Commitment,
    },
    /// The sender cancelled the payment `slate_id` its receiver had answered.
    Cancelled { slate_id: SlateId },
    /// The payer declined the invoice `slate_id`, or the payee refused the payment `slate_id`.
    Declined {
        slate_id: SlateId,
        reason: Option<Reason>,
    },
    /// The issuer cancelled the invoice `slate_id` or let it expire.
    Withdrawn { slate_id: SlateId },
    /// The contact finished its side of the pairing (RFC 0002).
    PairFinished,
    /// The contact judged the pairing's words a match; the hash of the SAS it judged.
    PairMatch { sas: [u8; VERDICT_LEN] },
    /// The contact judged the pairing's words a mismatch; the hash of the SAS it judged.
    PairMismatch { sas: [u8; VERDICT_LEN] },
    /// The contact removed the pairing (RFC 0002 7.6).
    Unpaired,
    /// The host's bytes `body` under the id `id`, which the core keeps for the host and does not
    /// read. It has no JSON form: it goes as the app payload message type.
    App { id: uuid::Uuid, body: Vec<u8> },
}

/// What a payload that arrived over a method is, as far as notices are concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// The fields of a notice as read. A field a kind does not use is ignored, whatever it holds.
#[derive(Deserialize)]
struct Fields {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    slate_id: Option<serde_json::Value>,
    #[serde(default)]
    excess: Option<serde_json::Value>,
    #[serde(default)]
    reason: Option<serde_json::Value>,
    #[serde(default)]
    sas: Option<serde_json::Value>,
}

/// A notice as written, its keys in this order.
#[derive(Serialize)]
struct Written {
    lepic: u64,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    slate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    excess: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sas: Option<String>,
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

/// [`classify`] for text: the one parser of every notice, and the entry point for fuzzing.
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
    read(&fields)
}

fn text_of(value: Option<&serde_json::Value>) -> Option<&str> {
    value.and_then(serde_json::Value::as_str)
}

fn read(fields: &Fields) -> Payload {
    let slate_id = || text_of(fields.slate_id.as_ref()).and_then(|id| SlateId::parse(id).ok());
    let sas = || text_of(fields.sas.as_ref()).and_then(|sas| hex::decode_array(sas).ok());
    let notice = match fields.kind.as_str() {
        PAIR_FINISHED => Some(Notice::PairFinished),
        PAIR_MATCH => sas().map(|sas| Notice::PairMatch { sas }),
        PAIR_MISMATCH => sas().map(|sas| Notice::PairMismatch { sas }),
        UNPAIRED => Some(Notice::Unpaired),
        POSTED => text_of(fields.excess.as_ref())
            .and_then(|excess| Commitment::from_hex(excess).ok())
            .zip(slate_id())
            .map(|(excess, slate_id)| Notice::Posted { slate_id, excess }),
        DECLINED => slate_id().map(|slate_id| Notice::Declined {
            slate_id,
            reason: match text_of(fields.reason.as_ref()) {
                Some(REASON_DECLINED) => Some(Reason::Declined),
                _ => None,
            },
        }),
        WITHDRAWN | CANCELLED => {
            slate_id().and_then(|slate_id| Notice::about_slate(&fields.kind, slate_id))
        }
        _ => return Payload::Unknown,
    };
    notice.map_or(Payload::Malformed, Payload::Notice)
}

impl Notice {
    /// The `withdrawn`, `cancelled` or reasonless `declined` named `kind` for `slate_id`, as
    /// kept by name in the store; `None` for any other name.
    pub fn about_slate(kind: &str, slate_id: SlateId) -> Option<Self> {
        match kind {
            DECLINED => Some(Self::Declined {
                slate_id,
                reason: None,
            }),
            WITHDRAWN => Some(Self::Withdrawn { slate_id }),
            CANCELLED => Some(Self::Cancelled { slate_id }),
            _ => None,
        }
    }

    /// The slate the notice is about; `None` for a notice about the pairing or for the host.
    pub const fn slate_id(&self) -> Option<SlateId> {
        match self {
            Self::Posted { slate_id, .. }
            | Self::Cancelled { slate_id }
            | Self::Declined { slate_id, .. }
            | Self::Withdrawn { slate_id } => Some(*slate_id),
            Self::PairFinished
            | Self::PairMatch { .. }
            | Self::PairMismatch { .. }
            | Self::Unpaired
            | Self::App { .. } => None,
        }
    }

    /// The notice's `type` on the wire.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Posted { .. } => POSTED,
            Self::Cancelled { .. } => CANCELLED,
            Self::Declined { .. } => DECLINED,
            Self::Withdrawn { .. } => WITHDRAWN,
            Self::PairFinished => PAIR_FINISHED,
            Self::PairMatch { .. } => PAIR_MATCH,
            Self::PairMismatch { .. } => PAIR_MISMATCH,
            Self::Unpaired => UNPAIRED,
            Self::App { .. } => APP,
        }
    }

    /// The notice as it goes over a method, padded to `length` of the method's `lengths`, which
    /// [`notice_length`] draws, or to the next of them it fits. The engine sends no notice over
    /// a method without lengths.
    pub fn encode_to(&self, lengths: &[usize], length: usize) -> WireSlate {
        debug_assert!(
            !lengths.is_empty(),
            "a notice over a method without notice lengths"
        );
        WireSlate::text(MediaType::JSON, self.to_padded_text(lengths, length))
    }

    /// The notice as JSON padded to `length` of `lengths`, or to the next of them it fits, as
    /// it goes in a sealed envelope through a pairing's mailbox.
    pub fn to_padded_text(&self, lengths: &[usize], length: usize) -> String {
        pad_object(&self.to_text(), lengths, length)
    }

    /// The notice as unpadded JSON, for a carrier that pads it itself, such as a sealed
    /// envelope at an epic1 key. An `app` notice has no JSON form and goes as the app payload
    /// message type; for one this writes only its type, which a reader ignores.
    pub fn to_text(&self) -> String {
        let sas = match self {
            Self::PairMatch { sas } | Self::PairMismatch { sas } => Some(hex::encode(sas)),
            _ => None,
        };
        let written = Written {
            lepic: NOTICE_VERSION,
            kind: self.kind(),
            slate_id: self.slate_id().map(|slate_id| slate_id.to_string()),
            excess: match self {
                Self::Posted { excess, .. } => Some(excess.to_hex()),
                _ => None,
            },
            reason: match self {
                Self::Declined {
                    reason: Some(Reason::Declined),
                    ..
                } => Some(REASON_DECLINED),
                _ => None,
            },
            sas,
        };
        // A struct of strings and a number always serializes.
        serde_json::to_string(&written).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use proptest::prelude::*;

    use super::*;

    /// A copy of the Epicbox method's notice lengths.
    const NOTICE_LENGTHS: [usize; 3] = [2423, 2522, 2621];

    const _: () = assert!(NOTICE_LENGTHS[2] <= MAX_NOTICE_LEN);

    fn encode(notice: &Notice) -> WireSlate {
        notice.encode_to(&NOTICE_LENGTHS, NOTICE_LENGTHS[0])
    }

    const SLATE_ID: &str = "0436430c-2b02-624c-2032-570501212b00";

    fn slate_id() -> SlateId {
        SlateId::parse(SLATE_ID).unwrap()
    }

    fn excess() -> Commitment {
        Commitment::commit_value(1).unwrap()
    }

    fn text(notice: &Notice) -> String {
        encode(notice).as_text().unwrap().to_owned()
    }

    /// The notice as written, up to its padding.
    fn unpadded(notice: &Notice) -> String {
        let text = text(notice);
        let (head, pad) = text.split_once(r#""pad":""#).unwrap();
        assert!(pad.trim_end_matches(['"', '}']).chars().all(|c| c == PAD));
        format!("{}}}", head.trim_end_matches(','))
    }

    fn every_kind() -> [Notice; 9] {
        let slate_id = slate_id();
        [
            Notice::Declined {
                slate_id,
                reason: None,
            },
            Notice::Withdrawn { slate_id },
            Notice::Posted {
                slate_id,
                excess: excess(),
            },
            Notice::Cancelled { slate_id },
            Notice::Declined {
                slate_id,
                reason: Some(Reason::Declined),
            },
            Notice::PairFinished,
            Notice::PairMatch { sas: [0xab; 32] },
            Notice::PairMismatch { sas: [0x01; 32] },
            Notice::Unpaired,
        ]
    }

    #[test]
    fn notices_are_written_with_the_version_first() {
        insta::assert_snapshot!(
            every_kind().iter().map(unpadded).collect::<Vec<_>>().join("\n"),
            @r#"
        {"lepic":1,"type":"declined","slate_id":"0436430c-2b02-624c-2032-570501212b00"}
        {"lepic":1,"type":"withdrawn","slate_id":"0436430c-2b02-624c-2032-570501212b00"}
        {"lepic":1,"type":"posted","slate_id":"0436430c-2b02-624c-2032-570501212b00","excess":"0950929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"}
        {"lepic":1,"type":"cancelled","slate_id":"0436430c-2b02-624c-2032-570501212b00"}
        {"lepic":1,"type":"declined","slate_id":"0436430c-2b02-624c-2032-570501212b00","reason":"declined"}
        {"lepic":1,"type":"pair-finished"}
        {"lepic":1,"type":"pair-match","sas":"abababababababababababababababababababababababababababababababab"}
        {"lepic":1,"type":"pair-mismatch","sas":"0101010101010101010101010101010101010101010101010101010101010101"}
        {"lepic":1,"type":"unpaired"}
        "#
        );
    }

    #[test]
    fn the_unpadded_text_is_the_padded_one_without_its_pad() {
        for notice in every_kind() {
            assert_eq!(notice.to_text(), unpadded(&notice), "{notice:?}");
        }
    }

    #[test]
    fn every_kind_is_written_at_one_length_and_reads_back() {
        for notice in every_kind() {
            assert_eq!(text(&notice).len(), NOTICE_LENGTHS[0], "{notice:?}");
            assert_eq!(classify(&encode(&notice)), Payload::Notice(notice.clone()));
            assert_eq!(
                classify_text(&notice.to_text()),
                Payload::Notice(notice.clone()),
                "{notice:?}"
            );
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
            r#"{"type":"unpaired"}"#,
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
            r#"{"lepic":2,"type":"unpaired"}"#.to_owned(),
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
            r#"{"lepic":1,"type":"pair-match"}"#.to_owned(),
            r#"{"lepic":1,"type":"pair-mismatch","sas":"00"}"#.to_owned(),
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
        let payload = format!(r#"{{"lepic":1,"type":"unpaired","pad":"{padding}"}}"#);
        assert_eq!(classify_text(&payload), Payload::Oversize);
    }

    #[test]
    fn fields_a_kind_does_not_use_are_ignored() {
        for (payload, notice) in [
            (
                format!(
                    r#"{{"lepic":1,"type":"cancelled","slate_id":"{SLATE_ID}","excess":"zz"}}"#
                ),
                Notice::Cancelled {
                    slate_id: slate_id(),
                },
            ),
            (
                format!(r#"{{"lepic":1,"type":"withdrawn","slate_id":"{SLATE_ID}","note":"x"}}"#),
                Notice::Withdrawn {
                    slate_id: slate_id(),
                },
            ),
            (
                format!(
                    r#"{{"lepic":1,"type":"declined","slate_id":"{SLATE_ID}","reason":"busy"}}"#
                ),
                Notice::Declined {
                    slate_id: slate_id(),
                    reason: None,
                },
            ),
            (
                format!(r#"{{"lepic":1,"type":"unpaired","slate_id":"{SLATE_ID}","sas":7}}"#),
                Notice::Unpaired,
            ),
        ] {
            assert_eq!(
                classify_text(&payload),
                Payload::Notice(notice),
                "{payload}"
            );
        }
    }

    #[test]
    fn stored_names_read_back_for_the_slate_kinds_only() {
        let slate_id = slate_id();
        for notice in every_kind() {
            let named = Notice::about_slate(notice.kind(), slate_id);
            match notice {
                Notice::Withdrawn { .. }
                | Notice::Cancelled { .. }
                | Notice::Declined { reason: None, .. } => assert_eq!(named, Some(notice)),
                Notice::Declined { .. } => assert!(named.is_some()),
                _ => assert_eq!(named, None, "{notice:?}"),
            }
        }
    }

    #[test]
    fn every_notice_length_is_written_exactly_and_none_is_an_old_one() {
        for length in NOTICE_LENGTHS {
            assert!(![256, 512].contains(&length));
            for notice in every_kind() {
                let wire = notice.encode_to(&NOTICE_LENGTHS, length);
                assert_eq!(wire.as_text().unwrap().len(), length, "{notice:?}");
                assert_eq!(classify(&wire), Payload::Notice(notice));
            }
        }
    }

    #[test]
    fn drawn_lengths_cover_every_bucket() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let drawn: std::collections::BTreeSet<usize> = (0..64)
            .map(|_| notice_length(&NOTICE_LENGTHS, &mut rng))
            .collect();
        assert_eq!(drawn, NOTICE_LENGTHS.into_iter().collect());
    }

    #[test]
    fn an_object_too_long_for_its_length_takes_the_next_one() {
        let long = format!(r#"{{"a":"{}"}}"#, "x".repeat(NOTICE_LENGTHS[0]));
        assert_eq!(
            pad_object(&long, &NOTICE_LENGTHS, NOTICE_LENGTHS[0]).len(),
            NOTICE_LENGTHS[1]
        );
        let longer = format!(r#"{{"a":"{}"}}"#, "x".repeat(NOTICE_LENGTHS[2]));
        assert_eq!(
            pad_object(&longer, &NOTICE_LENGTHS, NOTICE_LENGTHS[0]),
            longer
        );
    }

    fn any_notice() -> impl Strategy<Value = Notice> {
        (any::<[u8; 16]>(), any::<[u8; 32]>(), 0..9_usize).prop_map(|(bytes, sas, at)| {
            let slate_id = SlateId::from_bytes(bytes);
            match at {
                0 => Notice::Declined {
                    slate_id,
                    reason: None,
                },
                1 => Notice::Declined {
                    slate_id,
                    reason: Some(Reason::Declined),
                },
                2 => Notice::Withdrawn { slate_id },
                3 => Notice::Posted {
                    slate_id,
                    excess: excess(),
                },
                4 => Notice::Cancelled { slate_id },
                5 => Notice::PairFinished,
                6 => Notice::PairMatch { sas },
                7 => Notice::PairMismatch { sas },
                _ => Notice::Unpaired,
            }
        })
    }

    proptest! {
        #[test]
        fn every_notice_reads_back_as_written(notice in any_notice()) {
            prop_assert_eq!(classify(&encode(&notice)), Payload::Notice(notice.clone()));
        }

        #[test]
        fn classifying_any_text_never_panics(text in ".{0,600}") {
            let _ = classify_text(&text);
        }
    }
}
