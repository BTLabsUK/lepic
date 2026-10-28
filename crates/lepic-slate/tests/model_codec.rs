// SPDX-License-Identifier: Apache-2.0
//! Codec registration, detection and dispatch, with codecs defined only for this test.

#![cfg(test)]

mod model_fixtures;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lepic_slate::codec::{Codec, CodecId, EncodeContext, MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, EncodeError, RegistryError, Unrepresentable};
use lepic_slate::model::Slate;
use lepic_slate::origin::WireOrigin;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::stage::Stage;
use model_fixtures::*;

const ALPHA: CodecId = CodecId::new("test.alpha");
const BETA: CodecId = CodecId::new("test.beta");
const ANY: CodecId = CodecId::new("test.any");

const CONTEXT: EncodeContext = EncodeContext {
    block_header_version: 6,
};

/// Writes `<prefix>:<stage>` and decodes it back to the fixture slate of that stage.
struct PrefixCodec {
    id: CodecId,
    prefix: &'static str,
    carries_payment_proof: bool,
    detect_calls: Arc<AtomicUsize>,
}

impl PrefixCodec {
    fn new(id: CodecId, prefix: &'static str) -> Self {
        Self {
            id,
            prefix,
            carries_payment_proof: true,
            detect_calls: Arc::default(),
        }
    }
}

fn fixture(stage: &str) -> Option<Slate> {
    Some(match stage {
        "S1" => s1(),
        "S2" => s2(),
        "S3" => s3(),
        "I1" => i1(),
        "I2" => i2(),
        "I3" => i3(),
        _ => return None,
    })
}

impl Codec for PrefixCodec {
    fn id(&self) -> CodecId {
        self.id
    }

    fn detect(&self, wire: &WireSlate) -> bool {
        self.detect_calls.fetch_add(1, Ordering::Relaxed);
        wire.as_text()
            .is_some_and(|text| text.starts_with(self.prefix))
    }

    fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError> {
        lepic_slate::validate::check_size(wire)?;
        let stage = wire
            .as_text()
            .and_then(|text| text.strip_prefix(self.prefix))
            .ok_or(DecodeError::NotRecognised { codec: self.id })?;
        let slate = fixture(stage).ok_or(DecodeError::Syntax {
            codec: self.id,
            position: None,
        })?;
        Ok(slate.with_origin(Some(WireOrigin::new(self.id))))
    }

    fn encode(&self, slate: &Slate, _: &EncodeContext) -> Result<WireSlate, EncodeError> {
        if slate.payment_proof().is_some() && !self.carries_payment_proof {
            return Err(EncodeError::Unrepresentable {
                codec: self.id,
                what: Unrepresentable::PaymentProof,
            });
        }
        Ok(WireSlate::text(
            MediaType::new("text/x-lepic-test"),
            format!("{}{}", self.prefix, slate.stage()),
        ))
    }
}

fn registry() -> CodecRegistry {
    let mut registry = CodecRegistry::new();
    registry
        .register(Box::new(PrefixCodec::new(ALPHA, "alpha:")))
        .unwrap();
    registry
        .register(Box::new(PrefixCodec::new(BETA, "beta:")))
        .unwrap();
    registry
}

fn text(content: &str) -> WireSlate {
    WireSlate::text(MediaType::new("text/x-lepic-test"), content.to_owned())
}

#[test]
fn detects_the_codec_and_dispatches_decoding_to_it() {
    let registry = registry();
    for (wire, codec) in [("alpha:S2", ALPHA), ("beta:I1", BETA)] {
        let wire = text(wire);
        assert_eq!(registry.detect(&wire).map(Codec::id), Ok(codec));
        let slate = registry.decode(&wire).unwrap();
        assert_eq!(slate.origin().map(WireOrigin::codec), Some(codec));
    }
    assert_eq!(
        registry.decode(&text("alpha:S2")).unwrap().stage(),
        Stage::S2
    );
    assert_eq!(
        registry.decode(&text("beta:I1")).unwrap().stage(),
        Stage::I1
    );
}

#[test]
fn bytes_are_detected_as_text_when_they_are_utf8() {
    let wire = WireSlate::binary(MediaType::OCTET_STREAM, b"beta:S3".to_vec());
    assert_eq!(registry().decode(&wire).unwrap().stage(), Stage::S3);
    let invalid = WireSlate::binary(MediaType::OCTET_STREAM, vec![0xff, 0xfe]);
    assert_eq!(registry().decode(&invalid), Err(DecodeError::UnknownFormat));
}

#[test]
fn encoding_then_decoding_returns_the_same_slate() {
    let registry = registry();
    for slate in [s1(), s2(), s3(), i1(), i2(), i3()] {
        for codec in [ALPHA, BETA] {
            let wire = registry.encode(codec, &slate, &CONTEXT).unwrap().unwrap();
            let decoded = registry.decode(&wire).unwrap();
            assert_eq!(decoded.origin().map(WireOrigin::codec), Some(codec));
            assert_eq!(decoded.with_origin(None), slate);
        }
    }
}

#[test]
fn rejects_input_no_codec_recognises() {
    assert_eq!(
        registry().decode(&text("gamma:S1")),
        Err(DecodeError::UnknownFormat)
    );
    assert_eq!(
        registry().decode(&text("")),
        Err(DecodeError::UnknownFormat)
    );
}

#[test]
fn decoding_errors_of_the_detected_codec_are_returned() {
    assert_eq!(
        registry().decode(&text("alpha:S9")),
        Err(DecodeError::Syntax {
            codec: ALPHA,
            position: None
        })
    );
}

#[test]
fn only_accepted_codecs_are_asked() {
    let registry = registry();
    let wire = text("alpha:S1");
    assert_eq!(
        registry.decode_accepted(&wire, &[BETA]),
        Err(DecodeError::UnknownFormat)
    );
    assert_eq!(
        registry
            .decode_accepted(&wire, &[BETA, ALPHA])
            .map(|slate| slate.stage()),
        Ok(Stage::S1)
    );
    assert_eq!(
        registry.decode_accepted(&wire, &[]),
        Err(DecodeError::UnknownFormat)
    );
}

#[test]
fn first_registered_codec_wins_when_several_recognise_the_input() {
    let mut registry = registry();
    registry
        .register(Box::new(PrefixCodec::new(ANY, "")))
        .unwrap();
    assert_eq!(registry.detect(&text("alpha:S1")).map(Codec::id), Ok(ALPHA));
    assert_eq!(registry.detect(&text("other")).map(Codec::id), Ok(ANY));
    assert_eq!(registry.ids().collect::<Vec<_>>(), [ALPHA, BETA, ANY]);
}

#[test]
fn rejects_a_second_codec_with_the_same_id() {
    let mut registry = registry();
    assert_eq!(
        registry.register(Box::new(PrefixCodec::new(ALPHA, "other:"))),
        Err(RegistryError::DuplicateCodec { codec: ALPHA })
    );
    assert_eq!(registry.ids().count(), 2);
}

#[test]
fn rejects_oversized_input_before_any_codec_looks_at_it() {
    let codec = PrefixCodec::new(ALPHA, "alpha:");
    let calls = Arc::clone(&codec.detect_calls);
    let mut registry = CodecRegistry::new();
    registry.register(Box::new(codec)).unwrap();
    let mut content = String::from("alpha:S1");
    content.push_str(&" ".repeat(MAX_WIRE_SLATE_LEN));
    let len = content.len();
    assert_eq!(
        registry.decode(&text(&content)),
        Err(DecodeError::TooLarge {
            len,
            max: MAX_WIRE_SLATE_LEN
        })
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn encoding_fails_instead_of_dropping_what_the_format_cannot_carry() {
    let mut registry = CodecRegistry::new();
    registry
        .register(Box::new(PrefixCodec {
            carries_payment_proof: false,
            ..PrefixCodec::new(BETA, "beta:")
        }))
        .unwrap();
    let proposal = lepic_slate::model::Proposal {
        payment_proof: Some(payment_proof()),
        ..send_proposal()
    };
    let slate =
        Slate::propose(lepic_slate::stage::Flow::Standard, proposal, participant(1)).unwrap();
    assert_eq!(
        registry.encode(BETA, &slate, &CONTEXT),
        Some(Err(EncodeError::Unrepresentable {
            codec: BETA,
            what: Unrepresentable::PaymentProof
        }))
    );
    assert_eq!(registry.encode(ALPHA, &slate, &CONTEXT), None);
}
