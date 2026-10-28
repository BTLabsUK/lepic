// SPDX-License-Identifier: Apache-2.0
//! Helpers the fuzz targets share. A target panics only to report a defect: a decoder that
//! panicked itself, or a decoded value that breaks a property the decoder promises.

use lepic_crypto::Commitment;
use lepic_primitives::amount::Fee;
use lepic_primitives::params::Network;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, EncodeContext};
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;

/// The fee rule is part of what the codecs check, so they get the real floonet base fee.
pub const BASE_FEE: Fee = Network::Floonet.params().default_base_fee();

pub const ENCODE_CONTEXT: EncodeContext = EncodeContext {
    block_header_version: 6,
};

/// Both legacy codecs, more specific first, as a wallet registers them.
pub fn legacy_codecs() -> CodecRegistry {
    let mut codecs = CodecRegistry::new();
    for codec in [
        Box::new(V3JsonCodec::new(BASE_FEE)) as Box<dyn Codec>,
        Box::new(V2JsonCodec::new(BASE_FEE)),
    ] {
        if codecs.register(codec).is_err() {
            panic!("the legacy codecs have distinct ids");
        }
    }
    codecs
}

/// A slate `codec` accepted must encode with the same codec and decode back to itself, and its
/// encoding must be stable. Only the wire origin may change on the way: the codecs write the
/// header version that follows the slate's shape (ADR 0020), whatever header it was read with.
pub fn assert_round_trips(codec: &dyn Codec, slate: &Slate) {
    let encoded = match codec.encode(slate, &ENCODE_CONTEXT) {
        Ok(encoded) => encoded,
        Err(error) => panic!("{} decoded a slate it cannot encode: {error}", codec.id()),
    };
    let decoded = match codec.decode(&encoded) {
        Ok(decoded) => decoded,
        Err(error) => panic!("{} rejected its own encoding: {error}", codec.id()),
    };
    assert_eq!(
        decoded.origin().map(|origin| origin.codec()),
        Some(codec.id()),
        "{} decoded its own encoding as another codec",
        codec.id()
    );
    assert_eq!(
        decoded.clone().with_origin(None),
        slate.clone().with_origin(None),
        "{} round trip changed the slate",
        codec.id()
    );
    match codec.encode(&decoded, &ENCODE_CONTEXT) {
        Ok(again) => assert_eq!(again, encoded, "{} encoding is not stable", codec.id()),
        Err(error) => panic!("{} cannot encode what it decoded: {error}", codec.id()),
    }
}

/// Every run of exactly 66 hex digits in `bytes` that parses as a commitment, in order. Lets a
/// target answer "was this commitment requested?" the way a client that asked for it would.
pub fn commitments_in(bytes: &[u8]) -> Vec<Commitment> {
    const HEX_LEN: usize = 66;
    bytes
        .split(|byte| !byte.is_ascii_hexdigit())
        .filter(|run| run.len() == HEX_LEN)
        .filter_map(|run| std::str::from_utf8(run).ok())
        .filter_map(|hex| Commitment::from_hex(hex).ok())
        .collect()
}
