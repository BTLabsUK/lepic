//! The codec registries legacy slates are read and written with: a V3 codec and a V2 codec,
//! plain or carrying the LEPIC marker.

use lepic_primitives::amount::Fee;
use lepic_slate::codec::Codec;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::registry::CodecRegistry;

/// The plain legacy codecs.
pub(crate) fn legacy(base_fee: Fee) -> CodecRegistry {
    legacy_with(
        Box::new(V3JsonCodec::new(base_fee)),
        Box::new(V2JsonCodec::new(base_fee)),
    )
}

/// The legacy codecs as `v3` and `v2`, a codec of each shape, such as one that carries the
/// LEPIC marker.
pub(crate) fn legacy_with(v3: Box<dyn Codec>, v2: Box<dyn Codec>) -> CodecRegistry {
    let mut codecs = CodecRegistry::new();
    // Registering fails only for an id already registered, and a codec of either shape keeps
    // the id of its shape, so the two never collide.
    let _ = codecs.register(v3);
    let _ = codecs.register(v2);
    codecs
}

#[cfg(test)]
mod tests {
    use lepic_epicbox::marker::v2::MarkedV2JsonCodec;
    use lepic_epicbox::marker::v3::MarkedV3JsonCodec;
    use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
    use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;

    use super::*;

    #[test]
    fn plain_and_marked_registries_hold_both_shapes() {
        let fee = Fee::new(1_000_000);
        let marked = legacy_with(
            Box::new(MarkedV3JsonCodec::new(V3JsonCodec::new(fee))),
            Box::new(MarkedV2JsonCodec::new(V2JsonCodec::new(fee))),
        );
        for codecs in [legacy(fee), marked] {
            let ids: Vec<_> = codecs.ids().collect();
            assert_eq!(ids, [LEGACY_V3_JSON, LEGACY_V2_JSON]);
        }
    }
}
