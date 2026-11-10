# lepic-legacy-slate

The V2 and V3 JSON slate codecs, matching the slates deployed `epic-wallet` versions read and
write, plus the LEPIC marker that one LEPIC wallet adds for another. A pure crate. The codecs
follow `epic-wallet` `v4.1.0` byte for byte, quirks included, and change only to fix a mismatch a
golden vector shows.

## Where it fits

- Depends on `lepic-crypto`, `lepic-primitives` and `lepic-slate`.
- Used by `lepic-wallet`, `lepic-wallet-contacts`, and by `lepic-transport` and `lepic-methods`
  under their `legacy` feature. Native slates between LEPIC wallets use `lepic-native-slate`
  instead (ADR 0052).
- No features.
- Does no I/O: it maps JSON text to a `Slate` and back.

## Core concepts

- **Two shapes, one model.** `V2JsonCodec` (id `legacy-v2`) and `V3JsonCodec` (id `legacy-v3`)
  both decode into the version-free `lepic_slate::model::Slate`. As in `epic-wallet`, the
  `ttl_cutoff_height` key alone tells the shapes apart: with it the slate is V3. V2 has no
  `payment_proof` either.
- **Fee floor.** Each codec takes a base fee and refuses a slate whose fee is below that fee per
  unit of the final transaction's weight.
- **Bounded decoding.** Arrays are read up to the counts a legacy slate may have; extra elements
  are counted but not parsed, so the memory a decode uses does not grow with the input.
- **The LEPIC marker.** `MarkedV2JsonCodec` and `MarkedV3JsonCodec` write the same slate plus a
  last top-level key `"lepic":{"version":1}`. Stock `epic-wallet` ignores the key and drops it
  when it rewrites the slate, so a reply that carries it came from LEPIC. Over Epicbox the
  marker can carry claimed feature bits (`f`) and the key native slates are sealed to; in a file
  or paste slate it can carry an X25519 reply key (RFC 0002 section 5). No slate signature covers
  the key, and it authenticates nothing. A marked codec shares the id of its plain codec, so a
  registry holds one or the other.

## Public API

| Module | Main items |
|---|---|
| `v2_json` | `V2JsonCodec::new(base_fee)`, `LEGACY_V2_JSON` |
| `v3_json` | `V3JsonCodec::new(base_fee)`, `LEGACY_V3_JSON` |
| `marker::v2` | `MarkedV2JsonCodec` (`new`, `with_features`, `with_native_claim`) |
| `marker::v3` | `MarkedV3JsonCodec` (`new`, `with_reply_key`, `with_features`, `with_native_claim`), `carries_lepic_marker`, `lepic_marker_features`, `lepic_marker_reply_key` |

## Example

Decode a slate file of either shape and print its stage:

```rust
use lepic_legacy_slate::v2_json::V2JsonCodec;
use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::registry::CodecRegistry;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: show-slate <file.json>")?;
    let json = std::fs::read_to_string(path)?;

    let base_fee = Network::Mainnet.params().default_base_fee();
    let mut codecs = CodecRegistry::new();
    codecs.register(Box::new(V3JsonCodec::new(base_fee)))?;
    codecs.register(Box::new(V2JsonCodec::new(base_fee)))?;

    let slate = codecs.decode(&WireSlate::text(MediaType::JSON, json))?;
    println!("{} at stage {:?}", slate.id(), slate.stage());
    Ok(())
}
```

## Related

- [Legacy slates](../../docs/compat/legacy-slates.md), the field-by-field reference
- [Architecture: slates, codecs and methods](../../docs/architecture.md#slates-codecs-and-methods)
- [ADR 0002: slate domain and codecs](../../docs/adr/0002-slate-domain-and-codecs.md),
  [ADR 0052: legacy at the edge](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)
- [`lepic-slate`](../lepic-slate/README.md), [`lepic-native-slate`](../lepic-native-slate/README.md)
