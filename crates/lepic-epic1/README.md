# lepic-epic1

The epic1 address and the epic1 payment link of RFC 0003: bech32m encoding, the two keys an
address holds, and the `epic:` link that adds route entries, an amount and a message. A pure
crate with no wallet, store, network I/O or FFI.

## Where it fits

- Depends on `lepic-contact` (the key types), `lepic-crypto`, `lepic-primitives` and
  `lepic-epicbox` (its `Network` type).
- Used by `lepic-wallet-contacts`, which pays and receives through epic1.
- No features.
- Hosts in a link come from untrusted input. This crate checks their syntax; the rule that
  decides which hosts a wallet dials is `host_rule` in `lepic-transport`.

## Core concepts

- **Address.** bech32m (BIP 350) with the human-readable part `epic` on mainnet and `tepic` on
  floonet. Its 66 data bytes are version `01`, the X25519 seal key and the secp256k1 delivery key
  (compressed, 33 bytes), and nothing else. A payer seals the slate to the seal key. The address
  is written in lower case and read in lower or upper case.
- **Link.** `epic:<epic1>?amount=<EPIC>&message=<text>&http=<host>[:<port>]&tor=<onion>[:<port>]`.
  The address part is the epic1 alone. The address's delivery key is its mailbox on every
  relay, so a link names no relay. `http=` and `tor=` entries say how else to deliver and never
  who is paid; a link with more than `MAX_TRANSPORTS` (3) of them is refused. An `epicbox=` entry,
  which links of earlier releases wrote, is not read and is reported in `Epic1Link::ignored`.
- **Amounts.** Decimal EPIC with up to eight decimals. Signs, exponents, separators, spaces and
  zero are refused.
- **Relay hosts.** Labels of letters, digits and hyphens; four decimal labels are an IPv4
  literal; IPv6 literals cannot be written.

## Public API

| Area | Items |
|---|---|
| Address | `Epic1Address` (`new`, `from_key_bytes`, `decode`, `decode_any`, `encode`, `network`, `seal_key`, `delivery_key`), `hrp`, `DATA_LEN`, `VERSION`, `Epic1Error` |
| Link | `Epic1Link` (`new`, `parse`, `to_uri`, `to_qr`), `Skipped`, `TransportFault`, `LinkError`, `MAX_TRANSPORTS` |
| Amounts and hosts | `parse_amount`, `format_amount`, `AmountError`, `RelayHost`, `parse_host_port`, `RelayHostError` |
| Encoding | `bech32m` |

## Example

```rust
use lepic_epic1::{Epic1Link, Network};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = Epic1Link::parse(
        "epic:epic1q8t44xqps2cs4d74f0ld8jtyquaqactj70d2vge94upp568hqag34pfq7qycjv98236gklwuks\
         l0wksdhuaq6f3crt6whf9f364fknn2dpsgqt?http=pay.example.org&amount=1.5&message=Rent",
    )?;
    assert_eq!(link.address.network(), Network::Mainnet);
    assert_eq!(link.message.as_deref(), Some("Rent"));
    for route in &link.routes {
        println!("also deliver via {} {}", route.method.as_str(), route.value);
    }
    Ok(())
}
```

## Related

- [epic1 addresses and links](../../docs/protocols/epic1.md)
- [RFC 0003: EPICTX native slates and sealing](../../docs/rfcs/0003-epictx-native-slates.md)
  (sections 5.13, 5.14 and Appendix B)
- [`lepic-seal`](../lepic-seal/README.md), [`lepic-wallet-contacts`](../lepic-wallet-contacts/README.md)
