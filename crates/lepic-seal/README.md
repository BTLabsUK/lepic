# lepic-seal

The sealed envelope format of RFC 0002 and RFC 0003: the header, HPKE encryption to an X25519
key, the signed inner TLV fields, padding, the text armors and the contact card. A pure crate:
callers pass in keys, the random number generator and the time.

## Where it fits

- Depends on no other LEPIC crate. It builds on `hpke`, `ed25519-dalek`, `x25519-dalek`,
  `sha2`, `hmac` and `base64`.
- Used by `lepic-contact`, which re-exports most items here and adds the pairing flows, and by
  `lepic-wallet-contacts`.
- No features.
- Holds the format only. Which key a wallet seals to, and what it does with an opened envelope,
  belongs to the crates above.

## Core concepts

- **Envelope.** A 16-byte header (magic `89 45 53 45`, version, network, suite, flags, hint),
  the 32-byte HPKE encapsulated key, and the encrypted inner fields, which carry the
  message type. An envelope is at most `MAX_ENVELOPE_LEN` (1 MiB). `SUITE` 1 is DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256 and ChaCha20-Poly1305 in base mode; `SUITE_PSK` is the same suite in PSK mode, for
  private pairings.
- **Signed fields.** The inner fields are TLV records. An envelope can be signed with the
  sender's Ed25519 key for this contact; the signature is tag `0xFF` and covers every field
  before it. Unknown tags below `0x80` refuse the envelope; from `0x80` up they are skipped.
- **Hint.** Eight bytes in the header let a recipient pick the key to open with, without trying
  every key it holds (`Hint`, `HintRule`).
- **Key classes.** HPKE `info` binds each envelope to a `KeyClass`: `Seal` (a contact, one-time
  reply or pairing key), `Epic1`, `Listener` (onion or web) and `Epicbox`. A key of one class
  cannot open an envelope sealed for another.
- **Slate envelopes.** A `lepic.v1` slate travels as message type `0A` (`NATIVE_SLATE`), always
  padded (padding field `0xFE`), with an optional reply mailbox (tag `09`). `seal_tx` writes it
  and `SealedEnvelope::open_tx` reads it; the RFC 0002 reader refuses both.
- **Armor and links.** Envelopes travel as text in `BEGINEPICSEALED. ... ENDEPICSEALED.`, or
  `BEGINEPICTX. ... ENDEPICTX.` for slate envelopes; readers take either. `classify` sorts pasted
  payment text into its kind. Contact cards travel as `epiccash://contact/1/` links.
- **Domain claims** (ADR 0043). A contact can claim a domain and prove it with a long-lived
  domain key that signs its pairing key. The claim travels as extension `0x83`. This crate checks
  signatures and names only; whether the domain publishes the key is for the host and the wallet
  to decide.

## Public API

| Area | Items |
|---|---|
| Sealing | `seal`, `seal_padded`, `seal_psk`, `seal_psk_padded`, `seal_tx`, `Content`, `TxContent`, `TxKey`, `MessageType`, `KeyClass`, `padme`, `pad_target` |
| Opening | `SealedEnvelope` (`decode`, `hint`, `open`, `open_from`, `open_tx`, `open_psk`, `open_from_psk`), `Opened`, `TxOpened` |
| Keys | `EncPublicKey`, `EncSecretKey`, `HintKey`, `PresharedKey`, `SigningKey`, `VerifyingKey`, `Hint`, `HintRule` |
| Armor | `armor`, `armor_tx`, `dearmor`, `dearmor_marked`, `looks_sealed`, `classify`, `PaymentFile` |
| Cards and claims | `ContactCard`, `CardFields`, `Capabilities`, `ContactKind`, `DomainClaim`, `DomainKey`, `DomainName` |
| Checked text | `ContactName`, `MailboxAddress`, `RelayHost`, `Reference`, `InviteId`, `PairingCode`, `ReplyMailbox` |
| Errors | `DecodeError`, `EncodeError`, `KeyError`, `Malformed`, `TextError`, `DomainError` |

## Related

- [EPICTX native slates](../../docs/protocols/epictx.md), [Contact pairing](../../docs/protocols/pairing.md)
- [RFC 0002: contact pairing](../../docs/rfcs/0002-contact-pairing.md),
  [RFC 0003: EPICTX native slates and sealing](../../docs/rfcs/0003-epictx-native-slates.md)
- [`lepic-contact`](../lepic-contact/README.md), [`lepic-native-slate`](../lepic-native-slate/README.md)
