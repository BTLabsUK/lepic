# lepic-contact

The message formats of contact pairing (RFC 0002): the invite, the pairing reply and confirm,
private pairings, the key check after a restore and the short authentication string (SAS). A pure crate: callers pass in keys, the random number generator and the time. It
builds on the envelope of `lepic-seal` and re-exports most of its items.

## Where it fits

- Depends on `lepic-seal`, plus `hpke`, `ed25519-dalek`, `x25519-dalek`,
  `chacha20poly1305`, `sha2`, `hmac` and `base64`.
- Used by `lepic-epic1`, `lepic-wallet` and `lepic-wallet-contacts`. The pairing state, the
  mailboxes and the store records live in `lepic-wallet-contacts`.
- No features.

## Core concepts

- **Invite.** A pairing starts with an invite from A: an `epiccash://pair/1/` link carrying A's
  name, an expiry, a random code, a commitment to A's card, the key B seals its reply to and the
  home relay of the pairing.
- **Reply and confirm.** B answers with an envelope sealed to the invite's key, carrying the code
  and B's contact card. A checks it, stores the pairing and answers with a signed confirm carrying
  A's card. A refusal is an unsigned (anonymous) envelope with one status byte. When the mailbox
  is not used, the same envelopes travel as `epiccash://pair-reply/1/` and `epiccash://pair-confirm/1/` links.
- **SAS.** Both screens show the same short string after pairing (`Sas`, `SasSymbol`), so two
  people can compare them.
- **Private pairings.** `PairingClass::Private` links two wallets of one owner. Every envelope of
  the pairing is sealed in HPKE PSK mode under a channel key built from both sides' random
  secrets, so the recovery phrase alone does not find, read or write the channel.
- **Key check.** After a restore, a wallet can ask a contact over a new pairing whether it can
  take back the keys of the old one (types `06` and `07`), and send a contact update (type `05`).
  A found or restored answer carries a proof by a key of the old pairing.

## Public API

| Area | Items |
|---|---|
| Invite | `Invite`, `InviteFields`, `INVITE_FORMAT`, `MAX_INVITE_LEN` |
| Reply and confirm | `seal_reply`, `open_reply`, `seal_confirm`, `open_confirm`, `seal_refusal`, `ReplyBody`, `ConfirmBody`, `Confirm`, `Refusal`, `PairingLink`, `pairing_envelope_link`, `pairing_envelope_from_link` |
| Private pairing | `PairingClass`, `PrivateSecret`, `ChannelKey`, `seal_private_reply`, `open_private_reply`, `seal_private_confirm`, `open_private_confirm`, `private_sas` |
| SAS | `Sas`, `SasSymbol`, `symbol` |
| Key check | `KeyCheck`, `KeyCheckAnswer`, `KeyCheckProof`, `seal_key_check`, `open_key_check`, `seal_found`, `seal_restored`, `seal_not_found`, `seal_contact_update`, `open_contact_update` |
| Envelope | most items of [`lepic-seal`](../lepic-seal/README.md): sealing, opening, keys, armor, cards and checked text |
| Errors | `DecodeError`, `EncodeError`, `KeyError`, `Malformed`, `TextError`, `SasTableError` |

## Related

- [Contact pairing](../../docs/protocols/pairing.md)
- [RFC 0002: contact pairing](../../docs/rfcs/0002-contact-pairing.md)
- [`lepic-seal`](../lepic-seal/README.md), [`lepic-wallet-contacts`](../lepic-wallet-contacts/README.md)
