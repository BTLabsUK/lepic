# ADR 0069: Payment proofs for epic1 payments, signed by a tweak of the delivery key

Status: accepted
Date: 2026-11-23

## Terms

This record uses the glossary of ADR 0065. A payment proof (a receipt in code and on the wire) is
a signature by the payee over the facts of one payment, which anyone can check with only the
payee's epic1 address.

## Context

ADR 0063 §2 dropped payment proofs for epic1: the address carries a seal key and a delivery key,
no signing key, and one key is not used for both signing and sealing. Its Consequences said epic1
has no receipts until a receipt key comes in pairing or in a later address version.

Payers asked for proofs: a shop or an exchange that is paid at an epic1 address cannot show that
the owner of the address took a payment. The owner decided on 2026-11-22:

- proofs between LEPIC wallets (the CLI, `lepic serve`, the BT wallet app through LEPIC); stock
  Epic wallets are out of scope;
- the epic1 address does not change;
- proofs are always on, with no setting;
- the payer's key in a proof is one-time, from the seed and the slate id;
- a payer can require a proof.

## Decision

### 1. The receipt key is a public tweak of the delivery key

```text
t = SHA-256("lepic-epic1-receipt-key/1" || D)
R = D + t·G          r = d + t (mod n)
```

`D` is the delivery key of ADR 0063 §1 and `d` its secret. Anyone computes `R` from the address;
only the payee can sign with `r`.

- The seal key (X25519) stays apart from every signing key. This keeps the rule of ADR 0063 §2.
- The delivery key's ECDSA signs only the mailbox's socket challenge, over text the mailbox picks.
  `r` signs only receipts, over a message that starts with its own domain string. No message is
  valid for both.
- `t` is public, so `r` and `d` stand or fall together. Both stay in the payee's wallet.

### 2. The proof rides in the tx envelope

- S1 tag `84`: the payer's one-time key `P` (33 bytes), from the seed under the label
  `lepic-wallet receipt payer key v1` (ADR 0033) with context `account || net || slate id`.
- S2 tag `85`: the payee's 64-byte Schnorr signature (secp256k1-zkp `aggsig`, the challenge holds
  `R`) over the network, `D`, the amount, the kernel excess, the slate id and `P`.
- Readers skip tags from `0x80` up, so older wallets pay and answer as before, with no proof.
- The slate-level proof of `lepic.v1` (flag `04`) at an epic1 address stays refused.

The bytes, the nonce rule and the vectors are in `docs/protocols/epic1-receipt.md`.

### 3. The payer keeps and shows it

- A payer checks the proof when it finalizes and keeps one that holds with the payment.
- It exports the proof as a JSON file (`application/vnd.lepic.receipt+json`). Anyone verifies it
  with the address and, for whether it was posted, one kernel lookup on a node.
- A payer that requires a proof (a flag on the payment, a wallet setting, a field of the serve
  API) refuses an answer without one that holds: the payment is cancelled unfinalized and its
  inputs are unlocked.

## Consequences

- ADR 0063 §2 and its Consequences line on receipts are amended: epic1 payments carry a proof
  between LEPIC wallets. The retired proof key labels stay retired.
- A payment to a payee on 0.6.1 or older has no proof. A payer that requires one cannot pay it.
- The sealed content of an S1 grows by 36 bytes and that of an S2 by 67, before padding.
- A proof does not name the payer; the payer shows it is theirs by signing with the secret of
  `P`. LEPIC has no command for that yet.
- Checkout receipts (ADR 0068) are not built. They can use the same file and commands with their
  own `type`, signed by the shop's checkout key.

## Alternatives considered

- **A signing key in the address.** A third key, a new address version and 51 more characters.
  Refused: the address stays as it is.
- **Sign with the delivery key itself.** One key would sign mailbox challenges and receipts. The
  tweak costs one hash and one point addition and keeps them apart.
- **A receipt key sent in pairing.** Only paired contacts could get proofs, and a link payment
  from a stranger, the common case for a shop, would have none.
- **The payer's long-lived key in the proof.** It would tie the payer's payments together for
  anyone shown two proofs.

## Related

- ADR 0063 §2 and Consequences: amended here.
- ADR 0033: one new label.
- RFC 0003 §5.6: tags `84` and `85`.
- ADR 0068: checkout requests, where a checkout receipt would plug in.
