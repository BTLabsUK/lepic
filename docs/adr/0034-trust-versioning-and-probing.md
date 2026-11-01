# 0034 Trust, versioning and probing between Epic wallets

Status: proposed
Date: 2026-11-01

Amends 0016 and RFC 0002 (3.3, 6.1, 7.1, 7.6, 10.2, 15, 16). Builds on 0016's schema-12 amendment
(storage and the per-exchange rule) and 0033 (keys and domains). Replaces the single compatibility
scale of earlier drafts.

## Context

LEPIC talks to wallets that are not LEPIC: the CLI, the old GUI, Stack Wallet and Epic Pay. They
never acknowledge a message that is not a slate, and the relay drops an address's whole queue after
three unacknowledged rounds. A LEPIC message sent to the wrong wallet costs its owner their pending
payments. At the same time LEPIC wants to offer more to LEPIC peers: notices, pair requests, an
address proof, linked devices.

Nothing can prove that a peer runs the official app. Any fork can send the marker and the bits.
Attestation (Play Integrity, TPM) is rejected: it is central and identifies users. So the design
learns what a key has shown, treats it as a hint, and lets a wrong hint hurt only the peer that
lied.

## Decision

### Two axes

*Compatibility* is what the software behind an Epicbox key has shown, learned per key.
*Relationship* is what the user has with a contact, and only the app can derive it because only the
app owns the address book. LEPIC stores the pairing facts (state, `verified_at`, `peer_heard_at`,
`ended_reason`) as columns (TODO(C: column names)), not new state codes, so older backups still import. An ended pairing
never counts as paired.

### Compatibility: stored and derived

Per Epicbox key, one sealed row (0016, schema 12) holds only: the last marked message, the last
unmarked slate, `claimed` (u32, the feature word of the latest marked message; bit 0 for a marker
without one), `works` (u32, bits that worked with this key), and when `claimed` was last written
(`None`: an older LEPIC that never sent one). The row is found by a keyed hash of the key (0033,
`lepic-wallet peer tag v1`). Only Epicbox counts; file, paste, QR and HTTP slates are tied to no
key and recorded for none.

Derived, never stored:

- **LEPIC or Epic.** LEPIC while the last marked message is newer than the last unmarked one; else
  Epic. "Epic" is every other wallet as one group; no brand is guessed.
- **LEPIC for a payments address.** Also needs a marked message in the last 30 days.
- **Fresh.** LEPIC for a payments address and no unmarked slate in the last 30 days. Unasked sends
  need it.

A pairing keeps its own copy of the peer's feature word, since a peer may have no proven key; rules
about a pairing read that copy, rules about a payments address read the key's row.

### The feature registry

A `u32` that only grows. A bit is never reused or redefined.

| Bit | Name | Claimed by | Works when |
|---|---|---|---|
| 0 | LEPIC marker and notices | any marker (implied when no word is sent) | a marked slate or an accepted notice from the key |
| 1 | Pair requests | marker word, pairing envelope | a pair reply arrived for a request sent to the key |
| 2 | Address proof | same | a proof from the key verified |
| 3 | Pairing-outcome notices | same | a verdict or `pair-finished` arrived in a pairing whose proof names the key |
| 4 | Linked-device forwarding | the app (host bit) | the app reports a forwarded item was taken |
| 5 | Directory and listings | the app (host bit) | the app reports a directory exchange succeeded |
| 6 to 31 | Reserved | | |

The marker word is `f` inside the marker; pairing envelopes carry the same `u32` in extension tag
`0x82`, big-endian, unknown bits kept and never refused. The app passes bits 4 and 5 as one build
constant; LEPIC masks the rest. TODO(B: marker codec names, `host_features`, the `0x82` vector).

### Rules that bind every check

1. **Bits never relax a check.** Signatures, the address proof, the short authentication string and sealed
   envelopes decide trust. A bit only decides whether to send a convenience to that key. No code
   reads a bit to skip a check; a peer that lies about a bit hurts only itself. Every review checks
   this.
2. **Never harm a relay queue.** A payload that is not a slate goes to a payments address only if
   the key is LEPIC within 30 days and the exchange's own incoming slate was marked (0016, schema
   12). An unasked send (the pair request) also needs the key fresh and bit 1 claimed. Mailbox
   traffic between paired contacts is always safe.
3. **Nothing is sent only to learn.** Learning uses messages the user's own actions caused:
   payments, pairings, invoices. With no user action, a full listen and drain cycle sends nothing
   to any payments address.
4. **Identity features are opt-in and per relationship.** Pairing, address proof, linked devices
   and listings add no field to a transaction, kernel, output or anything signed by them, and send
   nothing to a key that did not first deal with this wallet.

### The learning loop

A claim (`f` or `0x82`) is a hint that a feature may be tried. A bit enters `works` only on the
event in the table's last column. Silence is never evidence; a person may ignore a request. A bit
leaves `works` on a feature-specific failure (a proof from the key fails; a pair request is
answered "unknown") or on a newer claim without the bit (an older LEPIC took over the phrase); it
leaves `claimed` too in the second case. An unmarked slate sets the last-unmarked date, which makes
the key Epic for every payments-address rule without touching the bits. The next marked message
refreshes the row. TODO(C: names of the event hooks and `peer_feature_result` for the host bits).

### The address proof

The pairing carries the peer's payments address in card tag `09` as `key@relay`. It is proved by a
designated-verifier MAC, never a signature: HMAC under a key from the prover's index-0 ECDH with
the verifier's own per-pairing mailbox key (0033), over hashes of both cards and of the invite.
The verifier can compute the same MAC, so the proof convinces nobody else. It is computed only
inside `lepic-wallet-contacts`; no signing call, listing signer or Ed25519 proof signature can
produce it, and no call exposes ECDH or a secret. A bad proof on a card update keeps the stored
address. TODO(B: extension tag and error names after B lands).

### Listings

The listing calls take `(dkey, gen)`, derive keys by label (0033), and refuse app domains that start
with `lepic`. A receive on a listing address never signs with index 0 and refuses a payment-proof
request; every later message of that transaction goes out from the listing key or is withheld.
Other wallets' proof requests on normal receives are handled as before.

### Privacy

- **Marker.** `f` travels only inside the Epicbox-encrypted slate, only where the marker already
  goes (an S1 sent, an S2 answering a marked S1), never in file, QR or paste slates. It is a
  constant of the build, the same for every user of a release, never from a setting. The marker's
  `version` stays 1 and no version string is sent.
- **Relay.** The relay is told `4.1.0`, as `epic-wallet` v4.1.0 sends (`RELAY_WALLET_VERSION`).
  Tor is recommended where Epicbox is set up.
- **Padding.** Readers accept notices up to 8 KiB. Writers pad every plain notice, sealed notice
  and pair request to a bucket drawn at random from the JSON lengths of an S1 this wallet would
  write with 1, 2 and 3 inputs, so none is told apart by size. There is no exception for older
  peers. A release with the 512-byte reader acknowledges and drops a longer notice, so it gets no
  notices from this build; it still acknowledges them, so no relay queue is harmed. That is the
  accepted cost of no compatibility code. TODO(C: `MAX_NOTICE_LEN`, bucket lengths).
  The residue is accepted: a third message after an S1 and S2 is a pattern, and a pair request
  links its two mailboxes to its two addresses at the relay.
- **At rest.** Compat rows are sealed, looked up by keyed hash, and deleted after 180 days
  untouched (`forget_peers`; the app passes the days).
- **Never logged or backed up.** No Epicbox key, bit or date per peer appears in logs at info or
  above, in the feedback report, in `.wfeh` or in contact backups. Facts are relearned after a
  restore. Deleting the wallet deletes them.

### Pairing outcome

TODO(C: Ended is final and never counts as paired; verdicts carry the hash of the short
authentication string and count as heard; the 7-day outbox; the standing invite; pair requests).
RFC 0002 sections 7.1, 7.6 and 10.2 carry the rules once pairing v3 lands.

## Consequences

- A stock wallet on the phrase of a LEPIC key is never sent a plain notice again. Two installs on
  one phrase flip the key as either answers; each flip is right for the moment it describes, and
  one notice per marked exchange is the accepted residue.
- A peer on an older LEPIC release may not read the padded notices and drops them after
  acknowledging; no wire or store code exists for peers or linked devices of older releases.
- New bits take a row here, a claim path and a `works` event, in the commit that adds them. Bits
  are switched on in as few release waves as possible, so few distinct words exist.
- Rule 1 is a review item for every change that reads `claimed` or `works`.

## Alternatives considered

- One compatibility level scale: a relationship and a capability are different facts with
  different owners and different lifetimes.
- A version string in the marker: fingerprints every user by build; the word is a constant instead.
- Probing with test messages: it hurts the wallets it probes and is a scanner.
- Trusting a claim to skip a check: a fork could skip any check by claiming the bit.
- Attestation: central, and identifies users.
