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
`ended_reason`) as columns of the contact record, not new state codes, so older backups still
import. The columns are `peer_heard_at`, `peer_verified_at`, `peer_verdict`, `peer_features`,
`payments_address`, `payments_key`, `ended_reason` (`mismatch`, `peer-mismatch`, `unpaired`,
`never-finished`) and `ended_at`, plus `heard_wait` and `heard_wait_mark` for the inviter's timer
(schema 13). The status shown is derived, first match winning: Ended, keys changed, Waiting (the
contact's wallet not heard yet), Verified, Paired. An ended pairing never counts as paired.

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
| 5 | Name service and listings | the app (host bit) | the app reports a name-service exchange succeeded |
| 6 | App payloads | marker word, pairing envelope | an app payload from the key was kept |
| 7 to 31 | Reserved | | |

The marker word is `f` inside the marker; pairing envelopes carry the same `u32` in extension tag
`0x82`, big-endian, unknown bits kept and never refused. The app passes bits 4 and 5 as one build
constant (`WalletConfig::host_features`); LEPIC keeps only those two bits of it and adds its own,
bits 0 to 3 and 6, so the word this build claims is 79 without the host and 127 with both host
bits. A wallet posting an app payload to a key whose recorded word is known and lacks bit 6
logs a warning and reports it to the caller; the payload is posted all the same.
The marked V2 and V3 JSON codecs (`MarkedV2JsonCodec`, `MarkedV3JsonCodec`) write it as `f`
(`with_features`) and read it back; an `f` that is no `u32` reads as a marker without a word. The
word is the same for every user of a build; the CLI, which has no app around it, takes the
host bits from its `host_features` setting, which the operator of a service sets once for its
wallets, masked to bits 4 and 5 the same way. Vectors:
`testdata/vectors/epicbox/marker_s1_v2_features_5` and `_53` (a marker with `f` of 5 and of 53,
to pin the codec).

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
event in the table's last column, and only if the key claimed it. Silence is never evidence; a
person may ignore a request. A bit leaves `works` when the host reports a failure of its own
feature, or on a newer claim without the bit (an older LEPIC took over the phrase), which also
takes it out of `claimed`. An unmarked slate sets the last-unmarked date, which makes the key
Epic for every payments-address rule without touching the bits. The next marked message refreshes
the row.

The hooks: a marked slate or an accepted notice records the marker bit and the word it carried; a
pairing that proved the contact's payments key records the word of its envelopes as the key's
claim and marks the address proof as working; a verdict or `pair-finished` from such a pairing
marks the outcome notices as working. The host reports its own two bits with
`peer_feature_result(address, bit, worked)`, which takes exactly one host bit and nothing else,
sends nothing, and cannot start a bit the key did not claim. A pair reply that arrives for a request
sent to the key marks the pair-request bit as working. `works` is bookkeeping for later gating,
not a check.

### The address proof

The pairing carries the peer's payments address in card tag `09` as `key@relay`. It is proved by a
designated-verifier MAC, never a signature: HMAC under a key from the prover's index-0 ECDH with
the verifier's own per-pairing mailbox key (0033), over hashes of both cards and of the invite.
The verifier can compute the same MAC, so the proof convinces nobody else. It is computed only
inside `lepic-wallet-contacts`; no signing call, listing signer or Ed25519 proof signature can
produce it, and no call exposes ECDH or a secret.

The proof key is `HKDF-SHA256(salt = lepic/addr-proof/1, ikm = x(ECDH), info = "mac" ‖ net ‖
step)`, with the step 1 for a reply, 2 for a confirm and 3 for a contact update; the MAC is
HMAC-SHA256 over `H(prover card) ‖ H(verifier card) ‖ H(invite)` (0033 explains why the info
carries a step and not a role). A slot for a hash the step does not have is 32 zero bytes: the
verifier's card in a reply, whose commitment is in the invite, and the invite in an update. A
contact update carries a proof only when the wallet's payments address changed (a relay switch).

A pairing made before this release never gets a proof: it stays unproven, reports no payments
address, and attaching it by address fails with `AddressProofMissing`. Pairing again gives it
one. Nothing marks such a pairing proven or verified.

Where it travels: envelope extension `0x81`, 32 bytes, in the reply, the confirm and the contact
update (any other length is skipped like an unknown extension). The inviter's mailbox key, the
key the invitee's proof is made for, is invite extension `0x81`, 33 bytes (the key of its card's
tag `08`). The verifier's key is always its own mailbox key of this pairing. A reply or confirm
that must name the payments address the user expected fails with `AddressProofMissing` when the
proof is absent or does not verify, and `OtherAddress` when it proves another address, with
nothing stored. A bad proof on a card update keeps the stored address; the card is still taken
for its other fields. Vector: `keys/address_proofs` (the three steps, made from both sides).

### Listings

The listing calls take `(service_key, gen)`, derive keys by label (0033), and refuse app domains
that start with `lepic`. A receive on a listing address never signs with index 0 and refuses a payment-proof
request; every later message of that transaction goes out from the listing key or is withheld.
Other wallets' proof requests on normal receives are handled as before.

### Privacy

- **Marker.** `f` travels only inside the Epicbox-encrypted slate, only where the marker already
  goes (an S1 sent, an S2 answering a marked S1), never in file, QR or paste slates. LEPIC's own
  bits are a constant of the build, the same for every user of a release; only the host bits come
  from the host, the app's build constant or the CLI's `host_features` setting, so a service
  stands out by the features it offers and a wallet does not. The marker's `version` stays 1 and
  no version string is sent.
- **Relay.** The relay is told `4.1.0`, as `epic-wallet` v4.1.0 sends (`RELAY_WALLET_VERSION`).
  Tor is recommended where Epicbox is set up.
- **Padding.** Readers accept notices up to 8 KiB. Writers pad every plain notice, sealed notice
  and pair request to a bucket drawn at random from the JSON lengths of an S1 this wallet would
  write with 1, 2 and 3 inputs, so none is told apart by size. There is no exception for older
  peers. A release with the 512-byte reader acknowledges and drops a longer notice, so it gets no
  notices from this build; it still acknowledges them, so no relay queue is harmed. That is the
  accepted cost of no compatibility code. `MAX_NOTICE_LEN` is 8,192 bytes; the three buckets are
  2,452, 2,551 and 2,650 bytes, the JSON length of an S1 with one, two and three plain inputs and
  one change output, carrying the marker with `f`.
  The residue is accepted: a third message after an S1 and S2 is a pattern, and a pair request
  links its two mailboxes to its two addresses at the relay.
- **At rest.** Compat rows are sealed, looked up by keyed hash, and deleted after 180 days
  untouched (`forget_peers`; the app passes the days).
- **Never logged or backed up.** No Epicbox key, bit or date per peer appears in logs at info or
  above, in the feedback report, in `.wfeh` or in contact backups: a contact backup carries the payments address and key a pairing
  proved, but not the peer's feature word or its heard and verified dates, and an import sets
  heard to the pairing's creation time. Facts are relearned after a restore. Deleting the wallet deletes them.

### Pairing outcome

- **Ended is final.** A pairing ends as `mismatch` (this side's check failed), `peer-mismatch`
  (the contact reported a failed check), `unpaired` (the contact took the pairing away) or
  `never-finished` (below). The row is kept, its invoices are dropped, nothing is sent through it
  and a later status message changes nothing. A mismatch also stops collecting that mailbox, so a
  sealed answer waits on the relay and the send can still be cancelled.
- **Heard.** A pairing is Waiting until the contact's wallet is heard in it: its confirm or a
  verified message of it, or a reply the user took by hand. Verdicts `pair-match` and
  `pair-mismatch` carry the unkeyed BLAKE2b-256 hash of `lepic-wallet pairing verdict v1` ‖ the
  short authentication string (0033), never the string, and count as heard; a verdict for another
  string is ignored and a repeated match changes nothing. Status notices are sealed to the
  contact's mailbox, padded as every notice, and sent only to a pairing whose peer claims bit 3.
- **Never finished.** An inviter that never hears the contact ends the pairing as
  `never-finished` after seven days of collecting, and tells it `unpaired`. The seven days count
  only time the wallet could collect: each counted gap between two collects counts for at most one hour
  (`HEARD_WAIT_MAX_GAP`), so a closed app adds at most an hour.
- **The outbox.** Status notices are kept and retried for 7 days, waiting 30 s, 2 min, 10 min and
  then 30 min between tries, and are dropped without an event. They live in `contact_status_out`
  (kinds `finished`, `match`, `mismatch`, `unpaired`).
- **Pair requests.** A request goes to a contact's payments address as the plain notice
  `{"lepic":1,"type":"pair","invite":"epiccash://pair/1/…"}` with an invite of its own, which binds
  the answer to that address (the pairing then expects a proof from that key). It goes only to a
  key that is fresh and claims bit 1, and a failed post takes the invite back. The receiver keeps
  at most 20 live and 100 settled requests (`pair_requests`), one per sender key with a newer
  replacing the older, stored before the relay message is acknowledged. A request from a key with
  a live pairing, or for an invite already dismissed or answered, is ignored.
- **The standing invite.** The invite a person shows to anyone lasts 7 days and is named by the
  setting `pairing.standing`. It is made anew after it was answered, when under a day is left, on
  a relay change and on a rename (which withdraws the old one).

RFC 0002 sections 7.1, 7.6 and 10.2 carry the rules.

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
