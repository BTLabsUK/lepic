# ADR 0034: Trust, versioning and probing between Epic wallets

Status: proposed

## Context

LEPIC talks to wallets that are not LEPIC: the CLI, the Epic GUI wallet, Stack Wallet and Epic
Pay. They never acknowledge a message that is not a slate, and an Epicbox relay drops an address's
whole queue after a few unacknowledged rounds. A LEPIC message sent to the wrong wallet costs its
owner their pending payments. LEPIC also wants to offer more to LEPIC peers: notices, pair
requests, an address proof, linked devices.

Nothing can prove that a peer runs the official app, since any fork can send the marker and the
feature bits. Attestation (Play Integrity, TPM) is central and identifies users. The design
therefore learns what a key has shown, treats that as a hint, and lets a wrong hint hurt only the
peer that gave it.

## Decision

### Two axes

*Compatibility* is what the software behind an Epicbox key has shown, learned per key.
*Relationship* is what the user has with a contact; only the app can derive it, because only the
app owns the address book. The pairing facts are columns of the contact record (`peer_heard_at`,
`peer_verified_at`, `peer_verdict`, `peer_features`, `payments_address`, `payments_key`,
`ended_reason`, `ended_at`, `heard_wait`, `heard_wait_mark`), not new state codes. The status
shown is derived, first match winning: Ended, keys changed, Waiting (the contact's wallet not
heard yet), Verified, Paired. An ended pairing never counts as paired.

### Compatibility: stored and derived

Per Epicbox key, one sealed `peer_compat` row holds only the time of the last marked message, the
time of the last unmarked slate, `claimed` (the `u32` feature word of the latest marked message),
`works` (the bits that worked with this key) and when `claimed` was last written. The row is found
by a keyed hash of the key (ADR 0033, `lepic-wallet peer tag v1`). Only Epicbox counts; file,
paste, QR and HTTP slates are tied to no key.

Derived (`PeerFacts::derive` in `lepic-wallet/src/peer_compat.rs`), never stored:

- **LEPIC or Epic.** LEPIC while the last marked message is newer than the last unmarked one;
  otherwise Epic. "Epic" is every other wallet as one group.
- **Notices.** LEPIC with a marked message within `NOTICE_WINDOW` (30 days).
- **Fresh.** Notices, and no unmarked slate within `NOTICE_WINDOW`. Unasked sends need it.

A pairing keeps its own copy of the peer's feature word, since a peer may have no proven key.
Rules about a pairing read that copy; rules about a payments address read the key's row.

### The feature registry

A `u32` that only grows. A bit is never reused or redefined (`lepic-transport/src/marker/features.rs`).

| Bit | Name | Meaning |
|---|---|---|
| 0 | `MARKER` | LEPIC marker and notices; implied by a marker without a word |
| 1 | `PAIR_REQUESTS` | Unasked pair requests over Epicbox |
| 2 | `ADDRESS_PROOF` | The address proof in pairing envelopes |
| 3 | `STATUS_NOTICES` | Pairing-outcome notices |
| 4 | `DEVICE_FORWARDING` | Linked-device forwarding (host bit) |
| 5 | `NAME_SERVICE` | Name service and listings (host bit) |
| 6 | `APP_PAYLOADS` | Keeping app payloads that arrive over a pairing |
| 7 | `NATIVE_SLATES` | `lepic.v1` slates (RFC 0003); never in the marker of a file or paste slate |
| 8 to 15 | | Reserved |
| 16 to 31 | `HOST_PROFILE` | The host's profile of its owner (ADR 0041) |

LEPIC claims bits 0 to 3 and 6 for itself, the same for every wallet of a build. Of the word a
host passes (`WalletConfig::host_features`) it keeps only bits 4 and 5. A build claims 79 without
host bits and 127 with both. The word travels as `f` in the marker, and in pairing envelopes in
extension tag `0x82`, big-endian, with unknown bits kept and never refused. An `f` that is no
`u32` reads as a marker without a word. A wallet posting an app payload to a key whose recorded
word is known and lacks bit 6 logs a warning and reports it to the caller; the payload is posted
all the same. The CLI takes the host bits from its `host_features` setting.

### Rules that bind every check

1. **Bits never relax a check.** Signatures, the address proof, the short authentication string
   and sealed envelopes decide trust. A bit only decides whether a convenience is sent to that
   key. No code reads a bit to skip a check, so a peer that lies about a bit hurts only itself.
   Every review checks this.
2. **Never harm a relay queue.** A payload that is not a slate goes to a payments address only if
   the key is LEPIC within 30 days and the exchange's own incoming slate was marked. An unasked
   send (the pair request) also needs the key fresh and bit 1 claimed. Mailbox traffic between
   paired contacts is always safe.
3. **Nothing is sent only to learn.** Learning uses messages the user's own actions caused:
   payments, pairings, invoices. With no user action, a full listen and drain cycle sends nothing
   to any payments address.
4. **Identity features are opt-in and per relationship.** Pairing, address proof, linked devices
   and listings add no field to a transaction, kernel or output, and send nothing to a key that
   did not first deal with this wallet.

### The learning loop

A claim is a hint that a feature may be tried. A bit enters `works` only on its own event, and
only if the key claimed it:

| Bit | Works when |
|---|---|
| 0 | a marked slate or an accepted notice came from the key |
| 1 | a pair reply arrived for a request sent to the key |
| 2 | an address proof from the key verified |
| 3 | a verdict or `pair-finished` arrived in a pairing whose proof names the key |
| 4, 5 | the host reports success with `peer_feature_result(address, bit, worked)` |
| 6 | an app payload from the key was kept |

Silence is never evidence. A bit leaves `works` when the host reports a failure of its own
feature, or on a newer claim without the bit. An unmarked slate sets the last-unmarked time, which
makes the key Epic for every payments-address rule without touching the bits; the next marked
message refreshes the row. `peer_feature_result` takes exactly one host bit, sends nothing and
cannot start a bit the key did not claim. `works` is bookkeeping for later gating, not a check.

### The address proof

A pairing carries the peer's payments address in card tag `09` as `key@relay`. It is proved by a
designated-verifier MAC, never a signature: HMAC-SHA256 under a key from the prover's index-0 ECDH
with the verifier's own per-pairing mailbox key (ADR 0033), over `H(prover card) ‖ H(verifier
card) ‖ H(invite)`. The verifier can compute the same MAC, so the proof convinces nobody else. It
is computed only inside `lepic-wallet-contacts`; no signing call, listing signer or Ed25519 proof
signature can produce it, and no call exposes ECDH or a secret.

The step is 1 for a reply, 2 for a confirm and 3 for a contact update. A slot for a hash the step
does not have is 32 zero bytes. A contact update carries a proof only when the wallet's payments
address changed.

It travels in envelope extension `0x81` (32 bytes) in the reply, the confirm and the contact
update. The inviter's mailbox key is invite extension `0x81` (33 bytes). A reply or confirm that
must name the payments address the user expected fails with `AddressProofMissing` when the proof is
absent or does not verify, and with `OtherAddress` when it proves another address, with nothing
stored. A bad proof on a card update keeps the stored address. A pairing without a proof reports
no payments address, and attaching it by address fails with `AddressProofMissing`. Pairing again
gives it one.

### Listings

The listing calls take `(service_key, gen)`, derive keys by label (ADR 0033) and refuse app
domains that start with `lepic`.

### Privacy

- **Marker.** `f` travels only inside the Epicbox-encrypted slate, only where the marker already
  goes (an S1 sent, an S2 answering a marked S1), never in file, QR or paste slates. LEPIC's bits
  are a constant of the build. The marker's `version` stays 1 and no version string is sent.
- **Relay.** The relay is told `4.1.0` (`RELAY_WALLET_VERSION`), the version `epic-wallet` sends.
- **Padding.** Readers accept notices up to 8 KiB (`MAX_NOTICE_LEN`). Writers pad every plain
  notice, sealed notice and pair request to a length drawn at random from three buckets, 2,452,
  2,551 and 2,650 bytes: the JSON length of an S1 with one, two and three plain inputs and one
  change output, carrying the marker with `f`. No notice stands out by size.
- **At rest.** Compat rows are sealed, looked up by keyed hash, and deleted when not heard from
  for the age the host passes to `forget_peers`.
- **Never logged or backed up.** No Epicbox key, bit or date per peer appears in logs at info or
  above, in the feedback report, in `.wfeh` files or in contact backups. A contact backup carries
  the payments address and key a pairing proved, but not the peer's feature word or its heard and
  verified dates; an import sets heard to the pairing's creation time. Facts are relearned after
  a restore.

### Pairing outcome

- **Ended is final.** A pairing ends as `mismatch` (this side's check failed), `peer-mismatch`
  (the contact reported a failed check), `unpaired` (the contact took the pairing away) or
  `never-finished`. The row is kept, its invoices are dropped, nothing is sent through it, and a
  later status message changes nothing. A mismatch also stops collecting that mailbox.
- **Heard.** A pairing is Waiting until the contact's wallet is heard in it: its confirm, a
  verified message of it, or a reply the user took by hand. The verdicts `pair-match` and
  `pair-mismatch` carry the unkeyed BLAKE2b-256 hash of `lepic-wallet pairing verdict v1` ‖ the
  short authentication string, never the string, and count as heard. A verdict for another string
  is ignored. Status notices are sealed to the contact's mailbox, padded as every notice, and sent
  only to a pairing whose peer claims bit 3.
- **Never finished.** An inviter that has not heard the contact after `NEVER_FINISHED_AFTER`
  (7 days) of collecting ends the pairing as `never-finished` and tells the contact `unpaired`.
  Each gap between two collects counts for at most `HEARD_WAIT_MAX_GAP` (one hour), so a closed
  app adds at most an hour.
- **The outbox.** Status notices live in `contact_status_out` (kinds `finished`, `match`,
  `mismatch`, `unpaired`) and are retried for `STATUS_RETRY_FOR` (7 days), waiting 30 s, 2 min,
  10 min and then 30 min between tries. They are dropped without an event after that.
- **Pair requests.** A request goes to a contact's payments address as the plain notice
  `{"lepic":1,"type":"pair","invite":"epiccash://pair/1/…"}` with an invite of its own, which
  binds the answer to that address. It goes only to a key that is fresh and claims bit 1, and a
  failed post takes the invite back. The receiver keeps at most `MAX_LIVE_REQUESTS` (20) live and
  `MAX_SETTLED_REQUESTS` (100) settled requests in `pair_requests`, one per sender key with a
  newer replacing the older, stored before the relay message is acknowledged. A request from a
  key with a live pairing, or for an invite already dismissed or answered, is ignored.
- **The standing invite.** The invite a person shows to anyone lasts `REQUEST_EXPIRY` (7 days) and
  is named by the setting `pairing.standing`. It is made anew after it was answered, when less
  than a day is left, on a relay change and on a rename.

RFC 0002 sections 7.1, 7.6 and 10.2 carry the rules.

## Consequences

- A stock wallet on the phrase of a LEPIC key is never sent a plain notice. Two installs on one
  phrase flip the key as either answers; each flip is right for the moment it describes, and one
  notice per marked exchange is the accepted residue.
- A message that carries `f` or the extension `0x82` is read by every build that knows the tag;
  bits it does not know are kept.
- A bit added later takes a row here, a claim path and a `works` event in the same commit.
- Rule 1 is a review item for every change that reads `claimed` or `works`.
- A third message after an S1 and S2 is a pattern, and a pair request links its two mailboxes to
  its two addresses at the relay.

## Alternatives considered

- One compatibility level scale: a relationship and a capability are different facts with
  different owners and different lifetimes.
- A version string in the marker: fingerprints every user by build; the word is a constant.
- Probing with test messages: it hurts the wallets it probes and is a scanner.
- Trusting a claim to skip a check: a fork could skip any check by claiming the bit.
- Attestation: central, and identifies users.

## Related

- ADR 0016: Epicbox notices and the per-exchange rule.
- ADR 0033: keys and domains.
- RFC 0002: contact pairing.
