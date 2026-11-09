# 0033 One registry of seed-derived keys and signature domains

Status: proposed
Date: 2026-11-01

Amends 0016 and RFC 0002 (sections 2 and 3.3) by listing the keys and tags they define.

## Context

LEPIC derives keys in four ways: BIP32 paths of the account (outputs, the Epicbox address, the
contact root), keyed BLAKE2b of the seed under a label, HKDF under a root or a code, and random
values. Each came with its feature and none was listed in one place. Three facts make a list
necessary:

- `m/<a>/1/<i>` is a branch other Epic wallets walk. `epic-wallet` hands out the key at any index
  and Stack Wallet's library signs Epicbox sends at any index. A LEPIC-only meaning on that branch
  can be reached, by accident, by another wallet on the same phrase.
- A signature made by another program with a key LEPIC also uses must not verify as a LEPIC
  message. Tags help only against signers that hash the message themselves; separate keys do not
  depend on that.
- Every restore, linked device and backup needs the same bytes from the same phrase for ever, so a
  shipped entry may not change meaning by accident.

Anyone holding the phrase holds every key below; no layout changes that. The registry decides only
that no honest wallet reaches a LEPIC key by chance and no LEPIC protocol accepts a foreign
signature.

## Decision

### The namespace

Every new key that is not a funds key is
`BLAKE2b-256(key = seed, msg = "lepic-wallet <purpose> v<n>" ‖ context)`, the construction of the
context key and the seed check. `seed` is the BIP39 entropy. No new BIP32 branch is used. A
32-byte result is an Ed25519 or X25519 secret directly; a secp256k1 key takes the first counter
value that makes a valid key, as `first_valid_key` does. The listing key's counter is one byte, tried from 0 up.
Each key has one function and one label constant in the crate that owns it, so a path or label is
changed in one edit and nothing else spells it. The wallet derives its subkeys in
`lepic_wallet::store_keys` (context key and peer tag key), `lepic_wallet::store_key` (database key,
0032) and `lepic_wallet::namespace` (listing keys and the device-link key).

Listing keys take `(service_key, gen)`: the service key (33 bytes) and a generation (u32 big-endian,
raised when a listing is left). Nothing is derived on `m/<a>/1/0x8000_0000` or above. A receive on
a listing address never signs with index 0 and refuses a payment-proof request.

### Rules

1. One key per purpose. A key that signs never encrypts or does ECDH. Index 0 of `m/<a>/1`, a
   listing key and the Epicbox mailbox keys are the recorded exceptions, below.
2. Every signature LEPIC defines is over a tagged digest or a domain-prefixed message. A new tag is versioned and
   distinct. LEPIC's own tags start `lepic/`; the domains an app passes to the listing signer never
   do, and the signer refuses any domain that starts with `lepic`, in any case. Shipped `epic-`
   tags are not renamed.
3. New tags are prefix-free among the tags used with one key or one primitive. Shipped tags that
   share a prefix (`epic-seal/1` and `epic-seal/1 sig`, `epic-pair/1 keycheck` and
   `epic-pair/1 keycheck found`, the `epic-private/1` family) stay apart by the primitive or the
   key they are used with, as the table says; they are not changed.
4. Labels end with ` v<n>`. No label is a prefix of another label followed by its context, and the
   context after a label is fixed-width or length-prefixed, so two entries cannot produce one
   input.
5. Nothing new goes on a BIP32 path. Index 0 does what stock does, plus the single use below.
6. A shipped entry never changes meaning. A change is a new label or tag version, a migration note
   and a new row; the old row becomes retired-reserved and its name is never reused.
7. No extended public key is exported.
8. Every entry LEPIC derives or signs has a vector under `testdata/vectors/`; vectors of new
   derivations go in `testdata/vectors/keys/`. No secret or ECDH output leaves LEPIC (0014).

### Recorded exception: index 0

One secret, `m/<a>/1/0`, serves the Epicbox address (ECDSA over the relay's challenge text),
Epicbox ECDH, the Ed25519 receiver and sender payment-proof key, and the seed of the previous
onion, as in `epic-wallet`. The onion LEPIC publishes has a key of its own (0044). Stock wallets send to this address and every wallet on the phrase drains its
mailbox, so it cannot move. LEPIC adds one use: an ECDH with a contact's mailbox key whose
output feeds only HKDF under `lepic/addr-proof/1` to make a MAC (0034). LEPIC makes no signature
of its own with this key: the device-link hello and the listing signer have keys of their own.
`lepic/address-signature/v1` is the shipped signature that did. The binding no longer exposes it
(`sign_with_address_key` and `verify_address_signature` are gone), the tag is retired-reserved, and
no LEPIC code signs under it.

### Recorded exception: the listing key

A listing key is the Epicbox identity of one name-service listing. It answers the relay's challenge
(ECDSA over text), does the Epicbox ECDH that opens messages to the listing address, and signs
the listing's messages under the listing tag (below). A payer sends to the address of the key that
signs the listing card, so the signer and the address cannot be two keys without a card that
carries both. The three uses stay apart by their inputs: the relay challenge is hashed as UTF-8
text, the listing signature is over a digest whose preimage holds a byte UTF-8 never uses, so no
text hashes to it; and the ECDH output goes only into Epicbox's own key derivation, never to a
signature or a MAC. A listing key is not reachable from the phrase by any stock wallet and no
other LEPIC key uses it. If this ever needs to change, the answer is a separate signing label and
a card that names both keys, as a new row.

### Recorded exception: Epicbox mailbox keys

The reply mailbox, post key and link mailbox keys (RFC 0003, ADR 0052) sign Epicbox texts
(`Subscribe`, `Made`, `PostSlate`) and do the Epicbox message ECDH, as the relay protocol requires
of any address key. Their ECDH output goes only into Epicbox's message cipher and their signatures
only over Epicbox texts. Every slate they carry is sealed again inside with HPKE to an X25519 seal
key that does nothing else, so the slate is readable only with that seal key. The contact mailbox
key, the pairing mailbox and the listing key sign and do ECDH in the same way. The exception covers
this class of key and no other use; the project owner approved it on 2026-11-08.

### The table

Columns: label or path · key type · purpose · owner crate · first release · status · vector.
"First release" is the first app release known to hold the entry; LEPIC has no tags, so older
entries read "≤ 26.10.24-r2". "Live" entries are in use or registered; "retired-reserved" are never
used again and never reused.

#### BIP32 paths (upstream defines them; LEPIC adds no use)

| Path | Type | Purpose | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| `m/<a>/0/<c>` | secp256k1 (Grin BIP32), switch commitment | Output blinding factors | `lepic-keychain` | ≤ 26.10.24-r2 | live | `keys/commitments_*`, `keys/derivation_*` |
| `m/<a>/1/0` | secp256k1; its bytes are also the Ed25519 and previous onion seed | Epicbox address, relay challenge signature, Epicbox ECDH, payment-proof key, previous onion (exception above, 0044) | `lepic-keychain`, `lepic-epicbox`, `lepic-tor` | ≤ 26.10.24-r2 | live | `keys/address_keys_*`, `epicbox/signature_*` |
| `m/<a>/1/1` to `m/<a>/1/0x7FFF_FFFF` | secp256k1 | Invoice inbox addresses of 26.10.0 to 26.10.15 | `lepic-wallet` | 26.10.0 | retired-reserved | none |
| `m/<a>/1/0x8000_0000` and above | none | Never used: reserved so no LEPIC key sits on the branch other wallets walk | none | none | retired-reserved | none |
| `m/<a>/2/0` | secp256k1, hashed into the contact root | Input of the contact root (below) | `lepic-wallet-contacts` | 26.10.20 | live | `pairing/contact_keys.json` |
| `m/<a>/2/<other>` | none | Reserved for LEPIC; nothing derived | none | none | retired-reserved | none |
| `m` (root, `derive_key(0, ROOT)`) | secp256k1 | Input of the backup-file keys (below); `epic-wallet` uses it for its own record keys | `lepic-keychain` | ≤ 26.10.24-r2 | live | `app_data/wfeh_*` |

#### Seed-keyed labels: `BLAKE2b(key = seed, label ‖ context)`

| Label | Type | Purpose | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| `lepic-wallet private context key v1` | 32-byte XChaCha20-Poly1305 key | Seals stored records: transaction contexts, pending invoices, pairing records and peer rows (associated-data domains under "Store domains") | `lepic-wallet` | ≤ 26.10.24-r2 | live | `store/peer_compat.json` |
| `lepic-wallet seed check v1` | 32-byte check value, not a key | Proves a phrase belongs to a database (setting `wallet.seed_check`) | `lepic-wallet` | ≤ 26.10.24-r2 | live | none yet |
| `lepic-wallet peer tag v1` | 32-byte BLAKE2b key | Keyed hash of an Epicbox key under which its compat row is stored | `lepic-wallet` | 26.10.25 | live | `store/peer_compat.json` |
| `lepic-wallet store key v1` | 32-byte raw key | Page encryption of the wallet database (0032) | `lepic-wallet` | 26.10.25 | live | `store_key/store_key_seed_*` |
| `lepic-wallet store check v1` ‖ salt(16) | BLAKE2b-128 keyed by the store key | The `.check` file that proves the store key before the database opens (0032) | `lepic-wallet` | 26.10.25 | live | `store_key/store_key_seed_*` |
| `lepic-wallet listing key v1` ‖ service_key(33) ‖ gen(u32 BE) ‖ ctr | secp256k1 (counter until valid) | Address, ECDH and signing key of one name-service listing (exception above) | `lepic-wallet::namespace` | 26.10.25 | live | `keys/listing_keys_seed32`, `keys/listing_keys_seed16` |
| `lepic-wallet onion key v1` | Ed25519 | The wallet's onion and the key that signs payment proofs asked for over it (0044). The 32 bytes are the Ed25519 seed; the context is empty | `lepic-wallet::namespace` | unreleased | live | `keys/onion_key_seed32`, `keys/onion_key_seed16` |
| `lepic-wallet api tls v1` | Ed25519 | The certificate key of `serve`'s owner TLS listener (0050). The 32 bytes are the Ed25519 seed; the context is empty | `lepic-wallet::namespace` | unreleased | live | `keys/api_tls_key_seed32`, `keys/api_tls_key_seed16` |
| `lepic-wallet seal key v1` ‖ account(u32 BE) ‖ net ‖ kind | X25519 | Opens envelopes sealed to the epic1 (`kind` 00), the onion listener (01) or the plain web listener (02) (RFC 0003, ADR 0052). The context is 6 bytes | `lepic-wallet::namespace` | unreleased | proposed | `pairing/seal_keys.json` |
| `lepic-wallet epic1 proof key v1` ‖ account(u32 BE) ‖ net | Ed25519 (the 32 bytes are the seed) | The proof key in the epic1 address; signs the payment proofs of slates that came to it (RFC 0003, O-8). The context is 5 bytes | `lepic-wallet::namespace` | unreleased | proposed | `keys/epic1_proof_key_seed32`, `keys/epic1_proof_key_seed16` |
| `lepic-wallet reply mailbox v1` ‖ account(u32 BE) ‖ net ‖ slate_id(16) ‖ ctr | secp256k1 (counter until valid) | Throwaway Epicbox mailbox for the answer to one slate; its address goes beside the reply key in envelope tag 09 (RFC 0003). The context is 22 bytes. Exception "Epicbox mailbox keys" | `lepic-wallet::namespace` | unreleased | proposed | `keys/reply_mailbox_seed32`, `keys/reply_mailbox_seed16` |
| `lepic-wallet post key v1` ‖ account(u32 BE) ‖ net ‖ slate_id(16) ‖ role ‖ ctr | secp256k1 (counter until valid) | Epicbox `from` key of every post to another party's mailbox for one slate; `role` 00 initiator, 01 responder. Nothing is received at it (RFC 0003). The context is 23 bytes. Exception "Epicbox mailbox keys" | `lepic-wallet::namespace` | unreleased | proposed | `keys/post_key_seed32`, `keys/post_key_seed16` |
| `lepic-wallet link mailbox v1` ‖ account(u32 BE) ‖ net ‖ kind ‖ n(u32 BE) ‖ ctr | secp256k1 (counter until valid) | Mailbox named by an epic1 link; `kind` 00 on screen (`n` 0 to 49, a new one per receive session or share, used in turn), 01 printed (`n` 0 to 31, fixed per code) (RFC 0003, ADR 0052). The context is 11 bytes. Exception "Epicbox mailbox keys" | `lepic-wallet::namespace` | unreleased | proposed | `keys/link_mailbox_seed32`, `keys/link_mailbox_seed16` |
| `lepic-wallet device link key v1` | Ed25519 | Signs the hello of a linked device; both devices on one phrase hold it, so a valid signature proves the same phrase. The 32 bytes are the Ed25519 seed; the context is empty | `lepic-wallet::namespace` | 26.10.25 | live | `keys/device_link_key_seed32`, `keys/device_link_key_seed16` |

#### HKDF and codes

| Label | Type | Purpose | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| HKDF-SHA256, salt `epic-contact/1`, ikm = BLAKE2b-256 of `m/<a>/2/0`, info `root` ‖ net | 32-byte root | Contact root | `lepic-wallet-contacts` | 26.10.20 | live | `pairing/contact_keys.json` |
| Expand(root, `enc` ‖ slot) | X25519 | Opens sealed envelopes of one contact | same | 26.10.20 | live | same |
| Expand(root, `sig` ‖ slot) | Ed25519 | Signs cards and envelopes to one contact | same | 26.10.20 | live | same |
| Expand(root, `hint` ‖ slot) | 32-byte key | Hint key of one contact | same | 26.10.20 | live | same |
| Expand(root, `box` ‖ slot ‖ box_salt ‖ ctr) | secp256k1 | Epicbox mailbox key of one contact | same | 26.10.20 | live | same |
| Expand(root, `reply` ‖ slate_id) | X25519 | One-time reply key | same | 26.10.20 | live | `pairing/reply_keys.json` |
| HKDF-SHA256, salt `epic-private/1 keys` ‖ random secret, ikm = root; info `private enc`, `private sig`, `private hint`, `private box` ‖ slot (‖ ctr) | X25519, Ed25519, 32-byte, secp256k1 | Private pairing (linked device) keys, slots from 65,536 | same | ≤ 26.10.24-r2 | live | none yet |
| HKDF-SHA256, salt `epic-pair/1 mailbox`, ikm = invite code, info `box` ‖ net ‖ ctr | secp256k1 | Throwaway pairing mailbox; not seed-derived | same | 26.10.20 | live | `pairing/mailbox_keys.json` |
| HKDF-SHA256, random salt, ikm = key at `m` (`derive_key(0, ROOT)`), info `wfe-history-export-v1/key` and `/check` | 32-byte ChaCha20-Poly1305 key and check | Backup files (`.wfeh`) | `lepic-keychain` | ≤ 26.10.24-r2 | live | `app_data/wfeh_*` |
| HKDF-SHA256, salt `lepic/addr-proof/1`, ikm = x(ECDH(index 0, contact's mailbox key)), info `mac` ‖ net ‖ step (u8: 1 reply, 2 confirm, 3 update) | 32-byte HMAC key | MAC that proves the payments address to one contact (0034); never a signature | `lepic-wallet-contacts` | 26.10.25 | live | `keys/address_proofs` |
| HKDF-SHA256, salt `epic-domain/1`, ikm = contact root, info `sign` ‖ net | Ed25519 (the 32 bytes are the seed) | Domain key of a service | `lepic-wallet-contacts` | 26.11.06 | live | `pairing/domain.json` |
| Random 32 bytes, wrapped by the backup key | AES-256 key | Address-book content key; not derived | app | 26.10.25 | live | none |

#### Tags and domains (signatures, MACs, hashes)

Shipped:

| Tag | Used with | Covers | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| `lepic/address-signature/v1` | ECDSA, index 0; `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` | Device-link hello | `lepic-epicbox` | ≤ 26.10.24-r2 | retired-reserved | none |
| `epic-card/1` | Ed25519, contact sig key | A contact card | `lepic-contact` | 26.10.20 | live | `pairing/cards_invites.json` |
| `epic-domain/1` | Ed25519 by the domain key | A contact's domain claim | `lepic-contact` | 26.11.06 | live | `pairing/domain.json` |
| `epic-seal/1` (HPKE info), `epic-seal/1 sig` (Ed25519 signing input), `epic-seal/1 fixed`, `epic-seal/1 reply` (SHA-256 hint domains) | HPKE, Ed25519, SHA-256 | Sealed envelopes and their hints | `lepic-seal` (was `lepic-contact`) | 26.10.20 | live | `pairing/envelopes.json` |
| `epic-pair/1 id`, `commit`, `sas` (SHA-256), `words` (Argon2id salt prefix), `keycheck` (SHA-256 tag, computed in `lepic-contact` and `lepic-wallet-contacts` as one value), `keycheck found`, `keycheck restored` (Ed25519 proof messages) | as listed | Invite id, commitment, short authentication string, pairing words, key check | `lepic-contact`, `lepic-wallet-contacts` | 26.10.20 | live | `pairing/keycheck.json`, `sas.json`, `words.json` |
| `epic-private/1` (PSK id), `epic-private/1 reply`, `channel`, `sas` (SHA-256) | HPKE PSK, SHA-256 | Private pairing channel | `lepic-contact` | ≤ 26.10.24-r2 | live | none yet |
| `lepic-store private context v1`, `pending invoice v1`, `pairing v1`, `peer compat v1`; `lepic-store peer tag v1` (BLAKE2b domain of the peer tag hash) | AEAD associated data, keyed BLAKE2b | Which table a sealed record belongs to; the peer hash | `lepic-store` | ≤ 26.10.24-r2 (`peer ...`: 26.10.25) | live | `store/peer_compat.json` |
| `wfe-history-export-v1` plus an inner kind header | ChaCha20-Poly1305 | Backup file | `lepic-keychain` | ≤ 26.10.24-r2 | live | `app_data/wfeh_*` |

New in this batch:

| Tag | Used with | Covers | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| `lepic/device-link/v1` | Ed25519, device-link key; signs `tag ‖ transcript` with no hash of the tag | The device-link hello transcript, which the app builds | `lepic-wallet::namespace` | 26.10.25 | live | `keys/device_link_key_seed32`, `keys/device_link_key_seed16` |
| `lepic/listing-signature/v1` | ECDSA, listing key; digest `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ len(u8) ‖ domain ‖ message)` | Any app domain below. A domain is `[a-z0-9-]+/[0-9]+`, 3 to 64 bytes; any domain starting with `lepic`, in any case, is refused. The tag's SHA-256 holds a byte UTF-8 never uses, so no text signature passes as a listing signature | `lepic-epicbox` | 26.10.25 | live | `keys/listing_signatures` |
| `lepic-wallet pairing verdict v1` | unkeyed BLAKE2b-256 over tag ‖ the 4-byte short authentication string | The hash a pairing verdict notice carries instead of the string (0034) | `lepic-wallet-contacts` | 26.10.25 | live | none yet |
| `epic-dir-hello/1` | listing signer | Name-service hello, over its fields, including the pairing's four SAS indexes (`bind`), which the wallet compares with the words it showed | app | not shipped (app) | live | none (app) |
| `epic-listing/1`, `epic-listing-moved/1`, `epic-payreq/1`, `epic-unlist/1` | listing signer | A listing; its move to a new address; a payment request; leaving | app | not shipped (app) | live | none (app) |
| `lepic/addr-proof/1` | HKDF salt (table above); the MAC covers `H(cardProver) ‖ H(cardVerifier) ‖ H(invite)`, with a zero slot for a hash the step does not have. A pairing made before this release has no proof and gets none; an address card goes out only when the payments address changes | Address proof | `lepic-wallet-contacts` | 26.10.25 | live | `keys/address_proofs` |

For RFC 0003 (ADR 0052):

| Tag | Used with | Covers | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| `epic-tx/1` ‖ net ‖ suite ‖ `00` or `01` (HPKE info) | HPKE, with the zero hint | Envelopes sealed to an epic1 seal key (`00`) or a listener seal key (`01`) | `lepic-seal` | unreleased | proposed | `pairing/epictx_envelopes.json` |
| `epic-check/1` | SHA-256 over tag ‖ the receiver's public excess (33 bytes) | The check code the receiver shows after it posts and the payer confirms before finalizing (O-16) | `lepic-wallet::namespace` | unreleased | proposed | `keys/check_codes` |

`epic-tx/1` and `epic-seal/1` are prefix-free with each other, and every context above is
fixed-width, so rules 3 and 4 hold.

The info of the proof key carries the step, not the role, and both sides compute the same key. The
roles stay apart anyway. In a reply and a confirm the message order is fixed (prover card, verifier
card, invite, a zero slot where a step has none) and the prover card must carry the payments key
the MAC is checked against. In an update both directions share the step byte and differ only by
which card is the prover's; the two cards differ, so a proof made one way does not verify the
other way (a test covers it).

Not listed: relay challenge texts (stock defines them) and the Ed25519 payment-proof signature
(upstream's message).

## Consequences

- A new key or tag is a row here and a vector in the same commit. Review checks every new key
  against the rules above.
- Moving listing keys off `m/<a>/1/0x8000_0000+` and the device hello off index 0 happen before
  anything of either ships; nothing already installed needs a migration, and linked devices on an
  older release do not verify the new hello.
- The device-link hello of an older build (index 0, `lepic/address-signature/v1`) is not accepted
  by the new one: the call that made it is gone from the binding and the verifier checks only the
  device-link key under `lepic/device-link/v1`.
- Shipped keys that break rule 1 or 3 stay as they are: changing the contact root or a tag would
  re-pair every contact.
- Adding a purpose never needs a new BIP32 branch, and a restore finds every entry by the
  phrase alone, except the random ones (private pairing secret, content key), which restore from
  backups.

## Alternatives considered

- A BIP32 purpose path of our own (`m/1017'`-style): Epic's tree is `m/a/b/c` from Grin's HMAC
  key, other wallets hand out any index on it, and none of our keys need public derivation.
- One HKDF root for all LEPIC keys: the contact root already does it for its subtree; for the rest
  the keyed hash is the same construction without a second root to protect.
- A domain argument on `sign_with_address_key`: still leaves a LEPIC-only message signed by the
  shared key. The device hello gets its own key instead and the call goes.
- Unregistered ad-hoc labels (the status quo): works until two labels collide; no way to review.
