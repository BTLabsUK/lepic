# ADR 0033: One registry of seed-derived keys and signature domains

Status: proposed

## Context

LEPIC derives keys in four ways: BIP32 paths of the account (outputs, the Epicbox address, the
contact root), keyed BLAKE2b of the seed under a label, HKDF under a root or a code, and random
values. Three needs call for one list of them:

- `m/<a>/1/<i>` is a branch other Epic wallets walk: `epic-wallet` hands out the key at any index
  and Stack Wallet's library signs Epicbox sends at any index. A LEPIC-only meaning on that
  branch could be reached by another wallet on the same phrase.
- A signature made by another program with a key LEPIC also uses must not verify as a LEPIC
  message. Tags help only against signers that hash the message themselves; separate keys do not
  depend on that.
- Every restore, linked device and backup needs the same bytes from the same phrase for ever, so
  a shipped entry may not change meaning by accident.

Anyone holding the phrase holds every key below. The registry makes sure that no honest wallet
reaches a LEPIC key by chance and no LEPIC protocol accepts a foreign signature.

## Decision

LEPIC keeps one registry, in this record, of every seed-derived key and every tag or domain it
signs or hashes under. The code follows it: `lepic_wallet::lifecycle` holds the labels and
derivations of the context key, peer tag key, store key and seed check, `lepic_wallet::namespace`
those of the other keys of the namespace below, and each other entry has one constant in the crate
that owns it. A change to a label is a change in that one place.

### The namespace

A key that is not a funds key is
`BLAKE2b-256(key = seed, msg = "lepic-wallet <purpose> v<n>" ‖ context)`, the construction of the
context key and the seed check (`seed` is the BIP39 entropy). No LEPIC key sits on a BIP32
branch other than the ones in the table. A 32-byte result is an Ed25519 or X25519 secret
directly. A secp256k1 key appends a one-byte counter to the context and takes the first counter,
tried from 0, that gives a valid key (`first_valid_key`).

### Rules

1. One key per purpose. A key that signs never encrypts or does ECDH. The exceptions are
   recorded below: index 0 of `m/<a>/1`, listing keys and Epicbox slot keys.
2. Every signature LEPIC defines is over a tagged digest or a domain-prefixed message. A new tag
   is versioned and distinct. LEPIC's own tags start `lepic/`. A domain an app passes to the
   listing signer never does: `ServiceDomain::parse` refuses any domain that starts with `lepic`,
   in any case, and accepts only lowercase `name/version` of 3 to 64 bytes. Shipped `epic-` tags
   are not renamed.
3. Tags are prefix-free among those used with one key or one primitive. Tags that share a prefix
   (`epic-seal/1` and `epic-seal/1 sig`, the `epic-pair/1` and `epic-private/1` families) stay
   apart by the primitive or key they are used with, as the tables show.
4. Labels end with ` v<n>`. No label is a prefix of another label followed by its context, and the
   context after a label is fixed-width, so two entries cannot produce one input.
5. Nothing goes on a BIP32 path beyond the entries below.
6. An entry never changes meaning. A change is a new label or tag version and a new row; the old
   row becomes retired-reserved and its name is never reused.
7. No extended public key is exported.
8. Every entry LEPIC derives or signs has a vector under `testdata/vectors/` (`keys/`,
   `pairing/`, `store/`, `store_key/`, `app_data/`). No secret or ECDH output leaves LEPIC
   (ADR 0014).

### Recorded exception: index 0

The key at `m/<a>/1/0` serves the Epicbox address (ECDSA over the mailbox's challenge text),
Epicbox ECDH, the Ed25519 payment-proof key and, as in `epic-wallet`, the seed of the onion
that key defines (the onion LEPIC publishes has a key of its own, ADR 0044). Stock wallets send to
this address and every wallet on the phrase drains its slot, so the key cannot move. LEPIC
adds one use: an ECDH with a contact's slot key whose output feeds only HKDF under
`lepic/addr-proof/1` to make a MAC (ADR 0034). LEPIC makes no signature of its own with this key.
The tag `lepic/address-signature/v1` was defined for one; nothing signs or verifies under it and it
is retired-reserved.

### Recorded exception: the listing key

A listing key is the Epicbox identity of one name-service listing. It answers the mailbox's
challenge (ECDSA over text), does the Epicbox ECDH that opens messages to the listing address,
and signs the listing's messages under the listing tag. A payer sends to the address of the key
that signs the listing card, so signer and address are one key. The three uses stay apart by
their inputs: the mailbox challenge is hashed as UTF-8 text; the listing signature is over a digest
whose preimage holds a byte UTF-8 never uses, so no text hashes to it; the ECDH output goes only
into Epicbox's own key derivation. No stock wallet reaches a listing key from the phrase, and no
other LEPIC key uses it.

### Recorded exception: Epicbox slot keys

The reply slot, post key and epic1 delivery keys (RFC 0003, ADR 0063) sign Epicbox texts
(`Subscribe`, `Made`, `PostSlate`, `CancelTx`) and do the Epicbox message ECDH, as the mailbox
protocol requires of any address key. Their ECDH output goes only into Epicbox's message cipher
and their signatures only over Epicbox texts. Every slate they carry is sealed again inside with
HPKE to an X25519 seal key that does nothing else. The post key also keys the HMAC that gives the
transaction id of a posted copy (`lepic/post-txid/v1`); that id is public. The contact
slot key, the pairing slot and the listing key sign and do ECDH in the same way. The
exception covers this class of key and no other use.

### The table

#### BIP32 paths (upstream defines them; LEPIC adds no use)

| Path | Type | Purpose | Owner | Status |
|---|---|---|---|---|
| `m/<a>/0/<c>` | secp256k1, switch commitment | Output blinding factors | `lepic-keychain` | live |
| `m/<a>/1/0` | secp256k1; its bytes are also the Ed25519 seed | Epicbox address, mailbox challenge signature, Epicbox ECDH, payment-proof key (exception above) | `lepic-keychain`, `lepic-epicbox` | live |
| `m/<a>/1/1` to `m/<a>/1/0x7FFF_FFFF` | secp256k1 | Invoice inbox addresses of earlier builds | none | retired-reserved |
| `m/<a>/1/0x8000_0000` and above | none | Never used, so no LEPIC key sits on the branch other wallets walk | none | retired-reserved |
| `m/<a>/2/0` | secp256k1, hashed into the contact root | Input of the contact root | `lepic-wallet-contacts` | live |
| `m/<a>/2/<other>` | none | Reserved; nothing is derived | none | retired-reserved |
| `m` (`derive_key(0, ROOT)`) | secp256k1 | Input of the backup-file keys; `epic-wallet` uses it for its own record keys | `lepic-keychain` | live |

#### Seed-keyed labels: `BLAKE2b(key = seed, label ‖ context)`

| Label ‖ context | Type | Purpose | Owner | Status |
|---|---|---|---|---|
| `lepic-wallet private context key v1` | XChaCha20-Poly1305 key | Seals stored records: transaction contexts, pending invoices, pairing records, peer rows | `lepic-wallet` | live |
| `lepic-wallet seed check v1` | 32-byte value, not a key | Proves a phrase belongs to a database (setting `wallet.seed_check`) | `lepic-wallet` | live |
| `lepic-wallet peer tag v1` | BLAKE2b key | Keyed hash of an Epicbox key under which its compat row is stored | `lepic-wallet` | live |
| `lepic-wallet store key v1` | 32-byte raw key | Page encryption of the wallet database (ADR 0032) | `lepic-wallet` | live |
| `lepic-wallet listing key v1` ‖ service_key(33) ‖ gen(u32 BE) ‖ ctr | secp256k1 | Address, ECDH and signing key of one name-service listing | `lepic-wallet::namespace` | live |
| `lepic-wallet onion key v1` | Ed25519 seed, empty context | The wallet's onion and the payment proofs asked for over it (ADR 0044) | `lepic-wallet::namespace` | live |
| `lepic-wallet api tls v1` | Ed25519 seed, empty context | Certificate key of the owner TLS listener of `serve` (ADR 0050) | `lepic-wallet::namespace` | live |
| `lepic-wallet device link key v1` | Ed25519 seed, empty context | Signs the hello of a linked device; both devices on one phrase hold it | `lepic-wallet::namespace` | live |
| `lepic-wallet seal key v1` ‖ account(u32 BE) ‖ net ‖ kind | X25519 | Opens envelopes sealed to an address: kind 00 the epic1 address at index 0, 01 the onion listener, 02 the plain web listener, 03 the Epicbox payments address | `lepic-wallet::namespace` | live |
| `lepic-wallet epic1 seal key v1` ‖ account(u32 BE) ‖ net ‖ index(u32 BE) | X25519 | Opens envelopes sealed to the epic1 address `index`, for index 1 and above; index 0 uses the `seal key v1` kind 00 key | `lepic-wallet::namespace` | live |
| `lepic-wallet epic1 delivery key v1` ‖ account(u32 BE) ‖ net ‖ index(u32 BE) ‖ ctr | secp256k1 | The delivery key in the epic1 address `index`, for every index, 0 included; the address's Epicbox slot on every mailbox (ADR 0063) | `lepic-wallet::namespace` | live |
| `lepic-wallet epic1 proof key v1` ‖ account(u32 BE) ‖ net | Ed25519 seed | The proof key of the epic1 address at index 0 in earlier builds | none | retired-reserved (ADR 0063) |
| `lepic-wallet epic1 indexed proof key v1` ‖ account(u32 BE) ‖ net ‖ index(u32 BE) | Ed25519 seed | The proof key of the epic1 address `index`, index 1 and above, in earlier builds | none | retired-reserved (ADR 0063) |
| `lepic-wallet reply mailbox v1` ‖ account(u32 BE) ‖ net ‖ slate_id(16) ‖ ctr | secp256k1 | Throwaway Epicbox slot for the answer to one slate | `lepic-wallet::namespace` | live |
| `lepic-wallet post key v1` ‖ account(u32 BE) ‖ net ‖ payment id(16) ‖ role ‖ ctr | secp256k1 | Epicbox `from` key of every post for one payment to another party's slot; role 00 initiator, 01 responder; keys the transaction id of a posted copy (`lepic/post-txid/v1`) | `lepic-wallet::namespace` | live |
| `lepic-wallet receipt payer key v1` ‖ account(u32 BE) ‖ net ‖ slate_id(16) ‖ ctr | secp256k1 | The payer's one-time key in the payment proof of one payment to an epic1 address (ADR 0069) | `lepic-wallet::namespace` | live |
| `lepic-wallet link mailbox v1` ‖ account(u32 BE) ‖ net ‖ kind ‖ n(u32 BE) ‖ ctr | secp256k1 | Slot named by an epic1 link in earlier builds; kind 00 on screen, 01 printed | none | retired-reserved (ADR 0063) |

`lepic-wallet store check v1` ‖ salt(16) is the check file of ADR 0032, keyed by the store key
rather than the seed; it is listed here so the label is reserved.

#### HKDF and codes

| Construction | Type | Purpose | Owner |
|---|---|---|---|
| HKDF-SHA256, salt `epic-contact/1`, ikm = BLAKE2b-256 of `m/<a>/2/0`, info `root` ‖ net | 32-byte root | Contact root | `lepic-wallet-contacts` |
| Expand(root, `enc` ‖ slot), `sig` ‖ slot, `hint` ‖ slot, `box` ‖ slot ‖ box_salt ‖ ctr | X25519, Ed25519 seed, 32-byte key, secp256k1 | Per-contact keys: open envelopes, sign cards and envelopes, hint key, Epicbox slot | same |
| Expand(root, `reply` ‖ slate_id) | X25519 | One-time reply key | same |
| HKDF-SHA256, salt `epic-private/1 keys` ‖ random secret, ikm = root; info `private enc`, `private sig`, `private hint`, `private box` ‖ slot ‖ ctr | X25519, Ed25519, 32-byte, secp256k1 | Private pairing (linked device) keys, slots from 65,536 | same |
| HKDF-SHA256, salt `epic-pair/1 mailbox`, ikm = invite code, info `box` ‖ net ‖ ctr and `from` ‖ net ‖ ctr | secp256k1 | Throwaway pairing slot (`box`) and the key its messages are posted from (`from`); not seed-derived | same |
| HKDF-SHA256, salt `epic-domain/1`, ikm = contact root, info `sign` ‖ net | Ed25519 seed | Domain key of a service | same |
| HKDF-SHA256, salt `lepic/addr-proof/1`, ikm = x(ECDH(index 0, contact's slot key)), info `mac` ‖ net ‖ step (1 reply, 2 confirm, 3 update) | HMAC key | MAC that proves the payments address to one contact (ADR 0034); never a signature | same |
| HKDF-SHA256, random salt, ikm = key at `m`, info `wfe-history-export-v1/key` and `/check` | ChaCha20-Poly1305 key and check | Backup files (`.wfeh`) | `lepic-keychain` |
| Random 32 bytes, wrapped by the backup key | AES-256 key | Address-book content key; not derived | app |

#### Tags and domains

| Tag | Used with | Covers | Owner | Status |
|---|---|---|---|---|
| `lepic/address-signature/v1` | ECDSA, index 0 | Nothing | `lepic-epicbox` | retired-reserved |
| `lepic/device-link/v1` | Ed25519, device-link key; signs tag ‖ transcript | The device-link hello transcript, which the app builds | `lepic-wallet::namespace` | live |
| `lepic/listing-signature/v1` | ECDSA, listing key; digest `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ len(u8) ‖ domain ‖ message)` | Any app domain (`epic-listing/1` and the like) | `lepic-epicbox` | live |
| `lepic/addr-proof/1` | HKDF salt; the MAC covers `H(cardProver) ‖ H(cardVerifier) ‖ H(invite)`, a zero slot for a hash the step lacks | Address proof | `lepic-wallet-contacts` | live |
| `lepic-wallet pairing verdict v1` | unkeyed BLAKE2b-256 over tag ‖ the 4-byte short authentication string | The hash a pairing verdict notice carries instead of the string | `lepic-wallet-contacts` | live |
| `epic-card/1` | Ed25519, contact sig key | A contact card | `lepic-seal` | live |
| `epic-domain/1` | Ed25519, domain key | A contact's domain claim | `lepic-seal` | live |
| `epic-seal/1` (HPKE info), `epic-seal/1 sig`, `epic-seal/1 fixed`, `epic-seal/1 reply` | HPKE, Ed25519, SHA-256 | Sealed envelopes and their hints | `lepic-seal` | live |
| `epic-pair/1 id`, `commit`, `sas`, `keycheck`, `keycheck found`, `keycheck restored` | SHA-256, Ed25519 | Invite id, commitment, short authentication string, key check | `lepic-contact`, `lepic-wallet-contacts` | live |
| `epic-pair/1 words` | Argon2id salt prefix | Pairing words of earlier builds | none | retired-reserved (RFC 0002 7.7) |
| `epic-private/1`, `epic-private/1 reply`, `channel`, `sas` | HPKE PSK, SHA-256 | Private pairing channel | `lepic-contact` | live |
| `lepic-store private context v1`, `pending invoice v1`, `pairing v1`, `peer compat v1`; `lepic-store peer tag v1` | AEAD associated data, keyed BLAKE2b | Which table a sealed record belongs to; the peer hash | `lepic-store` | live |
| `wfe-history-export-v1` plus an inner kind header | ChaCha20-Poly1305 | Backup file | `lepic-keychain` | live |
| `epic-tx/1` ‖ net ‖ suite ‖ 00, 01 or 02 | HPKE | Envelopes sealed to an epic1 seal key (00), a listener seal key (01) or the seal key of an Epicbox payments address (02) (RFC 0003). Wallets seal and open with 00 only; the codec keeps 01 and 02, and the pairing kit's vectors cover them | `lepic-seal` | live |
| `lepic/post-txid/v1` | HMAC-SHA256 keyed by the post key, over tag ‖ payment id(16) ‖ stage (`S1` to `S3`, `I1` to `I3`); the first 16 bytes, set as a version 4 id; a post of no stage carries no id | The transaction id of every copy of one post, which a mailbox cancel names (ADR 0063) | `lepic-wallet-contacts` | live |
| `epicbox-cancel/1:` ‖ transaction id | ECDSA over text, the key the message was posted from | A `CancelTx` to a mailbox that offers the separated form (ADR 0061) | `lepic-epicbox` | live |
| `lepic-epic1-receipt-key/1`, `lepic-epic1-receipt/1`, `lepic-epic1-receipt-nonce/1` | SHA-256 over tag ‖ the delivery key; the receipt message; tag ‖ receipt secret ‖ digest | The receipt key tweak, the signed receipt and its nonce; secp256k1-zkp single Schnorr with the receipt key (ADR 0069) | `lepic-epic1` | live |
| `epic-check/1` | SHA-256 over tag ‖ the answering party's 33-byte public excess | The four-digit check code shown after an answer (RFC 0003) | `lepic-wallet::namespace` | live |

The `epic-tx/1` and `epic-seal/1` tags are prefix-free with each other, and every context above is
fixed-width, so rules 3 and 4 hold. The address-proof MAC takes the step, not the role, so both
sides compute the same key. The message order is fixed in a reply and a confirm, and an update's
two directions differ by which card is the prover's, so a proof made one way does not verify the
other way. Mailbox challenge texts (stock defines them) and the Ed25519 payment-proof signature
(upstream's message) are not listed.

## Consequences

- A new key or tag is a row here and a vector in the same commit. Review checks every new key
  against the rules above.
- Keys that break rule 1 or 3 stay as they are: changing the contact root or a shipped tag would
  re-pair every contact.
- Adding a purpose needs no new BIP32 branch. A restore finds every entry by the phrase alone,
  except the random ones (private pairing secret, address-book content key), which restore from
  backups.
- A linked device verifies only the device-link key under `lepic/device-link/v1`.

## Alternatives considered

- A BIP32 purpose path of LEPIC's own (`m/1017'`-style): Epic's tree is `m/a/b/c` from Grin's
  HMAC key, other wallets hand out any index on it, and none of LEPIC's keys need public
  derivation.
- One HKDF root for all LEPIC keys: the contact root does it for its subtree; for the rest the
  keyed hash is the same construction without a second root to protect.
- A domain argument on a signing call with the shared index-0 key: a LEPIC-only message would
  still be signed by the shared key. The device hello has its own key instead.
- Unregistered ad-hoc labels: they work until two collide and cannot be reviewed.

## Related

- ADR 0014: no secrets or ECDH output leave LEPIC.
- ADR 0016 and RFC 0002 (sections 2 and 3.3): the keys and tags this record lists.
- ADR 0032, 0034, 0044, 0050, 0052, 0061, 0063.
