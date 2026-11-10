# Pairing

Two LEPIC wallets pair once. They can scan each other's card in person, or exchange an invite
link or five pairing words online. Each side then holds keys made for that one contact and a
mailbox on the pairing's home relay. Slates, invoices and notices between them travel sealed and
signed. This guide shows the messages, the calls that make them and the limits in the code. The
normative rules are in [RFC 0002](../rfcs/0002-contact-pairing.md), and its edge cases in
[the cases file](../rfcs/0002-contact-pairing-cases.md).

| Crate | Holds |
|---|---|
| [`lepic-contact`](../../crates/lepic-contact/README.md) | Invites, reply and confirm, private pairing, the key check, the SAS, pairing words; pure |
| [`lepic-seal`](../../crates/lepic-seal/README.md) | The envelope, contact cards, domain claims; re-exported by `lepic-contact` |
| `lepic-wallet-contacts` | `ContactBook`: pairing records, mailboxes, collecting, sealed sends, invoices, relay moves |

Pairing messages use only Epicbox mailboxes, never the payments address, HTTP, Tor or the node.
Every part that can go by hand has a link form for when no relay is reachable.

## Keys and cards

Each contact has a numbered slot. The slot and a random 16-byte `box_salt` derive the keys from
the seed ([RFC 0002 §2.2](../rfcs/0002-contact-pairing.md#22-keys-for-one-contact)):

- `enc` (X25519), the key envelopes to this wallet are sealed to;
- `sig` (Ed25519), the key that signs this wallet's envelopes;
- `hint` (32 bytes), from which each envelope's hint is computed;
- `box`, a secp256k1 key whose address is this wallet's mailbox for the contact.

Ordinary slots run from 0 to 65,535 (`SLOT_COUNT`). Private pairings take slots from 65,536 up
(`PRIVATE_SLOT_BASE`) and keys of their own.

A **card** is a self-signed TLV list of at most 1,024 bytes (`MAX_CARD_LEN`). It holds a name
(at most 48 bytes), the three public keys, the mailbox, an optional payments address, caps and a
`seq` ([§6.1](../rfcs/0002-contact-pairing.md#61-fields)). A stored card is replaced only by one
with the same keys, a valid signature and a higher `seq`. The name is a claim: the app shows the
user's own label first.

As text a card is `epiccash://contact/1/<base64url of card || H(H(card))[0..4]>`. `contact`,
`pair`, `pair-reply` and `pair-confirm` links all end with this checksum.

## Online pairing

```text
A (inviter)                       home relay                       B (invitee)
  invite link ─────────────────── any channel ─────────────────────►
                                      ◄── reply (03), anonymous ── B posts to the reply mailbox
  A drains the reply mailbox ◄──
  A posts confirm (04), signed ──►
                                      ── B drains the confirm mailbox ─►
  both show the SAS
```

### Invite

`epiccash://pair/1/<base64url>` holds a TLV list of at most `MAX_INVITE_LEN`, 1,024 bytes
([§7.1](../rfcs/0002-contact-pairing.md#71-invite)). The main fields:

| Tag | Field |
|---|---|
| `05` | Expiry, unix seconds |
| `06` | `code`, 16 bytes; the seed of the reply mailbox |
| `07` | `commit = H("epic-pair/1 commit" \|\| nA \|\| H(cardA))` |
| `08` | A's enc key for this contact; the reply is sealed to it |
| `09` | The home relay, `domain[:port]` |
| `80` | A link secret: makes the invite private |
| `81` | A's mailbox key, against which the reply's address proof is computed |

```rust
use lepic_contact::Invite;

let invite = Invite::from_link(text, network)?;
if invite.is_expired(now) { /* refuse */ }
let class = invite.class(); // ordinary or private
```

`ContactBook::pairing_invite` makes one and keeps a pending pairing. The host sets the expiry. A
wallet holds at most 64 pending pairings, and one invite pairs one contact.

### Reply and confirm

`pairing_accept` takes a slot and makes B's card, `nB` and `rc`. It then seals a type `03`
envelope to the invite's enc key, anonymous, with the invite id as hint
(`lepic_contact::seal_reply`). The body is `code || nB || rc || cardB`. The reply goes to the
reply mailbox, and is posted again on every collect until the confirm arrives.

A drains the reply mailbox. For the first reply that opens with the right code and a valid card,
A:

1. stores the pairing record and computes the SAS;
2. posts a signed type `04` envelope with body `nA || cardA || 01` to the confirm mailbox, which
   derives from `rc`;
3. deletes `nA`, so no second reply can pair.

B checks the confirm: it is signed by cardA's sig key, the commit matches, and cardA's enc key is
the invite's (`ConfirmBody::matches_invite`). A mismatch ends the pairing with "This invite was
changed on the way".

A reply that cannot be accepted gets an anonymous one-byte confirm, a `Refusal`:

| Byte | `Refusal` |
|---|---|
| `02` | `AlreadyUsed` |
| `03` | `Expired` |
| `04` | `CancelledByInviter` |

An invite answers at most 3 refusals. A refusal is advisory: nothing is stored on either side.

When a post fails, or the user sends by hand, the envelope is shown as
`epiccash://pair-reply/1/…` or `epiccash://pair-confirm/1/…` (`pairing_envelope_link`).
`pairing_enter_link` takes either. The text is limited to `MAX_PAIRING_ENVELOPE_LEN`, 4,096
bytes.

### Pairing mailboxes

The reply and confirm mailboxes are on the home relay. Their keys derive from a 16-byte seed
(`code`, `rc`, or the seed from pairing words) by HKDF, and messages to them are posted from a
second key of the same seed. The relay sees two unknown keys. These keys are forgotten when the
pairing ends ([§8.1](../rfcs/0002-contact-pairing.md#81-pairing-mailboxes)).

They are read with one-off drains: one connection per relay, at most 32 messages per mailbox, each
acknowledged once its effect is stored ([§8.2](../rfcs/0002-contact-pairing.md#82-one-off-drains)).

| Constant | Value |
|---|---|
| `CLOCK_SKEW` | 10 minutes; A drains its reply mailbox this long past the expiry |
| `CONFIRM_WAIT` | 1 hour at least for B to wait for the confirm |
| `LATE_DRAIN_WAIT` | 1 hour; a pairing past its deadline ends at the next drain of its relay, or after this |

### SAS

```text
sas = H("epic-pair/1 sas" || net || H(cardA) || H(cardB) || nA || nB)[0..4]
```

Each byte indexes the 256-entry table `testdata/sas/emoji-v1.txt`: an emoji and a short name. A
commits to `nA` before B picks `nB`, so a man in the middle matches by chance with probability
2^-32 ([§7.5](../rfcs/0002-contact-pairing.md#75-sas)).

```rust
use lepic_contact::Sas;

let sas = Sas::compute(network, &card_a, &card_b, &n_a, &n_b);
let shown = sas.symbols()?; // four SasSymbol, emoji and name
```

`pairing_sas(contact, decision)` records the user's `SasDecision`:

| Decision | Result |
|---|---|
| `Match` | Verified |
| `Skip` | Paired, not verified |
| `Mismatch` | The pairing ends on both sides; its invoices and queued messages are dropped |

The outcome travels to the contact as a sealed status notice (`pair-finished`, `pair-match`,
`pair-mismatch`, `unpaired`), only when its feature word claims them. The notices carry a hash of
the SAS, never the SAS itself ([§7.6](../rfcs/0002-contact-pairing.md#76-pairing-record)).

## In person

Each phone shows its card QR (`pairing_show_card`, a fresh slot per showing) and scans the
other's (`pairing_scan_card`). Both nonces are zero, and the card with the lower sig key is
card A (`Sas::in_person`). No network is used. Each side delivers to the mailbox on the other's
card. On its first collect each wallet sends the contact a new card with a fresh mailbox, since
anyone nearby saw the QR ([§7.4](../rfcs/0002-contact-pairing.md#74-in-person)).

## Pairing words

Five SAS entries (`WORD_COUNT`) replace a link when there is nothing to scan or paste
([§7.7](../rfcs/0002-contact-pairing.md#77-pairing-words)):

1. A makes an invite with a 10-minute expiry (`WORDS_INVITE_EXPIRY`) and 5 random bytes.
2. `PairingWords::stretch` runs Argon2id over the words and the 10-minute `WordsWindow`. The
   result gives a rendezvous mailbox and an invite key.
3. A posts the encrypted invite, at most `MAX_POSTED_LEN` (4,096 characters), to the rendezvous
   mailbox on every built-in relay of the network.
4. B types the words, and tries the current window and the one before (`WordsWindow::to_try`).
   It opens the first message that decrypts and acknowledges it.

Words are not offered on a network with no built-in relay, or with Epicbox off. The meeting list
holds at most `MAX_MEETING_RELAYS`, 16.

## Private pairings

An invite with tag `80` (a 32-byte link secret `sA`) is private
([§7.9](../rfcs/0002-contact-pairing.md#79-private-pairings)):

- The reply is sealed in PSK mode, suite `0x41` (`SUITE_PSK`), and carries B's secret `sB`.
- Every later envelope is sealed in PSK mode under a channel key from `sA` and `sB`. A base-mode
  envelope on the pairing is refused.
- The keys come from a random secret in the record, not from the seed alone.
- The SAS also covers `H(sA || sB)` (`private_sas`).
- Private pairings carry only app payloads, type `40`. They are not moved by a relay move of the
  owner.

## Contact mailboxes and collecting

After pairing, each side posts to the other's card mailbox on the home relay, from its own `box`
key for the contact. A wallet that switches its own relay changes nothing for paired contacts.

`contacts_collect(relays, trigger)` drains them, one connection per home relay:

| `CollectTrigger` | Mailboxes | Backoff |
|---|---|---|
| `Open` | All | Cleared; the outbox sends everything |
| `Pull` | All | As `Open` |
| `Foreground` | Those with something pending, or all on at most 3 relays | Respected |
| `Push` | All | Kept |

- A cycle reads at most 50 mailboxes, round-robin, and at most 32 messages per mailbox.
- A relay that does not answer backs off 30 s, 2 min, 10 min, then 30 min.
- An outbox entry not delivered after `OUTBOX_STUCK_AFTER`, 24 hours, raises `OutboxStuck`.
- A message that cannot be taken yet stays unacknowledged until the host's patience ends; see
  [Epicbox](epicbox.md#messages-that-cannot-be-taken-yet).

## Sealed slates

To a paired contact with sealing on, a file or paste send writes a signed envelope
([§9](../rfcs/0002-contact-pairing.md#9-sealed-slates-between-paired-contacts)):

- type `01`, a marked V3 slate, armored `BEGINEPICSEALED.`;
- or type `0A`, a native slate, armored `BEGINEPICTX.`. This happens when `native_direct` is on
  and the contact's feature word claims native slates (bit 7).

| Call | Does |
|---|---|
| `contact_seal_slate` | Seals a slate to the contact for a file or paste |
| `contact_send`, `contact_post_slate` | Sends through the contact's mailbox, or posts a waiting send again |
| `sealed_open`, `epictx_open` | Opens an envelope and names the contact it came from |
| `sealed_receive`, `sealed_pay`, `sealed_finalize` | Answers or finalizes it, sealed back on the same channel |
| `contact_plain_fallback` | Writes the same stored slate as plain V3 when the contact cannot open sealed ones |

A send through the mailbox finalizes only an S2 that comes back from the contact the S1 went
to, and raises `ContactPaymentFinalized`. A contact with no opened envelope for `SEAL_LAPSE`, 90
days, still gets sealed slates, and the send screen offers plain.

## Contact invoices

"Allow invoices" is a switch per pairing, off by default, which can be turned on only for a
Verified contact (`contact_set_allow_invoices`)
([§11](../rfcs/0002-contact-pairing.md#11-invoice-trust-on-contacts)). An invoice is trusted only
when it arrives in the contact's mailbox, sealed and signed by the contact, with the switch on.

- It parks and raises `InvoiceFromContact`. Nothing pays without the user (`contact_pay_invoice`,
  `contact_decline_invoice`).
- At most 10 parked invoices per contact and 100 in all. More are acknowledged and dropped.
- Two requests for the same amount from one contact within 10 minutes (`SAME_AMOUNT_WINDOW`) are
  grouped, and the wallet asks before a second payment.

`contact_issue_invoice` sends an invoice to a contact that allows them.

## Key check

When the user adds a new pairing to an address-book entry that already has a record, the wallet
asks the other side whether it holds the old keys
([§7.8](../rfcs/0002-contact-pairing.md#78-re-pairing-after-a-restore-the-key-check)). Each step
travels over the new pairing:

| Type | Step |
|---|---|
| `06` | Check: the old card's `seq` and a tag over its hint key and both new sig keys (`key_check_tag`) |
| `07` `01` | Not this wallet |
| `07` `02` | Found: the old slot's card with a higher `seq`, and a proof signed by the old key |
| `07` `03` | Restored: the asker's old card and a proof signed by its old key |

When both proofs verify, both sides keep the old record with the new pairing's trust and delete
the new pairing. `ContactKeysRestored` is raised. Without an answer within `KEY_CHECK_WINDOW`
(24 hours), the new pairing goes to Keys changed and raises `ContactKeysChanged`.
`contact_keys_resolve` then keeps the old record or uses the new keys.

## Domain proof

A service can show the domain it runs on
([§6.3](../rfcs/0002-contact-pairing.md#63-domain-claim)). Its domain key signs
`"epic-domain/1" || net || sig_key || issued_at || domain`, and the claim rides as extension `83`
in the reply, the confirm and contact updates. The domain serves the keys at
`https://<domain>/.well-known/epic-wallet.json`:

```json
{"version":1,"networks":{"mainnet":{"domain_keys":["<64 hex digits>"]}},"relays":["relay.example:443"]}
```

LEPIC makes no network access for this. The host fetches the file over HTTPS with no redirects,
at most `DOMAIN_FILE_MAX` (4,096 bytes), and calls `lepic_wallet_contacts::domain::verify`. The
result is a `DomainVerdict`: `Proven`, or `Refused` with a `DomainRefused`:

| `DomainRefused` | `as_str` |
|---|---|
| `FileTooLarge` | `file_too_large` |
| `FileMalformed` | `file_malformed` |
| `UnsupportedVersion` | `unsupported_version` |
| `NetworkAbsent` | `network_absent` |
| `DomainMismatch` | `domain_mismatch` |
| `NoKeyMatches` | `no_key_matches` |

At most 8 keys per network are read. A proven claim changes no check of the pairing.

## Relay moves

**Moving one's own home.** `contacts_move_home(relays, host, drain)` sends every paired contact
one type `05` update with a card naming the mailbox on `host`, and moves this wallet's mailboxes
there in the same write ([§8.5](../rfcs/0002-contact-pairing.md#85-a-contact-moves-to-another-relay)).

- Private pairings and pairings in progress keep their relay.
- For `drain`, at most `MAX_HOME_DRAIN` (365 days), every collect still reads the old mailboxes,
  and a contact check there is answered with the new card.

**Following a contact.** The receiver never follows by itself:

- An update naming a mailbox on the same relay is applied at once.
- One naming another relay is stored, and the wallet raises `ContactRelayMoveRequested`.
  `apply_relay_move(contact, host)` follows it: the wallet delivers to the new mailbox, moves its
  own mailbox for the contact there, sends its new card, and reads the old mailbox for 7 days.

**Contact check (type `09`).** `contact_check` asks a contact for its current card. The answer is
a `05`, within a pace the host sets (by default one an hour and three a day per contact).

**Limits on updates:** `UPDATES_PER_CONTACT_PER_DAY`, 3, and `UPDATES_PER_HOUR`, 100, across all
contacts. Extra updates are acknowledged and dropped. A card naming another mailbox is taken
only from a `05`.

## Errors

`lepic-wallet-contacts` returns a `ContactError`. Through the FFI each pairing failure has a
stable `WalletErrorKind` code:

| Code | `WalletErrorKind` | When |
|---|---|---|
| 81 | `OtherAddress` | The pairing proves another payments address than the one given |
| 82 | `AddressProofMissing` | A payments address was given and the pairing proves none |
| 83 | `PeerNotProven` | `pairing_request_send` to a key that never claimed pair requests; offer the invite |
| 84 | `PairingInProgress` | A pairing or live request with that wallet is under way |
| 85 | `PairingCrossed` | This wallet's own pairing with the same wallet wins under the lower-key rule |
| 86 | `InviteDismissed` | The invite of a request this wallet dismissed |
| 87 | `PairingEnded` | The pairing ended; nothing new goes through it |
| 88 | `PairingWaiting` | The contact's wallet has not been heard in this pairing yet |

The table of every code is in `crates/lepic-ffi/src/api/error.rs`.

## From the CLI

```bash
lepic contact invite --name Anna
lepic contact accept 'epiccash://pair/1/AQAB...' --name Ben
lepic contact collect
lepic contact sas <ID> match
lepic contact move-home relay.example --drain-days 7
```

[docs/cli.md](../cli.md#contacts-and-pairing) has every command.
