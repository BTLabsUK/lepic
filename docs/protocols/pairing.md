# Pairing

Two LEPIC wallets pair once, by exchanging an invite link, a reply and a confirm. Pairing by
card and by spoken pairing words is no longer implemented. Each side then holds keys made for
that one contact and a slot key for it, read on the mailboxes of its list. Slates, invoices and
notices between them travel sealed and signed. This guide shows the messages, the calls that
make them and the limits in the code. The normative rules are in
[RFC 0002](../rfcs/0002-contact-pairing.md), and its edge cases in
[the cases file](../rfcs/0002-contact-pairing-cases.md).

| Crate | Holds |
|---|---|
| [`lepic-contact`](../../crates/lepic-contact/README.md) | Invites, reply and confirm, private pairing, the key check, the SAS; pure |
| [`lepic-seal`](../../crates/lepic-seal/README.md) | The envelope, contact cards, domain claims; re-exported by `lepic-contact` |
| `lepic-wallet-contacts` | `ContactBook`: pairing records, slots, collecting, sealed sends, invoices, mailbox moves |

Pairing messages use only Epicmail slots, never the payments address, HTTP, Tor or the node.
Every part that can go by hand has a link form for when no mailbox is reachable.

## Keys and cards

Each contact has a numbered slot. The slot and a random 16-byte `box_salt` derive the keys from
the seed ([RFC 0002 §2.2](../rfcs/0002-contact-pairing.md#22-keys-for-one-contact)):

- `enc` (X25519), the key envelopes to this wallet are sealed to;
- `sig` (Ed25519), the key that signs this wallet's envelopes;
- `hint` (32 bytes), from which each envelope's hint is computed;
- `box`, a secp256k1 key whose address is this wallet's slot for the contact.

Ordinary slots run from 0 to 65,535 (`SLOT_COUNT`). Private pairings take slots from 65,536 up
(`PRIVATE_SLOT_BASE`) and keys of their own.

A **card** is a self-signed TLV list of at most 1,024 bytes (`MAX_CARD_LEN`). It holds a name
(at most 48 bytes), the three public keys, the slot, an optional payments address, caps and a
`seq` ([§6.1](../rfcs/0002-contact-pairing.md#61-fields)). A stored card is replaced only by one
with the same keys, a valid signature and a higher `seq`. The name is a claim: the app shows the
user's own label first.

As text a card is `epiccash://contact/1/<base64url of card || H(H(card))[0..4]>`. `contact`,
`pair`, `pair-reply` and `pair-confirm` links all end with this checksum.

## Online pairing

```text
A (inviter)              each mailbox of A's and B's lists,              B (invitee)
                         and the invite's mailbox
  invite link ─────────────────── any channel ───────────────────────────►
                              ◄── reply (03), anonymous ── B's outbox row
  A reads its reply slot ◄──
  A's outbox row: confirm (04), signed ──►
                              ── B reads its confirm slot ────────────►
  both show the SAS
```

### Invite

`epiccash://pair/1/<base64url>` holds a TLV list of at most `MAX_INVITE_LEN`, 1,024 bytes
([§7.1](../rfcs/0002-contact-pairing.md#71-invite)). The main fields:

| Tag | Field |
|---|---|
| `05` | Expiry, unix seconds |
| `06` | `code`, 16 bytes; the seed of the reply slot |
| `07` | `commit = H("epic-pair/1 commit" \|\| nA \|\| H(cardA))` |
| `08` | A's enc key for this contact; the reply is sealed to it |
| `09` | The invite's mailbox, `domain[:port]` |
| `80` | A link secret: makes the invite private |
| `81` | A's slot key, against which the reply's address proof is computed |

```rust
use lepic_contact::Invite;

let invite = Invite::from_link(text, network)?;
if invite.is_expired(now) { /* refuse */ }
let class = invite.class(); // ordinary or private
```

`ContactBook::pairing_invite` makes one and keeps a pending pairing. The host sets the expiry.
One invite pairs one contact. At most 64 pairings that wait for their answer are kept
(`MAX_PENDING_PAIRINGS`): every invitee's until the pairing is made, and each inviter's until
its reply is taken. An inviter's pairing that has its answer is kept until the invite ends and
does not count. Cancelled invites have a cap of their own, also 64.

### Reply and confirm

`pairing_accept` takes a slot and makes B's card, `nB` and `rc`. It then seals a type `03`
envelope to the invite's enc key, anonymous, with the invite id as hint
(`lepic_contact::seal_reply`). The body is `code || nB || rc || cardB`. The reply is stored as
an outbox row and posted at once (see [Delivery](#delivery)).

A reads the reply slot. For the first reply that opens with the right code and a valid card,
A:

1. stores the pairing record and computes the SAS;
2. stores a signed type `04` envelope with body `nA || cardA || 01` as an outbox row to the
   confirm slot, which derives from `rc`, and posts it;
3. deletes `nA`, so no second reply can pair.

A copy of the reply read on a second mailbox is dropped by its seen mark before it is opened.
The same reply is opened twice only after a crash between storing the pairing and marking the
envelope seen. It pairs nothing new then, and its confirm is the row still waiting, if one is;
none once the invite's mailbox took the confirm; a new row when the first one failed. A confirm
that failed on every mailbox is not posted again by a later read of the reply: the pairing
completes only when B uses the confirmation link by hand, else fails as not confirmed when the
invite expires.

B checks the confirm: it is signed by cardA's sig key, the commit matches, and cardA's enc key is
the invite's (`ConfirmBody::matches_invite`). A mismatch ends the pairing with "This invite was
changed on the way". Once B has taken the confirm, B's reply row ends, whether it is still
owed to the invite's mailbox or was posted.

A reply that cannot be accepted gets an anonymous one-byte confirm, a `Refusal`:

| Byte | `Refusal` |
|---|---|
| `02` | `AlreadyUsed` |
| `03` | `Expired` |
| `04` | `CancelledByInviter` |

An invite answers at most 3 refusals. A refusal is advisory: nothing is stored on either side.
It is posted once, with no outbox row, to the same mailboxes a confirm goes to; a failed post is
logged and not tried again.

When a post fails, or the user sends by hand, the envelope is shown as
`epiccash://pair-reply/1/…` or `epiccash://pair-confirm/1/…` (`pairing_envelope_link`).
`pairing_enter_link` takes either. The text is limited to `MAX_PAIRING_ENVELOPE_LEN`, 4,096
bytes.

### Pairing slots

The reply and confirm slots are keys, not places. Their keys derive from a 16-byte seed
(`code` or `rc`) by HKDF, and messages to them are posted from a second key of the same seed,
named on the invite's mailbox. The mailbox sees two unknown keys. These keys are forgotten when the
pairing ends ([§8.1](../rfcs/0002-contact-pairing.md#81-pairing-mailboxes)).

Each side watches its pairing slot on every mailbox of its list and on the invite's mailbox when
the list lacks it, the same mailboxes the other side posts to. A message is acknowledged once its
effect is stored ([§8.2](../rfcs/0002-contact-pairing.md#82-reading-mailboxes)), so a mailbox that
is down does not stop a pairing while another mailbox of both lists is up.

| Constant | Value |
|---|---|
| `CLOCK_SKEW` | 10 minutes; A reads its reply slot this long past the expiry |
| `CONFIRM_WAIT` | 1 hour at least for B to wait for the confirm |
| `LATE_DRAIN_WAIT` | 1 hour; a pairing past its deadline ends at the next read of its mailbox, or after this |

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

### Status notices

The outcome travels to the contact as a sealed, signed status notice: `pair-finished` when B
has taken the confirm, `pair-match` or `pair-mismatch` for a decision. Each goes only to a
contact whose feature word claims them (bit 3, `STATUS_NOTICES`), and carries a hash of the
SAS, never the SAS itself ([§7.6](../rfcs/0002-contact-pairing.md#76-pairing-record)). A notice
read on two mailboxes is applied once.

An inviter waits until it hears the contact in the pairing. One that never hears it during
`NEVER_FINISHED_AFTER`, 7 days of collecting, ends the pairing and tells the contact it was
unpaired.

### Unpairing

`contact_unpair` tells the contact before the record goes: a signed `unpaired` notice is
stored as an outbox row and posted once, then the record is removed
([§7.6](../rfcs/0002-contact-pairing.md#76-pairing-record)). A row no mailbox took stays and is
posted again by the outbox's back-off. The post also reaches the contact's mailbox when the list
lacks it. When the list's mailboxes took the notice and the contact's mailbox did not, the row is
owed to the contact's mailbox alone and keeps that mailbox after the record is gone. A row that no
mailbox took before the record went has no mailbox of the contact's left, so it reaches only the
mailboxes of the list. Nothing is sent Offline, for a pairing still in progress,
or for one that ended. `contact_remove` removes a pairing without a word.

All status and unpaired notices are padded to one of `NOTICE_LENGTHS`, so their sizes do not
tell them apart.

## Delivery

Every pairing message but the refusal is an outbox row, stored in the write that makes it and
posted after that write, so a crash leaves it to post. The outbox's back-off is its only retry.

**Where it goes.** The rule is the one for all native mail ([Delivery](delivery.md#where-mail-goes)).
A row's route is the peer's slot key. Each post goes to that key on the mailbox the message
names, plus the 2 healthiest others of the wallet's list:

| Message | Named mailbox |
|---|---|
| Reply | The invite's mailbox |
| Confirm, refusal | The invite's mailbox |
| Status and unpaired notices | The mailbox of the contact's card |
| Card update, mailbox move, contact check, invoice and its payment | The mailbox of the contact's card |

The same sealed bytes go to each. The outbox stores which mailboxes took the post.

**What a post's answers do to the row.**

| Answer | Row |
|---|---|
| Any mailbox took it | Posted; the mailboxes that did not are tried again on the back-off until the message ends |
| None took it and one or more wrote it and gave no answer | Uncertain; the same bytes later |
| Nothing reached a mailbox, or a mailbox asked to come back later | Queued again later |
| Every mailbox refused it, or the address or size is not taken | Failed; not posted again |

A mailbox that fails stays in the list and the other mailboxes carry the mail. A message to a
contact arrives while the mailbox of the pairing is down if another mailbox is shared, and a
mailbox move reaches a contact on any mailbox the two share.

The back-off is 30 seconds, 2 minutes, 10 minutes, then 30 minutes. A row not posted within
`OUTBOX_STUCK_AFTER`, 24 hours, ends. Pairing mail has no cutoff height.

**When a row ends.**

- A row stops posting when it is Posted or Failed, or when it is not posted within
  `OUTBOX_STUCK_AFTER`.
- B's reply row ends when B takes the confirm, and with the pending pairing in any case. Until
  then it stays: posted, or tried again on the back-off.
- A's confirm row ends with A's pending pairing, at the invite's deadline. A confirm that any
  mailbox took marks the pairing's confirm as sent, so the pairing ends quietly then. It is marked
  at the first mailbox that took it, the invite's mailbox or another: a B that reads that mailbox
  finishes from there, and A would otherwise end a finished pairing as not confirmed.
- A status or unpaired row ends when it is posted or fails. A posted row of a contact is kept
  by LEPIC's own prune, `prune_outbox`, for `DELIVERED_KEPT` (`lepic_epicbox::RELAY_RETENTION`,
  7 days), then deleted; one whose record was removed is deleted when it ends.

**Copies left on other mailboxes.** A post stays on every mailbox that took it. Nothing cancels those copies: a mailbox cancels only a message whose sender names
its transaction id, and pairing mail carries none. The receiver reads one copy and drops the
rest by the envelope's hash; the others expire at the mailbox's retention, which the mailbox's
operator sets.

**Sender.** A reply or confirm goes from the pairing's own slot, named on the invite's
mailbox. Mail to a contact goes from this wallet's slot key for the contact, named on that
slot's mailbox. Once the record is removed, an unpaired notice still waiting goes from a
fresh key that belongs to no pairing; the contact checks the envelope's signature, not the
mailbox's sender.

## In person and pairing words

LEPIC no longer implements pairing by card QR or by the five pairing words
([§7.4](../rfcs/0002-contact-pairing.md#74-in-person),
[§7.7](../rfcs/0002-contact-pairing.md#77-pairing-words)). The RFC sections remain as the record
of the design.

## Private pairings

An invite with tag `80` (a 32-byte link secret `sA`) is private
([§7.9](../rfcs/0002-contact-pairing.md#79-private-pairings)):

- The reply is sealed in PSK mode, suite `0x41` (`SUITE_PSK`), and carries B's secret `sB`.
- Every later envelope is sealed in PSK mode under a channel key from `sA` and `sB`. A base-mode
  envelope on the pairing is refused.
- The keys come from a random secret in the record, not from the seed alone.
- The SAS also covers `H(sA || sB)` (`private_sas`).
- Private pairings carry only app payloads, type `40`, and the `unpaired` notice. They are not
  moved by a mailbox move of the owner. An app payload is the host's `app` notice
  ([ADR 0067](../adr/0067-one-notice-path.md)): sent and taken on the one notice path, its bytes
  unchanged.

## Contact slots and collecting

After pairing, each side reads its own slot key for the contact on every mailbox of its list and
on the mailbox its own card names. Messages for the contact go from this wallet's `box` key for
the contact to the contact's slot key, on the mailbox of the contact's card and the 2 healthiest others of
the wallet's list: payments, contact updates, checks and payloads
([Delivery](#delivery)). The card carries one home mailbox, as before; it is no longer the only
way to the contact.

`contacts_collect(relays, trigger)` reads them through the push sessions, one per mailbox:

| `CollectTrigger` | Mailboxes asked | Backoff |
|---|---|---|
| `Open` | All | Cleared; the outbox sends everything |
| `Pull` | All | As `Open` |
| `Foreground` | Those with something pending, or all on at most 3 mailboxes | Respected |
| `Push` | All | Kept |

- A cycle reads at most 50 slots, round-robin, and at most 32 messages per slot.
- A mailbox that does not answer backs off 30 s, 2 min, 10 min, then 30 min.
- An outbox entry not delivered after `OUTBOX_STUCK_AFTER`, 24 hours, raises `OutboxStuck`.
- A message that cannot be taken yet stays unacknowledged until the host's patience ends; see
  [Epicbox](epicbox.md#messages-that-cannot-be-taken-yet).

## Sealed slates

To a paired contact with sealing on, a file or paste send writes a signed envelope
([§9](../rfcs/0002-contact-pairing.md#9-sealed-slates-between-paired-contacts)):

- type `01`, a V3 slate, armored `BEGINEPICSEALED.`;
- or type `0A`, a native slate, armored `BEGINEPICTX.`, only as the answer to a native slate
  the contact sent. A new slate always goes as type `01`.

| Call | Does |
|---|---|
| `contact_seal_slate` | Seals a slate to the contact for a file or paste |
| `contact_send`, `contact_post_slate` | Sends through the contact's slot, or posts a waiting send again |
| `sealed_open`, `epictx_open` | Opens an envelope and names the contact it came from |
| `sealed_receive`, `sealed_pay`, `sealed_finalize` | Answers or finalizes it, sealed back on the same channel |

A send through the slot finalizes only an S2 that comes back from the contact the S1 went
to, and raises `ContactPaymentFinalized`. A contact with no opened envelope for `SEAL_LAPSE`, 90
days, still gets sealed slates; its view carries `lapsed`, so a host can warn that the contact
needs LEPIC to open them.

## Contact invoices

"Allow invoices" is a switch per pairing, off by default, which can be turned on only for a
Verified contact (`contact_set_allow_invoices`)
([§11](../rfcs/0002-contact-pairing.md#11-invoice-trust-on-contacts)). An invoice is trusted only
when it arrives in the contact's slot, sealed and signed by the contact, with the switch on.
One from a Paired contact not yet Verified, or with the switch off, parks nothing; the contact
gets a sealed `declined`, once while it waits in the outbox. One from a contact whose keys changed
is dropped, and nothing is sent to it.

- It parks and raises `InvoiceFromContact`. Nothing pays without the user (`contact_pay_invoice`,
  `contact_decline_invoice`).
- At most 10 parked invoices per contact and 100 in all. More are acknowledged and dropped.
- Two requests for the same amount from one contact within 10 minutes (`SAME_AMOUNT_WINDOW`) are
  grouped, and the wallet asks before a second payment.

`contact_issue_invoice` sends an invoice to a Verified contact that allows them; one paired but
not verified fails with `NotVerified` before anything is stored.

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
{"version":1,"networks":{"mainnet":{"domain_keys":["<64 hex digits>"]}},"relays":["mailbox.example:443"]}
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

## Mailbox moves

**Moving one's own home.** `contacts_move_home(relays, host, drain)` sends every paired contact
one type `05` update with a card naming the slot on `host`, and moves this wallet's slots
there in the same write ([§8.5](../rfcs/0002-contact-pairing.md#85-a-contact-moves-to-another-relay)).

- Private pairings and pairings in progress keep their mailbox.
- For `drain`, at most `MAX_HOME_DRAIN` (365 days), every collect still reads the old slots,
  and a contact check there is answered with the new card.
- An old home that is still a mailbox of the list is read as any mailbox of the list is, whatever
  `drain` says. The drain matters only for an old home outside the list.

**Following a contact.** The receiver never follows by itself:

- An update naming a slot on the same mailbox is applied at once.
- One naming another mailbox is stored, and the wallet raises `ContactRelayMoveRequested`.
  `apply_relay_move(contact, host)` follows it: the wallet delivers to the new slot, moves its
  own slot for the contact there and sends its new card. It reads the old slot for 7 days
  when that mailbox is outside the list; a mailbox of the list stays read in any case.

**Contact check (type `09`).** `contact_check` asks a contact for its current card. The answer is
a `05`, within a pace the host sets (by default one an hour and three a day per contact).

**Limits on updates:** `UPDATES_PER_CONTACT_PER_DAY`, 3, and `UPDATES_PER_HOUR`, 100, across all
contacts. Extra updates are acknowledged and dropped. A card naming another slot is taken
only from a `05`.

## Errors

`lepic-wallet-contacts` returns a `ContactError`. Through the FFI each pairing failure has a
stable `WalletErrorKind` code:

| Code | `WalletErrorKind` | When |
|---|---|---|
| 81 | `OtherAddress` | The pairing proves another payments address than the one given |
| 82 | `AddressProofMissing` | A payments address was given and the pairing proves none |
| 84 | `PairingInProgress` | A pairing with that wallet is under way |
| 85 | `PairingCrossed` | This wallet's own pairing with the same wallet wins under the lower-key rule |
| 87 | `PairingEnded` | The pairing ended; nothing new goes through it |
| 88 | `PairingWaiting` | The contact's wallet has not been heard in this pairing yet |

The table of every code is in `crates/lepic-ffi/src/api/error.rs`.

## From the CLI

```bash
lepic contact invite --name Anna
lepic contact accept 'epiccash://pair/1/AQAB...' --name Ben
lepic contact collect
lepic contact sas <ID> match
lepic contact move-home mailbox.example --drain-days 7
```

[docs/cli.md](../cli.md#contacts-and-pairing) has every command.
