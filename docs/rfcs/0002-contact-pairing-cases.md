# RFC 0002 cases: what happens when pairing and sealing meet the real world

Companion to [RFC 0002](0002-contact-pairing.md); section numbers like "8.4" refer to it. Each
case says what happens, what the user sees, and the test that proves it. Test kinds: **unit** (a
pure function), **engine** (`lepic-wallet` with the mock relay and mock node), **kit** (the
exchange kit's own suite), **e2e** (V-15: two LEPIC wallets and the kit against `epic-wallet`
v4.1.0 on the local chain, floonet once before release). The exchange deposit and withdrawal
timings are in RFC section 12.6 and are tested in V-15 as listed there.

## Outcomes at a glance

| # | Case | Outcome |
|---|---|---|
| C-01 | Either side switches relay before, during or after pairing | Nothing breaks: pairing and delivery use the home relay, not either wallet's relay |
| C-02 | A paired contact's address changes domain | No effect on the pairing; only the optional plain payments address in its card refreshes |
| C-03 | Sealed slate or invoice in flight during a relay switch | Unaffected: files do not use relays, mailbox messages sit on the home relay |
| C-04 | Pairing mailbox relay differs from both wallets' relays | Expected and fine: one-off drains connect to any relay |
| C-05 | Home relay down | Outbox and collecting back off; "X's relay isn't answering"; the relay's 7-day queue loses nothing once it is back |
| C-06 | Many paired contacts on different relays | One connection per relay, 50 mailboxes per cycle, foreground drains only where something is pending |
| C-07 | A service moves its home relay; the update is lost; both sides move | Old relay drained 7 days; the card in every later envelope heals a lost update; people re-pair |
| C-08 | Push registered on one relay while pairing on another | Push stays on the wallet's address; pairing mailboxes never use push; contact mailboxes use push only where their home relay has it |
| C-09 | Tor on, off or Tor only | Mailbox drains and posts follow the wallet's Epicbox route; onion used when given; a relay unreachable over Tor falls back to the by-hand links |
| C-10 | Offline | Online pairing and collecting are unavailable; in-person QR pairing and sealed files work |
| C-11 | Two devices on one seed | Different `contact_id`s, so different keys and mailboxes; the pairing lives on the device that paired |
| C-12 | Restore from seed; a contact's keys change | Records come back from the `.wfeh` backup; without it, re-pair; the contact sees "Keys changed" and trust resets |
| C-13 | Seed later used in a stock wallet | Sealed files cannot be opened there; "Send as plain instead" resends the same slate, never a second payment |
| C-14 | Invite expired | Both apps refuse it; the inviter makes a new one |
| C-15 | Invite used twice, forwarded or leaked | First valid reply wins; later ones get "already used"; the SAS and the claimed name expose an impostor |
| C-16 | B answers after A deleted the invite | A ignores the reply; B times out after 1 hour with "No answer from A" |
| C-17 | Both invite each other at once | Two independent pairings; the second one completed is offered as a duplicate and merged |
| C-18 | SAS mismatch | The pairing is deleted on that side, the other side is told, nothing is trusted |
| C-19 | Contact deleted, then added again | Deleting removes the pairing and its mailboxes; adding again is a new pairing with new keys |
| C-20 | Invoice trust revoked while an invoice is pending | Unpaid invoices from the contact are deleted; a paid one finishes; new ones are dropped |
| C-21 | Paired contact also an address-book contact; contacts with several addresses | The pairing attaches to one address-book entry; duplicates are offered for merge; addresses are hints, keys are identity |
| C-22 | A shop or exchange pairing with many customers | Shared inbox with fixed hints, indexed lookups, per-key and global rate limits, invites bound to accounts |
| C-23 | An invoice that looks trusted but comes from an unpaired key | It cannot reach a contact mailbox signed by a contact; anything else is dropped |
| C-24 | A bounce from a stock wallet | Cannot happen for sealed invoices; plain file invoices behave as today |
| C-25 | Withdrawn and declined notices with sealing | Sealed and signed in the contact mailbox; ADR 0016 rules otherwise; signed withdrawn on a paid invoice auto-cancels |
| C-26 | Clock skew | Only expiries use clocks; 10 minutes of tolerance; the inviter's clock decides |
| C-27 | App killed mid-pairing | Pending pairings are stored; draining resumes on the next open |
| C-28 | Partial scans; camera denied | QR checksums reject partial reads; "Show code" and "Paste code" replace the camera |
| C-29 | Downgrade: forcing plain, stripping the marker | Paired sends seal by policy; plain only by the user's choice; stripping a reply key yields today's plain answer |
| C-30 | An older LEPIC without the feature | Plain answers; invites ignored; sealed files refused clearly; the fallback resends plain |
| C-31 | Epic Pay and the reply key in the marker | Unverified; tested in V-15 before release, and the marker can be left off file S1 if it fails |
| C-32 | Relay or address update floods | Not possible for relay switches; service moves are rate-limited on both sides |

## Relays

### C-01 Either side switches relay before, during or after pairing

- **What happens.** The invite names a home relay (7.1); the reply, confirm and every later message
  for the relationship use mailboxes on it (8.3). A wallet's own relay is only where its listener
  runs. Switching it before pairing changes which relay A puts in its next invite; during pairing
  it changes nothing (the pending pairing keeps the invite's relay); after pairing it changes
  nothing for any paired contact. No message is sent about it (8.5).
- **User sees.** Nothing.
- **Test.** engine: pair A and B with the home relay R1; switch A to R2 and B to R3 before the
  confirm, then deliver an invoice and a withdrawal; all arrive. e2e: the same with three relays.

### C-02 A paired contact's address changes domain

- **What happens.** The relationship does not use either wallet's ordinary address. If the
  contact's card carries the optional payments address (tag 09) and it changed, the next envelope
  from the contact (tag 07) refreshes it, and plain Epicbox sends to the contact use the new one.
  Until then a plain send goes to the old address, as for any address-book contact today.
- **User sees.** Nothing; the contact's details show the newest address after the refresh.
- **Test.** unit: a card with a higher `seq` replaces the stored one, a lower or equal one is
  ignored. engine: an envelope with a newer card updates the address.

### C-03 A sealed slate or invoice is in flight while a relay switch happens

- **What happens.** Sealed files and pastes do not touch a relay. A sealed invoice, withdrawal,
  I2 or S2 in a mailbox sits on the home relay, which neither wallet's switch affects. An outbox
  entry posts to the home relay.
- **User sees.** Nothing.
- **Test.** engine: queue an I2 in the outbox, switch the wallet's relay, run the outbox; it
  reaches the home relay. e2e: switch relays between I1 and I2.

### C-04 The pairing mailbox's relay differs from both wallets' relays

- **What happens.** That is the normal case for a person invited by someone on another relay, and
  for every service. `drain_mailbox_once` opens its own connection to the relay in the invite.
- **User sees.** Nothing.
- **Test.** engine: A on R1 invites with home relay R3, B on R2; pairing completes. e2e: same.

### C-05 The home relay is down

- **What happens.** Collecting backs off per relay (8.4); the outbox retries with its schedule
  (12.4). Messages already on the relay wait there for 7 days. A pairing whose mailbox relay is
  down offers the by-hand reply and confirm links.
- **User sees.** On the contact: "Exchange X's relay isn't answering — retrying". On a payment
  after 24 h: "Couldn't reach Exchange X yet. Your funds are safe; they unlock if it doesn't
  post." During pairing: "Can't reach the relay. Send your answer by hand?"
- **Test.** engine: the mock relay refuses connections; backoff steps, `HomeRelayUnreachable`,
  `OutboxStuck` after 24 h of mock time, delivery once the relay returns.

### C-06 Many paired contacts on different relays

- **What happens.** One connection per distinct relay per cycle, sequential subscribes on it
  (8.2), at most 50 mailboxes per cycle round-robin. In the foreground only contacts with
  something pending are drained every 45 s, unless all sit on at most 3 relays. Opening the app
  drains all of them once.
- **User sees.** Nothing; pull-to-refresh drains everything.
- **Test.** engine: 120 contacts on 7 relays; one cycle opens 7 connections and reads at most 50
  mailboxes; three cycles cover all; pending contacts are read every cycle.

### C-07 A service moves its home relay; the update is lost; both sides move

- **What happens.** The service keeps the old relay for at least 7 days and sends one signed
  update into each customer's mailbox on the old relay (8.5). The wallet collects it there,
  switches delivery to the new mailbox and drains its own mailbox on both relays for 7 days.
  - Update lost: the wallet keeps using the old relay, which still runs; the first envelope from
    the service through the new relay is not seen until the wallet learns the new mailbox, so
    the kit also sends from the old relay for those 7 days, and every envelope carries the card
    (tag 07). An outbox post to the old relay that gets no answer within 30 s is retried on the
    new one once known.
  - Both sides move: only a service's move is a protocol event; a person's relay switch is
    nothing (C-01). Two people who want a new home relay re-pair.
- **User sees.** Nothing.
- **Test.** kit + engine: move the kit's home relay; an S1 posted before the move on the old
  relay and an invoice after it on the new relay both reach the wallet; with the update dropped
  by the mock relay, the next envelope heals it.

### C-08 Push registration on one relay while pairing on another

- **What happens.** The wallet's own push registration stays on its own address and relay.
  Pairing mailboxes are never registered for push, so the push service never learns of a
  pairing; they are drained on screen and on open (8.2). Contact mailboxes are registered for
  push only when their home relay runs LEPIC's push service (8.6), signed with `box_sk`.
- **User sees.** A deposit request wakes the phone when the exchange's home relay has push; else
  it appears on the next open.
- **Test.** engine: pairing makes no push registration; a contact on a push-enabled relay
  registers its mailbox with a signature that verifies under `box_pk`; a contact elsewhere makes
  none.

## Network modes

### C-09 Tor on, off and Tor only during pairing and sealed sends

- **What happens.** Mailbox drains and posts take the wallet's Epicbox route: over Tor when
  Epicbox over Tor is on (ADR 0021), to the onion in the invite or card when there is one, and
  through an exit otherwise. A relay that refuses Tor exits and has no onion is unreachable in
  Tor-only mode; pairing then offers the by-hand links, and collecting marks the relay as not
  answering. Sealed files and pastes do not use the network.
- **User sees.** "Can't reach the relay over Tor. Send your answer by hand?" during pairing;
  otherwise the C-05 messages.
- **Test.** engine: with the Tor connector mocked, drains go to the onion when given and through
  the exit route otherwise; Tor-only with no onion and a refused exit yields the by-hand offer.

### C-10 Offline

- **What happens.** Offline makes no network calls (ADR 0021's modes). Online pairing,
  collecting and the outbox are paused; in-person QR pairing (7.4) and sealed files and pastes
  work. The outbox resumes when the mode changes.
- **User sees.** "Pair online" is disabled with "You're offline. Pair in person instead."
- **Test.** engine: in Offline `drain_mailbox_once` and outbox posts return the offline error
  without connecting; in-person pairing completes.

## Devices and restores

### C-11 Two devices on one seed

- **What happens.** Both derive the same `root`, but every pairing uses a random `contact_id`, so
  the two devices never share contact keys or mailboxes (9.5). A pairing lives on the device
  that made it. Only one device answers an invite: the one where the user tapped it. If the user
  taps the same invite on both, A accepts the first reply and answers the second with status 02;
  the second device shows "This invite was already used". The ack rules of the 26.10.8 amendment
  are not needed for mailboxes, because no mailbox is shared; they still apply to the ordinary
  payments address. Restoring a backup with pairings onto the second device while the first
  still runs makes both drain the same mailboxes; the app imports them as "on another device"
  and asks before using them (9.5).
- **User sees.** Contacts paired on the phone are not on the desktop unless restored from a
  backup there; then "Use your contacts on this device? Your other device should stop using
  them."
- **Test.** engine: two wallets on one seed pair with different contacts; their keys and
  mailboxes differ; the same invite opened twice yields one pairing and one status 02.

### C-12 Restore from seed, re-pairing, and a contact's keys changing

- **What happens.** The `.wfeh` backup carries the pairing records (10.5); with it, keys and
  mailboxes come back unchanged and nothing changes for contacts. Without it, the contacts are
  gone; the user re-pairs and gets new keys. The contact's wallet sees a new pairing whose card
  names the same ordinary payments address or the same app contact as an existing pairing, or
  the user re-pairs from that contact's page: the record goes to `keys-changed` holding both
  cards. A key never changes any other way: a card or envelope signed by another key is never a
  silent update.
- In `keys-changed`: nothing is sealed to either key without asking, invoices are not accepted,
  and "Allow invoices" and Verified are reset, so an impostor who re-pairs as the contact
  inherits nothing.
- **User sees.** "Anna's keys changed. This happens when she reinstalls or restores her wallet.
  Verify again" with the SAS check, or "Keep the old keys" and "Use the new keys".
- **Test.** engine: restore with the backup → same keys, contacts unaffected; without → new keys,
  the peer's record goes to `keys-changed` with trust reset; verifying moves it to `verified`.

### C-13 A seed later used in a stock wallet

- **What happens.** A stock wallet cannot open `.epicsealed` files and never subscribes to
  contact mailboxes. A LEPIC sender whose sealed slate gets no answer uses "Send as plain
  instead" (9.3), which writes the stored slate of the same stage: same slate id, inputs and
  signatures. A stock receiver answers it as any V3 slate. A LEPIC S1 still pending when its
  owner moved to stock cannot be finalized by the stock wallet (it lacks the context), so the
  sender's funds unlock at the TTL or by cancel; a new payment from the stock wallet is a new
  slate, and the old S1 can never be posted.
- **User sees.** On the stock side: "not a slate file". On the LEPIC side, after no answer: "Anna
  can't open sealed files? Send as plain instead".
- **Test.** unit: the fallback output decodes to the identical slate. e2e: seal to a contact,
  the contact's seed in `epic-wallet` v4.1.0 refuses the sealed file and accepts the plain
  fallback; exactly one transaction confirms.

## Invites

### C-14 The invite expired

- **What happens.** B's app refuses an invite past its expiry plus 10 minutes of skew (C-26) with
  no network call. A drains the reply mailbox until expiry plus 10 minutes, then deletes the
  pending pairing; a later reply is never read.
- **User sees.** B: "This invite has expired. Ask Anna for a new one." A: the invite shows
  "Expired" with "Invite again".
- **Test.** unit: expiry checks with skew. engine: a reply posted after A's deadline is never
  opened and A's pending pairing is gone.

### C-15 The invite used twice, forwarded to a third person, or leaked publicly

- **What happens.** A pairs with the first valid reply and answers every later one with status 02
  (7.3). If the first replier is not the intended person, A sees their claimed name in "Anna
  answered your invite" and a SAS that will not match on a call. A service binds each invite to
  a logged-in account and expires it in 15 minutes, so a leaked service invite pairs at most one
  wallet to that account, which the account page shows and can remove.
- **User sees.** The intended B, if late: "This invite was already used. Ask for a new one." A:
  "Someone else also answered this invite. If you didn't share it with them, remove them" when a
  second reply arrives.
- **Test.** engine: two replies to one invite → one pairing, one status 02, the second replier's
  record is deleted, A gets the warning.

### C-16 B pairs but A has deleted the invite

- **What happens.** A cancelled or deleted the invite, so it no longer drains the mailbox, or
  drains it once more and answers status 04. B waits 1 hour for a confirm, then deletes its
  pending pairing. The reply expires on the relay after 7 days.
- **User sees.** B: "No answer from Anna. The invite may have been cancelled."; with status 04:
  "Anna cancelled this invite."
- **Test.** engine: cancel on A; B's pending pairing ends after its timeout, or at once with 04.

### C-17 Both invite each other at once

- **What happens.** Two invites, two independent pairings, each with its own keys. Whichever
  completes second finds a record with the same peer card name and app contact and asks to keep
  one. The other is removed on both sides at the next envelope (a pairing that receives nothing
  for 90 days just lapses as 9.4 says).
- **User sees.** "You're already paired with Anna. Keep the newer pairing?"
- **Test.** engine: cross invites complete; the duplicate prompt is raised once.

## SAS

### C-18 SAS mismatch

- **What happens.** "They don't match" deletes the record on that side. A sends a confirm with
  status 04 if it has not been read yet; B tells A nothing it could misuse, and A's pending
  record expires or the users repeat the check from A's side too. Nothing was trusted before the
  check except "paired, not verified", and no invoice switch is on by default.
- **User sees.** "The codes don't match. Someone may have changed the invite on the way. Pair
  again, in person or with a fresh invite."
- **Test.** unit: a changed card or nonce changes the SAS. engine: a MITM relay that swaps the
  invite's key is caught by B's commitment check; a swapped reply gives different SAS on the
  two sides.

## Contacts

### C-19 Contact deletion and re-adding

- **What happens.** "Remove pairing" deletes the record and any pending pairing for it, our keys
  stop being used, the mailboxes
  are no longer drained, pending invoices from the contact are deleted. The contact is not told
  (a removal message would tell an attacker that guessed a pairing). Its envelopes now find no
  key: over files "sealed for another wallet"; in its mailbox nobody reads them. Adding again is
  a new pairing with new keys; the contact sees C-12's "Keys changed" if it kept the old record.
- **User sees.** "Remove the pairing with Anna? Sealed payments and invoices from Anna will stop."
- **Test.** engine: after removal, the mailbox is not drained and a sealed file from the contact
  is unopenable; re-pairing leads the peer to `keys-changed`.

### C-20 Revoking invoice trust while an invoice is pending

- **What happens.** As 11.1: unpaid parked invoices from the contact are deleted, and a signed
  `declined` is sent for each, so the service stops waiting; a paid invoice finishes as any paid
  invoice; new invoices are acknowledged and dropped.
- **User sees.** "Invoices from Exchange X are off. 1 open request was declined."
- **Test.** engine: two parked and one paid invoice; switch off; two deleted and declined, the
  paid one completes.

### C-21 A paired contact who is also an address-based contact, and multi-address contacts

- **What happens.** The address book stays in the app's history (the `Contact` type); a pairing
  record points to one entry (`app_contact`). After pairing, the app offers to attach it to an
  existing entry whose ordinary address equals the card's payments address, or to a new entry.
  An entry has at most one pairing. A second pairing that names the same entry goes through
  C-12 or C-17. Addresses on an entry are hints for plain sends; the pairing's mailbox is not
  shown as an address and never typed by users.
- **User sees.** "Anna is already in your contacts. Add the pairing to her?" The contact page shows
  "Paired" or "Verified" with the trust switches.
- **Test.** app: attaching, the merge prompt, and one pairing per entry.

## Invoices

### C-22 A shop or exchange pairing with many customers

- **What happens.** Section 13.4: one shared inbox found by fixed hints, indexed, at most one
  envelope opened per message, per-key and global limits, invites bound to accounts and capped.
  Wallet side, each customer sees the service as one contact.
- **User sees.** Nothing.
- **Test.** kit: 100,000 customers in the store, a burst of 10,000 messages; constant-time lookup,
  drops over the limits, no envelope opened without a hint match.

### C-23 A paired-trusted invoice arriving from an unpaired key

- **What happens.** Contact mailboxes are known only to the contact; an invoice in one must open
  with that contact's key and carry its signature. An unpaired key cannot produce either, so
  its message is acknowledged and dropped. An I1 to the ordinary payments address is not an
  invoice path any more (11.5) and is handled as today's unexpected I1 there.
- **User sees.** Nothing.
- **Test.** engine: an I1 sealed by a stranger to a guessed mailbox, a plain I1 in a mailbox and a
  contact's I1 signed by another key are all dropped and none parks.

### C-24 A bounce from a stock wallet

- **What happens.** Sealed invoices go only to paired LEPIC contacts' mailboxes, which a stock
  wallet never subscribes, so there is no bounce. Plain invoices over file are as today, and
  over Epicbox the old bounce detection (`docs/compat/epicbox.md`, Bounce) is no longer reached,
  since issuing over Epicbox requires a pairing.
- **User sees.** Nothing.
- **Test.** none beyond C-23; the bounce code path is removed with the invoice address.

### C-25 Withdrawn and declined notices with sealing

- **What happens.** Section 11.4: type `02` envelopes in the contact mailboxes, accepted only
  from the contact, advisory except that a signed `withdrawn` for a paid invoice cancels the
  payment and releases its inputs.
- **User sees.** "Exchange X withdrew the request; your funds are unlocked." "Declined."
- **Test.** engine: each notice, from the contact and from another key; the auto-cancel path.

## Time, lifecycle and input

### C-26 Clock skew

- **What happens.** Clocks are used only for invite expiry, invoice and withdrawal `expires`,
  lapses and backoff. B accepts an invite up to 10 minutes past its expiry by B's clock; A, whose
  clock set it, decides finally. Envelope `expires` is advisory: the chain's TTL height decides
  what can be finalized. Nothing in the SAS or the signatures depends on time.
- **User sees.** Nothing unless a clock is far off; then "This invite has expired" with a hint to
  check the phone's time.
- **Test.** unit: expiry with ±10 minutes.

### C-27 App killed mid-pairing

- **What happens.** Every pending pairing is in the store before anything is posted (7.1, 7.2);
  draining resumes on the next open (8.2). Messages read but not stored are not acknowledged, so
  the relay hands them out again.
- **User sees.** The invite or the waiting screen again, under Contacts › Pending.
- **Test.** engine: kill the wallet after posting the reply and before the confirm; reopen; the
  pairing completes.

### C-28 Partial scans; camera denied

- **What happens.** A QR code either decodes completely or not at all, and the payload's checksum
  rejects a corrupted read. If the camera is denied or missing, the card and invite screens show
  "Show code" (the text form) and "Paste code".
- **User sees.** "Allow the camera to scan, or paste the code instead."
- **Test.** unit: a flipped byte fails the checksum with its own error. app: the denied-camera
  path.

## Attacks and versions

### C-29 Downgrade: forcing plain, stripping the marker

- **What happens.** Between paired contacts the sender seals because the record says so; nothing
  on a channel can turn that off. Plain happens only when the user taps "Send as plain
  instead" or turns sealing off for the contact. A plain payload in a contact mailbox is
  dropped. For unpaired peers, an attacker who strips or replaces the reply key in a plain S1
  gets a plain or attacker-sealed S2, which is what the plain S2 gave before this RFC. A plain
  slate from a paired contact over file (its user chose plain) is accepted with "This arrived
  unsealed".
- **User sees.** The "Send as plain instead" confirmation explains that anyone with the file can
  read it.
- **Test.** engine: a mailbox plain payload is dropped; the reply-key strip yields a plain S2;
  the paired path never writes plain without the explicit call.

### C-30 Version skew: an older LEPIC peer

- **What happens.** An older LEPIC writes no reply key, so answers to it are plain. It does not
  handle `epiccash://pair`, so the invite expires (C-14). It reads a sealed file as not a slate;
  the sender's fallback applies (9.3). A newer envelope or card version is refused with "made by
  a newer wallet"; senders use the lower of the two versions (section 4).
- **User sees.** "Update Epic Cash to open this" for a newer version.
- **Test.** unit: an envelope with version 2 is refused with its own error; the marker without
  `reply` yields a plain answer.

### C-31 Epic Pay and the reply key

- **What happens.** `epic-wallet` v4.0.2 and v4.1.0 ignore unknown top-level keys; Epic Pay was
  not checked. If V-15's check, or a manual check with Epic Pay, shows that it refuses a marked
  V3 S1 file, LEPIC writes the marker on file S1 only to known LEPIC peers.
- **User sees.** Nothing.
- **Test.** e2e: a marked S1 file into `epic-wallet` v4.1.0; manual: Epic Pay, recorded in the
  release notes.

### C-32 Relay or address update floods

- **What happens.** A user's relay switch sends nothing (8.3), however often the user flips. Only
  services send home relay moves; receivers take only a higher `seq` with a valid signature from a
  paired key, at most 3 a day per contact and 100 an hour in total, and the kit applies the same
  limits to anything its customers send (13.4). The card in every envelope heals anything a
  limit dropped.
- **User sees.** Nothing.
- **Test.** engine and kit: 10 updates from one contact in an hour → 3 applied; an equal or lower
  `seq` ignored; an update signed by another key dropped.
