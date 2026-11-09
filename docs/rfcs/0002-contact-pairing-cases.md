# RFC 0002 cases: pairing and sealing under real conditions

Companion to [RFC 0002](0002-contact-pairing.md); section numbers such as "8.4" refer to it. Each
case says what happens, what the user sees, and the test that covers it.

Test kinds:

- **unit**: a pure function;
- **engine**: `lepic-wallet` with the mock relay and the mock node;
- **kit**: the exchange kit's own suite (RFC 0002 section 13);
- **e2e**: two LEPIC wallets and the kit against `epic-wallet` v4.1.0 on a local chain;
- **app**: the host application's own tests.

The exchange deposit and withdrawal timings are in RFC 0002 section 12.6.

## Outcomes at a glance

| # | Case | Outcome |
|---|---|---|
| C-01 | Either side switches relay before, during or after pairing | Pairing and delivery use the home relay, so nothing changes |
| C-02 | A paired contact's payments address changes | The pairing is unaffected; the card's payments address refreshes |
| C-03 | A sealed slate or invoice is in flight during a relay switch | Files use no relay; mailbox messages sit on the home relay |
| C-04 | The pairing relay differs from both wallets' relays | One-off drains connect to any relay |
| C-05 | The home relay is down | Collecting and the outbox back off; the relay keeps messages 7 days |
| C-06 | Many contacts on different relays | One connection per relay, 50 mailboxes per cycle |
| C-07 | A contact moves to another relay | The wallet reports the move and the host decides |
| C-08 | No push | Mailboxes are drained by collecting |
| C-09 | Tor on, off, or Tor only | Drains and posts follow the wallet's Epicbox route; by-hand links remain |
| C-10 | Offline | Online pairing and collecting pause; in-person pairing and sealed files work |
| C-11 | Two devices on one seed | Different mailboxes always, different slots almost always |
| C-12 | Restore from seed; a contact's keys change | The key check brings the old keys back, or reports Keys changed |
| C-13 | The seed is later used in a stock wallet | "Send as plain instead" resends the same slate |
| C-14 | The invite expired | Both sides refuse it |
| C-15 | The invite is used twice, forwarded or leaked | The first valid reply wins; the SAS exposes an impostor |
| C-16 | B answers after A cancelled the invite | B is refused with status `04`, or times out |
| C-17 | Both invite each other at once | The key check folds the second pairing into the first |
| C-18 | The SAS does not match | The pairing ends on both sides; nothing is trusted |
| C-19 | A contact is removed, then paired again | The contact is told; pairing again finds the old slot |
| C-20 | Invoice trust is turned off with an invoice pending | Unpaid invoices are declined; a paid one finishes |
| C-21 | A pairing and the address book | A pairing attaches to one entry; one address per method |
| C-22 | A service with many customers | Shared inbox, fixed hints, limits, invites bound to accounts |
| C-23 | An invoice from an unpaired key | Dropped |
| C-24 | A bounce from a stock wallet | Cannot happen for sealed invoices |
| C-25 | Withdrawn and declined notices | Sealed and signed in the contact mailbox |
| C-26 | Clock skew | 10 minutes of tolerance on invite expiry |
| C-27 | The app is killed mid-pairing | Pending pairings are stored; draining resumes |
| C-28 | Partial scans; camera denied | Checksums refuse partial reads; words replace the camera |
| C-29 | Downgrade to plain | Paired sends seal by policy |
| C-30 | An older LEPIC peer | Plain answers; a newer version is refused with its own error |
| C-31 | The reply key in the marker and other wallets | Stock `epic-wallet` ignores it |
| C-32 | Update floods | Signed, `seq` only rises, 3 a day per contact, 100 an hour in all |
| C-33 | Pairing words typed wrong, guessed or used twice | Nothing is found; the first use takes the invite |
| C-34 | Epicbox switched off | No relay traffic; by-hand pairing and sealed files work |

## Relays

### C-01 Either side switches relay before, during or after pairing

- **What happens.** The invite names a home relay (7.1). The reply, the confirm and every later
  message of the relationship use mailboxes on it (8.3). A wallet's own relay is only where its
  listener runs. Switching it before pairing changes the relay of A's next invite; during or after
  pairing it changes nothing for the pairing. No message is sent about it.
- **User sees.** Nothing.
- **Test.** engine: pair A and B with home relay R1, switch A to R2 and B to R3 before the confirm,
  then deliver an invoice and a withdrawal; all arrive. e2e: the same with three relays.

### C-02 A paired contact's payments address changes

- **What happens.** The relationship does not use either wallet's payments address. When the card's
  optional payments address (tag `09`) changes, the contact sends an update with an address proof
  (6.1), and plain Epicbox sends to the contact use the new address. An update whose proof fails
  keeps the stored address.
- **User sees.** The contact's details show the new address.
- **Test.** unit: a card with a higher `seq` replaces the stored one; an equal or lower one is
  ignored. engine: an update with a valid proof changes the address; one with a bad proof does not.

### C-03 A sealed slate or invoice is in flight during a relay switch

- **What happens.** Sealed files and pastes use no relay. A sealed invoice, withdrawal, I2 or S2 in
  a mailbox sits on the home relay, which neither wallet's switch affects. An outbox entry posts to
  the home relay.
- **User sees.** Nothing.
- **Test.** engine: queue an I2 in the outbox, switch the wallet's relay, run the outbox; the I2
  reaches the home relay. e2e: switch relays between I1 and I2.

### C-04 The pairing relay differs from both wallets' relays

- **What happens.** This is the usual case for a person invited by someone on another relay, and
  for every service. A one-off drain (8.2) opens its own connection to the relay in the invite.
- **User sees.** Nothing.
- **Test.** engine: A on R1 invites with home relay R3, B on R2; pairing completes.

### C-05 The home relay is down

- **What happens.** Collecting backs off per relay (8.4) and the outbox retries on its schedule
  (12.4). Messages already on the relay wait there for 7 days. A pairing whose relay is down offers
  the by-hand reply and confirm links.
- **User sees.** On the contact: "Exchange X's relay isn't answering". On a payment after 24 hours:
  "Couldn't reach Exchange X yet. Your funds are safe; they unlock if it doesn't post." During
  pairing: "Can't reach the relay. Send your answer by hand?"
- **Test.** engine: the mock relay refuses connections; the backoff steps, `HomeRelayUnreachable`,
  `OutboxStuck` after 24 hours of mock time, and delivery once the relay returns.

### C-06 Many contacts on different relays

- **What happens.** One connection per relay per cycle, mailboxes in turn on it (8.2), at most 50
  mailboxes per cycle, round-robin. On the host's foreground tick only contacts with something
  pending are drained, unless all sit on at most 3 relays. Opening the app drains every mailbox.
- **User sees.** Nothing. Pull to refresh drains every mailbox.
- **Test.** engine: 120 contacts on 7 relays; one cycle opens 7 connections and reads at most 50
  mailboxes; three cycles cover all; pending contacts are read every cycle.

### C-07 A contact moves to another relay

- **What happens.** The mover sends one signed update (`05`) to each contact and reads its old
  mailboxes for the drain period it chose (8.5). The receiver stores the newer card, keeps
  delivering to the mailbox in use, and raises `ContactRelayMoveRequested` with the contact and the
  relay. When the host applies the move, the wallet delivers to the new mailbox, moves its own
  mailbox for the contact to the new relay, sends its new card in a `05`, and reads its previous
  mailbox for 7 days. When the host does not, nothing changes. The contact's kind plays no part.
  - **The update is lost.** A card that names another mailbox outside a `05` is ignored, so the
    card in a later envelope moves nothing. A contact check (`09`) at the old mailbox during the
    drain period is answered with the new card, which reports the move. Otherwise the contact sends
    the move again with a higher `seq`.
  - **Both sides move.** A user's own relay switch changes nothing (C-01). Each move is one `05`
    that the other side follows only when its host applies it.
- **User sees.** What the host shows for the request.
- **Test.** engine: an update naming another relay leaves the mailbox in use, stores the card and
  raises the request once, for a person and a service alike; applying it moves the mailbox, queues
  our new card and keeps the old mailbox 7 days; applying another relay, or with no request, is
  refused. engine: with the update dropped by the mock relay, the card in the next envelope does
  not move the mailbox, and a new `05` with a higher `seq` is reported.

### C-08 No push

- **What happens.** No mailbox is registered for push (8.6). Pairing mailboxes are drained on the
  pairing screens and on open (8.2); contact mailboxes by collecting (8.4).
- **User sees.** A deposit request appears on the next collect.
- **Test.** engine: pairing and contacts make no push registration.

## Network modes

### C-09 Tor on, off, or Tor only

- **What happens.** Mailbox drains and posts take the wallet's Epicbox route: over Tor when Epicbox
  over Tor is on ([ADR 0021](../adr/0021-epicbox-over-tor.md)), to the onion in the invite or card
  when there is one, and through an exit otherwise. A relay that has no onion and cannot be reached
  through an exit is unreachable in Tor-only mode; pairing then offers the by-hand links and
  collecting marks the relay as not answering. Sealed files and pastes use no network.
- **User sees.** "Can't reach the relay over Tor. Send your answer by hand?" during pairing;
  otherwise the messages of C-05.
- **Test.** engine: with the Tor connector mocked, drains go to the onion when given and through the
  exit otherwise; Tor only, with no onion and a refused exit, gives the by-hand offer.

### C-10 Offline

- **What happens.** Offline makes no network calls. Online pairing, collecting and the outbox
  pause; in-person pairing (7.4) and sealed files and pastes work. The outbox resumes when the mode
  changes.
- **User sees.** "Pair online" is disabled with "You're offline. Pair in person instead."
- **Test.** engine: Offline, one-off drains and outbox posts return the offline error without
  connecting; in-person pairing completes.

## Devices and restores

### C-11 Two devices on one seed

- **What happens.** Both derive the same `root`. Each install keeps its own slot counter, and a
  store without one starts at a random slot (2.2), so two devices rarely pick the same slot. Their
  mailboxes always differ because `box_salt` is random. When they meet in a slot, the two contacts
  of that slot see the same keys for this wallet, and each envelope still reaches the right record,
  chosen by the sender's signing key (3.4). A pairing lives on the device that made it.
  - **One invite opened on both.** A accepts the first reply and answers the second with status
    `02`.
  - **A backup restored on the second device while the first runs.** Both drain the same
    mailboxes. The app imports the records as "on another device" and asks before using them
    (9.5).
- **User sees.** Contacts paired on the phone are not on the desktop unless restored from a backup
  there; then "Use your contacts on this device? Your other device should stop using them." The
  device whose reply came second shows "This invite was already used".
- **Test.** engine: two wallets on one seed pair with different contacts and their mailboxes
  differ; forced into one slot, envelopes from each contact reach the right record; one invite
  opened twice gives one pairing and one status `02`.

### C-12 Restore from seed; a contact's keys change

- **What happens.** With the `.wfeh` backup (10.5) the records and the slot counter come back with
  the same keys, mailboxes and trust, and contacts notice nothing. Without it, the user pairs again,
  and the contact adds the new pairing to the existing address-book entry. The contact holds the
  old record and runs the key check (7.8): the restored wallet finds its old slot (2.5) and proves
  it with the old key, the contact proves its own old key back, the old record keeps its trust and
  Verified mark, and the new pairing is deleted. The restored side's own switches for the contact
  start at their defaults, and its mailbox is new.
  - **The slot is not found** (the other wallet uses another seed), or no answer comes within 24
    hours: the old record stays as it was and the new pairing goes to Keys changed. That pairing
    seals nothing and takes no invoices until the user keeps the old record or uses the new keys.
    An impostor who pairs again as the contact inherits nothing and cannot change the old record.
  - A key changes no other way: a card or envelope signed by another key, or a contact update on
    the old pairing, never completes a check.
- **User sees.** When the slot is found: "Anna's keys are back." When it is not: "Anna's keys
  changed. This can mean she uses a different wallet, or someone else is using her name. Check the
  words again." with "Check the words", "Keep the old keys" and "Use the new keys".
- **Test.** engine:
  - restore with the backup: the same keys and pairings, the contact unaffected;
  - restore without it and pair again: the same keys, the contact's record and trust kept, no Keys
    changed;
  - pair again with a wallet of another seed, or with no answer in 24 hours: the new pairing in
    Keys changed, the old record unchanged;
  - a `05` on the old pairing during an open check does not complete it;
  - a found answer without a valid old-key proof is refused, and so is a restored answer without
    X's old-key proof.
  - vectors: `keycheck.json`.

### C-13 The seed is later used in a stock wallet

- **What happens.** A stock wallet cannot open `.epicsealed` files and never reads contact
  mailboxes. A LEPIC sender whose sealed slate gets no answer uses "Send as plain instead" (9.3),
  which writes the stored slate of the same stage: same slate id, inputs and signatures. A stock
  receiver answers it as any V3 slate. A LEPIC S1 still pending when its owner moved to a stock
  wallet cannot be finalized there; the sender's funds unlock at the TTL or on cancel, and the old
  S1 is never posted.
- **User sees.** On the stock side, the file is refused as not a slate. On the LEPIC side, after no
  answer: "Anna can't open sealed files? Send as plain instead".
- **Test.** unit: the fallback output decodes to the identical slate. e2e: seal to a contact, the
  contact's seed in `epic-wallet` v4.1.0 refuses the sealed file and takes the plain fallback;
  exactly one transaction confirms.

## Invites

### C-14 The invite expired

- **What happens.** B's app refuses an invite past its expiry plus 10 minutes, without a network
  call. A drains the reply mailbox until the expiry plus 10 minutes, and once more at its first
  drain of that relay after the deadline, or one hour after it (8.2); then the pending pairing
  ends. A reply posted after that drain is never read. A reply that reached the relay in time still
  pairs, however late it is collected.
- **User sees.** B: "This invite has expired. Ask Anna for a new one." A: the invite shows
  "Expired" with "Invite again".
- **Test.** unit: expiry with the 10-minute tolerance. engine: a reply posted after A's deadline is
  never opened, and A's pending pairing is gone.

### C-15 The invite is used twice, forwarded, or leaked

- **What happens.** A pairs with the first valid reply and answers each later one with status `02`
  (7.3), an anonymous one-byte confirm that carries none of A's keys or nonces; an invite answers
  at most 3 refusals. When the first replier is not the intended person, A sees its claimed name
  and a SAS that does not match on a call. A service binds each invite to a logged-in account and
  expires it in 15 minutes, so a leaked service invite pairs at most one wallet to that account,
  which the account page shows and can remove.
- **User sees.** A late B: "This invite was already used. Ask for a new one." A, when a second reply
  arrives: "Someone else also answered this invite. If you didn't share it with them, remove them".
- **Test.** engine: two replies to one invite give one pairing and one status `02`; the second
  replier's pending pairing ends; A is warned.

### C-16 B answers after A cancelled the invite

- **What happens.** An invite A cancelled keeps its pending row until it expires, and a reply to it
  gets status `04` (10.2). An invite A deleted is no longer drained. B waits for a confirm 1 hour,
  and at least until A could no longer take the reply (8.2), then its pending pairing ends. The
  reply expires on the relay after 7 days.
- **User sees.** B: "Anna cancelled this invite." with status `04`; otherwise "No answer from Anna.
  The invite may have been cancelled."
- **Test.** engine: cancel on A; B ends at once with `04`, or after its wait when A deleted the
  invite.

### C-17 Both invite each other at once

- **What happens.** Two invites make two pairings. When the user adds the second to the same
  address-book entry, the key check (7.8) runs: the other side finds the slot among its own records
  first and the second pairing is folded into the first.
- **User sees.** One contact, paired once.
- **Test.** engine: crossed invites complete; one record remains on each side, with the older keys.

## SAS

### C-18 The SAS does not match

- **What happens.** "They don't match" ends the pairing on that side with reason `mismatch` and
  drops its invoices and queued messages (7.5). A contact that claims the status notices gets a
  sealed `pair-mismatch` and ends its side with `peer-mismatch`. An inviter also posts a refusal to
  the invitee's confirm mailbox, best effort. Nothing was trusted before the check except "Paired,
  not verified", and no invoice switch is on by default.
- **User sees.** "The codes don't match. Someone may have changed the invite on the way. Pair
  again, in person or with a fresh invite."
- **Test.** unit: a changed card or nonce changes the SAS (`sas.json`). engine: a relay that swaps
  the invite's key is caught by B's commitment check; a swapped reply gives a different SAS on each
  side; a mismatch ends both sides.

## Contacts

### C-19 A contact is removed, then paired again

- **What happens.** "Remove pairing" deletes the record and any pending pairing for it; the slot
  stays used. Before the record goes, the wallet sends the contact a signed `unpaired` notice once,
  waiting at most 10 seconds for the relay (7.6). The contact marks its record "removed by the
  contact" and takes nothing more through it. Envelopes the contact sent before it learned this
  find no record: over files "sealed for another wallet or install"; in its mailbox nobody reads
  them. Pairing again with a contact that kept its record runs the key check (7.8) and takes the old
  slot back.
- **User sees.** "Remove the pairing with Anna? Sealed payments and invoices from Anna will stop."
  On the contact's side, the pairing shows as removed by the contact.
- **Test.** engine: after removal the mailbox is not drained, the contact receives `unpaired`, and
  a sealed file from the contact does not open; pairing again with a contact that kept its record
  restores the old slot.

### C-20 Invoice trust is turned off with an invoice pending

- **What happens.** As 11.1: unpaid parked invoices from the contact are deleted, each with a
  signed `declined`, so the service stops waiting; a paid invoice finishes as any paid invoice;
  new invoices are acknowledged and dropped.
- **User sees.** "Invoices from Exchange X are off. 1 open request was declined."
- **Test.** engine: two parked invoices and one paid; switch off; two are deleted and declined, the
  paid one completes.

### C-21 A pairing and the address book

- **What happens.** The address book is the host's. A pairing record points to one entry
  (`app_contact`, at most 256 bytes). After pairing, the app offers to attach it to an entry the
  user picks or to a new entry; it never suggests an entry because of the payments address a card
  claims. An entry has at most one pairing; a second pairing added to it runs the key check (7.8).
  - An entry holds at most one address per method: one Epicbox, one HTTP and one Tor address.
  - The card's proven payments address fills the Epicbox address of a new entry, and replaces a
    different one only after the user agrees.
  - The pairing's mailbox is never shown as an address.
  - An unpaired entry's addresses change only when the user edits them.
- **User sees.** "Save as a new contact" or "Add to a contact" with a picker. The contact page shows
  "Paired" or "Verified" with the trust switches.
- **Test.** app: attaching, the entry picker, one pairing per entry, one address per method.

## Invoices

### C-22 A service with many customers

- **What happens.** As 13.4: one shared inbox found by fixed hints, indexed, at most one envelope
  opened per message, per-key and global limits, invites bound to accounts and capped. Each customer
  sees the service as one contact.
- **User sees.** Nothing.
- **Test.** kit: 100,000 customers in the store and a burst of 10,000 messages; lookups by index,
  drops over the limits, no envelope opened without a hint match.

### C-23 An invoice from an unpaired key

- **What happens.** A contact mailbox is known only to its contact, and an invoice in it must open
  with that contact's key and carry its signature (11.2). An unpaired key can do neither, so its
  message is acknowledged and dropped. The payments address is not an invoice path (11.5).
- **User sees.** Nothing.
- **Test.** engine: an I1 sealed by a stranger to a guessed mailbox, a plain I1 in a mailbox, and a
  contact's I1 signed by another key are all dropped, and none parks.

### C-24 A bounce from a stock wallet

- **What happens.** Sealed invoices go only to the mailboxes of paired LEPIC contacts, which a
  stock wallet never reads, so nothing bounces. Plain invoices over file follow the legacy rules.
  Issuing an invoice over Epicbox needs a pairing, so the bounce handling of
  [Epicbox compatibility](../compat/epicbox.md) does not apply to it.
- **User sees.** Nothing.
- **Test.** As C-23.

### C-25 Withdrawn and declined notices

- **What happens.** As 11.4: type `02` envelopes in the contact mailboxes, accepted only from the
  contact, advisory, except that a signed `withdrawn` for a paid invoice cancels the payment and
  releases its inputs.
- **User sees.** "Exchange X withdrew the request; your funds are unlocked." "Declined."
- **Test.** engine: each notice, from the contact and from another key; the cancel path.

## Time, lifecycle and input

### C-26 Clock skew

- **What happens.** Clocks are used for invite expiry, envelope age (extension `80`), invoice and
  withdrawal `expires`, lapses and backoff. B accepts an invite up to 10 minutes past its expiry by
  B's clock, and A, whose clock set it, decides. An envelope sealed more than 24 hours ahead of the
  recipient's clock is refused. Envelope `expires` is advisory: the slate's TTL height decides what
  can be finalized. Neither the SAS nor the signatures depend on time.
- **User sees.** Nothing unless a clock is far off; then "This invite has expired" with a hint to
  check the phone's time.
- **Test.** unit: expiry with 10 minutes either way.

### C-27 The app is killed mid-pairing

- **What happens.** Every pending pairing is in the store before anything is posted (7.1, 7.2), and
  draining resumes on the next open (8.2). A message read but not stored is not acknowledged, so
  the relay hands it out again.
- **User sees.** The invite or the waiting screen again, under Contacts › Pending.
- **Test.** engine: stop the wallet after posting the reply and before the confirm, reopen; the
  pairing completes.

### C-28 Partial scans; camera denied

- **What happens.** A QR code decodes completely or not at all, and the link's checksum refuses a
  corrupted read with its own error. When the camera is denied or missing, the pairing screens
  offer pairing words (7.7) and "Enter link or words", which takes a pasted link or typed words.
- **User sees.** "Allow the camera to scan, or use words instead."
- **Test.** unit: a flipped byte fails the checksum with its own error. app: the denied-camera path.

## Attacks and versions

### C-29 Downgrade to plain

- **What happens.** Between paired contacts the sender seals because the record says so, and
  nothing on a channel turns that off. Plain happens only when the user taps "Send as plain
  instead" or turns sealing off for the contact. A plain payload in a contact mailbox is dropped.
  For unpaired peers, someone who strips or replaces the reply key in a plain S1 gets a plain or
  self-sealed S2, which the plain S2 would have shown anyway. A plain slate from a paired contact
  over file (its user chose plain) is taken with "This arrived unsealed".
- **User sees.** The "Send as plain instead" confirmation says that anyone with the file can read
  it.
- **Test.** engine: a plain payload in a mailbox is dropped; stripping the reply key gives a plain
  S2; the paired path writes plain only on the explicit call.

### C-30 An older LEPIC peer

- **What happens.** A peer that writes no reply key gets plain answers. A peer that does not handle
  `epiccash://pair` lets the invite expire (C-14). A peer that reads a sealed file as not a slate
  leaves the sender the fallback (9.3). A newer envelope or card version is refused as "made by a
  newer wallet", and senders use the lower of the two envelope versions (section 4).
- **User sees.** "Update the wallet to open this" for a newer version.
- **Test.** unit: an envelope of version 2 is refused with its own error; a marker without `reply`
  gives a plain answer.

### C-31 The reply key in the marker and other wallets

- **What happens.** The marker (section 5) is one top-level JSON key. Stock `epic-wallet` v4.1.0
  ignores unknown top-level keys and drops it, so its answers are plain.
- **User sees.** Nothing.
- **Test.** e2e: a marked S1 file into `epic-wallet` v4.1.0 is answered.

### C-32 Update floods

- **What happens.** A user's relay switch sends nothing (8.3), however often the user switches.
  Receivers take an update only with a higher `seq` and a valid signature from a paired key, at
  most 3 a day per contact and 100 an hour in all, and the kit applies its own limits to what
  customers send (13.4). A move to another relay is only reported; the host decides whether to
  follow. The card in a later envelope heals a dropped change of name or payments address, but a
  card that names another mailbox moves nothing outside a `05`, so a dropped move waits for the
  contact to send it again. Contact checks are answered within the host's pace (8.5).
- **User sees.** Nothing.
- **Test.** engine and kit: 10 updates from one contact in an hour, 3 applied; an equal or lower
  `seq` ignored; an update signed by another key dropped.

## Words and relay mode

### C-33 Pairing words typed wrong, guessed, or used twice

- **What happens.** Wrong words derive other mailboxes, which hold nothing; B drains each built-in
  relay once and stops. Guessing is costly (7.7). The first B that opens the words acknowledges the
  message, so a second finds nothing; a party that read the invite first is in the position of a
  leaked invite (C-15). Words are not offered on a network with no built-in relay.
- **User sees.** "No invite found for these words. Check them, or ask for new ones."
- **Test.** unit: `words.json`. engine: wrong words find nothing after one drain per built-in relay;
  the right words open the invite and pairing completes; a second use finds nothing.

### C-34 Epicbox switched off

- **What happens.** As 8.7: no relay connections; in-person and by-hand pairing and sealed files
  work; collecting, contact invoices and the outbox pause and resume when Epicbox is back.
- **User sees.** "Paused while Epicbox is off" on the contact page and in Settings › Invoices;
  "Pair online" offers only the by-hand links.
- **Test.** engine: with Epicbox off, drains and outbox posts return the off error without
  connecting; in-person pairing completes; the outbox posts after Epicbox is back.
