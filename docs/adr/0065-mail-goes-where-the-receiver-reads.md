# ADR 0065: Mail goes where the receiver reads

Status: accepted
Date: 2026-11-19

## Terms

This record uses the owner's glossary of 2026-11-19. ADRs 0062 to 0064 and the code use older
words.

| Here | Meaning | ADR 0062 to 0064 and the code |
|---|---|---|
| Epicmail | the protocol a mailbox speaks, with its mux/1 push | Epicbox, the Epicbox protocol |
| mailbox | a server that runs Epicmail | mailbox |
| slot | the box of one key on a mailbox, which a wallet watches | mailbox |
| request link | the payment link with an amount, a message or both, which fill in the payer's Send screen | link with an amount |
| payment link | the account's one epic1 address as a link, payable any number of times | open link |
| invoice | a payment request between paired contacts; never a link | invoice, contact invoice |
| legacy Epicbox address | the index-0 Epicbox address | classic address, payments address |

Names in code are quoted as they are today (`RelayNotRead`, `pairing_servers`, the home mailbox
field). Names this record adds use the glossary (`NoSharedMailbox`, `lepic mailbox`). Renaming
the code is a later task.

## Context

ADR 0064 made Epicmail the transport of every native call and left three things open: picking
mailboxes by health, failing over between mailboxes, and one place where the user edits the mailbox list.
A review of the branch before release found that each kind of message picks its
mailboxes by a rule of its own:

| Message | Posted to | Read on |
|---|---|---|
| Payment to an epic1 address, or a request or payment link without entries | every mailbox in the payer's list | the payee's list |
| Answer or refusal to a payment | the one mailbox the payment was read on | the payer's list |
| Pairing reply, confirmation, status and unpaired notices | the sender's list and the invite's mailbox | list and the invite's mailbox |
| Card update, mailbox move, contact check, invoice and its payment | the one mailbox of the pairing | list and that mailbox |
| Cancel of a copy | the mailboxes usable now, except the one read on | |
| Legacy Epicbox address | the host in the address | that host |

What follows from it:

- A payment arrives only when the two lists share a mailbox. Nothing checks this and nobody is told
  (`lepic-wallet-contacts/src/epic1.rs:669-678`, `delivery/epicbox.rs:262-292`).
- A post counts as done when one mailbox takes it. The mailboxes that failed are not tried again and
  the mailboxes that took it are not stored (`delivery/epicbox.rs:262-337`).
- The answer to a payment and every message between paired contacts depend on one mailbox
  (`epic1.rs:1707-1714`, `invoices.rs:257-291`). A mailbox move is announced through the mailbox
  being left (`manage.rs:698`).
- A cancel goes to the mailboxes usable at that moment, not to the mailboxes that hold a copy, and is
  not retried (`delivery/outbox.rs:1213-1216`).
- One greeting answered without mux/1 marks a mailbox as without push until the process ends. A
  mailbox at its connection limit answers the same way. The mailbox then leaves posts, watches,
  restore and cancels (`lepic-epicbox/src/mux/manager.rs:195-250`, `sessions.rs:281-299`).
- A mailbox is "usable" when it is not known to lack push. No failure count or last success exists
  (`delivery/epicbox.rs:35-47`).
- One mailbox that cannot be read fails a whole restore (`epic1.rs:2635-2663`).
- The list has two parts, the own mailbox and the meeting mailboxes, set by different calls. The CLI
  and `serve` cut the list to 3 (`lepic-cli/src/settings_file.rs:163`) and cannot change it while
  running. A shipped list never reaches an install that already has a settings file.
- Four FFI calls and one CLI command pass `Online` whatever the host chose
  (`lepic-ffi/src/session/contact.rs:604-653`, `lepic-cli/src/commands/contact.rs:222`).

The owner's goals: mailboxes are invisible to nearly every user; a user who cares has Tor, the kill
switch and a mailbox of their own; no link and no sealed payment ever names a mailbox; the core offers
tools and holds no policy; services and their customers share a few mailboxes.

## Decision

### 1. One mailbox list

- A wallet has one mailbox list for all native mail: the mailboxes shipped with the host's release,
  plus the mailboxes the user added, minus the shipped mailboxes the user removed.
- The host stores only `added` and `removed`. The shipped part comes from the release in use, so
  a release that changes it reaches every install.
- The own mailbox, the meeting mailboxes and `pairing_servers` are removed as concepts for native
  mail. Nothing native depends on a mailbox's position in the list.
- The legacy Epicbox address keeps its host. That host is a setting of the legacy lane and decides
  nothing for native mail.
- The list holds at most 16 mailboxes and never fewer than 1. A wallet that should reach no mailbox
  uses `Offline`.

### 2. Reading

A wallet attaches every native slot it watches on every mailbox of its list that offers mux/1.
This is ADR 0063 §3, now for every class of slot.

### 3. Posting: one rule for every native message

A message is posted to its receiver's slot key on at most 3 mailboxes, never on every mailbox of
the list:

- a payment or other new message: the 3 healthiest mailboxes of the sender's list (or of the
  list given for one payment, section 6). Between mailboxes of equal health the shipped ones
  come first, in the list's order;
- for mail to a paired contact: the mailbox of the contact's card (section 8), plus the 2
  healthiest others of the list;
- for an answer, a refusal or a notice about a received message: the mailbox that message was
  read on, plus the 2 healthiest others of the list.

Health (section 7) orders the pick: a mailbox that posts could not reach lately, or with more
failures since its last success, comes after one without. It drops no mailbox from the list, and
reading is unchanged (section 2). A retry of the whole message picks again, so a picked mailbox
that keeps failing gives its place to the next healthiest; a copy owed to one mailbox is tried
again on that mailbox. After a post could not reach a mailbox, the mailbox holds posts back for
30 seconds, doubling to 10 minutes: while it does, a post that has other mailboxes to go to
leaves it out without connecting, so a dead mailbox adds no connect timeout to every post, and
owes it a copy for after the hold. The same sealed bytes go to each. The outbox stores the result per mailbox. The entry is posted
when one mailbox took it, and the mailboxes that did not take it are tried again on the outbox's
schedule until the message is answered or ends. A route of the form `key@host`, which posts to
one mailbox only, is no longer written for native mail.

A cancel (ADR 0060) goes to the mailboxes stored as having taken a copy, and is tried again on the
same schedule while the payment is open.

### 4. No link and no payment names a mailbox

- An address, a payment link and a request link carry no mailbox, whatever the wallet's list
  holds. This is ADR 0063 §3 and §6, kept without exception. `mailbox=` is not added.
- A sealed payment names no mailbox either. The reply route keeps the reply key alone
  (ADR 0063 §5). No code path connects to a host read from a link or a sealed message.
- A user who reads a private mailbox only is paid by wallets that list the same mailbox. The
  user asks the payer to add it. Section 10 makes adding one a single step.
- An invite and a contact card keep the home mailbox field they have today (one host). They do
  not change on the wire.

### 5. Connecting to a mailbox outside the list

A wallet connects to a mailbox outside its list in one case: the mailbox of a paired contact's
card or of an invite the user accepted (the host applies a contact's move, ADR 0039). The
connection uses TLS to a public name; an address, a local name and port 0 are refused, as
`endpoint_for` does today. With Tor on it goes through Tor.

### 6. No shared mailbox is an error, at once

Two wallets on shipped lists always share a mailbox. When the payer's list holds no shipped
mailbox, `epic1_pay` cannot know that the payee reads any mailbox of the payer's list. It then
fails with `NoSharedMailbox` before anything is stored. The error lists the shipped mailboxes
and says that the payer and the payee need one mailbox in common. The pay call takes an
optional list of mailboxes to use for this one payment, so a host can ask its user ("the payee
gave me a mailbox") and pay through them once, or pass the wallet's own list when its user
runs a private setup with the payee.

### 7. Health is recorded per mailbox, and no verdict is final

- One record per mailbox, kept by the session service in `lepic-epicbox`: whether it offers push,
  the time of the last success, the count of failures since, the last error, and the posts in a
  row that could not reach it with the time it holds posts back until (section 3). A post it
  answers, taken or refused, clears the post fields.
- "No push" is asked again: after 1 minute, doubling to 1 hour. The answer of a mailbox at its
  connection limit and the answer of a mailbox without mux/1 look the same on the wire, so both
  get the same treatment.
- A mailbox that fails stays in the list. Posts to it are retried by section 3, its session
  reconnects with the backoff it has today, and the other mailboxes carry the mail meanwhile.
  Health orders which 3 mailboxes a post goes to (section 3); the core adds and removes no
  mailbox by itself.
- The record is part of the mailbox status the host reads. One event is raised when no mailbox of
  the list can be reached, and one when a mailbox comes back.
- The first reconnect after a lost session is spread over 1 to 10 seconds.

### 8. Contact mail

Card updates, mailbox moves, contact checks, invoices and their payments are posted by
section 3 to the contact's key, with the mailbox of the contact's card as the named mailbox. The
mailbox of a pairing is no longer the only way to a contact. A mailbox move stays a card update
(ADR 0040, 0042); it now reaches a contact on any mailbox the two share.

### 9. Restore

A restore reads every mailbox of the list it can reach and reports the ones it could not. It fails
only when none could be read.

### 10. One set of calls for the list

- Core: read the list with each mailbox's origin (shipped or added) and health; probe a host (TLS,
  greeting, push offered); set `added` and `removed`. A change applies to the running sessions.
- CLI: `lepic mailbox list`, `add`, `remove`, `probe`. Service API: `GET /mailboxes`, `POST /mailboxes`,
  `DELETE /mailboxes/{host}`, applied while `serve` runs.
- The probe reports what it found. Whether a mailbox that fails the probe is saved anyway is the
  host's choice.
- Every FFI call and CLI command takes the mailbox mode from the host. None passes `Online` by
  itself.
- Note, 2026-11-20: not built for four FFI calls. `pairing_standing_invite`,
  `contacts_set_own_name`, `contacts_move_home` and `contact_check` pass `Online` themselves
  (`crates/lepic-ffi/src/session/contact.rs`).

### 11. The transport boundary

Features reach mailboxes through one interface with five calls: post, cancel, watch a set, how
much waits, status. Constants of the Epicmail protocol (slots per session and the like) stay
inside `lepic-epicbox`. A later transport implements the same five calls and derives its own
identifiers from the address's delivery key.

### 12. Rules for the shipped list

These bind the hosts that ship a list (the app, the CLI); the core checks none of them.

- At least 3 mailboxes that offer mux/1, run by at least 2 operators.
- A release changes at most one mailbox of the list, so two neighbouring releases always share
  two.
- The app and the CLI of one release ship the same list; a test compares them.

## Consequences

- Two wallets on shipped lists always share a mailbox. A payment between them survives the loss
  of any mailbox but the last.
- A post costs at most 3 connections however long the list is. A payee that reads only mailboxes
  of the payer's list the payer did not pick is reached once the pick changes, which it does when
  a picked mailbox fails. Watching still holds one socket per listed mailbox; a cap on that is a
  later decision.
- An answer always goes to the mailbox its payment was read on, which the payer posted to and
  so watches.
- A user who left the shipped mailboxes is paid only by wallets that list one of the user's
  mailboxes. A payer off the shipped list is told at once; a payer on the shipped list that pays
  such a user is not, and its payment ends at its deadline.
- No link shows which mailbox a user reads, and no payer connects to a mailbox it did not choose.
- Every shipped mailbox carries every wallet on the shipped list, so adding a mailbox adds
  redundancy and no capacity. See "Alternatives considered" for the step that changes this.
- An answer and a contact message can sit on several mailboxes. Each copy is deleted when read, and
  at the latest at the mailbox's retention.
- Code goes: the own-mailbox and meeting-mailbox split, `pairing_servers`, the `key@host` route for
  native mail, the narrowing of pairing mail to a named mailbox, and the process-long "no push"
  verdict.
- Docs change: `docs/protocols/delivery.md`, `epic1.md`, `pairing.md`,
  `docs/cli.md`, `docs/api/README.md`, `openapi.json`.

## Tests the implementation needs

- A payment posted to three mailboxes where two refuse: posted at once, the two tried again, and
  the mailboxes that took it stored.
- A payee that reads a copy on mailbox A while A refuses posts: the answer reaches the payer
  through another mailbox both use.
- A cancel goes to exactly the mailboxes that took a copy, and is tried again after a failure.
- A mailbox that answers a greeting without mux/1 is asked again and used once it offers it.
- A link with `mailbox=` is read with the parameter reported as ignored, and no connection is
  made to its host.
- A payer with no shipped mailbox gets `NoSharedMailbox` and nothing is stored; the same call
  with mailboxes given pays.
- Neither a link nor an envelope can make a wallet connect to a host: no code path dials a host
  read from a link or a sealed message.
- A contact message arrives when the mailbox of the pairing is down and another shared mailbox is
  up; a mailbox move does too.
- A restore with one of three mailboxes down completes and reports that mailbox.
- `serve`: a mailbox added through the API is read without a restart.
- A settings file that stores only `added` and `removed` follows a changed shipped list.
- The app's and the CLI's shipped lists are equal.

## Alternatives considered

- **A signed mailbox list and 3 mailboxes picked per address by a fixed rule.** It spreads load once
  there are many mailboxes, as Session's swarms do. It needs a list every wallet agrees on to the
  byte, with a signer, a version and a refresh path, and a migration each time the list changes.
  With 4 public mailboxes the pick would return nearly the whole list. It becomes worth its cost
  above about 6 shipped mailboxes or when one mailbox nears its connection limit; the delivery key
  can seed the pick then without a new address.
- **A mailbox named in a link** (`mailbox=`, for wallets off the shipped list). A stranger could
  then pay a user on a private mailbox. The link would show which mailbox the user reads, break
  when the user leaves it, and make the payer connect to a host it did not choose. The owner
  refused it on 2026-11-19: no mailbox name in a link, ever.
- **A reply mailbox inside the sealed message.** The payer already watches its reply slot on
  every mailbox it posted to, so the answer needs no host. A host in the envelope would let anyone
  who holds an address make that wallet connect where they choose, which shows them its network
  address. Refused by the owner on 2026-11-19. Between paired contacts the card carries the mailbox, which is
  the same idea with a known sender.
- **The core switches away from a failing mailbox.** It switches where it posts (section 3,
  among the 3 picked) and nothing else: a switch of where the wallet reads would change it
  without the user's say.
- **A mailbox change for crowded networks** (count connections per network only until a slot
  key is proven, or a refusal with a wait time). The first is a small change in mailbox software
  and no wire change; the second changes the frozen mux/1 wire. Neither is needed for wallets to
  work once "no push" is asked again and the other mailboxes carry the mail. Left to mailbox
  operators.

## Related

- Supersedes in part ADR 0063: in §4 the payee "answers a payment once, on the mailbox it read it
  from" and the default-host notice, and §11 (pairing mail follows section 3 here). "A private
  mailbox works only when both sides list it" and "a link cannot point a payer to a mailbox" stay.
- Supersedes in part ADR 0047: the mailbox of a pairing (there: mailbox) as the single route between contacts.
- Completes ADR 0064, which left health, failover and the list's editing open.
- Uses ADR 0039 (the host applies a mailbox move), ADR 0060 (cancel on the mailbox), ADR 0036 (policy
  values are host parameters).
- ADR 0066 holds the address model: one epic1 address per account, and a request link that only
  fills in the payer's Send screen. No references, extra addresses or shared slots are built.
