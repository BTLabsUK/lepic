# 0039 The host applies a contact's relay move

Status: accepted
Date: 2026-11-04

## Context

A paired contact tells this wallet about a new mailbox with a contact update (RFC 0002 8.5).
Until now `lepic-wallet-contacts` decided by the contact's kind whether to follow a move to
another relay: a shop or exchange moved this wallet's delivery and its own mailbox to the new
relay when that relay was a meeting relay or a named host on the default port, and a person's
update naming another relay was dropped. The kind on a card is the contact's own claim, so the
rule trusted a claim, and which relays are acceptable is a policy that belongs to the app, not
to core. the owner decided on 2026-11-04 that core stops judging relay moves.

## Decision

1. The collector never reads a contact's kind. A contact update is treated the same for a
   person, a shop and an exchange.
2. An update whose card names a mailbox on the same relay is applied as before: the stored card,
   the peer mailbox and the outbox destination change.
3. An update whose card names a mailbox on another relay stores the newer card and leaves the
   mailbox and this wallet's own card as they are. Core logs it and raises
   `Event::ContactRelayMoveRequested { contact_id, host }`, `host` as `domain:port`. A repeat of
   the same card raises nothing, since only a higher `seq` is taken. The update limits stay.
4. `ContactBook::apply_relay_move(contact_id, host)` applies the move: the outbox is redirected,
   this wallet's card is re-signed for its mailbox on the new relay and queued to the contact in
   a contact update in the same write, and the previous home is still drained for seven days.
   It fails with `ContactError::RelayMoveNotRequested` unless `host` is the relay the stored
   card names and differs from both the relay in use and the home relay.
5. `ContactView::requested_relay` shows a move that waits, derived from the stored card and the
   mailbox, so a host sees it after a restart. There is no schema change.
6. A card outside a contact update that names another mailbox is still ignored.
7. The FFI carries the event as `WalletEventKind::ContactRelayMoveRequested` (`contact_id`,
   `relay`), the call as `EpicWallet::contact_apply_relay_move`, the field as
   `ContactView::requested_relay`, and the refusal as `WalletErrorKind::RelayMoveNotRequested`
   (code 92).

## Consequences

- The app decides which relays to follow. BT Wallet follows only relays in its own Epicbox
  server list and shows any other request to the user.
- Moves core applied by kind before this change stay as they are: no migration touches existing
  mailboxes.
- The meeting-relay and default-port rule is gone from core. A host that wants it applies it
  itself before calling `apply_relay_move`.
- A person can now ask to be followed to another relay with a contact update; before, the update
  was dropped and people re-paired.
- Breaking FFI change: a new event kind, a new `ContactView` field and a new error kind.
- This amends RFC 0002 8.5, which allowed home relay moves only from services and only to a
  meeting relay or a named host on the default port.

## Alternatives considered

- Keep the rule by kind in core: the kind is a claim of the contact, and the relay policy is the
  app's.
- Apply every move to another relay at once: a contact could then steer this wallet's traffic to
  any relay without the app knowing.
- A setting in core listing the relays to follow: that is policy in core, and the app already
  holds its server list.
