# ADR 0039: The host applies a contact's relay move

Status: accepted

## Context

A paired contact tells this wallet about a new mailbox with a contact update (RFC 0002 8.5). The
update may name a mailbox on another relay. Which relays a wallet follows a contact to is a policy
of the app that holds the user's server list and settings, not of core. The kind on a contact's
card is the contact's own claim, so a core rule that keyed on it would trust a claim.

## Decision

1. **No judgment in core.** The collector never reads a contact's kind. A contact update is treated
   the same for a person, a shop and an exchange.
2. **Same relay.** An update whose card names a mailbox on the same relay is applied: the stored
   card, the peer mailbox and the outbox destination change.
3. **Another relay.** An update whose card names a mailbox on another relay stores the newer card
   and leaves the mailbox in use and this wallet's own card as they are. Core logs it and raises
   `Event::ContactRelayMoveRequested`, which carries `contact_id` and `host` as `domain:port`. A
   repeat of the same card raises nothing, since only a higher `seq` is taken. The update limits
   of RFC 0002 8.5 stay.
4. **Applying it.** `ContactBook::apply_relay_move(contact_id, host)` redirects the outbox,
   re-signs this wallet's card for its mailbox on the new relay and queues it to the contact in a
   contact update, in one write. The previous home relay is still drained for seven days
   (`PREVIOUS_HOME_KEPT`). It fails with `ContactError::RelayMoveNotRequested` unless `host` is the
   relay the stored card names and differs from both the relay in use and the home relay, with
   `Ended` for an ended pairing and with `UnknownContact` for an unknown one.
5. **Pending moves.** `ContactView::requested_relay` shows a move that waits, derived from the
   stored card and the mailbox, so a host sees it after a restart. No state is stored for it.
6. **Cards elsewhere.** A card outside a contact update that names another mailbox is ignored.
7. **Binding.** The FFI carries the event as `WalletEventKind::ContactRelayMoveRequested`
   (`contact_id`, `relay`), the call as `EpicWallet::contact_apply_relay_move`, the field as
   `ContactView::requested_relay` and the refusal as `WalletErrorKind::RelayMoveNotRequested`
   (code 92).

RFC 0002 8.5 describes the contact update.

## Consequences

- The app decides which relays to follow, and may show the relay in use on a contact's page. A
  host that wants a rule, such as meeting relays only, applies it before calling
  `apply_relay_move`.
- A person can ask to be followed to another relay with a contact update, and a service can do the
  same.
- The binding has an event kind, a `ContactView` field and an error kind for it.

## Alternatives considered

- A rule by kind in core: the kind is a claim of the contact, and the relay policy is the app's.
- Apply every move to another relay at once: a contact could steer this wallet's traffic to any
  relay without the app knowing.
- A setting in core that lists the relays to follow: that is policy in core, and the app already
  holds its server list.

## Related

- ADR 0040: the relay move a wallet asks for itself.
- ADR 0042: draining the previous home.
- RFC 0002: contact pairing.
