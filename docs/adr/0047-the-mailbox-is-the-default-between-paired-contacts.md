# 0047 The mailbox is the default between paired contacts

Status: accepted
Date: 2026-11-06

Amends RFC 0002 (sections 9.1, 10.5 and 15, and the tag `09` row). Uses 0033 (address proof).

## Context

RFC 0002 said a send to a paired contact over Epicbox goes to the contact's payments address, unless
the user chooses the mailbox. The core already sends through the pairing (`contact_send`) and
checks it before it locks any input. BT Wallet had the mailbox as an off-by-default switch on the phone and no route on the desktop.

## Decision

The host picks the default route for a send to a paired contact. The core states no default.

BT Wallet sends through the pairing when the pairing can carry payments, and keeps the
payments address (tag `09`) as the fallback.

| Case | Route |
|---|---|
| Paired or verified contact, card opens sealed, Epicbox online, no reason below | Pairing |
| Contact not paired, or the pairing is waiting, paused, ended or has changed keys | Payments address, as for any unpaired contact |
| The send call fails | The user may send to the public address with one tap; nothing is locked, because the core cancels a send it could not queue |
| No answer for 24 hours | The user is asked first; the app then cancels the waiting send and sends an ordinary one to the payments address. Later sends to that contact default to the address until a sealed message arrives |
| Not picked up at 7 days | The same prompt |
| The receiver refuses the slate (ADR 0045) | No fallback; the receiver refuses plain slates too |

The fallback is never automatic. It moves money, and it leaves two rows.

Tag `09` stays in every contact card, unchanged. The fallback is safe because it goes to an address
the pairing proved.

After `ContactKeysRestored`, the core redirects only undelivered outbox entries. A host may post a
waiting send again with `contact_post_slate`.

## Consequences

- No wire change, no new core code, no stored-data change. Older peers receive mailbox slates if
  their wallet collects contact slates; a failure shows as the 24-hour case.
- A pairing without a proven address (made before address proofs) still sends through the
  mailbox. Its fallback goes to the unproven address in Contacts.
- A stock wallet on the same seed cannot read the mailbox. While it answers plain slates, the
  host keeps the default on the address.
- The "Seal payments" switch no longer matters to this route. It governs files and pastes only
  (RFC 0002 section 9.1).

## Alternatives considered

- Automatic fallback: cancel and send again with no tap. Refused: money moves without the user.
- A plain resend of the same slate over Epicbox, one row. Refused: it needs a core call to lift
  the refusal of a plain resend of a contact-linked S1 and to set the counterparty so the S2 is
  accepted. That is a new path for a rare case; cancel and send again already works.
- Core reposts delivered entries on `ContactKeysRestored`. Refused: deciding when a send counts as
  lost is host policy, and the host can do it with `contact_post_slate`.
- Leave tag `09` out of invite and QR cards, and keep it only in way-1 request cards. Refused,
  checked on 2026-11-06. Nothing but the fallback send may break, and more does:
  1. Attaching such a pairing to a contact that has an Epicbox address is refused with
     `AddressProofMissing` (`contact_attach`, `check_attach_address`), and the app offers only
     "Save as a new contact". This covers pairing by QR with someone already in Contacts, and
     re-pairing after a seed-only restore.
  2. The duplicate-pairing guards look contacts up by payments key (`check_free`,
     `live_pairing_with`, `unheard_with`). Without it, a request to or from a contact already
     paired by QR is not stopped.
  3. The core learns compat from the pairing (`learn_from_pairing`). Without it, way-1
     eligibility and the other-app detection know less.
  4. "Proves another address" can no longer fire.

  Unchanged by narrowing: way-1 pairing without words, auto-fill of the fallback address (only the
  fallback is lost), refusals by pairing id, name-service payments key, restore. Narrowing would
  also need `queue_card_update` and `confirm_proofs` to follow the new rule. Relaxing
  `contact_attach` for unproven pairings would not restore cases 2 and 3.
