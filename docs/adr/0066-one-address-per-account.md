# ADR 0066: One epic1 address per account; a request link only fills in the Send screen

Status: accepted
Date: 2026-11-19 (amended the same day: references, end dates, closing, refusing and extra
addresses removed)

## Terms

This record uses the owner's glossary of 2026-11-19, as ADR 0065 does. ADRs 0062 to 0064 and the
code use older words. Code names are quoted as they are today; renaming them is a later task and
no part of this record.

| Here | Meaning | ADR 0062 to 0064 and the code |
|---|---|---|
| Epicmail | the protocol a mailbox speaks | Epicbox, the Epicbox protocol |
| mailbox | a server that runs Epicmail | mailbox |
| slot | the box of one key on a mailbox, which a wallet watches | mailbox |
| epic1 address | the account's one epic1 address, index 0 of ADR 0063 §1 | public address, first address |
| payment link | the epic1 address as a link, payable any number of times | open link |
| request link | the payment link with an amount, a message or both, which fill in the payer's Send screen | link with an amount |
| invoice | a payment request: pushed only between paired contacts, or opened by the payer as a scan, a file or an invoice link (ADR 0068); never sent to an address | invoice, contact invoice |
| checkout request | an in-person invoice code that a shop's `lepic serve` issues for one order, signed for the shop's domain (ADR 0068) | paypoint code, in-person invoice |
| invoice link | a checkout request as `epiccash://invoice/1/<code>`; needs a checked domain (ADR 0068) | |
| legacy Epicbox address | the old index-0 Epicbox address | classic address, payments address |

## Context

ADR 0063 §7 gave every link an address of its own: a new address index, a new slot on every
mailbox, at most 256 open per account, and a restore that watches 101 slots past the highest
known index. A scale review of the branch before release found what this costs. A restored wallet
can hand out an address a second time. A restored app cannot make a link at all, because nothing
calls `epic1_issue_here`. Nothing closes a link, so the 256 run out. The direct endpoint tries
every open key on each payment. A shop needs one slot per order.

The first version of this record replaced that with one main address, requests matched by a
reference sealed into the payment, end dates, closing, refusals by request state and extra
addresses made by hand. The owner found that too complex and cut it on 2026-11-19 to what
follows.

## Decision

### 1. One epic1 address per account

- Each account has one epic1 address: index 0 of ADR 0063 §1, with the format, the keys and the
  slot it has today. Anyone pays it any number of times.
- The payment link is that address, as a link.
- No other address of an account is made, issued, watched or tried. The address format does not
  change and nothing is added to the envelope.
- Extra addresses are not part of this record. Separate accounts come later, as their own topic.

### 2. A request link fills in the Send screen

- A request link is the payment link with an amount, a message or both:

  ```
  epic:<address>[?amount=<n>][&message=<text>][&label=…][&http=…][&tor=…]
  ```

- The amount and the message only fill in the payer's Send screen. The payer may change both
  before paying. The payer's wallet does not refuse a payment whose amount differs from the
  link's.
- The payee keeps no record of a request link. Making one stores nothing and derives no key.
  The same link can be made any number of times and is always the same text for the same fields.
- Every payment arrives as a normal payment to the address, with the payer's message. Nothing
  matches a payment to a link, and nothing refuses a payment because of a link.
- A shop puts its order number in the message and matches payments itself. The message is
  written by the payer and proves nothing.
- `http` and `tor` entries stay as ADR 0063 §6 says. They describe how the wallet takes payments,
  not one link, so the wallet writes the entries of its running listeners into every link.

Note, 2026-11-20: the last bullet is not built. A wallet writes no listener entries into a link
by itself. In the CLI only `--http-host` and `--tor` add entries; `POST /links` takes `account`,
`amount` and `message` only and makes a link without entries.

### 3. How the payee takes a payment

- A payment to the address is taken, any amount, unless the wallet refuses payments nobody asked
  for (`refuse_unsolicited_payments`, ADR 0045). With that switch on, the epic1 address takes
  nothing and every payment to it is declined with `declined`, as ADR 0063 §9 says for the
  public address. Only invoices between contacts are asked for. A request link does not make a
  payment asked for.
- The refusal reason `amount` is no longer sent for a payment to the address. Readers keep
  understanding it, and invoices keep it.

### 4. Restore

- A wallet rebuilt from its phrase watches the epic1 address of each account and the slots of
  its contacts, on every mailbox of its list (ADR 0065 §9: read every mailbox that answers,
  report the rest). There is no gap, no window and no rounds over indexes.
- A restored install can share its address and make request links at once. Two installs on one
  recovery phrase share the one address. One install reads at a time per mailbox (see the note
below).

Note, 2026-11-19: two installs on one recovery phrase without a link are unsupported; users are
told to link the device instead. This section describes how that setup fails safe, not a feature.

Note, 2026-11-19: the sentence "both read it" was wrong. A mailbox slot has one reader. The
newest attach takes the slot; the mailbox tells the replaced socket, and mail not acknowledged
goes to the next attach. Two installs on one phrase stay in step this way:

- **Who reads.** Whichever install holds the slot reads the payment, stores it and answers it.
  It does not matter which one.
- **The other is told by the chain.** The payment is a normal receive. Once it is mined, the
  other install's refresh and update scan find the output and record an incoming entry from
  another wallet, confirmed (`TxOrigin::OtherWallet`). The chain is the one record both
  installs read, so nothing is counted twice. If an acknowledgement is lost and both installs
  answer one payment, the twins rules (`tests/wallet/twins.rs`) end the answer the payer did not
  finalize. The other install does not see the payment before it is mined, nor the payer's
  message.
- **Hand-off.** No mark is stored. A replaced slot stays with the other install until its
  hold-off (10 minutes) ends, then the session attaches it again. A pull only retries the
  reconnect, so two installs that both pull do not trade the slot. An open (start, unlock,
  `epic1_restore`) takes the slot back at once, and a new process holds no replaced state, so a
  restart takes the slot too. Neither install stops reading for longer than the hold-off.
- **Where the update scan runs.** The app runs it after each refresh, and so does `lepic serve`
  (its loop and `POST /sync`). A CLI command such as `wallet info` only refreshes; `lepic wallet
  scan` records the payment there. The update scan starts from the last scanned block, so a
  wallet made with a new phrase, which has none until its first full scan, does not run it
  after a refresh.

### 5. Service API and CLI

- `POST /links` builds a link from `account`, `amount` and `message` and returns its text. It
  stores nothing and has no id. `GET /links`, `POST /links/{id}/retire` and `POST /addresses`
  are removed. `GET /addresses` lists each account's epic1 address and legacy Epicbox address,
  without an index.
- A payment and its webhook carry no `link_id`, and `GET /payments` has no `link_id` filter. The
  payer's message is in `their_message`.
- CLI: `lepic epic1 address`, `link [--amount] [--message]`, `read`, `pay` and `restore` stay;
  `pay` takes the link's amount and message unless the command gives others. `new-address`,
  `issue-here`, `addresses`, `links` and `retire` are removed, and `address --index` goes.
- The API path and every version stay as they are.

### 6. Contacts

Unchanged. A paired contact has one slot from its pairing, as built. Invoices travel only
between verified contacts (ADR 0063 §8). The mailbox rules of ADR 0065 are unchanged: the list
is shipped + added − removed, no mailbox name in any link, no reply mailbox inside a payment,
health shown and never used to drop a mailbox, and an immediate error when payer and payee share
no mailbox.

### 7. Addresses and links made before this record

- Numbered addresses (index 1 and up) made by the 2026-11-17 pre-release build (schema 17) or by the branch before release are no
  longer watched or tried. A payment sent to one after the upgrade is not read; the payer's
  wallet cancels it at its deadline and frees its inputs. Coins already received at such an
  address stay in the wallet: they come from the seed, not from the address.
- The store is not migrated. The rows of the open set, the issuing install, the restore gap and
  the link records are no longer read. LEPIC is alpha; ADR 0063 accepted the same break for the
  link ring of the pre-release build.

## Consequences

- A wallet watches one slot per account plus one per contact. A shop with a million orders
  watches one.
- A restored wallet can ask for payment at once and cannot hand out a used address, because
  there is only one.
- Everyone who holds a user's links sees the same address. A user who wants two payers not to
  know they pay the same wallet uses a second account.
- The payee cannot tell which link a payment answers, and the wallet checks no amount. A shop
  reads the message and the amount and decides. Wrong amounts and changed messages are the
  shop's to handle.
- A wallet with `refuse_unsolicited_payments` on cannot be paid through a request link.
- Code goes: the open set and `MAX_OPEN`, `TooManyOpen`, `NotIssuingInstall`, `NoAddressLeft`,
  `AddressNotIssued`, the restore gap (`RESTORE_GAP`, `in_gap`, `past_gap`), the issuing install
  (`epic1_issuing`, `epic1_issue_here`), `epic1_new_address`, link records and link ids,
  `retire`, the amount check on both sides of an epic1 payment, and the restore rounds.
- Docs change: `docs/protocols/epic1.md`, `docs/cli.md`, `docs/api/README.md`, `openapi.json`,
  the binding guide.

## Tests the implementation needs

- Two payments with different amounts and messages to the same address are both taken and each
  shows its own message.
- A payer pays a request link with another amount and another message; the payment goes through
  and is taken.
- Making 1,000 request links stores nothing, attaches no slot and derives no key.
- With `refuse_unsolicited_payments` on, a payment to the address is declined with `declined`.
- A restored wallet takes a payment to its address and makes a request link without another
  step.
- A store holding numbered addresses and link rows opens, takes payments to index 0, and does
  not read or try the numbered ones.
- `POST /links` returns a link, twice the same text for the same fields; `GET /links` is gone.
- Link vectors are unchanged.

## Alternatives considered

- **One address and slot per link (ADR 0063 §7).** Each payer sees a different address. It
  costs a slot per link, a cap, an issuing install and a restore that guesses. Replaced.
- **A reference in the link, sealed into the payment and matched by the payee, with end dates,
  closing and refusals** (this record's first version). It lets a wallet tell requests apart
  and refuse late or repeated payments. It needs request records, states, new refusal reasons,
  idempotent API calls and a rule for unknown references. Removed by the owner on 2026-11-19 as
  too complex; the message carries an order number instead.
- **Extra addresses made by hand** (the first version). A second address for privacy needs
  numbering, naming, closing and a restore window. Left out; separate accounts come later.
- **Shared slots with a number sealed into the payment.** It changes the address format and the
  envelope. Not built.

## Related

- Supersedes in part ADR 0063: §7 (a link per address, the link id, the 256 bound, the restore
  gap), the `POST /addresses` and link id lines of §8, the amount check of §7 and §9, and in §9
  "payments to an open link's address".
- Supersedes in part ADR 0058: link ids.
- ADR 0063 §1 to §6 and §10 stay: the address format, the delivery key as the slot, links with
  `http` and `tor` entries, upper-case QR for a bare address.
- ADR 0065: the mailbox list, the posting rule and the transport boundary.
- ADR 0045: refusing what was not asked for.
