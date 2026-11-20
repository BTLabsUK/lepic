# Legacy transactions

The address decides the protocol. A classic address, Epicbox, HTTP, Tor or a slate file, gets
the V2 or V3 JSON slates that stock `epic-wallet` reads and writes, and nothing else; native
slates go only to an [epic1 address](epic1-overview.md), a paired contact or a code scanned in
person.

## The classic paths

| Path | LEPIC sends | LEPIC accepts | The other side | Detail |
|---|---|---|---|---|
| Epicbox, `KEY@DOMAIN` | A new slate as V2; a reply in the shape it answers | An S1 or S2, V3 then V2 by shape | Stock wallets and other LEPIC wallets, each reading its mailbox on a relay | [Epicbox](protocols/epicbox.md#sending) |
| HTTP, `http://` or `https://HOST[:PORT]` | An S1 as V2 by `receive_tx`; a reply in the shape it answers | An S1, V3 then V2 by shape, at `/v2/foreign` | Exchanges, pools (`build_coinbase`) and stock wallets that serve or call the foreign API | [HTTP](protocols/http.md#the-foreign-api) |
| Tor, `NAME.onion` | As HTTP, at the onion's port 80 | As HTTP | Stock wallets with a Tor listener | [Tor](protocols/tor.md#sending) |
| Slate file | V3, new slates and replies | V2 or V3, by the slate's version | Any wallet that reads and writes slate files, offline | [Legacy slates](compat/legacy-slates.md) |

## A classic send

1. `lepic tx send 1.5 --to KEY@DOMAIN` builds the S1 and locks its inputs.
2. The wallet writes the S1 as V2 JSON, encrypts it to the payee's Epicbox key and posts it
   through its own relay. A relay of 3.1.0 or later also gets a transaction id, so the send
   can be cancelled there.
3. The payee's wallet reads the S1 from its mailbox, signs it and posts the S2 back to the
   payer's address.
4. The payer's next `lepic epicbox listen` or `lepic epicbox drain` reads the S2, finalizes
   it and posts the transaction to the node.

To an HTTP or Tor address, step 2 is `check_version` and then `receive_tx`; the S2 comes back
in the same exchange, and the same command finalizes and posts. With `--to-file` the S1 is a
V3 file, the payee runs `lepic tx receive FILE`, and the payer finalizes the
`FILE.response` with `lepic tx finalize`.

## A classic receive

1. `lepic wallet address` prints the payments address, `KEY@DOMAIN`, where `DOMAIN` is the
   wallet's relay. The sender pays it.
2. `lepic epicbox listen`, or `lepic epicbox drain` once, reads the S1, in V3 or V2.
3. The wallet signs it and posts the S2 to the sender's address, in the shape the S1 came in.
4. The sender finalizes the S2 and posts the transaction.

With `refuse_unsolicited_payments = true`, every new S1 to the payments address is refused and
the sender is told nothing. `lepic http listen` and `lepic tor listen` answer `receive_tx` in
the same request; `lepic tx receive FILE` writes the reply to `FILE.response`.

## Invoices

A classic invoice travels only as a file. `lepic invoice issue AMOUNT --to-file FILE` writes
it; `--to ADDRESS` is refused with exit code 2 and stores nothing. The payer runs
`lepic invoice pay FILE AMOUNT`, typing the amount again; another amount is refused, and the
wallet pays only after the payer saw the amount and message and agreed, at the prompt or with
`--yes`. The issuer finalizes the answer with `lepic tx finalize FILE.response`.

An invoice that reaches the payments address over Epicbox is dropped, and the listeners answer
payments only. Invoices between wallets that are not files go only between paired contacts, and
the payer takes one only from a contact it verified and allowed to send invoices
([Pairing](protocols/pairing.md)). [cli.md](cli.md#invoices) has every option.

## The foreign API

LEPIC answers `check_version`, `receive_tx` and, when asked, `build_coinbase` at `/v2/foreign`,
and calls `check_version` and `receive_tx` as a sender. `check_version` answers foreign API
version 2 and slate versions V3 and V2, the stock keys only. `build_coinbase` is off unless the
listener runs with `--coinbase`, and a Tor listener never serves it. Any other method is answered
as unknown. [compat/foreign-api.md](compat/foreign-api.md) has the requests, answers and limits.

## What LEPIC does not do on a classic address

- No native `lepic.v1` slates.
- No sealed envelope.
- No marker key in a slate.
- No notices.
- No invoices over Epicbox.
- No version advert in `check_version`.
- No peer pins or peer facts.
- No setting or flag that turns a native path on.

These were dropped in the unreleased work; the [CHANGELOG](../CHANGELOG.md) lists each one.

## Cancel, expiry and recovery

`lepic tx cancel` frees a send's inputs, and asks an Epicbox relay of 3.1.0 or later to drop the
slate first; a send whose transaction was posted is refused
([After the send](cli.md#after-the-send)).
A V2 slate has no TTL field, so the wallet keeps the `--ttl-blocks` height itself and expires an
unanswered send at refresh ([Send](cli.md#send)). A posted send that cannot complete is spent back
by `lepic tx recover`, the last resort of
[ADR 0062](adr/0062-the-address-decides-the-protocol.md).
