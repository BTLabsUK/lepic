# cli-0.6.0

A wallet made by the LEPIC CLI build of 2026-11-17 (the pre-release build, schema 17, never
published; not the 0.6.0 release; the folder name keeps "0.6.0" because tests load it by path), with the open Epicbox work a user of that build can have
when they upgrade, and the mailboxes the relay held for it. Size: about 940 KB.

| | |
|---|---|
| Made by | LEPIC `8c5078971` (the tag `v0.6.0` now marks the release, not this commit) |
| Store schema | 17 (`SCHEMA_VERSION` of that commit; the file is encrypted, so the number is not readable from outside) |
| Network | floonet, a scripted node and a mock Epicbox relay, all in process |
| Phrase | the CLI test harness's `SENDER_MNEMONIC`: `abandon` 23 times, then `art` |
| Password | `upgrade fixture password` (`wallet/`), `upgrade peer password` (`payer/`) |
| Cargo features | none selected; the test build of `lepic-cli` has `lepic-keychain/test-kdf`, `lepic-node/mock` and `lepic-epicbox/mock-relay` from its dev-dependencies, so the wallets open only in a build with `test-kdf` |

## Files

- `wallet/`: the data directory of the wallet under test (the sender). Git keeps no file modes;
  the test sets 0700 and 0600 on its copy. The empty `.lepic.lock` is left out; the CLI makes it.
- `payer/`: the data directory of the second wallet (the peer), copied before the marked send
  reached it. Its phrase is random and not kept; the password opens it.
- `chain.json`: the scripted node's chain when the generator stopped, and the one transaction
  pushed and not mined. `RecordedChain` in `lepic-node` (`mock`) loads it.
- `expected.json`: what the pre-release build printed with `--json`: `wallet info`, `wallet address`,
  `wallet outputs`, `tx list`, `tx show` for every transaction, `contact list`,
  `invoice list`, `contact requests`, `epic1 links`, `epic1 address`; `payer` (the second
  wallet's `tx list`, `invoice list` and `contact requests`); `made` (what each step printed);
  `ids`.
- `mailbox.json`: the wallet's index-0 payments mailbox as the mock relay held it when the
  generator stopped: the address and, per message, `label`, `from`, `str`, `signature` (DER
  hex) and `txid` (null: the relay had no cancel).
- `payer-mailbox.json`: the same for the second wallet's mailbox, taken when `payer/` was copied.

## History

The wallet under test, in order:

1. Nine funding outputs of 10 EPIC found by `wallet restore`: transactions 1 to 9, confirmed.
2. A paired contact: a third wallet (the receiver, not kept) accepted the wallet's invite and both
   collected until paired (`ids.contact`).
3. A pending pairing: an invite named "Pending friend" that nobody answered
   (`ids.pending_contact`, in `made.pending_invite`). It is not shown by `contact list`.
4. Send A, by file, received by the second wallet, finalized and mined: transaction 10
   (`ids.mined`), confirmed.
5. A payment of 1 EPIC to the second wallet over Epicbox, finalized: transaction 11
   (`ids.epicbox`).
6. A payment of 0.5 EPIC over Epicbox to a fourth wallet (the stranger, not kept), finalized:
   transaction 12. It makes the wallet one the stranger may send a pairing request to.
7. A sent pairing request by Epicbox address to the second wallet (`contact request`,
   `ids.request_contact`), listed in `contact_list.sent_requests`.
8. A native send of 1 EPIC to the second wallet (`LEPIC_NATIVE_DIRECT`): transaction 13
   (`ids.native`), state `sent`. The second wallet answered with a sealed slate, which waits.
9. The stranger sent a pairing request to the wallet's Epicbox address: a notice that waits.
10. The second wallet issued an invoice of 1.5 EPIC to the wallet over Epicbox
    (`ids.incoming_invoice_slate`): an I1 that waits.
11. An epic1 reply mailbox and an epic1 link: the wallet paid the second wallet's printed epic1
    link (`epic1 pay`, transaction 14, `sent`, transport file), then printed a link of its own
    (`epic1 link --printed 2`), listed in `epic1_links`.
12. An in-person invoice of 1 EPIC (`in-person invoice`): transaction 15, `received`.
13. Send C, cancelled: transaction 16 (`ids.cancelled`).
14. Send B, by file, finalized and pushed, not mined: transaction 17 (`ids.pending`, `posted`).
    The sync test mines it.
15. An open Epicbox invoice of 1 EPIC from the wallet to the second wallet: transaction 18
    (`ids.open_invoice_slate`), `received`, unpaid.
16. An open marked send: an S1 of 1.25 EPIC to the second wallet's classic Epicbox address,
    carrying the LEPIC marker: transaction 19 (`ids.marked`), `sent`. The second wallet's copy in
    `payer/` was taken before it arrived. The second wallet then answered it (in the generator,
    not in `payer/`); the S2 waits for the wallet.
17. `epic1 address` printed the wallet's `tepic1` address.

## Mailboxes

`mailbox.json`, the wallet's index-0 payments mailbox, holds four messages, none acknowledged:

| Label | What it is | From |
|---|---|---|
| `sealed_slate` | the sealed S2 answering the native send (step 8) | second wallet |
| `notice` | a pairing request by Epicbox address (step 9), notice-shaped | stranger |
| `invoice_i1` | an I1 for the wallet to pay (step 10) | second wallet |
| `marked_reply` | the S2 answering the marked send (step 16) | second wallet |

`payer-mailbox.json`, the second wallet's mailbox, holds two:

| Label | What it is | From |
|---|---|---|
| `invoice_i1` | the open invoice's I1 (step 15) | the wallet |
| `marked_s1` | the marked S1 (step 16) | the wallet |

The tests post them to a fresh mock relay with their recorded `from`, `str` and `signature`,
so the relay checks the signatures as it did when they were sent.

## Held and not held

What the main store holds for the migration to schema 18 to read:

- a paired contact: held (step 2);
- a pending pairing: held, as an unanswered invite (step 3), and as a sent request (step 7);
- an epic1 link: held, one printed link (step 11);
- an epic1 reply mailbox: held, from paying the second wallet's link (step 11, transaction 14);
- an in-person mailbox: held, from the in-person invoice (step 12, transaction 15).

The open Epicbox invoice has one store per side: the issuer is `wallet/` (transaction 18) and the
payer is `payer/`, where the invoice is only an unread I1 in `payer-mailbox.json`. The pre-release build parks
an I1 only from a paired contact and refuses others (`park_contact_invoice` and the inbox's
`Refusal::UnsupportedStage`), so a payer store with a parked invoice from a non-contact cannot be
made with that build; `invoice_list` is empty on both sides.

Not held:

- a pairing request the wallet received and kept: `contact requests` is empty, because the
  stranger's request is still on the relay (the `notice` message);
- a received invoice the wallet declined: the pre-release build cannot decline an I1 it refused, see above;
- the receiver, the stranger and the second wallet's own history after `payer/` was copied;
- anything the harness cannot make offline: Tor, a real node, mainnet, coinbase outputs.

## Generator

`generator/upgrade_fixture.rs` is an ignored test of `lepic-cli`, a module of the `cli` test
binary of the pre-release build. `generator/mock_relay_waiting.patch` adds `MockRelay::waiting` to
`crates/lepic-epicbox/src/mock_relay.rs` of that commit, so the generator can read the messages the
relay holds; it is the only change to that commit, and only test code. To make the fixture again:

```sh
git worktree add --detach "$SCRATCH/gen-060" 8c5078971
cd "$SCRATCH/gen-060"
git apply <repo>/testdata/upgrade/cli-0.6.0/generator/mock_relay_waiting.patch
cp <repo>/testdata/upgrade/cli-0.6.0/generator/upgrade_fixture.rs crates/lepic-cli/tests/cli/
sed -i 's/^mod upgrade;$/mod upgrade;\nmod upgrade_fixture;/' crates/lepic-cli/tests/cli/main.rs
mkdir "$SCRATCH/cli-0.6.0"   # an empty directory
LEPIC_UPGRADE_OUT="$SCRATCH/cli-0.6.0" CARGO_INCREMENTAL=0 \
  cargo test -p lepic-cli --test cli upgrade_fixture -- --ignored
```

Generated ids, the other wallets' keys, kernel excesses, the messages' encryption and the dates of
the sends and requests (wall clock of the run) differ on every run, so a regenerated fixture
replaces every file; do not mix files from two runs.

## Meaning changes since the pre-release build

- `contact_list.sent_requests` and `contact_requests`: this build lists no pairing requests, so
  the test does not compare them. The rows stay in the store, unread.
- The unanswered invite of step 3 expires a day after the generator ran. No listing the test
  compares shows it.
