# 0035 Restore from a start height

Status: accepted
Date: 2026-11-03

## Context

A wallet restored from its recovery phrase refuses to create outputs, so to receive, to invoice
or to send with change, until a scan of the chain from genesis has completed
(`wallet.restore_scan_required`, `WalletError::RestoreScanRequired`). On mainnet that scan reads
every output since 2019 and takes long enough that users give up before the wallet is usable.

The gate was added when every database handed out keys from the same counter start. A restored
wallet had to find the highest key the phrase had used, or it would hand out a key again, and a
scan from genesis found the unspent outputs of those keys and moved the counter past them. Even
then it never found spent outputs, so keys whose outputs were spent stayed invisible to it.

Since then each database draws a random key start in `[2^20, 2^31 - 2^24)`
(`wallet.output_key_start`), and a restore draws a fresh one. What keeps a restored wallet's keys
apart from the keys the phrase used before is that draw, not the scan. Wallets that do not draw a
start, such as epic-wallet, use keys from `m/0/0/1` up, in the low thousands, below `2^20`.

The app wants a phrase restore to start at a recent height that it picks, and the wallet to be
fully usable once that scan reaches the tip.

## Decision

1. A restore may start its scan at a height H. `Wallet::restore_from_height` takes it;
   `Wallet::restore` is the restore from 0. In `lepic-ffi`, `create` and `create_with_pin` take
   `restore_from_height: Option<u64>`, where `None` and `0` mean genesis and a height without a
   mnemonic is refused before anything is written. The CLI has `lepic wallet restore
   --from-height`. LEPIC holds no default height; the caller picks it.
2. The start is recorded in the existing setting. `wallet.restore_scan_required` keeps `true` for
   a restore from genesis, an import from `wallet.seed`, an open on a missing database and a
   rollback. A restore from H > 0 stores the decimal H. A reader takes an absent setting as not
   pending, a value of ASCII digits as that height, and anything else as 0.
3. While a restore is pending, a scan that reaches the tip from a start at or below the recorded
   start completes it. From 0 the completion is exactly as before: it sets
   `scan.genesis_completed` and flags imported history the chain lacks. From a start in (0, H] it
   clears the pending setting, moves the key counters (below) and stores the start in
   `scan.restore_completed_from`. It sets neither the genesis flag nor flags imported history,
   because outputs below the start were never looked for.
4. A scan without a start while a restore is pending starts at the recorded start: genesis for
   `true`, H for a height.
5. The update scan and the detection of outputs received by another wallet with the same phrase
   run after either completion. An output is taken as received elsewhere only at or above the
   height the completed scan covered from; an older one the update meets is an output found by
   the scan, as on a restore.
6. At a completion from a start above 0, each unhardened account's counter n moves past the keys
   the scan found near it. With GAP = 2^20: while some found child c lies in `[n - GAP, n + GAP)`,
   n becomes the highest such c plus 1 plus GAP. A counter that would reach the hardened range
   stays where it is. Key derivation and paths do not change; a counter only moves upward.

A found key near the counter means another install of the phrase hands out keys in that range.
Its keys used before H lie below its found keys, because counters only rise, and moving past the
highest found key by GAP leaves room for more keys than one install hands out.

## Consequences

- A restore from a recent height is usable after a short scan. Reusing a key the phrase used
  before H needs the fresh key start to land within the thousands of keys of an earlier install
  with none of that install's outputs unspent at or above H, about `2^13 / 2^31 = 2^-18` per
  earlier install, and the gap rule removes the case where its outputs are still on chain. Keys
  of epic-wallet installs lie below every drawn start.
- Unspent outputs older than H are not found, so their balance is missing. A scan from 0, or from
  any height below them, finds them; after a completion from a height, a later scan from 0 sets
  the genesis flag and flags imported history as before.
- Existing databases, including restores still pending with `true`, read and behave exactly as
  before, and a restore from 0 is unchanged. One setting gets a new value form, written only by a
  new restore from a height, and one setting is new. Nothing is migrated.
- An older LEPIC that opens a database with a decimal pending value reads it as pending and asks
  for a scan from genesis, which completes the restore as it always did.
- In `lepic-ffi` the new parameter of `create` and `create_with_pin` breaks the binding's
  signature; no error kind is added.

## Alternatives considered

- Drop the gate and let every restore be usable at once. Rejected: a restore that has not scanned
  anywhere has not seen the keys it might reuse near its counter, and the gap rule needs the found
  keys.
- Keep the gate and scan from genesis in the background after a scan from H. Rejected: it keeps
  the slow scan the change is meant to remove and blocks receiving until it ends.
- A new setting for the start height beside `wallet.restore_scan_required`. Rejected: two
  settings can disagree. An older LEPIC that completes the restore clears only the first and
  leaves a start height behind; the decimal in the one setting goes with it.
- A fixed default height in LEPIC. Rejected: the height is app policy and depends on the network.
