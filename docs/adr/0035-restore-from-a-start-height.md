# ADR 0035: Restore from a start height

Status: accepted

## Context

A wallet restored from its recovery phrase refuses to create outputs, so to receive, to invoice
or to send with change, until a scan has completed (`wallet.restore_scan_required`,
`WalletError::RestoreScanRequired`). A scan from genesis reads every output of the chain, which
takes long enough on mainnet that a user may give up before the wallet is usable.

Each database draws a random output key start in `[2^20, 2^31 - 2^24)`
(`wallet.output_key_start`), and a restore draws a fresh one. This draw keeps a restored wallet's
keys apart from the keys the phrase used before. Wallets that draw no start, such as epic-wallet,
use keys from `m/0/0/1` up, in the low thousands, below `2^20`. A scan finds the unspent outputs
of earlier installs and never the spent ones, so it cannot list every key the phrase used.

The app wants a phrase restore to start at a recent height that it picks, and the wallet to be
fully usable once that scan reaches the tip.

## Decision

1. **A start height.** `Wallet::restore_from_height(password, phrase, scan_from)` takes a height;
   `Wallet::restore` is the restore from 0. In `lepic-ffi`, `create` and `create_with_pin` take
   `restore_from_height: Option<u64>`. `None` and `0` mean genesis, and a height without a
   mnemonic is refused as `InvalidArgument` before anything is written. The CLI has
   `lepic wallet restore --from-height`. LEPIC holds no default height; the caller picks it.
2. **One setting.** `wallet.restore_scan_required` is `true` for a restore from genesis, an import
   of `wallet.seed`, an open on a missing database and a rollback. A restore from a height H above
   0 stores the decimal H. A reader takes an absent setting as not pending, a value of ASCII
   digits as that height, and anything else as 0 (genesis). `Wallet::restore_scan_start` returns
   the height a pending restore scan must start at or below.
3. **Completion.** A scan that reaches the tip while a restore is pending completes it when its
   start is at or below the recorded start.
   - From 0 it clears the pending setting, sets `scan.genesis_completed` and flags imported
     history the chain lacks.
   - From a start in (0, H] it clears the pending setting, moves the key counters (rule 5) and
     stores the start in `scan.restore_completed_from`. It sets neither the genesis flag nor flags
     imported history, because outputs below the start were never looked for.
4. **Default start.** The hosts, not the engine, pick the start of a scan that names none: the
   recorded start of a pending restore (genesis for `true`, H for a height), else the last
   scanned height for an update (`lepic-ffi/src/session.rs`, `lepic-cli/src/commands.rs`).
5. **Key counters.** At a completion from a start above 0, each unhardened account's counter n
   moves past the keys the scan found near it. With `RESTORE_KEY_GAP` = 2^20: while some found
   child c of `m/<account>/0/<c>` lies in `[n - GAP, n + GAP)`, n becomes the highest such c plus
   1 plus GAP. A counter that would reach the hardened range stays. Counters only move up;
   key derivation and paths do not change.
6. **Later scans.** The update scan and the detection of outputs received by another install of
   the phrase run after either completion, and not while a restore waits. An output counts as
   received elsewhere only at or above the height the completed scan covered from
   (`scan::covered_from`: genesis after a scan from genesis, else `scan.restore_completed_from`).
   An older output an update meets is an output the restore scan found.

A found key near the counter means another install of the phrase hands out keys in that range.
Its keys used before H lie below its found keys, because counters only rise, and moving past the
highest found key by GAP leaves room for more keys than one install hands out.

## Consequences

- A restore from a recent height is usable after a short scan. Reusing a key the phrase used
  before H needs the fresh key start to land within the few thousand keys of an earlier install
  that has no output unspent at or above H, roughly `2^13 / 2^31 = 2^-18` per earlier install. The
  gap rule removes the case where such an output is on chain. Keys of epic-wallet installs lie
  below every drawn start.
- Unspent outputs older than H are not found, so their balance is missing. A scan from 0, or from
  any height below them, finds them; a later scan from 0 sets the genesis flag and flags imported
  history.
- A database whose pending value is a decimal reads as pending in an older LEPIC, which asks for
  a scan from genesis and completes the restore from there.
- The new parameter of `create` and `create_with_pin` changes the binding's signature; no error
  kind is added.

## Alternatives considered

- Drop the gate and make every restore usable at once: a restore that has scanned nowhere has not
  seen the keys it might reuse near its counter, and the gap rule needs the found keys.
- Keep the gate and scan from genesis in the background after a scan from H: it keeps the slow
  scan the change removes and blocks receiving until it ends.
- A second setting for the start height beside `wallet.restore_scan_required`: two settings can
  disagree. An older LEPIC that completes the restore clears only the first and leaves a start
  height behind.
- A fixed default height in LEPIC: the height is app policy and depends on the network.
