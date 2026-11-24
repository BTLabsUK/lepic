# ADR 0070: Coinbase candidates are checked by block, and a reward a reorganisation takes expires

Status: accepted
Date: 2026-11-24

## Context

ADR 0046 had a refresh ask the node for every coinbase candidate by commitment, as for any other
output. A wallet that serves a mining node holds one candidate per block template, a few per
height, and keeps them for 50 blocks past the tip. The node logs a warning for each commitment it
does not hold (`Output … Not found`), so a mining node's log filled with misses for candidates
that never won, on every refresh.

A pool on LEPIC 0.6.1 had three blocks orphaned after a refresh confirmed their rewards. The
wallet kept each reward as a confirmed payment, and `GET /outputs` listed its output as `spent`,
so a sum of confirmed rewards counted 2.9667 EPIC that the chain never paid. The cause: a refresh
looks again at a confirmed payment within 1,440 blocks and reopens it when neither its outputs
nor its kernel are on chain, but it skipped entries with no slate, and a reward has none. The
missing output then went the way of any unspent output the chain no longer holds: marked spent.
No other-wallet spend was recorded for it, since an immature coinbase cannot have been spent.

## Decision

### Candidates by block

- A refresh checks candidates by the height they were built for. It reads the header at that
  height, then the block's range of the output MMR (`get_pmmr_indices` for the one height) and
  its unspent outputs, and keeps the coinbase ones. It reads the header again afterwards; a block
  replaced meanwhile is read again on the next refresh. A block replaced and restored during the
  read (A, B, A) reads as A, which it is. It never asks for a candidate by commitment.
- A coinbase cannot be spent before it matures, so its block's unspent outputs hold it.
- While the wallet is unlocked it remembers, per height, the block hash it read and the
  candidates that block did not hold. A later refresh reads the block again only when the hash
  changed or new candidates were built for it.
- `REORG_WINDOW` (10 blocks): once the tip is more than 10 above a height, the candidates its
  block did not hold are deleted. Within it they stay, so a reorganisation that brings in a block
  holding one confirms it.
- A candidate above the tip is not looked up. One more than `STALE_AFTER` (50) blocks above it,
  or built for height 0, is deleted as before. The cap of ADR 0048 is unchanged.
- A scan finds a reward whose candidate was deleted, as before.

### A reward whose block is replaced

- A refresh looks again at a confirmed reward within 1,440 blocks (`CONFIRMATION_RECHECK_BLOCKS`)
  like any confirmed payment. A reward's kernel follows from its output: the output's commitment
  less a commitment to its value, with no key. When the chain holds neither the output nor the
  kernel, the reward expires.
- An expired reward is `expired` with the reason `Orphaned` (`expired_orphaned` in the serve
  API), and a `payment.state_changed` from `confirmed`. Its output stays, linked to it,
  `unconfirmed`, with no MMR index. It counts in no balance.
- While its height is within 1,440 blocks of the tip, a refresh checks the block at that height
  for it, as for a candidate, and remembers the block hash the same way. A block that holds it
  again confirms the reward again: `expired` to `confirmed`, the output `unspent` with its lock
  height. The window is the recheck window, not `REORG_WINDOW`, so a reward a lagging node showed
  as gone heals on a later refresh. Past it only a scan finds it.
- A scan looks up the kernel of each confirmed reward whose output is stored `spent` while no
  other-wallet spend lists it, at any depth, and expires those the chain does not hold. This
  repairs wallets that marked such outputs spent before this change. The kernel lookup is
  definitive: a kernel stays on chain once its block is in it, spent or not. A lookup that fails
  leaves the reward for the next scan and does not fail the scan, which is stored by then.
- A scan that finds the output again confirms the reward again. The repair of
  `scan --delete_unconfirmed` keeps an orphaned reward's output, the record of the expired entry.

## Consequences

- A mining node logs no miss for a candidate. Each refresh reads one header per candidate height
  up to the tip, and the outputs of a block only when its hash or its candidates changed.
- An orphaned reward costs one miss, on the refresh that finds it gone.
- `ExpiredReason::Orphaned` is a new variant. The enum is `#[non_exhaustive]`; the FFI maps a
  variant it does not know to no reason, so the binding shows such a reward as expired with no
  reason until it adds the variant.
- A wallet that marked an orphaned reward spent shows it confirmed until its next scan.

## Alternatives considered

- Asking the node for candidates by commitment only once the tip passes their height: still one
  miss per losing candidate.
- Reading the whole block (`get_block`): a node call the wallet does not use today, and the answer
  carries every input, kernel and proof of the block. The MMR range needs only calls a scan already
  makes.
- Keeping an orphaned reward `confirmed` and only marking its output: payment totals would still
  count it.
- Deleting the orphaned output: the expired entry would show an amount with no output, and a
  block that comes back would need a scan.

## Related

- ADR 0046: a wallet for a mining node. Its "Confirming and cleaning" refresh rules are superseded
  here.
- ADR 0048: who is served, and the cap on candidates.
