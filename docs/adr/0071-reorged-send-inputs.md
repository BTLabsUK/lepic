# ADR 0071: A send whose inputs a reorganisation took waits for them

Status: proposed
Date: 2026-11-25

## Context

A send can spend the change of an earlier transaction of the same wallet as soon as that
transaction is confirmed. When a reorganisation replaces the block that confirmed it, the change
leaves the UTXO set until a block of the new branch includes the earlier transaction again.

Until now the wallet read every missing input as a spend by another wallet on the same phrase:

- a post or push the node refused for a missing input ended the send (`InputsSpentElsewhere`);
- a refresh ended a posted send whose input was gone and whose kernel was neither in the pool nor
  on chain;
- the input, missing from the UTXO set, was marked spent and recorded as another wallet's spend.

A reorganisation of a few blocks is routine on Epic. A send cancelled for it gives up a payment
that would have gone through a few blocks later, and the record of another wallet's spend is
false.

## Decision

- A coin's origin is derived from what the store already holds; the store schema stays at 22.
  Locking a coin links it to the send that spends it, so its maker is found again by the outputs
  of the stage it built: S1 or I2 minus I1 for an outgoing transaction, S2 minus S1 or I1 for an
  incoming one. Candidates are the transactions confirmed at the coin's height and the open ones.
- A missing input of a send is taken by a reorganisation when its maker is open again (a refresh
  reopened it) or when the node no longer finds the maker's kernel, looked up from the maker's
  confirmation height up to the tip. Kernels stay on chain while their block does, so a maker
  whose kernel is gone lost its block. Every missing input must pass for the send to count as
  reorged; one that fails, or whose maker is not known, means a spend by another wallet as
  before.
- A block reward counts the same way: its maker is the reward's own entry, and its kernel is
  the reward kernel. A send of a reward whose kernel is gone is reorged, waits, and its refusal
  names the reorganisation. The reward comes back if the chain returns to its block (ADR 0070's
  confirmation recheck); the reward's own `expired` (`orphaned`) stays as ADR 0070 has it.
- A post or push refused for reorged inputs keeps the send. `finalize` and `post` return
  `FinalizeError::InputsReorged`, `pay_invoice` returns `InvoiceError::InputsReorged`; the
  transaction stays finalized or posted, its coins held. A refresh pushes it again with the usual
  backoff, and the push goes through once the maker is mined again. A recovery leaves such a
  send unchanged.
- A refresh keeps a posted send whose inputs are reorged and logs `inputs reorged, waiting`
  (`warn`, fields `tx_id` and `inputs`). It no longer marks a coin of an open send spent while the
  maker is off chain.
- A coin whose maker is open again and that no open send holds goes back to the maker: it is
  `unconfirmed`, linked to the maker, and becomes `unspent` when the maker is mined again. This
  covers a send cancelled while its input is reorged.
- The wait is bounded: `REORG_WAIT_BLOCKS` = 60 blocks from the tip at which the wallet first
  saw the send waiting. A send still waiting at that tip ends `expired`; its coins go back to
  their makers (a reward's coin to the reward, in the state ADR 0070's orphan rule gives it),
  and the refresh logs `inputs reorged, expired` (`warn`, fields `tx_id` and `inputs`). The post cutoff still
  ends the send earlier if it comes first. Either way a send that carries the mark ends with
  the reason `InputsReorged`, which wins over `RejectedByNode`; the serve API names it
  `expired_inputs_reorged`. The bound: Epic blocks come every 60 seconds and mainnet
  reorganisations replace one to three blocks (ADR 0070); the maker comes back as soon as any
  node or the payer's wallet posts it again; about an hour caps how long the send's other
  inputs stay held.
- The marks live under settings keys, so the store schema stays: `send.inputs_reorged.<slate
  id>` holds the tip of first sight, `tx.reopened.<slate id>` the tip at which a refresh
  reopened a confirmed transaction. A push the node accepts deletes the first; a refresh sweeps
  a key whose transaction is gone or ended any way the key does not explain, and keeps the
  first with an `expired` send as the record of its reason.
- `TransactionDetails::chain_replaced` says why an open transaction may read oddly:
  `InputsReplaced` for a send with the `inputs_reorged` mark, `Reopened` for a transaction with
  the `reopened` mark, `Recent` for an incoming one while the session saw a block replaced within
  the last 60 blocks (session memory, gone when the wallet closes). It is `None` once the
  transaction ended.
- The error kind is not permanent: it reads as "not posted, waiting". The CLI exits with the
  `Incomplete` code and names `lepic tx post` and `lepic tx cancel`; the serve API code is
  `inputs_reorged`; the FFI kind is `InputsReorged` (126).

## Consequences

- A send that spends the change of a reorged transaction goes through once that transaction is
  mined again, with no action from the user.
- A send stays open while its maker is off chain, for at most 60 blocks or until its post
  cutoff. It ends by confirmation, by the owner's cancel, by the spent-elsewhere rule once the
  maker's kernel is back and the coin is still gone, or `expired` with `InputsReorged` once the
  wait runs out. A maker that is never mined again gets its coin back, unconfirmed.
- Each refused push or refresh check of a send with a missing input costs a kernel lookup per
  missing input whose maker is held confirmed.
- A coin spent by a send that was later cancelled is not followed; the maker's own
  confirmation recheck (`states.md`) still reopens and confirms the maker.
- Inputs a peer contributed (the payer's inputs of an invoice this wallet issued) are not this
  wallet's coins and are still read as spent.

## Alternatives considered

- A stored link from each coin to its maker (a store schema change): exact and cheap to read, but
  migrating an existing install's store needs the owner's approval and a tested migration. It is
  kept aside for a later decision.
- Waiting with no bound for the maker: the send's other inputs would stay held until the owner
  cancels, for a maker that may never come back.
- Ending a send of a reorged block reward at once, as another wallet's spend: the reward can come
  back if the chain returns to its block, and the record of another wallet's spend is false.
- Asking the node for the block of each missing input: the node keeps no index of spent outputs
  by block, and a replaced block is not served.

## Related

- ADR 0070: coinbase candidates by block, and a reward a reorganisation takes.
- [states.md](../compat/states.md): states and transitions.
