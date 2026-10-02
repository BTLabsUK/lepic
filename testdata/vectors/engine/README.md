# Engine vectors

Generator: `conformance/vectors/src/engine/`. Consumers: W-02 (selection), W-06 (restore), W-07
(refresh), through `MockNode` (N-01) for the node side.

Every case drives an upstream `epic-wallet` instance (`DefaultLCProvider` over its sqlite backend)
through its public owner and foreign API. `upstream` names the wallet commit, which pins the node
commit in its own lockfile. Wallets use an empty password and derive their keychain with
`is_floonet = false`, which is what `epic-wallet` does on every chain type except floonet. The chain
type is `AutomatedTesting`, so coinbase maturity is 3 blocks.

`selection_*`: one stored UTXO set and one send request each. `inputs.utxos` lists the outputs in
the order they were stored; `index` is the position in that list, and upstream breaks ties between
equal values in that order. `expected.estimate` is the result of `init_send_tx` with
`estimate_only`, `expected.send` the inputs (by `index`), change outputs (`n_child`, `key_id`,
`value`), amount and fee of a real `init_send_tx`, or the `not_enough_funds` error with upstream's
`available` and `needed`. The node in these cases is a fixed stand-in, not a chain: it reports
`inputs.tip_height`, reports itself synced, and reports exactly the `Unspent` and `Locked` outputs
of the set as on chain, so upstream's pre-selection refresh leaves the set unchanged.

`restore_*` and `refresh_*`: sessions of one subject wallet on an in-process upstream test chain.
`inputs.chain` lists every block the chain received, in order, with its reward recipient, the proof
builder of the reward output, the transactions it carries, `fork_of` for blocks of a fork, and
`orphaned` for blocks a longer fork replaced; `inputs.chain.transactions` describes each
transaction. Coinbase outputs and slates are built in upstream's test mode, so the chain and every
response regenerate byte for byte. `inputs.subject.mnemonic` is the subject's seed.
`inputs.session` is `restore` (a new wallet from the mnemonic runs its first update, which scans the
whole chain) or `refresh` (the existing wallet runs `update_wallet_state`, the update behind
`epic-wallet info` and `txs`). `inputs.before` is the subject's state before a refresh.
`expected.exchanges` is every node call of the session, in order, and `expected.after` the state
upstream ended in.

Wallet state (`before`, `after`) holds every stored output (sorted by `n_child`), every transaction
log entry (sorted by `id`), `last_confirmed_height`, `last_scanned_block`, the account's
`next_child_index` and `init_status`. Status and type names are upstream's enum variant names.
Timestamps and slate ids are left out, because upstream takes them from the clock and from a
process-wide counter; `has_slate_id` says whether an entry has one.

Blocks are processed without proof-of-work checks and carry upstream's placeholder proof. A header
hash covers the proof but not the body, so fork blocks use a different placeholder from the block
they replace; otherwise the two would share a hash.

The recorded exchanges follow [Recorded node exchanges](../README.md#recorded-node-exchanges).
