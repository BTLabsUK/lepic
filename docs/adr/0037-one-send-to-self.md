# 0037 One send-to-self primitive

Status: accepted
Date: 2026-11-04

## Context

A wallet sends to itself to split outputs, to merge them and to move outputs back after a
cancelled send. `lepic-wallet` had three ways in: `Wallet::self_send` with a
`SelfSendShape` (`Split(SplitCount)` or `Consolidate`), `Wallet::spend_outputs_to_self` for
named commitments, and `Wallet::estimate_self_send`. `lepic-ffi` exposed five functions on
top: `estimate_split`, `split_outputs`, `estimate_consolidate`, `consolidate_outputs` and
`spend_outputs_to_self`. None could pay out chosen amounts, such as outputs sized for later
sends, and each new shape would have added more functions. the owner decided on 2026-11-04 to
replace them with one primitive.

`node_tip` without an open wallet always went directly to the node. An app that keeps its
traffic on tor, through a SOCKS proxy it runs itself, could not ask a node's tip before a
wallet was open without leaving tor.

## Decision

1. `Wallet::send_to_self(options, request, propagation)` and
   `Wallet::estimate_send_to_self(options, request)` replace `self_send`,
   `spend_outputs_to_self`, `estimate_self_send` and `SelfSendShape`. A `SelfSendRequest` has
   inputs and outputs:
   - `SelfInputs::All`: every spendable output, at most the input cap, the smallest first.
   - `SelfInputs::Smallest`: the fewest smallest outputs that cover the amounts and the fee.
     Only with `SelfOutputs::Amounts`; with `Count` it is an invalid argument.
   - `SelfInputs::Named(commitments)`: exactly those outputs, each the wallet's own, unspent
     and confirmed.
   - `SelfOutputs::Count(n)`: the inputs less the fee, spread over `n` outputs.
   - `SelfOutputs::Amounts(amounts)`: one output per amount, each above zero, and the rest,
     when above zero, as one more output.
2. A send makes 1 to 10 outputs (`MAX_SELF_SEND_OUTPUTS`), the remainder included. `All` and
   `Smallest` refuse to spend one input into one output with `NothingToConsolidate`: that
   only pays a fee. `Named` allows it, because moving a named output back after a cancelled
   send is that shape.
3. The estimate is the selection the send makes at the same tip, so its fee equals the sent
   fee.
4. `lepic-ffi` has `EpicWallet::send_to_self(request, minimum_confirmations)` and
   `EpicWallet::estimate_send_to_self(request, minimum_confirmations)`. Its
   `SelfSendRequest` is flat, so that the generated Dart needs no sealed classes: the kinds
   `SelfInputs` and `SelfOutputs` are plain enums, and `named`, `count` and `amounts` carry
   their data. A field the kind does not use must be empty or zero, or the request is an
   invalid argument. No new error kinds.
5. `node_tip(config, route)` takes a `NodeRoute`. `socks: None` goes directly. `socks:
   Some("127.0.0.1:port")` goes through the host's SOCKS5 proxy and never falls back to a
   direct connection; LEPIC opens no tor of its own for it. The route has no default. An
   address that does not parse or is not loopback is an invalid argument; a build without tor
   refuses a SOCKS route as unsupported. A loopback node is reached directly on either route,
   as everywhere else.

## Consequences

- Breaking for `lepic-wallet` and `lepic-ffi` callers: the five FFI functions and the three
  wallet methods are gone, and `node_tip` takes a route. The app migrates split to
  `Count(n)` with `All`, consolidate to `Count(1)` with `All`, and spend-back to `Count(n)`
  with `Named`.
- Nothing changes on the wire or in stored data. A send to self is stored and posted as
  before.
- New shapes, such as amounts from named outputs, need no new functions.

## Alternatives considered

- Keep the old functions and add an amounts variant: a sixth and seventh FFI function, and
  the same selection rules spread over more entry points.
- FFI enums with data (`SelfInputs::Named(Vec<String>)`): flutter_rust_bridge makes them
  freezed sealed classes, a dependency the app does not have.
- Refuse one input into one output for `Named` too: the move back after a cancel needs it.
- A `node_tip` that opens LEPIC's own tor without a wallet: a second tor beside the host's,
  and a slow start for a tip query.
