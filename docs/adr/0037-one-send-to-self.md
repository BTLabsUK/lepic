# ADR 0037: One send-to-self primitive

Status: accepted

## Context

A wallet sends to itself to split outputs, to merge them and to move outputs back after a
cancelled send. An app also wants outputs of chosen sizes for later sends. Each shape as its own
entry point multiplies functions and spreads the selection rules over many places.

An app that keeps its traffic on tor through a SOCKS proxy it runs itself asks a node's tip before
a wallet is open. That request must not leave the proxy.

## Decision

1. **One request.** `Wallet::send_to_self(options, request, propagation)` and
   `Wallet::estimate_send_to_self(options, request)` take a `SelfSendRequest` with inputs and
   outputs (`lepic-wallet/src/selection.rs`):
   - `SelfInputs::All`: every spendable output, the smallest first, at most the output limit
     (500 by default).
   - `SelfInputs::Smallest`: the fewest smallest outputs that cover the amounts and the fee, within
     the same limit. Only with `SelfOutputs::Amounts`; with `Count` it is refused.
   - `SelfInputs::Named(commitments)`: exactly those outputs, each an unspent output of the
     account that may be spent at the tip, named once. The output limit does not apply.
   - `SelfOutputs::Count(n)`: the inputs less the fee, in `n` outputs of nearly equal value.
   - `SelfOutputs::Amounts(amounts)`: one output per amount, each above zero, and the rest, when
     above zero, as one more output.
2. **Limits.** A send makes 1 to 10 outputs (`MAX_SELF_SEND_OUTPUTS`), the remainder included.
   `All` and `Smallest` refuse to spend one input into one output with `NothingToConsolidate`:
   that only pays a fee. `Named` allows it, because moving a named output back after a cancelled
   send has that shape.
3. **Estimate.** The estimate runs the selection the send runs, so at the same tip its fee equals
   the fee sent.
4. **Binding.** `EpicWallet::send_to_self(request, minimum_confirmations)` and
   `EpicWallet::estimate_send_to_self(request, minimum_confirmations)` take a flat
   `SelfSendRequest` so that the generated Dart needs no sealed classes. `SelfInputs` and
   `SelfOutputs` are plain enums, and `named`, `count` and `amounts` carry the data. A field the
   kind does not use is empty or zero, or the request is an invalid argument.
5. **Tip without a wallet.** `node_tip(config, route)` takes a `NodeRoute`. `socks: None` goes
   directly. `socks: Some("127.0.0.1:port")` goes through the host's SOCKS5 proxy and never falls
   back to a direct connection; LEPIC opens no tor of its own for it. The route has no default.
   An address that does not parse or is not loopback is an invalid argument, and a build without
   tor refuses a SOCKS route as unsupported. A loopback node is reached directly on either route.

Callers build the common shapes from the request: a split into `n` is `All` with `Count(n)`, a
merge is `All` with `Count(1)`, and a spend-back is `Named` with `Count(n)`.

## Consequences

- A new shape, such as amounts from named outputs, needs no new function.
- The binding has two functions for every shape, and a flat request type with fields that depend on
  the kind.
- A send to self is stored and posted as any other send; nothing changes on the wire or in stored
  data.

## Alternatives considered

- One function per shape: each new shape adds more functions and repeats the selection rules.
- FFI enums with data (`SelfInputs::Named(Vec<String>)`): flutter_rust_bridge makes them freezed
  sealed classes, a dependency the app does not have.
- Refuse one input into one output for `Named` too: the move back after a cancel needs it.
- A `node_tip` that opens LEPIC's own tor without a wallet: a second tor beside the host's, and a
  slow start for a tip query.
