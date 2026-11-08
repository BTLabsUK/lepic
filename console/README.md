# lepic-console

A local page that shows one LEPIC wallet through the API of `lepic serve`: serve's status,
the wallet's height against the node tip, balances, address, transactions, outputs, the live
event stream, and the API document rendered as a reference.

It is its own program and workspace. It depends on no LEPIC crate and the `lepic` binary
carries none of its HTML, so no policy of the console can reach the wallet core (ADR 0050).
The page is plain HTML, CSS and JavaScript with no build step, embedded in the binary.

## Run

Start `lepic serve` for the wallet, then the console:

```
cd console
cargo run --locked -- --network floonet
```

Open <http://127.0.0.1:7421/>. Flags:

- `--socket PATH`: the socket serve answers on. Without it the console uses the socket in
  the default data dir of `--network` (`mainnet` unless given).
- `--listen ADDR`: the loopback address and port to serve the page on.

## What it answers

- Requests whose `Host` header is exactly its own listen address. Anything else is refused
  with 421, so a page on another host name cannot reach it through DNS tricks.
- Reads from any page on this machine; writes (anything but GET) only with an `Origin`
  header equal to the console's own origin. Other origins and an absent origin get 403.
- A fixed list of API routes under `/api`: the status, wallet, address, outputs,
  transactions, transaction detail, node, event stream and OpenAPI document reads, and the
  cancel of one transaction. Nothing else is proxied.
- Every response carries a Content-Security-Policy that allows scripts, styles and
  connections from the console itself only, with no frames and no forms. There are no CORS
  headers and nothing is loaded from the internet.

The console binds loopback addresses only and refuses any other `--listen`.

## Test

```
cd console
cargo test --locked
```

## Third party

`ui/vendor/scalar.js` is the standalone bundle of `@scalar/api-reference` (MIT); its licence
and version are in `ui/vendor/`. It runs with web fonts, the request proxy and telemetry off.
