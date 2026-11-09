# lepic-console

A local page that shows one LEPIC wallet through the API of `lepic serve`: serve's status,
the wallet's height against the node tip, balances, address, transactions, outputs, the live
event stream, and the API document rendered as a reference.

The console is its own program and workspace. It depends on no LEPIC crate, and the `lepic`
binary carries none of its HTML, so no policy of the console reaches the wallet core
([ADR 0050](../docs/adr/0050-one-wallet-api.md)). The page is plain HTML, CSS and JavaScript with
no build step, embedded in the console binary.

## Run

Start `lepic serve` for the wallet, then the console:

```bash
cd console
cargo run --locked -- --network floonet
```

At launch the console draws a link token and prints one line on stderr:

```text
lepic-console on http://127.0.0.1:7421/#token=<64 hex digits> for <socket>
```

Open that link. The token is in the URL fragment, so the browser never sends it to a server.
The page reads it, removes it from the address bar and trades it for a session with
`POST /session`. The page keeps the session in `sessionStorage` and sends it on every API
request, so a reload keeps it and each tab and each console (each address has its own origin)
holds its own. The link works once: when it is used, the console prints a new link on stderr
(`lepic-console: the link was used; for another tab open http://127.0.0.1:7421/#token=<new>`).
A page opened without a valid link or stored session shows a message that says to open the
console with the link from its terminal.

Flags:

- `--socket PATH`: the socket `lepic serve` answers on. Without it the console uses
  `~/.lepic/<network>/lepic.sock`.
- `--network mainnet|floonet`: the network whose default data dir holds that socket. The
  default is `mainnet`.
- `--listen ADDR`: the loopback address and port to serve the page on. The default is
  `127.0.0.1:7421`.

Two consoles on different ports, for example mainnet on 7421 and floonet on 7422, draw their
own tokens and sessions and do not affect each other.

## What it answers

- The page and its assets (`/`, `/console.css`, `/console.js`, `/vendor/scalar.js`) to any
  request for its own address. They are the same embedded files in every binary and hold no
  secret. No cookie is set anywhere.
- `POST /session` with the link token in the header `X-Lepic-Console-Link` and the console's
  own `Origin`. The token is compared in constant time. On success the console answers 200
  with `{"session": "<64 hex digits>"}`, keeps the session (at most 16; the oldest is dropped
  for a new one), replaces the link token with a new one and prints it. A wrong or missing
  token gets 401 and changes nothing. Of concurrent exchanges of one token exactly one wins.
- `/api` requests that carry `Authorization: Bearer <session>` with a session the console
  handed out. A request without one, or with another value, gets 401.
- Requests whose `Host` header is exactly its own listen address. Anything else is refused
  with 421, so a page on another host name cannot reach it through DNS tricks.
- Reads under `/api` with a session; writes (anything but GET) also need an `Origin` header
  equal to the console's own origin. Other origins and an absent origin get 403.
- A fixed list of API routes under `/api`: the status, wallet, address, outputs,
  transactions, transaction detail, node, event stream and OpenAPI document reads, and the
  cancel of one transaction. Nothing else is proxied.
- Every response carries a Content-Security-Policy that allows scripts, styles and
  connections from the console itself only, with no frames and no forms. There are no CORS
  headers and nothing is loaded from the internet.

The console binds loopback addresses only and refuses any other `--listen`.

## Test

```bash
cd console
cargo test --locked
```

## Third party

`ui/vendor/scalar.js` is the standalone bundle of `@scalar/api-reference` (MIT). Its licence and
version are in [ui/vendor/](ui/vendor/README.md). It runs with web fonts, the request proxy and
telemetry off.
