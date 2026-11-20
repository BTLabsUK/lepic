# ADR 0021: Epicbox over Tor

Status: accepted

## Context

A wallet keeps one websocket to one Epicbox mailbox, the mailbox of its own address, and posts every
slate there; the mailbox forwards to other mailboxes itself. That connection shows the mailbox the
wallet's IP address next to its Epicbox address. A wallet that runs tor for direct transactions
(ADR 0018) can take that connection through tor as well.

A mailbox can also be an onion service that presents the same TLS certificate as its domain, and
describe itself at `/.well-known/epicbox.json`.

## Decision

- Only the byte stream to the mailbox changes. The TLS server name, the certificate check and the
  websocket URL stay the mailbox's domain, and Epicbox addresses keep their domain.
- `lepic-epicbox` has a `Tunnel` trait and a `TunnelConnector`. While the tunnel is active, a
  mailbox connection goes through it: to the mailbox's onion when one is known, else to
  `domain:port` through a Tor exit, with tor resolving the name. It never goes directly then.
  A loopback mailbox is always reached directly. `lepic-epicbox` does not depend on `lepic-tor`.
- Known onions are `OnionRoutes`, a list the caller gives and may replace while the connector is
  in use (ADR 0030). Each route names a host and port and the onion and port to dial instead.
  The CLI ships its routes in `[[tor.onions]]` of `lepic-config.toml` (at most 256). A route wins
  over discovery.
- For a mailbox with no route the connector fetches `https://<domain>/.well-known/epicbox.json`
  once per connector through tor (at most `MAX_DISCOVERY_LEN`, 4,096 bytes), and uses its onion
  only when the document names the mailbox itself and a valid v3 onion. Any other outcome means
  the exit. A mailbox that could not be reached for discovery is asked again after a pause
  (`discovery_retry`). An onion a contact named for the mailbox is used when the mailbox has no route
  and the name is a valid onion, and discovery is then not asked.
- `lepic-tor` has `RelayTor`: the setting, and the tor it goes through. The mailbox connection
  goes through tor while the setting is on and a tor is attached, being started, or expected
  (`expect`). A connection made before tor has bootstrapped waits for it, within the connect
  timeout of the tunnel (`TunnelTimings`), and a failed one is retried as any lost mailbox
  connection is. Each connection uses fresh SOCKS credentials, so it gets a circuit of its own.
  Only `detach`, or turning the setting off, lets the mailbox be reached directly.
- When the route changes (the setting, or tor starting or stopping), a held listener connection
  is replaced once the messages in flight on it are acknowledged, within 30 seconds. The mailbox
  keeps every message until it is acknowledged, so nothing is lost, and the new connection
  subscribes again with the same address. Sends use their own short connections and finish on
  the route they started with.
- `lepic-ffi`: `set_epicbox_over_tor` and `epicbox_over_tor`; `expect_tor` lets the app hold the
  first mailbox connection for a tor it is about to start, so a wallet that opens with tor on does
  not reach the mailbox directly first. `lepic-cli`: `epicbox_tor_socks` (a running tor on this
  computer) or `epicbox_tor_binary` (a tor the CLI runs in `tor-epicbox/` of the data directory),
  in `settings.toml`.

## Consequences

- A wallet on a mailbox with an onion route never leaves the Tor network to reach it. Wallets on
  other mailboxes reach them through an exit until those mailboxes publish an onion.
- Reaching the mailbox through tor takes longer, mostly for the first circuit, so the connection
  limits are larger.
- A mailbox may describe an onion that is down. The wallet then keeps retrying through tor and
  does not fall back to a direct connection. Turning the setting or tor off is the way back.

## Related

- ADR 0018, ADR 0022, ADR 0030
