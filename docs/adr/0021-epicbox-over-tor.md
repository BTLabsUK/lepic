# 0021 Epicbox over Tor

Status: accepted
Date: 2026-10-23

## Context

A wallet keeps one websocket to one Epicbox relay, the relay of its own address, and posts every
slate there; the relay forwards to other relays itself. That connection shows the relay the
wallet's IP address next to its Epicbox address. Wallets that run tor for direct transactions
(ADR 0018) can take that connection through tor as well. the owner decided on 2026-10-23 to do so,
on by default.

The BT Labs relay `flooepicbox.btlabs.uk` (port 443, mainnet and floonet) is also an onion
service that presents the same TLS certificate as the domain, and it describes itself at
`/.well-known/epicbox.json`.

## Decision

- Only the byte stream to the relay changes. The TLS server name, the certificate check and the
  websocket URL stay the relay's domain, and Epicbox addresses keep their domain.
- `lepic-epicbox` gains a `Tunnel` trait and a `TunnelConnector`. While the tunnel is active, a
  relay connection goes through it: to the relay's onion when one is known, else to
  `domain:port` through a Tor exit, with tor resolving the name. It never goes directly then.
  A loopback relay is always reached directly. `lepic-epicbox` does not depend on `lepic-tor`.
- Known onions: a built-in table, today `flooepicbox.btlabs.uk:443` to
  `j2xf5rizkow5jtrdf6edotk5qam4kohavip23dqeuih5bq4yqisbz5ad.onion:443`, the same on every
  network. For any other relay the connector fetches `https://<domain>/.well-known/epicbox.json`
  once per wallet session through tor (at most 4 KiB), and uses its onion only when `domain`,
  `tls_name` and `port` name the relay itself and `onion` is a valid v3 onion. Any other outcome
  means the exit. The built-in table wins.
- `lepic-tor` gains `RelayTor`: the setting, and the tor it goes through. It is active while the
  setting is on and a tor is attached or being started, or ended on its own and has not been
  stopped by the app; a connection made before tor has
  bootstrapped waits for it, within a connection limit of at least 90 seconds, and a failed one
  is retried as any lost relay connection is. Each connection uses fresh SOCKS credentials, so
  it gets a circuit of its own. Tor off or the setting off: the relay is reached directly.
- When the route changes (the setting, or tor starting or stopping), a held listener
  connection is replaced once the messages in flight on it are acknowledged, at most 30 seconds
  later. The relay keeps every message until it is acknowledged, so nothing is lost; the new
  connection subscribes again with the same address. Sends use their own short connections and
  finish on the route they started with.
- `lepic-ffi`: `set_epicbox_over_tor` and `epicbox_over_tor`, on when a wallet opens, with the
  wallet's own tor; `expect_tor` lets the app hold the first relay connection for a tor it is
  about to start, so a wallet that opens with tor on never reaches the relay directly first. `lepic-cli`: `epicbox_tor_socks` (a running tor on this computer) or
  `epicbox_tor_binary` (a tor the CLI runs in `tor-epicbox/` of the data directory).

## Consequences

- Wallets on the BT Labs relay never leave the Tor network to reach it. Wallets on other relays
  reach them through an exit until those relays publish an onion.
- Reaching the relay through tor takes longer, mostly the first circuit; connection limits
  grow to match.
- A relay may describe an onion that is down; the wallet then keeps retrying through tor and
  does not fall back to a direct connection. Turning the setting or tor off is the way back.
