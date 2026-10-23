# 0022 Node over Tor

Status: accepted
Date: 2026-10-23

## Context

ADR 0021 takes the Epicbox relay connection through the wallet's tor. The node client shows the
node the wallet's IP address next to every address it asks about, so it needs the same
protection. the owner decided on 2026-10-23 that, with Tor on, the user's node stays the node the
user chose and is reached through tor, and that nothing goes through a Tor exit unencrypted.

The BT Labs node `node.btlabs.uk` (port 443) is also an onion service that presents the same
TLS certificate as the domain.

## Decision

- Only the byte stream to the node changes. The TLS server name, the certificate check and the
  `Host` header stay the node's domain.
- `lepic-node` gains a `NodeDialer` trait and `HttpTransport::with_dialer`; the default
  transport is unchanged. `lepic-node` depends on neither `lepic-tor` nor `lepic-epicbox`.
- `lepic-ffi` implements the dialer over a `RelayTor` of its own for the node, attached to the
  same tor as the relay's but with its own setting. While the setting is on and tor runs or is
  expected, a connection goes to the node's onion when the shared onion routes (ADR 0021) list
  it, else to `host:port` through a Tor exit, with tor resolving the name (SOCKS domain address
  type, fresh credentials per connection). It never goes directly then: a connection made
  while tor starts waits for it, within the request timeout, and a tor that fails is a
  connection error. Tor off or the setting off: direct. A loopback node is always direct.
- The built-in onion routes gain `node.btlabs.uk:443`.
- Plain `http` is refused for any host but loopback, and `.onion` (which tor encrypts), as it
  already was for the direct client; so nothing leaves a Tor exit unencrypted.
- `lepic-ffi`: `set_node_over_tor` and `node_over_tor`, on when a wallet opens. `TorStatus` and
  the `Bootstrapped`, `Publishing` and `Ready` events carry `socks_port`, the loopback port of
  tor's SOCKS5 proxy, so the app can send its own HTTP through the same tor. `lepic-cli`:
  `node_over_tor`, using the tor named by the `epicbox_tor_*` settings.
- The node request timeout grows from 30 to 90 seconds, for a first circuit.

## Consequences

- The BT Labs node never sees the wallet's IP address when Tor is on; other `https` nodes see
  an exit's.
- Requests are slower through tor, mostly the first circuit.
- The proxy is on loopback with any credentials accepted; apps that use it must connect to
  that address only.
