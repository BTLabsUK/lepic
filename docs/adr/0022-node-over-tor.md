# ADR 0022: Node over Tor

Status: accepted

## Context

The node client shows the node the wallet's IP address next to every address it asks about. A
wallet that runs tor takes its Epicbox relay connection through it (ADR 0021), and the node
connection needs the same protection. With Tor on, the node stays the one the user chose and is
reached through tor. Nothing goes through a Tor exit unencrypted.

A node can also be an onion service that presents the same TLS certificate as its domain.

## Decision

- Only the byte stream to the node changes. The TLS server name, the certificate check and the
  `Host` header stay the node's domain.
- `lepic-node` has a `NodeDialer` trait and `HttpTransport::with_dialer`. Without a dialer,
  hyper's own connector resolves and connects. `lepic-node` depends on neither `lepic-tor` nor
  `lepic-epicbox`.
- `lepic-ffi` implements the dialer (`TorNodeDialer`) over a `RelayTor` of its own for the node.
  It attaches to the same tor as the relay's `RelayTor` and has its own setting. While the
  setting is on and tor runs or is expected, a connection goes to the node's onion when the
  shared onion routes (ADR 0021) list the node, else to `host:port` through a Tor exit, with tor
  resolving the name. The connections of one node backend share tor circuits.
- A connection made while tor starts waits for it. A tor that fails is a connection error: the
  dialer does not go around it. With the setting off, or no tor, a node host is reached
  directly; an onion host has no direct route and fails. A loopback node is always direct.
- The routes in `[[tor.onions]]` of the CLI's `lepic-config.toml` include the BT Labs node, with
  the port the node serves TLS on.
- Plain `http` is refused for any host but loopback, and for `.onion` hosts it is accepted only
  when a dialer takes the connection to tor, which encrypts it to the onion. So nothing leaves a
  Tor exit unencrypted.
- `lepic-ffi`: `set_node_over_tor` and `node_over_tor`, on by default. `TorStatus` carries
  `socks_port` once tor has bootstrapped, the loopback port of tor's SOCKS5 proxy, so an app can
  send its own HTTP through the same tor; the `Bootstrapped`, `Publishing` and `Ready` events
  carry it too. `lepic-cli`: `node_over_tor` in `settings.toml`, which needs one of the
  `epicbox_tor_*` settings, since it uses the tor those name.
- The shipped node `request_timeout_s` is 90 seconds, which leaves room for a first circuit.

## Consequences

- A node with an onion route never sees the wallet's IP address when Tor is on. Other `https`
  nodes see an exit's address.
- Requests are slower through tor, mostly the first circuit.
- The SOCKS proxy listens on loopback only, and its port changes when tor restarts. An app that
  uses it reads the port from `TorStatus` each time.

## Related

- ADR 0018, ADR 0021, ADR 0030
