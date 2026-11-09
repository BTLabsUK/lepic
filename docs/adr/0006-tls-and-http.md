# ADR 0006: rustls with ring, hyper for HTTP, tokio-tungstenite for websockets

Status: accepted

## Context

LEPIC needs TLS for the node API and for Epicbox. The constraints are no OpenSSL, no CMake, small
binaries, and cross-compiles for Android and iOS.

rustls 0.23 defaults to the aws-lc-rs provider, which needs a C++ compiler on mobile targets;
ring needs only a C compiler and is smaller. A reqwest stack with a platform certificate verifier
needs host-app work on Android (a Kotlin component and a JVM call before the first handshake) and
fails there when that work is missing. A hyper stack with bundled roots needs none.

## Decision

- TLS is rustls with the `ring` provider and `default-features = false`. No crate in the product
  graph enables aws-lc-rs, OpenSSL or native-tls; `deny.toml` bans the OpenSSL and native-tls
  crates (ADR 0010).
- Certificates are verified against the Mozilla roots in `webpki-roots`.
- HTTP uses `hyper` 1.x with the `hyper-util` client and `hyper-rustls` (`ring`, `http1`,
  `tls12`). HTTP/1.1 is the only HTTP version.
- Websockets use `tokio-tungstenite` with only the `handshake` feature, on a stream from
  `tokio-rustls`. Its built-in TLS features stay off.
- A rustls `ClientConfig` is built where it is needed (`lepic-node`'s `webpki_tls_config`) and
  handed to the HTTP and websocket clients as an explicit parameter. LEPIC installs no
  process-wide default provider (ADR 0011).
- `lepic-node` takes a node URL with `https`. Plain `http` is accepted only to a loopback host
  (`localhost`, 127.0.0.0/8, `::1`) or, when the connection runs through Tor, to an onion
  address. Any other plain-http URL fails with `PlainHttpToRemoteHost`, because a node API
  secret is sent as Basic auth on every request and plain http elsewhere would put it on the
  wire unencrypted.
- The node client sets body-size caps (8 MiB per answer) and timeouts itself on top of hyper.

## Consequences

- The host app needs no TLS setup on Android or iOS.
- Roots change only when `webpki-roots` is updated; Dependabot proposes updates (ADR 0010).
- Certificates from user-installed or enterprise CAs are not trusted. A node or relay with a
  private CA needs an explicit trust-anchor setting, which does not exist.
- The node client carries more code than reqwest would.

## Plain http to a node on the local network

Epic's node API answers plain http, and people run a node on a home network or reach it through
a tailnet. LEPIC still refuses plain http to anything but loopback and onion hosts. An app that
wants to support such a node relays it itself: it listens on loopback and hands LEPIC
`http://127.0.0.1:<port>/<token>`, then passes each request on to the node. The traffic and any
node API secret cross the local network in plain http, so the app warns the user. LEPIC takes no
part in deciding what counts as local, and no other host of LEPIC gets the exception by accident.

## Related

- ADR 0010: dependency policy.
- ADR 0011: no process-wide state.
