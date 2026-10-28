# 0006 rustls with ring, hyper for HTTP, tokio-tungstenite for websockets

Status: accepted
Date: 2026-10-02 (amended 2026-10-28 to record plain http to the node and the app's exception
for nodes on the local network)

## Context

LEPIC needs TLS for the node API and for Epicbox. Constraints: no OpenSSL, no CMake, small binaries,
Android and iOS cross-compiles.

Findings, 2026-10-02:

- rustls 0.23 defaults to the aws-lc-rs provider. Non-FIPS aws-lc-rs builds need only a C/C++
  compiler; ring needs only a C compiler and is smaller.
  (https://aws.github.io/aws-lc-rs/requirements/index.html,
  https://github.com/briansmith/ring/blob/main/BUILDING.md)
- reqwest 0.13 defaults to rustls with aws-lc-rs and `rustls-platform-verifier`. The feature
  `rustls-no-provider` leaves the provider to the application but still pulls in the platform
  verifier. The platform verifier needs an extra Kotlin component on Android, added through Gradle.
  (https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md,
  https://github.com/rustls/rustls-platform-verifier)

Spike F-03 measured two stacks on Android. Both use rustls with ring, and both run websockets through
tokio-tungstenite. Details and commands are in `docs/spikes/f-03-mobile-build.md`.

| | reqwest + platform verifier | hyper + hyper-rustls + webpki-roots |
|---|---|---|
| Extra build tools | none | none |
| Stripped `.so`, aarch64-linux-android | 4,128,472 bytes | 3,430,592 bytes |
| Crates in the target graph | 134 | 88 |
| Android 16 emulator, HTTPS and WSS | panics until the app initialises the verifier from the JVM | pass |
| Host-app work on Android | Gradle component, plus JNI init with a `Context` before the first handshake | none |

iOS was not built, because the spike machine had no Xcode.

## Decision

- TLS is rustls 0.23 with the ring provider, `default-features = false`. No crate in the product graph
  may enable aws-lc-rs.
- Certificates are verified against the Mozilla roots bundled in `webpki-roots`.
- HTTP uses `hyper` 1.x with the `hyper-util` client and `hyper-rustls` with the `ring` feature. HTTP/1.1
  is the only HTTP version.
- Websockets use `tokio-tungstenite` with only the `handshake` and `stream` features, on a stream from
  `tokio-rustls`. Its built-in TLS features stay off.
- One rustls `ClientConfig` is built per wallet and passed to both clients as an explicit parameter.
  There is no process-wide default provider (ADR 0011).

## Consequences

- Size and host-app work are as measured above. The app needs no TLS setup on Android or iOS.
- Roots change only when `webpki-roots` is updated. Dependabot proposes updates weekly (ADR 0010).
- Certificates from user-installed or enterprise CAs are not trusted. On Android, apps targeting
  API 24 or higher do not trust them by default either. A node or relay with a private CA needs an
  explicit extra-trust-anchor setting. That setting belongs to N-01 and E-02 if they need it.
- The node client sends Basic auth headers, caps body sizes and sets timeouts itself on top of hyper.
  That is more code than reqwest, and it lives in `lepic-node`.
- The macOS CI job (U-03) is the first iOS build of this stack.

## Plain http to the node, and the app's local-network relay

`lepic-node` takes a node URL with `https`, or with plain `http` only to loopback (`localhost`,
127/8, `::1`) or, over Tor, to an onion address; any other plain-http URL is refused
(`PlainHttpToRemoteHost`). A node API secret is sent as Basic auth on every request, so plain
http elsewhere would put it on the wire unencrypted.

Epic's node API answers plain http, and people run their node on their home network or reach it
through a tailnet. The Epic Cash wallet app therefore relays such a node itself: a plain-http
node at a private or link-local address, at a `.local` / `.lan` name that resolves only to such
addresses, or, once the user agreed for that node, at a 100.64.0.0/10 address (a Tailscale
tailnet, which cannot be told apart from a provider's carrier-grade NAT), is handed to LEPIC as
`http://127.0.0.1:<port>/<token>`, a relay in the app that passes each request on to the node.
The relay answers only requests whose path starts with its random 128-bit token, so another
program or app on the device cannot use it. This is a deliberate exception to the loopback rule,
kept in the app rather than in LEPIC:

- the traffic and any node API secret still cross the local network or the tailnet in plain
  http; the app warns on the node's row when a secret would, and asks before it uses a
  100.64.0.0/10 address;
- LEPIC itself still refuses plain http to anything but loopback, so no other host of LEPIC gets
  the exception by accident;
- the app decides what counts as local, once per address, and connects to the address it looked
  up, so a later lookup cannot move the node to a public address.

## Alternatives considered

- reqwest with `rustls-platform-verifier`: 0.70 MB larger on arm64, 46 more crates. It needs Kotlin
  and JNI work in the host app, and it panics instead of returning an error when that work is missing.
  The gain on Android is OS-managed roots and revocation checks.
- reqwest with its platform verifier replaced by a preconfigured webpki-roots config: still compiles
  the verifier, the JNI crates and the reqwest layer, for convenience that hyper covers with a little
  code.
- aws-lc-rs as the rustls provider: larger, and it needs a C++ compiler for the mobile targets.
