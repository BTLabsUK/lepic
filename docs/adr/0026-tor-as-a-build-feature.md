# ADR 0026: Tor is a build feature of the binding

Status: accepted

## Context

An app can ship a build without Tor, for app stores and for places where Tor is a problem. That
build never starts tor, but it should hold no Tor code: no tor controller, SOCKS client, onion
service or `tor` transport.

The binding's two halves are generated from `crates/lepic-ffi/src/api` once (ADR 0007, ADR 0023),
and the Dart half refuses a library whose API hash differs, so both builds must expose the same
API.

## Decision

- `lepic-ffi` has a default feature `tor` that enables the optional `lepic-tor` dependency,
  `lepic-methods/tor` and everything that uses them (ADR 0018, ADR 0021, ADR 0022).
- Built without it (`--no-default-features`, or `cargo xtask mobile --package --no-tor`),
  `lepic-tor` is not compiled. The API keeps every Tor function with the same signature, so the
  generated halves are the same for both builds. In that build:
  - `onion_address`, `start_tor`, `refresh_tor`, `tor_network_lost`, `send_tor` and `resend_tor`
    (and their dialect forms) fail with `Unsupported` and the message "this build of LEPIC has
    no Tor". `start_tor` reports no event.
  - `tor_status` is `Off`. `stop_tor` does nothing, `expect_tor` only checks that the wallet is
    unlocked, and `set_onion_routes` accepts any list and keeps none.
  - `epicbox_over_tor`, `node_over_tor` and `http_over_tor` read `false`, and their setters
    change nothing. The relay and the node are reached directly, and an onion host cannot be
    reached.
  - `validate_onion_address` is `false` for every address.
- `lepic-cli` keeps `lepic-tor`: it is a desktop tool and is not part of an app build.
- `cargo xtask mobile --package` writes a `FEATURES` file next to each library listing the
  `lepic-ffi` features it was built with, so the binding's build hook can tell the two builds
  apart. `cargo xtask check` runs clippy on `lepic-ffi` without default features, with its
  tests.

## Consequences

- One generated binding serves both builds. An app built for Tor that loads the library without
  it gets `Unsupported` from `start_tor` instead of a missing symbol.
- The dependency from `lepic-ffi` to `lepic-tor` is optional.
- A new Tor function in the API needs a branch for the build without Tor, or the clippy step of
  `cargo xtask check` fails.

## Related

- ADR 0018, ADR 0021, ADR 0022, ADR 0023
