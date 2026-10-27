# 0026 Tor is a build feature of the binding

Status: accepted
Date: 2026-10-27

## Context

The app has a build without Tor (`WFE_TOR=0`) for app stores and for places where Tor is a
problem. It never starts tor, but `lepic-ffi` depended on `lepic-tor` unconditionally (ADR 0018,
ADR 0021, ADR 0022), so that build still carried the tor controller, the SOCKS client, the onion
service and the `tor` transport. The operator asked on 2026-10-27 for a library with no Tor code
in it.

The binding's two halves are generated from `crates/lepic-ffi/src/api` once (ADR 0007, ADR 0023)
and the Dart half refuses a library whose API hash differs, so both builds must expose the same
API.

## Decision

- `lepic-ffi` has a default feature `tor` that enables the optional `lepic-tor` dependency and
  everything that uses it. Every existing build keeps it.
- Built without it (`--no-default-features`, `cargo xtask mobile --package --no-tor`),
  `lepic-tor` and the code only it needs are not compiled. The API keeps every Tor function with
  the same signature, so the generated halves are the same for both builds:
  - `start_tor`, `refresh_tor`, `onion_address`, `send_tor` and `resend_tor` fail with
    `Unsupported` ("this build of LEPIC has no Tor"); `start_tor` reports no event.
  - `tor_status` is `Off`; `stop_tor` and `tor_network_lost` do nothing; `expect_tor` only checks
    the wallet is unlocked; `set_onion_routes` accepts any list and keeps none.
  - `epicbox_over_tor` and `node_over_tor` read `false` and their setters change nothing: the
    relay and the node are always reached directly. A node or relay at an onion host fails to
    connect; nothing goes to an onion.
  - `validate_onion_address` is `false` for every address.
- `lepic-cli` keeps `lepic-tor`: it is a desktop tool and never ships in an app.
- `cargo xtask mobile --package` writes a `FEATURES` file next to each library listing the
  `lepic-ffi` features it was built with, so the binding's build hook can tell the two builds
  apart. `cargo xtask check` runs clippy on `lepic-ffi` without default features.

## Consequences

- One generated binding serves both builds; no Dart or `frb_generated.rs` change. An app built
  for Tor against the library without it sees `Unsupported` from `start_tor` instead of a
  missing symbol.
- The crate edge `lepic-ffi -> lepic-tor` stays in `docs/architecture.md`; it is optional.
- New Tor functions of the API need a branch in the build without Tor too; the clippy step of
  `cargo xtask check` fails until they have one.

## Alternatives considered

- Leaving the Tor functions out of the API without the feature: the generated halves would then
  differ per build, needing two Dart packages or a generated file per variant.
- A new error kind `TorNotBuilt`: a change to the binding's shape and to every app's error
  mapping, for a case `Unsupported` ("not available in this build") already names.
- Keeping `lepic-tor` and not calling it, as the app did: the code stays in the library.
