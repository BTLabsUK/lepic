# 0006 rustls with ring; HTTP and websocket stack chosen by spike F-03

Status: proposed
Date: 2026-10-02

## Context

LEPIC needs TLS for the node API and for Epicbox. Constraints: no OpenSSL, no CMake, small binaries,
Android and iOS cross-compiles.

Findings, 2026-10-02:

- rustls 0.23 defaults to the aws-lc-rs provider. Non-FIPS aws-lc-rs builds need only a C/C++
  compiler; ring needs only a C compiler and is smaller.
  (https://aws.github.io/aws-lc-rs/requirements/index.html,
  https://github.com/briansmith/ring/blob/main/BUILDING.md)
- reqwest 0.13 defaults to rustls with aws-lc-rs and `rustls-platform-verifier`. The feature
  `rustls-no-provider` leaves the provider to the application. The platform verifier needs an extra
  Kotlin component on Android, added through Gradle.
  (https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md,
  https://github.com/rustls/rustls-platform-verifier)

## Proposed decision

- rustls with the ring provider for both HTTP and websockets.
- Choose between two stacks by measurement in spike F-03:
  1. `reqwest` with `rustls-no-provider` plus ring, using the platform verifier;
  2. `hyper` with `hyper-rustls` and `webpki-roots`, a smaller client with bundled roots.
- Criteria: cross-builds for `aarch64-linux-android` and `aarch64-apple-ios` with no extra tools;
  stripped size of a minimal static library; effort for the host app; certificate behaviour on
  devices with user-installed CAs.

## Consequences

Accepted when F-03 records its measurements in `docs/spikes/f-03-mobile-build.md` and updates this
record.
