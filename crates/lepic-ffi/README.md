# lepic-ffi

The LEPIC wallet engine as a library for Flutter apps on Android, iOS, Linux and Windows. Its
`api` module is the surface the app calls, and `flutter_rust_bridge` turns it into the Dart
package `package:lepic`, generated in
[lepic-flutter](https://github.com/BTLabsUK/lepic-flutter). [docs/ffi.md](../../docs/ffi.md) is
the full guide.

## Where it fits

- Sits at the top of the workspace, beside `lepic-cli`. It uses `lepic-wallet` and
  `lepic-wallet-contacts` for the wallet, `lepic-store` for the database, `lepic-keychain` for
  the vault, `lepic-node`, `lepic-epicbox`, `lepic-transport`, `lepic-methods` and `lepic-tor`
  for the network, and `lepic-telemetry` for logs.
- Builds as `lib`, `cdylib` and `staticlib`. `cargo xtask mobile --package` builds the
  libraries lepic-flutter bundles.
- `src/frb_generated.rs` is generated. `bridge.sha256` records the fingerprint of it and of
  `src/api/`; `cargo xtask repo-lint` fails when either changes without a new generator run.
- Features: `tor` (default) is the wallet's own tor and sends to onions
  ([ADR 0026](../../docs/adr/0026-tor-as-a-build-feature.md)); `mock` adds a scripted node and
  relay for the binding's tests and never goes in an app build.

## Core concepts

- **One runtime, no globals.** The app creates a `LepicRuntime` and passes it to every call that
  opens a wallet. Each call runs as a task on it; a panic becomes a `Panic` error.
- **The app's secret store.** The app passes an `AppSecretStore` built from three Dart
  callbacks. LEPIC keeps the encrypted vault and the PIN key there under fixed `lepic.*` keys, so
  each wallet needs its own store.
- **Password and PIN wallets.** A PIN wallet's password is generated and sealed inside Rust;
  Dart holds only the sealed text.
- **Streams.** Wallet events, the Epicbox listener, push session states, refresh and scan
  progress, tor and logs arrive as Dart streams.
- **Typed errors.** Every failure is a `WalletError` with a `WalletErrorKind` and a fixed number.

## Secrets that cross the boundary

As [ADR 0014](../../docs/adr/0014-secrets-at-the-flutter-boundary.md) requires:

- **Into Rust:** the wallet password, the PIN, the recovery phrase and
  `WalletConfig.node_api_secret`.
- **Out of Rust:** the recovery phrase, only from `mnemonic` and `mnemonic_with_pin`, for the
  backup screen.
- **Both ways:** pairing invite links and the five pairing words. LEPIC never stores or logs
  them.
- **To the app's store only:** the sealed vault and the PIN key.
- **Never out:** seed bytes, private keys, blinding factors, nonces, vault keys and a PIN
  wallet's generated password.

## Public API

| Area | Items |
|---|---|
| Runtime and logs | `LepicRuntime`, `init_app`, `LogLevel`, `LogEntry` |
| Wallet | `EpicWallet`, `PinWallet`, `WalletConfig`, `NetTuning`, `HostPolicy`, `PinSettings` |
| Store | `AppSecretStore`, `SecretReply` |
| Payments | `wallet`, `invoice`, `contact`, `http`, `tor`, `in_person` and `epic1` modules |
| Epicbox push sessions | `epicbox_sessions` module: `start_listener_via`, `contacts_push_start`, `contacts_push_stop`, `epicbox_sessions`, `watch_epicbox_sessions` |
| Data | `at_rest`, `app_data` |
| Errors | `WalletError`, `WalletErrorKind` |

## Related

- [docs/ffi.md](../../docs/ffi.md): sessions, streams, modules, error codes and the build
- [docs/configuration.md](../../docs/configuration.md#through-the-ffi): `WalletConfig` and the
  host parameters
- [lepic-flutter](https://github.com/BTLabsUK/lepic-flutter): the Dart package
- [ADR 0011: no global state](../../docs/adr/0011-no-global-state.md)
- [`lepic-cli`](../lepic-cli/README.md): the same engine on the command line
