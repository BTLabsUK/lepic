# LEPIC

## TL;DR

LEPIC (light Epic) is a mobile-first Epic Cash wallet written in Rust: a small library with a CLI and
Android/iOS bindings. It sends and receives transactions with the reference `epic-wallet` over the
Epicbox and file methods, and it carries no mining, chain-storage or C++ dependencies. The project is
in the planning stage. Nothing is built yet.

Status: pre-alpha, design and plan only. Not for real funds.

## What makes it different

- One wallet engine, many front ends. The CLI and the mobile apps call the same Rust API.
- Wire formats are pluggable. Each transaction method declares which slate formats it speaks, so the
  legacy formats stay exact while new methods can use better ones.
- Correctness is shown, not argued. Money-handling code is checked byte for byte against the reference
  wallet and node with golden vectors and differential tests.
- Builds need Rust and a C compiler, nothing else.

## Layout

| Path | Contents |
|---|---|
| `crates/` | Workspace crates (created in plan task F-01) |
| `conformance/` | Separate workspace that runs the reference wallet to produce golden vectors |
| `docs/architecture.md` | Crates, allowed dependencies, data flow |
| `docs/adr/` | Architecture decisions and their reasons |
| `docs/compat/` | Wire formats and algorithms LEPIC must match |

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through [SECURITY.md](SECURITY.md).

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Parts of LEPIC are ported from the Epic
Cash node and wallet, which are Apache-2.0 and descend from Grin.
