# Architecture decision records

Each record states one decision, why it was made, and what it costs. Status is `accepted`,
`proposed` (needs a decision or a spike), or `superseded by NNNN`. Change a decision by writing a new
record that supersedes the old one; accepted records are not rewritten.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-port-not-depend.md) | Port the node and wallet logic; no Epic crates in the product graph | accepted |
| [0002](0002-slate-domain-and-codecs.md) | One version-free slate model, one codec per wire format | accepted |
| [0003](0003-transport-format-policy.md) | Transports declare the slate formats they speak | accepted |
| [0004](0004-epicbox-client.md) | Async Epicbox client with listen and drain modes, acknowledge after store | accepted |
| [0005](0005-storage.md) | SQLite storage, platform keystore for secrets, legacy seed import | accepted |
| [0006](0006-tls-and-http.md) | rustls with ring, hyper for HTTP, tokio-tungstenite for websockets | accepted |
| [0007](0007-mobile-bindings.md) | flutter_rust_bridge bindings for the existing Flutter frontend | accepted |
| [0008](0008-logging-and-errors.md) | tracing everywhere, host-installed subscribers, typed errors | accepted |
| [0009](0009-conformance.md) | Separate conformance workspace on public pins, golden vectors | accepted |
| [0010](0010-dependency-policy.md) | Latest stable crates and toolchain, banned list, update bots | accepted |
| [0011](0011-no-global-state.md) | No process-global state; network and settings are parameters | accepted, `ChainParams` contents superseded by 0013 |
| [0012](0012-native-slate-format.md) | A compact native slate format for LEPIC-to-LEPIC methods | proposed |
| [0013](0013-network-parameters.md) | Network parameters live with the format that uses them | accepted |

Template:

```
# NNNN Title

Status: proposed | accepted | superseded by NNNN
Date: YYYY-MM-DD

## Context
## Decision
## Consequences
## Alternatives considered
```
