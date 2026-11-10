# What LEPIC takes from upstream 4.1.2

The `epic` node pin in `upstream.toml` is `v4.1.2` (`bd3a8c8c`, ADR 0038). `epic-wallet` stays
at `v4.1.0` (`845b3fcf`), which has no later commits. Every node module of `upstream.toml`
records `bd3a8c8c`. The rules LEPIC ports are the ones in
[upstream-4.1.0-review.md](upstream-4.1.0-review.md), because no ported file differs between
`v4.1.0` (`82fa7e81`) and `v4.1.2`.

## Ported paths

`git diff --stat 82fa7e81 bd3a8c8c` is empty over every path of any node module's
`upstream.paths`:

- `api/src/{foreign,foreign_rpc,rest,types}.rs`
- `core/src/{consensus,global,ser}.rs`
- `core/src/core/{committed,hash,transaction}.rs`
- `core/src/libtx/{aggsig,mod,proof,secp_ser}.rs`
- `keychain/src/{extkey_bip32,keychain,mnemonic,types}.rs`

`cargo xtask upstream-drift` lists no upstream commit that touched them since the recorded commit.

## Other upstream changes

These files differ between the two releases and no LEPIC module ports them:

| Upstream files | Change | Effect on LEPIC |
|---|---|---|
| `chain/src/pipe.rs` | Header validation refuses a block whose `bottles` differ from the ones the chain expects. | None. LEPIC does no proof of work and builds no blocks. The interop miners take the bottles from the node's template (`getjobtemplate`, `get_block_template`). |
| `api/src/handlers/mining_api.rs`, `servers/src/mining/mine_block.rs` | The block template takes its bottles from the template's previous block (`bottles_iter_from`). | None, as above. |
| `api/src/auth.rs`, `api/src/router.rs`, `api/src/handlers.rs` | `GET /v1/status` is public like `/v1/version`. The router ignores repeated leading slashes. | None. LEPIC calls the foreign JSON-RPC at `/v2/foreign` ([node-api.md](node-api.md)), whose path and policy are the same. |
| `p2p/src/msg.rs`, `servers/src/epic/seed.rs`, `chain/src/chain.rs` | Bounded reads when a message is discarded. Outbound peer recovery. | None. These are node-to-node. |
| `Cargo.toml`, `*/Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Dependency updates. The node pins Rust `1.99.1`. | The interop builds compile the node and the miners with `NODE_RUST` (`interop/pins.env`). |

## What stays at v4.1.0

The conformance workspace and the golden vectors are on `epic` `v4.1.0`, the node crates that
`epic-wallet` `v4.1.0` links. The ported files are identical at both commits, so the vectors are
the same under either.
