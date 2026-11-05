# Upstream review: epic v4.1.0 to v4.1.2

The Epic node moved from `v4.1.0` (`82fa7e81`) to `v4.1.2` (`bd3a8c8c`, tags `v4.1.1` and
`v4.1.2`, ten commits). `epic-wallet` has no commits after `v4.1.0` (`845b3fcf`), so its pin
stays. This page is the review that `upstream.toml` asks for before its node commits move
(ADR 0038).

## Ported paths

No file in any node module's `upstream.paths` changed between the two commits:
`git diff --stat 82fa7e81 bd3a8c8c` over `api/src/{foreign,foreign_rpc,rest,types}.rs`,
`core/src/{consensus,global,ser}.rs`, `core/src/core/{committed,hash,transaction}.rs`,
`core/src/libtx/{aggsig,mod,proof,secp_ser}.rs` and
`keychain/src/{extkey_bip32,keychain,mnemonic,types}.rs` is empty. `cargo xtask upstream-drift`
reports no change either. Every node module moves to `bd3a8c8c` with no port and no new vectors.

## Other changes

| Upstream files | Change | Effect on LEPIC |
|---|---|---|
| `chain/src/pipe.rs` | Header validation refuses a block whose `bottles` differ from the ones the chain expects. | None: LEPIC does no proof of work and builds no blocks. The interop miners take the bottles from the node's template (`getjobtemplate`, `get_block_template`). |
| `api/src/handlers/mining_api.rs`, `servers/src/mining/mine_block.rs` | The block template takes its bottles from the template's previous block (`bottles_iter_from`). | None, as above. |
| `api/src/auth.rs`, `api/src/router.rs`, `api/src/handlers.rs` | `GET /v1/status` is public like `/v1/version`; the router ignores repeated leading slashes. | None: LEPIC calls the foreign JSON-RPC at `/v2/foreign` (`node-api.md`), whose path and policy are unchanged. |
| `p2p/src/msg.rs`, `servers/src/epic/seed.rs`, `chain/src/chain.rs` | Bounded reads when discarding a message; outbound peer recovery. | None: node to node only. |
| `Cargo.toml`, `*/Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Dependency updates; the node now pins Rust `1.99.1`. | The interop builds compile the node and the miners with `NODE_RUST` (`interop/pins.env`). |

## What stays at v4.1.0

The conformance workspace and the golden vectors stay on `epic` `v4.1.0`, the node crates
`epic-wallet` `v4.1.0` links. The ported files are identical at both commits, so the vectors are
the same either way.
