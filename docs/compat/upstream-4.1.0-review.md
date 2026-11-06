# Upstream review: v4.0.x to v4.1.0

ADR 0020 moved the reference to `epic` `v4.1.0` (`82fa7e81`) and `epic-wallet` `v4.1.0`
(`845b3fcf`), and left every `upstream.toml` module whose upstream files changed at its old commit,
`epic` `v4.0.4` (`9d022b1d`) or `epic-wallet` `v4.0.2` (`465d499f`), until the change was reviewed.
This page is that review. Every module is now recorded at the `v4.1.0` commits.

On the wallet side every change between the two tags is one upstream commit, "v4.1.0 hardening and
fixes" (`6d136d2e`). On the node side the changes are in the files listed below. ADR 0020 already
lists the effects on the wire; this page goes module by module. "Neutral" means a slate, node
answer, file or database LEPIC accepts or writes reads and behaves the same at both pins, and
anything upstream now refuses LEPIC already refuses.

## epic (node), `9d022b1d` to `82fa7e81`

| LEPIC module | Upstream files | Change | Verdict |
|---|---|---|---|
| `lepic-primitives` `ser` | `core/src/ser.rs` | Length prefixes go through `usize::try_from`; the 100 000-byte single-read cap becomes a named constant; the streaming reader gets a frame limit. | Neutral: `MAX_READ_LEN` caps every read and lengths are converted with `try_from` already. |
| `lepic-primitives` `crypto_ser`; `lepic-crypto` `commitment`, `signature`, `proof` | `core/src/ser.rs`, `core/src/libtx/secp_ser.rs` | A range proof in JSON must be exactly `MAX_PROOF_SIZE` bytes of hex. | Neutral: a bulletproof is always that size; the node wire already requires it (`parse_bulletproof`). A slate proof of another length fails verification in LEPIC instead of parsing; either way it is refused. |
| `lepic-primitives` `fee`, `amount`, `params`; `lepic-crypto` `limits` | `core/src/consensus.rs`, `core/src/global.rs`, `core/src/libtx/mod.rs` | Proof-of-work policy selection returns errors instead of panicking; the foundation file path and the graph-weight lock change. `libtx/mod.rs` is unchanged. | Neutral: none of it is fee, amount, network or limit arithmetic, and LEPIC does no proof of work. |
| `lepic-node` `wire` | `api/src/foreign.rs`, `api/src/foreign_rpc.rs`, `api/src/types.rs`, `api/src/rest.rs`, `core/src/libtx/secp_ser.rs` | New foreign call `ready_for_txs`; printable outputs require a canonical range proof. | Neutral: LEPIC judges sync from the tip and the status call, and already requires the canonical proof. |

## epic-wallet, `465d499f` to `845b3fcf`

| LEPIC module | Upstream files | Change | Verdict |
|---|---|---|---|
| `lepic-slate` `model` | `libwallet/src/slate.rs` | Participant data is validated (non-zero count, ids in range and unique, one kernel), and missing signatures or kernels are errors; amount plus fee is checked. | Neutral: the LEPIC model refuses the same slates at decode. |
| `lepic-slate` `codec::legacy` `fields` | `libwallet/src/slate_versions/ser.rs` | Fixed-length, checked hex for keys, signatures, offset, commitments and range proofs. | Neutral: LEPIC's field decoders check the same lengths. |
| `lepic-slate` `codec::legacy` `v3_json`, `v2_json` | `libwallet/src/slate_versions/v3.rs`, `v2.rs` | Serde helpers renamed to the checked ones above; the version a converted slate carries follows its shape. | Neutral: the header rule is ADR 0020's and LEPIC writes it. |
| `lepic-wallet` `selection`, `send`, `receive`, `invoice`, `finalize`, `cancel` | `libwallet/src/internal/{selection,tx}.rs`, `libwallet/src/slate.rs`, `libwallet/src/types.rs`, `libwallet/src/api_impl/{owner,foreign}.rs` | Checked sums; change output count bounded by block weight; change split with the true remainder (`change % count`, where `v4.0.2` took `change % part`); the receiver validates the slate before adding its output; `tx.rs` returns an error when the kernel or slate id cannot be read. | Neutral: LEPIC already sums checked, bounds the transaction weight, splits with the true remainder (the two differ only for change smaller than about the square of the output count) and validates before signing. |
| `lepic-wallet` `refresh` | `libwallet/src/internal/updater.rs` | The tip is read only when `is_node_ready` says so (the new `ready_for_txs` call, falling back to the status call). | Neutral: LEPIC reads the tip from the foreign API and its own sync judgement. |
| `lepic-node` `client` | `impls/src/node_clients/http.rs` | `is_node_ready` over `ready_for_txs`; answers parsed into typed errors. | Neutral, as above. |
| `lepic-foreign` `rpc` | `api/src/foreign_rpc.rs`, `impls/src/adapters/http.rs` | Version and slate answers parsed into typed errors; doc tests for V3 slates. | Neutral: same calls and parameters (ADR 0017). |
| `lepic-epicbox` `crypto` | `libwallet/src/crypto.rs`, `libwallet/src/message.rs` | Hex decoding of message fields refuses empty, odd or non-hex text with an error. | Neutral: LEPIC's decoders refuse the same text. |
| `lepic-epicbox` `session`, `client_inbox` | `impls/src/adapters/epicbox.rs` | A slate that arrives before the relay challenge is an error. | Neutral: LEPIC signs only after the challenge. |
| `lepic-store` `legacy` | `impls/src/backends/{db,lmdb}.rs`, `libwallet/src/types.rs`, `libwallet/src/slate.rs` | SQL statements take parameters and retry while the database is busy; keys are encoded as before. | Neutral: the stored layout is unchanged, so the import reads both versions alike. |
