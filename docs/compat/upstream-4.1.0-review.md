# What LEPIC takes from upstream 4.1.0

LEPIC's reference is `epic` `v4.1.0` (`82fa7e81`) and `epic-wallet` `v4.1.0` (`845b3fcf`)
(ADR 0020). This page lists, module by module, the rules of those releases that LEPIC ports and
how LEPIC matches each one. `upstream.toml` names the files each module ports. ADR 0020 lists the
effects on the wire. The later node release is in [upstream-4.1.2-review.md](upstream-4.1.2-review.md).

A slate, node answer, file or database that LEPIC accepts or writes reads and behaves the same
under the upstream rule. A value upstream refuses, LEPIC refuses too. The wallet release is one
upstream commit over `v4.0.2`, "v4.1.0 hardening and fixes" (`6d136d2e`).

## epic (node)

| LEPIC module | Upstream files | Upstream rule | How LEPIC matches |
|---|---|---|---|
| `lepic-primitives` `ser` | `core/src/ser.rs` | Length prefixes are converted with `usize::try_from`. A single read is capped at 100,000 bytes. The streaming reader has a frame limit. | `MAX_READ_LEN` (`ser.rs`) caps every read, and lengths are converted with `try_from`. |
| `lepic-primitives` `crypto_ser`; `lepic-crypto` `commitment`, `signature`, `proof` | `core/src/ser.rs`, `core/src/libtx/secp_ser.rs` | A range proof in JSON is exactly `MAX_PROOF_SIZE` bytes of hex. | A bulletproof is always that size, and the node wire requires it. A slate proof of another length fails verification in LEPIC instead of parsing. Both are refused. |
| `lepic-primitives` `fee`, `amount`, `params`; `lepic-crypto` `limits` | `core/src/consensus.rs`, `core/src/global.rs`, `core/src/libtx/mod.rs` | Proof-of-work policy selection returns errors. The foundation file path and the graph-weight lock are fixed. | None of it is fee, amount, network or limit arithmetic. LEPIC does no proof of work. |
| `lepic-node` `wire` | `api/src/foreign.rs`, `api/src/foreign_rpc.rs`, `api/src/types.rs`, `api/src/rest.rs`, `core/src/libtx/secp_ser.rs` | The foreign call `ready_for_txs` answers whether the node is synced and takes transactions. Printable outputs carry a canonical range proof. | `lepic-node` calls `ready_for_txs` (`client.rs`); a node that answers `-32601` gives no answer. `lepic-ffi` reports it beside the tip. LEPIC reads the tip from `get_tip` and requires the canonical proof. |

## epic-wallet

| LEPIC module | Upstream files | Upstream rule | How LEPIC matches |
|---|---|---|---|
| `lepic-slate` `model` | `libwallet/src/slate.rs` | Participant data is validated: a non-zero count, ids in range and unique, one kernel. Missing signatures or kernels are errors. Amount plus fee is checked. | The model refuses the same slates at decode. |
| `lepic-legacy-slate` `lib`, `fields` | `libwallet/src/slate_versions/mod.rs`, `libwallet/src/slate_versions/ser.rs` | Keys, signatures, offsets, commitments and range proofs are fixed-length, checked hex. | The field decoders check the same lengths. |
| `lepic-legacy-slate` `v3_json`, `v2_json` | `libwallet/src/slate_versions/v3.rs`, `libwallet/src/slate_versions/v2.rs` | The version a converted slate carries follows its shape. | The header rule is ADR 0020's, and LEPIC writes it. |
| `lepic-wallet` `selection`, `send`, `receive`, `invoice`, `finalize`, `cancel` | `libwallet/src/internal/{selection,tx}.rs`, `libwallet/src/slate.rs`, `libwallet/src/types.rs`, `libwallet/src/api_impl/{owner,foreign}.rs` | Sums are checked. The number of change outputs is bounded by block weight. Change splits with the true remainder (`change % count`). The receiver validates the slate before adding its output. `tx.rs` returns an error when the kernel or slate id cannot be read. | LEPIC sums checked, bounds the transaction weight, splits with the true remainder and validates before signing. The split differs from `change % part` only for change smaller than about the square of the output count. |
| `lepic-wallet` `refresh` | `libwallet/src/internal/updater.rs` | The tip is read only when the node is ready. | LEPIC reads the tip from the foreign API and judges sync itself. |
| `lepic-node` `client` | `impls/src/node_clients/http.rs` | `is_node_ready` goes over `ready_for_txs`. Answers are parsed into typed errors. | As above. |
| `lepic-legacy-rpc` `rpc` | `api/src/foreign_rpc.rs`, `impls/src/adapters/http.rs` | Version and slate answers are parsed into typed errors. | The same calls and parameters (ADR 0017, [foreign-api.md](foreign-api.md)). |
| `lepic-epicbox` `crypto` | `libwallet/src/crypto.rs`, `libwallet/src/message.rs` | Hex decoding of message fields refuses empty, odd or non-hex text. | The decoders refuse the same text. |
| `lepic-epicbox` `session`, `client_inbox` | `impls/src/adapters/epicbox.rs` | A slate that arrives before the relay challenge is an error. | LEPIC signs only after the challenge. |
| `lepic-store` `legacy` | `impls/src/backends/{db,lmdb}.rs`, `libwallet/src/types.rs`, `libwallet/src/slate.rs` | SQL statements take parameters and retry while the database is busy. Keys are encoded as in `v4.0.2`. | The stored layout is the same, so the import reads both versions alike. |
