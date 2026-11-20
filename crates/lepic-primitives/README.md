# lepic-primitives

Epic Cash transaction types and the rules around them: inputs, outputs, kernels, transactions,
the node's binary serialization, BLAKE2b hashing, weights, fees and per-network chain parameters.
A pure crate. Each type encodes and hashes byte for byte as the Epic node's `core` crate does.

## Where it fits

- Depends on `lepic-crypto`.
- Used by every crate above the crypto layer.
- No features.
- Does no I/O. Reading is bounded: a reader never allocates more than a maximum the caller gives,
  so a hostile length field cannot make it reserve memory.
- Holds no global network state. Each wallet carries its own `ChainParams` (ADR 0011).

## Core concepts

- **Typed numbers.** `Amount`, `Fee` and `Height` are separate types with checked arithmetic.
  One EPIC is `EPIC_BASE` (100,000,000) base units.
- **Networks.** `Network` is `Mainnet` or `Floonet`. `Network::params()` gives the
  `ChainParams`: coinbase maturity, weight limits, the protocol version, the first hard fork, the
  block header version at a height, the default base fee and the block reward schedule.
- **Weights and fees.** `BodyCounts` holds the input, output and kernel counts of a transaction and
  computes its weight and its fee, as the node's `TransactionBody::weight` and `libtx::tx_fee`
  do.
- **Validation.** `Transaction::validate` runs the checks the node runs on a transaction:
  weight, sorting, cut-through, range proofs, kernel signatures, features and kernel sums. Lock
  heights, coinbase maturity and the pool's fee rules are left to the node.

## Public API

| Module | Main items |
|---|---|
| `amount` | `Amount`, `Fee`, `Height`, `EPIC_BASE`, `MILLI_EPIC`, `ArithmeticError` |
| `params` | `Network`, `ChainParams`, `MAX_BLOCK_WEIGHT`, `MAX_TX_WEIGHT` and the block weight constants |
| `fee` | `BodyCounts` (`tx_weight`, `weight_as_block`, `tx_fee`) |
| `input`, `output`, `kernel` | `Input`, `Output`, `OutputFeatures`, `OutputIdentifier`, `TxKernel`, `KernelFeatures` |
| `tx` | `Transaction`, `TransactionBody`, `TxError` |
| `validate` | `ValidationError`; `Transaction::validate` |
| `committed` | `sum_commitments`, `sum_kernel_excesses`, `verify_kernel_sums`, `KernelSumError` |
| `crypto_ser` | `BlindingFactor` and the binary forms of the crypto types |
| `ser` | `Writeable`, `Readable`, `Reader`, `Writer`, `ser_vec`, `deserialize`, `ProtocolVersion` |
| `hash` | `Hash`, `Hashed`, `blake2b_256`, `blake2b_256_keyed` |
| `error_chain` | `ErrorChain`, an error's display with its source chain |
| `open_flags` (Unix) | `O_NONBLOCK`, `O_NOFOLLOW` for hosts that open files with `custom_flags` |

## Example

```rust
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::params::Network;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_fee = Network::Mainnet.params().default_base_fee();
    // One input, two outputs (payment and change), one kernel.
    let fee = BodyCounts::new(1, 2, 1).tx_fee(base_fee)?;
    println!("fee: {} base units", fee.value());
    Ok(())
}
```

## Related

- [Architecture](../../docs/architecture.md)
- [ADR 0011: no process-global state](../../docs/adr/0011-no-global-state.md),
  [ADR 0013: network parameters](../../docs/adr/0013-network-parameters.md),
  [ADR 0038: reference node 4.1.2](../../docs/adr/0038-reference-node-4-1-2.md)
- `upstream.toml` at the repository root lists the node files each module follows.
