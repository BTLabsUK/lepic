# Golden vectors

Expected values produced by the reference Epic node and `epic-wallet` code at the commits pinned in
`docs/adr/0009-conformance.md`. Product crates test against these files and never against upstream
code. Only the generator in `conformance/vectors` writes them; never edit one by hand.

## Commands

| Command | Effect |
|---|---|
| `cargo xtask vectors generate [--area <area>]` | Runs the generator for one area, or all areas, and rewrites `testdata/vectors/<area>/`. |
| `cargo xtask vectors verify` | Runs `cargo test --workspace --test vectors`, the vector tests of every product crate. Succeeds with a notice while no crate has a `vectors` test. |

`cargo xtask vectors generate` runs the generator with the conformance workspace's own toolchain
(`conformance/rust-toolchain.toml`), not the product toolchain. Without `xtask`, it runs directly:
`cargo run --manifest-path conformance/Cargo.toml -p vectors -- generate [--area <area>] [--out <dir>]`.
`vectors list` prints the known areas. Generating an area also deletes JSON files in its directory
that the generator no longer produces.

After generating, review the diff with `git diff testdata/vectors`. A deterministic area must show no
diff unless the generator's cases or a pin changed.

## File format

One JSON file per case at `testdata/vectors/<area>/<name>.json`. A case is either a single computation
or a coherent grid of them that shares its inputs, such as one seed on one network across several
paths and amounts; a grid lists its entries under `expected` in a fixed order.

```json
{
  "schema": 1,
  "area": "smoke",
  "name": "plain_kernel_hash",
  "generator": "conformance/vectors/smoke",
  "upstream": {
    "repo": "https://github.com/EpicCash/epic",
    "commit": "9d022b1d521d3f705532e12ab77e0a429f6fde1f"
  },
  "inputs": { },
  "expected": { }
}
```

| Key | Meaning |
|---|---|
| `schema` | Format version of this envelope. Currently `1`. A change to the envelope bumps it. |
| `area` | The directory the file lives in. |
| `name` | The file name without `.json`, lowercase with underscores. |
| `generator` | The generator module that wrote the file. |
| `upstream` | The repository and full commit whose code computed `expected`, read from `conformance/Cargo.lock` at build time. |
| `inputs` | Everything the case was computed from. |
| `expected` | Everything upstream produced, including any value it drew at random. |

Encoding rules:

- Bytes are lowercase hex without a prefix.
- Unsigned 64-bit values (amounts, fees, heights) are decimal strings, because JSON numbers lose
  precision above 2^53. Small counts and indices are JSON numbers.
- Where upstream emits text (slate JSON, Epicbox frames), the exact upstream bytes are stored as a JSON
  string, so whitespace and key order survive.
- Keys appear in the order the generator declares them, which is stable across runs. Files are
  pretty-printed with two-space indentation and end with a newline. Consumers must not depend on key
  order.
- Secret keys, nonces and passwords in vectors are fixed test values chosen for the vector. They are
  never real wallet material.

## Deterministic and randomized areas

A deterministic area is one where the generator supplies every value upstream would otherwise draw at
random: keys, nonces, offsets, salts. It regenerates byte for byte on every run, and CI may regenerate
and diff it.

A randomized area exercises an upstream code path that draws randomness internally with no way to pass
it in. Its files record the values upstream chose in `expected`. LEPIC is checked against them by
consistency, not by regenerating the same bytes: it decrypts, rewinds or verifies what upstream
produced, it reproduces the output when given the recorded random values, and the differential suite
checks that upstream accepts what LEPIC produces. A randomized area is regenerated only when a pin or
its case set changes, and every random value is then expected to change in the diff.

Where upstream has a test-RNG mode, the generator uses it so that the case becomes deterministic.
`epic-wallet` v4.0.2 passes `use_test_rng` through slate building: it fixes the secret nonce and the
message-signature nonce to `[1; 32]`, draws the transaction offset from `StepRng::new(1234567890, 1)`,
and derives slate ids from a process-wide counter. The counter makes slate ids depend on how many
slates the process created before, so the slates generator builds its flows in a fixed order in a
single process. The counter is a `u8` that starts at 0 and becomes the last byte of the id, so one
process can create at most 256 test-RNG slates; larger case sets are split across processes.

| Area | Task | Class | Notes |
|---|---|---|---|
| `smoke` | F-04 | deterministic | One plain kernel signed with a fixed key and nonce. |
| `keys` | G-01 | deterministic, except the seed file | Mnemonics, derivation, commitments, switch commitments, both proof builders with fixed nonces and their rewinds, address keys. |
| `keys` seed file | G-01 | randomized | Upstream draws the `wallet.seed` salt and nonce; recorded with the known password. |
| `primitives` | G-02 | deterministic | Serialization, hashes, kernel messages, weights and fees, validation outcomes. |
| `aggsig` | G-02 | deterministic | Two-party flow with fixed nonces. |
| `slates` | G-03 | deterministic under test-RNG | Slate ids, offsets and nonces come from the test-RNG mode. Any value still drawn at random is recorded, and the vector says which. |
| `epicbox` | G-04 | randomized for messages | Addresses and signatures are deterministic. Encrypted messages record the salt, nonce and ciphertext upstream drew. |
| `engine` | G-05 | deterministic | Selection and the recorded node responses of a test chain built in a fixed order. |

## Areas present

### smoke

`plain_kernel_hash`: a `Plain` kernel with a fixed fee, excess blinding factor and signature nonce.
`expected` holds the excess commitment, the kernel signature message, the signature in compact form,
the kernel serialized at protocol versions 1 and 2, and the kernel hash. The node hashes every kernel
in the version 1 layout, so `hash` is unkeyed BLAKE2b-256 of `serialized_v1`. The binary layouts
carry the signature in the wrapper's internal form, which is the compact form with each 32-byte half
byte-reversed.

### primitives

Binary layouts, unkeyed and keyed BLAKE2b-256, kernel signature messages, weights and fees over a
count grid, mainnet and floonet chain parameters, weight limits, and valid and invalid transactions
with the rule each breaks. Files and conventions are in [primitives/README.md](primitives/README.md).

### aggsig

The two-party aggregate-signature flow for a plain and a height-locked kernel, and single-signer
signatures, each with the verification calls upstream accepts and rejects. The generator is
`conformance/vectors/src/primitives/aggsig.rs`. Details are in [aggsig/README.md](aggsig/README.md).
