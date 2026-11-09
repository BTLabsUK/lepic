# Golden vectors

Golden vectors are expected values that the reference Epic node and `epic-wallet` code computed
at the commits in `conformance/Cargo.lock` ([ADR 0009](../../docs/adr/0009-conformance.md)).
Product crates test against these files and never against upstream code. The generator in
`conformance/vectors` writes them. Do not edit a file by hand.

## Commands

| Command | Effect |
|---|---|
| `cargo xtask vectors generate [--area <area>]` | Runs the generator for one area, or for all areas, and rewrites `testdata/vectors/<area>/`. |
| `cargo xtask vectors verify` | Runs `cargo test --workspace --locked --test vectors`, the vector tests of every product crate. Fails when no crate has a `vectors` test. |

`generate` runs the generator with the conformance workspace's toolchain
(`conformance/rust-toolchain.toml`), not the product toolchain. Without `xtask` the equivalent is:

```bash
cargo run --manifest-path conformance/Cargo.toml -p vectors -- generate [--area <area>] [--out <dir>]
cargo run --manifest-path conformance/Cargo.toml -p vectors -- list
```

`list` prints the areas the generator knows: `smoke`, `primitives`, `aggsig`, `keys`, `epicbox`,
`slates`, `slates_native`, `engine`, `app_data`, `store` and `store_key`.

Generating an area deletes JSON files in its directory that the generator does not produce.
After generating, review the diff with `git diff testdata/vectors`. A deterministic area shows no
diff unless a case or a pin changed.

### The pairing area

The `pairing` area has no upstream implementation. It comes from an independent Python kit and
follows RFC 0002 section 14. `cargo xtask vectors generate --area pairing` runs

```bash
python -m epic_pairing.vectors <dir> --sas-table testdata/sas/emoji-v1.txt
```

from the kit in `$EPIC_PAIRING_KIT` (default `~/epic-pairing-kit`), using the kit's `.venv` Python
when it exists. `generate` with no `--area` runs the generator and then the kit. The files keep the
kit's format instead of the envelope below:

```json
{"meta": {"generator": "epic-pairing-kit", "kit_version": "...", "git_commit": "...",
          "rfc": "0002-contact-pairing", "file": "sas.json"}, "vectors": []}
```

`testdata/sas/emoji-v1.txt` is the table of 256 emoji and names that the kit's `sas` vectors use.

## File format

One JSON file per case at `testdata/vectors/<area>/<name>.json`. A case is one computation, or a
grid of computations that share their inputs, such as one seed on one network across several
paths and amounts. A grid lists its entries under `expected` in a fixed order.

```json
{
  "schema": 1,
  "area": "smoke",
  "name": "plain_kernel_hash",
  "generator": "conformance/vectors/smoke",
  "upstream": {
    "repo": "https://github.com/EpicCash/epic",
    "commit": "82fa7e813dc3b9bf137b9dd523d847f4210f5ba4"
  },
  "inputs": { },
  "expected": { }
}
```

| Key | Meaning |
|---|---|
| `schema` | Version of this envelope, currently `1`. |
| `area` | The directory the file lives in. |
| `name` | The file name without `.json`, lowercase with underscores. |
| `generator` | The generator module that wrote the file. |
| `upstream` | The repository and commit of the node code that computed `expected`, read from `conformance/Cargo.lock` at build time. |
| `inputs` | Everything the case was computed from. |
| `expected` | Everything the reference produced, including any value it drew at random. |

Encoding rules:

- Bytes are lowercase hex without a prefix.
- Unsigned 64-bit values (amounts, fees, heights) are decimal strings, because JSON numbers lose
  precision above 2^53. Small counts and indices are JSON numbers.
- Where upstream emits text (slate JSON, Epicbox frames), the exact bytes are stored as a JSON
  string, so whitespace and key order survive.
- Keys appear in the order the generator declares them. Files are pretty-printed with two-space
  indentation and end with a newline. Consumers must not depend on key order.
- Secret keys, nonces and passwords in vectors are fixed test values. They are never real wallet
  material.

## Deterministic and randomized areas

In a deterministic area the generator supplies every value that upstream would otherwise draw at
random: keys, nonces, offsets, salts. The area regenerates byte for byte.

A randomized area exercises an upstream code path that draws randomness internally and takes no
input for it. Its files record the drawn values in `expected`. LEPIC is checked by consistency: it
decrypts, rewinds or verifies what upstream produced, and it reproduces the output when given the
recorded random values. The generator keeps a committed randomized case while its inputs and pin
match and upstream still accepts it, so regeneration changes it only when a case or a pin changes.

Where upstream has a test-RNG mode, the generator uses it. `epic-wallet` passes `use_test_rng`
through slate building. It fixes the secret nonce and the message-signature nonce to `[1; 32]`,
draws the transaction offset from `StepRng::new(1234567890, 1)`, and derives slate ids from a
process-wide `u8` counter that becomes the last byte of the id. Slate ids therefore depend on how
many slates the process created before. The slates generator builds its flows in a fixed order in
one process.

| Area | Class | Contents |
|---|---|---|
| `smoke` | deterministic | One plain kernel signed with a fixed key and nonce. |
| `primitives` | deterministic | Serialization, hashes, kernel messages, weights and fees, validation outcomes. |
| `aggsig` | deterministic | Two-party and single-signer signatures with fixed nonces. |
| `keys` | deterministic, except `wallet_seed_*` | Mnemonics, derivation, commitments, proofs, address keys, `epic1` addresses and links, and LEPIC's own keys. |
| `slates` | deterministic under test-RNG | Slate stages of the standard and invoice flows, and parse outcomes of malformed slates. |
| `slates_native` | deterministic | The `slates` flows encoded in the native `lepic.v1` layout. |
| `epicbox` | randomized for `message_*` | Addresses, signatures, encrypted messages and the LEPIC marker. |
| `engine` | deterministic | Output selection, and recorded node exchanges of restore and refresh sessions. |
| `app_data` | deterministic | The `WFEH` foreign-data file. |
| `store` | deterministic | The sealed peer record of the wallet database. |
| `store_key` | deterministic | The key of the wallet database and its check file. |
| `pairing` | deterministic, from the kit | Contact pairing, mailboxes, envelopes and EPICTX files. |

## Areas

### smoke

`plain_kernel_hash`: a `Plain` kernel with a fixed fee, excess blinding factor and signature nonce.
`expected` holds the excess commitment, the kernel signature message, the signature in compact
form, the kernel serialized at protocol versions 1 and 2, and the kernel hash. The node hashes
every kernel in the version 1 layout, so `hash` is unkeyed BLAKE2b-256 of `serialized_v1`. The
binary layouts carry the signature in the wrapper's internal form, which is the compact form with
each 32-byte half byte-reversed.

### primitives

Binary layouts, unkeyed and keyed BLAKE2b-256, kernel signature messages, weights and fees over a
count grid, mainnet and floonet chain parameters, weight limits, and valid and invalid
transactions with the rule each breaks. See [primitives/README.md](primitives/README.md).

### aggsig

The two-party aggregate-signature flow for a plain and a height-locked kernel, single-signer
signatures, and the cases that separate `verify_completed_sig` from kernel verification. See
[aggsig/README.md](aggsig/README.md).

### keys

Mnemonics, BIP32 derivation on both networks, commitments, Bulletproofs and their rewind, address
and payment-proof keys, the `wallet.seed` file, `epic1` addresses and links, and the keys and tags
of LEPIC's own namespace. See [keys/README.md](keys/README.md).

### slates

Stage vectors of the standard and invoice flows over the file and Epicbox methods, and upstream's
parse outcomes for malformed slates. See [slates/README.md](slates/README.md).

### slates_native

The flow slates of the `slates` area in the native `lepic.v1` layout, with their JSON view, the
same slates with a TLV tail, and malformed byte strings with the error the decoder names. See
[slates_native/README.md](slates_native/README.md).

### epicbox

The reference is `epic-wallet`. Files by prefix:

- `address_*`: a text and the network it is read on. An accepted case records the base58 key, the
  33-byte key in hex, the domain, the port, upstream's `Display` form (the `from`/`to` form) and
  the destination JSON. A rejected case records only `"accepted": false`.
- `signature_*`: ECDSA over SHA-256 of `text`, as DER hex, for a challenge, a `str` and a message
  id.
- `message_*`: randomized. `expected.random` names the drawn values. `str` is the exact posted
  text, `salt`, `nonce` and `encrypted_message` are copied from it, `key` is the PBKDF2 output and
  `signature` is over `str`.
- `marker_*`: a V2 S1 with the LEPIC marker `"lepic":{"version":1,"f":<bits>}` as its last key.
  The generator checks that the Epicbox listener of `epic-wallet` decodes the marked text to the
  same V2 slate as the plain one. `marker_s1_v2_native_claim_207` carries the native-slate bit and
  the sender's seal key in the marker.

### engine

Output selection over stated UTXO sets, and restore and refresh sessions of an upstream wallet on
an in-process test chain: every node exchange of each session and the wallet state upstream ended
in. See [engine/README.md](engine/README.md) and
[Recorded node exchanges](#recorded-node-exchanges).

### app_data, store and store_key

Formats of LEPIC's own storage, written by code independent of LEPIC. See
[app_data/README.md](app_data/README.md), [store/README.md](store/README.md) and
[store_key/README.md](store_key/README.md).

### pairing

Files of the kit, one per topic: `cards_invites`, `contact_keys`, `domain`, `envelopes`,
`hpke_rfc9180_a2`, `keycheck`, `mailbox_keys`, `malformed`, `reply_keys`, `sas`, `seal_keys`,
`words`, and `epictx_envelopes`, `epictx_files`, `epictx_malformed`, `epictx_padding` and
`epictx_reply_mailbox`. RFC 0002 section 14 describes them.

## Recorded node exchanges

Vectors that record a node session (`engine/restore_*` and `engine/refresh_*`) list its calls
under `expected.exchanges`. Each element is one JSON-RPC call over HTTP, as upstream's
`HTTPNodeClient` sent it and the node's API handlers answered it:

```json
{
  "endpoint": "/v2/foreign",
  "method": "get_tip",
  "params": null,
  "response": {
    "id": 1,
    "jsonrpc": "2.0",
    "result": { "Ok": { "height": 9, "last_block_pushed": "…", "prev_block_to_last": "…", "total_difficulty": { } } }
  }
}
```

| Key | Meaning |
|---|---|
| `endpoint` | The request path: `/v2/foreign`, or `/v2/owner` for `get_status`. |
| `method` | The JSON-RPC method. |
| `params` | The JSON-RPC params as sent, except that `get_outputs` commitments are sorted. |
| `response` | The JSON-RPC response object. A handler result is `{"Ok": value}` or `{"Err": error}` inside `result`; a protocol failure is an `error` object instead. |
| `built` | Present and `true` only on an answer the generator built instead of a node handler serving it: owner `get_status`, see the notes below. |

All recorded calls are read-only, so a session can be replayed in two ways.

### Strict replay

The generator uses strict replay, with upstream's own `HTTPNodeClient`, to show that a recording
is complete:

1. For each request, serve the first exchange not yet served whose `endpoint`, `method` and
   `params` equal the request's. Compare `params` as JSON values. For `get_outputs`, sort the
   request's commitment list first. Answer with `response`, with `id` set to the request's id.
2. A request with no matching exchange fails the test.
3. When the session ends, every exchange must have been served.

The generator replays every session this way into a second upstream wallet that starts from the
same state (a copy of the subject's wallet directory for a refresh, a new wallet from the mnemonic
for a restore) and requires it to end in `expected.after`.

### LEPIC replay

`MockNode` serves a session to LEPIC's engine tests. LEPIC's node client does not need to repeat
upstream's call sequence, so the session is served as a fixed node state instead of a script:

1. A recorded answer may be served any number of times, or not at all.
2. `get_tip` and `get_pmmr_indices` are served by equal `endpoint`, `method` and `params`. Owner
   `get_status` is served the same way if asked. LEPIC does not call the owner API, so a session
   that never asks for it is complete.
3. `get_outputs` is answered per commitment from the union of the session's recorded `get_outputs`
   exchanges. A commitment listed in a request's params with an output in the answer is found. One
   listed with no output is not found. A commitment no recorded request listed fails the test.
   Chunking and order of LEPIC's requests do not matter.
4. `get_unspent_outputs` is answered from the session's recorded listing, which is complete
   (`last_retrieved_index` equals `highest_index`). For a request `[start, end, max, true]`,
   return the recorded outputs whose `mmr_index` lies in `start..=end`, at most `max` of them.
   Set `highest_index` to `end`. Set `last_retrieved_index` to the `mmr_index` of the last output
   returned when `max` cut the window short, and to `end` otherwise. A window that reaches past the
   recorded listing's `highest_index` fails the test. A null `end` means the last position of the
   output MMR, which for a recording is its `highest_index`. The node caps `max` at 10,000, and no
   recorded request asks for more.
5. Any other request fails the test.
6. The session passes when LEPIC's wallet ends in `expected.after`, mapped through
   [states.md](../../docs/compat/states.md). Unused exchanges do not fail it.

Notes for consumers:

- Upstream builds the `get_outputs` commitment list from a hash map, so its order changes between
  runs. The generator sorts it, and because the node answers in request order, the response lists
  outputs sorted by commitment. Upstream reads the response into a map, so the order carries no
  meaning.
- Upstream checks `get_status` on the owner endpoint before every refresh and refreshes only when
  `sync_status` is `no_sync`. The in-process node has no peers and never syncs, so the generator
  builds that status the way the node's status handler does, with `connections` 0 and
  `sync_status` `no_sync`, and marks the exchange `built`. Every other response comes from the
  node's own handlers over the chain.
- Responses are stored as JSON values, so their key order is the generator's.
- The same call can appear more than once in a session with the same answer, for example
  `get_tip`.
