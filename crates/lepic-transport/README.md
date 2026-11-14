# lepic-transport

The ports between the engine and the ways a slate travels: the `Transport` trait and its
capabilities, the `Method` port, and the `FormatPolicy` that picks a slate's wire format. With
the `legacy` feature it also holds the legacy codec registries and the file method. The engine
calls these traits and never names a transport or a codec.

## Where it fits

- Depends on `lepic-crypto`, `lepic-primitives` and `lepic-slate`; on `lepic-legacy-slate` with
  `legacy`.
- Used by `lepic-epicbox`, `lepic-legacy-rpc`, `lepic-methods`, `lepic-wallet`,
  `lepic-wallet-contacts`, `lepic-cli`, `lepic-ffi`, the conformance suite and the fuzz targets.
- Features: `legacy` (default) adds the V2/V3 codec registries, the marker codecs and the file
  method (ADR 0052); `loopback` adds an in-memory transport pair for engine tests.

## Core concepts

- **Capabilities.** A `Transport` has an id and a format policy, and returns the capabilities it
  offers: `Outbound` (deliver an envelope), `Inbound` (receive and acknowledge envelopes) and
  `Exchange` (export to and import from a `Location`). The engine asks for the one it needs
  (ADR 0003).
- **Format policy.** A `FormatPolicy` lists the codecs a transport decodes, detects the format of
  an incoming slate, and chooses the `Encoding` of a slate the wallet starts or answers. An answer
  echoes the format the peer sent.
- **Methods.** `Method` extends `Transport` with what a method's slates may carry (`Carries`),
  how it decodes and encodes them, and how it tells peers apart. `MethodLookup` finds the method a
  stored payment went over by its id.
- **File method.** `FileTransport` writes V3 (ADR 0015) and reads at most `MAX_WIRE_SLATE_LEN`
  bytes from a regular file. `FilePolicy` detects the format without building a JSON tree.
  `response_path` names the answer file for an input file.
- **Marker.** A LEPIC wallet adds a `"lepic":{"version":1}` key to the V2 and V3 slates it sends
  over Epicbox, so the peer knows it runs LEPIC. `marker::features` holds the feature bits a
  wallet claims there and in pairing envelopes. A claimed bit only decides whether a convenience
  is offered; no check is skipped because of one.
- **Host rule.** `host_rule` classifies a host taken from untrusted input, such as a relay named
  in a payment link. Loopback and unspecified addresses are refused. Callers resolve a name once
  and classify each address before connecting to it.

## Public API

| Module | Main items |
|---|---|
| `transport` | `Transport`, `Outbound`, `Inbound`, `Exchange`, `TransportId`, `Destination`, `Envelope`, `AckToken`, `Location` |
| `method` | `Method`, `MethodLookup`, `Carries`, `PeerFormats`, `Sending`, `SenderFacts`, `Encoded`, `EncodeContext` |
| `policy` | `FormatPolicy`, `Encoding`, `encode_with` |
| `codecs` (`legacy`) | `legacy(base_fee)`, `legacy_with(v3, v2)` |
| `file` (`legacy`) | `FileTransport`, `FilePolicy`, `FILE`, `response_path`, `MAX_WIRE_SLATE_LEN` |
| `marker` | `features` (`MARKER`, `PAIR_REQUESTS`, `NATIVE_SLATES`, `LEPIC_FEATURES`, `claimed`, …); `v2`, `v3` with `legacy` |
| `host_rule` | `classify_name`, `classify_addr`, `classify_resolved`, `HostClass`, `RefusedHost`, `HostReport` |
| `epicbox_link` | `epicbox_of_link`, `is_epicbox_link`: the Epicbox address a chat app turned into an `https://key@relay/` link |
| `loopback` (`loopback`) | `LoopbackTransport` |
| `error` | `TransportError`, `FileError`, `FileOperation`, `FormatError` |

## Related

- [Architecture: slates, codecs and methods](../../docs/architecture.md#slates-codecs-and-methods)
- [ADR 0003: transport format policy](../../docs/adr/0003-transport-format-policy.md),
  [ADR 0015: the file method writes V3](../../docs/adr/0015-file-method-writes-v3.md),
  [ADR 0052: legacy at the edge](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)
- [Legacy slate compatibility](../../docs/compat/legacy-slates.md)
- [`lepic-slate`](../lepic-slate/README.md), [`lepic-legacy-slate`](../lepic-legacy-slate/README.md),
  [`lepic-methods`](../lepic-methods/README.md)
