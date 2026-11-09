# ADR 0003: Transports declare the slate formats they speak

Status: accepted. The file row of the policy table: see ADR 0015.

## Context

`epic-wallet` dispatches methods by string in several files, and only some methods implement its
adapter traits. Each method also decides the slate version in its own way. A wallet core that
serves many apps needs one place that says how each method reads and writes slates, and a way to
add a method without touching the engine.

## Decision

`lepic-transport` defines the port between the engine and a transaction method.

- `TransportId` is a typed id per method (`epicbox`, `file`, `http`, `tor`).
- Capability traits: `Outbound` delivers a wire slate to a `Destination`; `Inbound` yields a stream of
  `Envelope`s, each settled with an explicit `AckToken`; `Exchange` exports and imports for manual
  methods such as files.
- `Transport` names a method and returns the capabilities it has (`outbound`, `inbound`,
  `exchange`) and its `FormatPolicy`.
- `FormatPolicy` states the codecs the transport accepts, the codec for a new slate, and the codec
  for a reply. The engine never names a codec; it asks the policy to decode and encode.
- `Method` extends `Transport` with what the engine needs beyond formats: `carries` (whether a
  slate may hold a reply key), `decode`, `sender_facts`, `encode_new`, `encode_reply`,
  `notice_lengths`, `peer_key`, `same_payee` and `delivery_is_permanent`. The defaults speak plain
  legacy slates through the policy. A method with its own codecs overrides the encoders.

`lepic-methods` holds the methods and the `Methods` registry the engine looks them up in.
`Methods::register` refuses a second method with the same id. Adding a method is one module and
one registration. The `epicbox`, `http` and `tor` modules are Cargo features; `file` is on by
default.

The legacy methods write the shapes `epic-wallet` accepts:

| Transport | Accepts | New slate | Reply |
|---|---|---|---|
| Epicbox | V3 and V2 shapes, V3 tried first | V2 shape | shape of the inbound slate, header echoed |
| HTTP | V3 and V2 shapes, V3 tried first | V2 shape | shape of the inbound slate, header echoed |
| File | V2 and V3 | see ADR 0015 | see ADR 0015 |

Over Epicbox the stage refines the new-slate rule. S1 goes out in the V2 shape and S2 in the shape
of its S1. An I1 goes out in the V3 shape, header `3/3/<b>`, because the payer's TTL on I2 has no
field in V2. Both stages LEPIC starts over Epicbox carry the LEPIC marker (ADR 0012). Stock
`epic-wallet` parses the I1 but does not pay invoices over Epicbox; it posts the I1 back
unchanged (`../compat/epicbox.md`). The Epicbox method chooses the shape per stage in its own
`encode_new`; its `FormatPolicy` returns V2 for every new slate.

A new method may declare new codecs. A legacy method moves to a new codec only when the peer has
shown it reads it (ADR 0012, ADR 0052).

## Consequences

- A payment proof or a TTL cannot travel over Epicbox in the V2 shape. The encoder returns
  `EncodeError::Unrepresentable` and LEPIC surfaces a typed error instead of dropping the field.
- The engine holds no per-method branches. A format change is a change to one policy.
- No global "preferred slate version" setting exists.

## Related

- ADR 0002: the codec contract the policies choose from.
- ADR 0015: the file method.
- ADR 0012: the LEPIC marker and the native codec.
