# 0003 Transports declare the slate formats they speak

Status: accepted
Date: 2026-10-02

## Context

`epic-wallet` dispatches methods by string in about four files and ten match arms, and only some
methods implement its adapter traits. Each method also decides the slate version in its own way.

## Decision

`lepic-transport` defines:

- `TransportId`, a typed id per method (`epicbox`, `file`, later others).
- Capability traits: `Outbound` (deliver a wire slate to a destination), `Inbound` (a stream of
  envelopes, each with an explicit acknowledge), and `Exchange` (export and import for manual
  methods such as files, text and QR).
- `FormatPolicy` on each transport: the codecs it accepts, how it chooses the codec for a new slate,
  and how it chooses the codec for a reply.
- A `TransportRegistry` the engine queries by id. Adding a method is one module plus one registration.

Policies for the legacy methods match `epic-wallet` `v4.0.2`:

| Transport | Accepts | New slate | Reply |
|---|---|---|---|
| Epicbox | V2 and V3 shapes | V2 shape | same shape as the inbound slate, header echoed |
| File | V2 and V3 | V2, or V3 when the slate has a TTL or a payment proof | same content rule as a new slate |

New methods may declare new codecs. A legacy method switches to a new codec only when the peer has
shown it understands it (ADR 0012). Never by default.

## Consequences

- Payment proofs and TTL cannot travel over Epicbox to a legacy peer, because the legacy sender always
  uses the V2 shape. LEPIC refuses with a typed error instead of dropping them silently; the CLI and
  app show why.
- The engine never names a codec. It asks the transport's policy.

## Alternatives considered

- A global "preferred slate version" setting, as `epic-wallet` has with `target_slate_version`. Two
  methods ignore it today, which shows the setting is in the wrong place.

## Amendment 2026-10-05: invoice stages over Epicbox

The operator approved invoices between LEPIC wallets over Epicbox . The payer sets a TTL
on I2, which the V2 shape cannot carry, and I2 answers in the shape of I1. So over Epicbox an I1 goes
out in the V3 shape, header `3/3/<b>`, and both invoice stages LEPIC writes carry the LEPIC marker
`"lepic":{"version":1}` (ADR 0012 amendment). S1 keeps the V2 shape and S2 the shape of its S1.
Stock `epic-wallet` tries V3 first, so it parses the I1; it does not pay invoices over Epicbox and
posts the I1 back unchanged (`docs/compat/epicbox.md`).

| Transport | Stage | New slate | Reply |
|---|---|---|---|
| Epicbox | S1, S2 | V2 shape | shape of the inbound slate, header echoed |
| Epicbox | I1, I2 | V3, header `3/3/<b>`, with the marker | V3 as I1 arrived, header echoed, with the marker |

The policy in `lepic-epicbox` still returns V2 for every new slate; until its `for_new_slate`
looks at the stage, the engine picks V3 for a new I1 over Epicbox itself. That is the one place the
engine names a codec.
