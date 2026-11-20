# ADR 0061: A domain-separated cancel signature, epicbox-cancel/1

Status: accepted
Date: 2026-11-16

## Context

[ADR 0060](0060-epicbox-310-cancel.md) has the `CancelTx` signature made over the bare 32
character txid. That is the same text, signed by the same key, as the `epicboxtxidsig` every
`PostSlate` carries. Whoever sees a `PostSlate` (the mailbox operator, and any mailbox it is forwarded
to) holds a valid cancel for that transaction and can replay it.

## Decision

- A cancel signature may be made over `epicbox-cancel/1:<txid>` instead of the bare txid. The
  prefix is the whole domain separation: a signature over the bare id never verifies over the
  prefixed text, and the other way round.
- The form is negotiated in band. A client that cancels offers the extension `epicbox-cancel/1` in
  `ClientDetails.ext`; a mailbox that accepts the form repeats it in the `Ok`. On a mux/1 socket the
  client always lists it with `mux/1` and `txcancel/1`, and the mailbox's `Ok` lists what it
  accepted. On a classic connection only the short cancel connection offers it, so every other
  greeting keeps its exact bytes.
- LEPIC signs the prefixed text when the mailbox echoed the extension, and the bare id otherwise: a
  mailbox without it, a mailbox of 3.1.0 that ignores `ext`, and a mailbox whose `Ok` has no `ext`.
  There is no second try with the other form.
- The mailbox also lists `epicbox-cancel/1` as a feature in `/.well-known/epicbox.json`, with the
  text it verifies. LEPIC does not fetch it; it is for other wallets and for operators.
- A mailbox keeps accepting the bare form, because stock 3.1.0 wallets and the reference
  `epic-wallet` branch sign it. While it does, a replayed `epicboxtxidsig` is still a valid bare
  cancel. The hole closes only when mailboxes stop taking the bare form, and that needs wallets to
  have moved. The mailbox's own settings decide that and when; this record does not.

## Consequences

- A cancel by a LEPIC wallet against a mailbox with the extension cannot be made from a
  `PostSlate` the mailbox or a peer saw.
- Against any other mailbox nothing changes, byte for byte.
- A mailbox forwards a cancel with the signature it was given, so a peer that supports the form
  verifies it and a peer that does not still reads the bare one.
