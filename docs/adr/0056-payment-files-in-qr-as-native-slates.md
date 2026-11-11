# ADR 0056: Payment files in QR codes as native slates

Status: accepted
Date: 2026-11-11

## Context

ADR 0025 put slate text in `ur:epic-slate` codes as deflated JSON, payload version 1. Range
proofs and the other hex fields do not compress, so an S2 or S3 is about 2.3 KB. A wallet that
draws every code at level H with a logo in the centre keeps each frame small with short
fragments, and a payment file then takes 20 to 40 parts. The in-person flow already sends
native `lepic.v1` slates and envelopes as version 2, about half the size of the same slate as
deflated text.

## Decision

- The binding's `encode_ur_slate` takes the chain and `native`. Without `native` it writes the
  slate of a payment file as version 1, the deflated text, which every reader takes. With it,
  it writes a version 2 payload: the slate's `lepic.v1` bytes with an empty tail
  (`lepic_wallet_contacts::payment_qr_native`). Released apps run LEPIC builds that read version
  1 only, and a QR code cannot tell the scanning wallet's version, so a wallet writes version 1
  until the wallets that scan its codes read version 2, then turns `native` on.
- With `native` it still writes version 1 where `lepic.v1` cannot carry the slate:
  - text the legacy codecs do not read;
  - a range proof that is not a single bulletproof;
  - a block header version other than the one the fork table gives the slate's height;
  - bytes that would not read back, such as a message over the `lepic.v1` limit.
- `decode_ur_slate` reads both versions:
  - version 1 gives the text as before;
  - a version 2 native slate gives its V3 JSON text (`payment_qr_text`) on the network its
    header names, so a slate for another network is refused as the same file is;
  - a native slate with a reply key or mailbox (an in-person code), or an envelope (an in-person
    answer), is `ForeignUrCode`.
- `in_person_qr_read` refuses a native slate without a reply key or mailbox as `InvalidSlate`,
  as it refuses version 1 text.
- `lepic.v1` leaves out the body of a proposal and the initiator's message in an answer (ADR
  0012). The engine completes an answer from the proposal it stored, whether the answer came as
  native bytes or as a file or text. A file or text answer is completed when it carries none of
  the initiator's inputs and outputs. One that carries some of them but not all is refused as
  changed, as before.
- The CLI and `lepic serve` keep writing version 1 through `lepic_slate::ur_slate`.

## Consequences

- With `native`, payment codes need about half as many parts as version 1, and an S1 or I1 far
  fewer. Without it the codes are as before and every reader takes them.
- The text read from a version 2 code is V3 JSON without the proposal's body, smaller than the
  file that was shown. Only the initiator that stored the proposal can finalize the answer.
- An app or wallet that reads only version 1 refuses a version 2 payment code as an unknown
  version. Codes and files from older apps and other wallets still read.
- An answer file that leaves out all of the initiator's inputs and outputs now finalizes from
  the stored proposal instead of being refused. The parts put back are the initiator's own
  record, and the kernel signature check covers the whole transaction. One that puts another
  output in place of the initiator's is refused by the fee or signature checks instead of as a
  changed output.

## Related

- ADR 0012, ADR 0025 (payload of `encode_ur_slate` and `decode_ur_slate` superseded here)
