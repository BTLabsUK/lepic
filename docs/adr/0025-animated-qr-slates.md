# ADR 0025: Slates as animated QR codes in `ur:epic-slate`

Status: accepted

## Context

Two people standing together can pay without a relay, a server or a file to share: one phone
shows the slate, the other scans it, and the answer goes back the same way. A deflated S1 or I1
slate is about 1.3 KB and an S2 or I2 about 2.2 KB; range proofs do not compress. One QR code
that a phone camera reads reliably holds a few hundred bytes, so a slate needs a sequence of
codes, and the receiver misses frames.

## Decision

- Slate text travels as a BC-UR multipart code of the type `epic-slate`
  (`docs/compat/ur-epic-slate.md`). The version 1 payload is a CBOR map `{1: 1, 2: <raw deflate
  of the slate JSON>}`. Fountain parts follow the plain fragments, so a looping sequence
  recovers from missed frames without the receiver asking for anything. The same module also
  writes and reads version 2, which carries native `lepic.v1` slates and envelopes as bytes
  (ADR 0012, ADR 0024); `encode_ur_slate` and `decode_ur_slate` are version 1 only.
- The codec is `lepic_slate::ur_slate`, a pure module with no I/O. `lepic-wallet` re-exports it.
  It does not parse the slate: the text goes on to the codecs exactly as slate text from a file
  does, and the app inspects it with `inspect_slate` and hands it to `receive_slate` or
  `finalize_and_post`.
- Decoding is stateless. The app passes every distinct part it has scanned; the decoder returns
  the progress and, once complete, the text. Every call is bounded before any work: the number
  of parts (`MAX_PARTS`), their length (`MAX_PART_TEXT_LEN`), the sequence length
  (`MAX_SEQUENCE_LEN`) and the inflated size (`MAX_SLATE_TEXT_LEN`, 64 KiB).
- Framing and bytewords come from the `ur` crate and deflate from `miniz_oxide`, both pure Rust.
  `ur` brings `minicbor`, licensed BlueOak-1.0.0, which `deny.toml` allows (ADR 0010).
- `lepic-ffi` has `encode_ur_slate` and `decode_ur_slate`, which need no wallet, with error
  kinds that tell a QR code of something else (`NotUrCode`), a code of another type
  (`ForeignUrCode`), parts of two codes (`MixedUrCodes`), a damaged code (`InvalidUrCode`) and an
  oversized one (`UrCodeTooLarge`) apart.

## Consequences

- QR transfer is a host-side method: the engine and the transports are unchanged, and a slate
  read from QR is accepted exactly when the same text from a file is.
- The slate is not encrypted. Anyone who can see the screen can read amounts, outputs and
  messages, as with a slate file.
- A reader refuses any payload version it does not know.
- `ur`, `minicbor` and `miniz_oxide` are in the product dependency graph.

## Related

- ADR 0010, ADR 0012, ADR 0024
