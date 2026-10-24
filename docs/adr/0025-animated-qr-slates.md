# 0025 Slates as animated QR codes in `ur:epic-slate`

Status: accepted
Date: 2026-10-24

## Context

Two people standing together want to pay without a relay, a server or a file to share: one
phone shows the slate, the other scans it, and the answer goes back the same way. The operator
decided on 2026-10-24 that this method carries the slate unencrypted and is offered on mobile
only. A deflated S1 or I1 slate is about 1.3 KB and an S2 or I2 about 2.2 KB; range proofs do not
compress. One QR code that a phone camera reads reliably holds a few hundred bytes, so a slate
needs a short sequence of codes, and the receiver will miss frames.

## Decision

- Slate text travels as a BC-UR multipart code of the type `epic-slate`
  (`docs/compat/ur-epic-slate.md`). The payload is a CBOR map `{1: 1, 2: <raw deflate of the
  slate JSON>}`. Fountain parts follow the pure fragments, so a looping sequence recovers from
  missed frames without the receiver asking for anything.
- The codec is `lepic_slate::ur_slate`, a pure module: no I/O, deterministic, fuzzed through its
  decoder. It sits in `lepic-slate` because it is a wire form of slate text with no state, and
  `lepic-wallet` re-exports it, so no crate gains a dependency edge. It does not decode the slate;
  the text goes on to the codecs exactly as slate text from a file does, and the app inspects it
  with `inspect_slate` and hands it to `receive_slate` or `finalize_and_post`.
- Decoding is stateless. The app passes every distinct part it has scanned; the decoder returns
  the progress and, once complete, the text. Every call is bounded before any work: the number of
  parts, their length, the sequence length and the inflated size (64 KiB, far below the file
  method's limit, which no QR sequence a person waits for approaches).
- Framing and bytewords come from the MIT `ur` crate, and deflate from `miniz_oxide`, both pure
  Rust. `ur` brings `minicbor` under BlueOak-1.0.0, a permissive licence now on the allow list
  (ADR 0010).
- The FFI exposes `encode_ur_slate` and `decode_ur_slate` without a wallet, like
  `inspect_slate`, with error kinds that tell a QR code of something else, a code of another
  wallet, parts of two codes, a damaged code and an oversized one apart.

## Consequences

- QR transfer is a host-side method: the engine and the transports are unchanged, and a slate
  read from QR is accepted exactly when the same text from a file is.
- Anyone who can see the screen can read the slate. It holds no secret that moves funds, but it
  shows amounts, outputs and messages, as a slate file does.
- A future payload changes the version in the map; this decoder refuses any version but 1.
- Two more crates and three of their small dependencies enter the product graph.

## Alternatives considered

- Plain multi-QR with an `n/m` prefix and no fountain codes: the receiver must catch every frame,
  and a missed one costs a whole loop.
- Our own fountain code: more code to review for the same result as the BC-UR scheme, which
  other wallets' scanners already speak.
- Base64 or base45 text instead of bytewords: denser, but the UR form with an uppercase body
  fits the QR alphanumeric mode, and the type name lets an app refuse another wallet's code with
  a clear message.
