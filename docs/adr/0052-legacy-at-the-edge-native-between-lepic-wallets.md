# ADR 0052: Epic compatibility at the edge, a native protocol between LEPIC wallets

Status: accepted

Specification: [RFC 0003](../rfcs/0003-epictx-native-slates.md) (EPICTX, native slates). It holds
the byte layouts and the flows; this record holds the decisions and the reasons. Section numbers
below are RFC 0003's.

## Context

Stock `epic-wallet` v4.1.0 speaks a fixed set of bytes, and exchanges and users run it. LEPIC
reads and writes them for as long as anyone sends them:

| Surface | Fixed on the wire |
|---|---|
| HTTP | `POST <base>/v2/foreign`, JSON-RPC 2.0, `check_version` then `receive_tx`; foreign API version 2 |
| Slates | V2 and V3 JSON; V2 carries no payment proof |
| Tor | the same HTTP body to the wallet's onion, port 80 |
| Epicbox | relay protocol 3.0.0 frames, `key@domain` addresses, a secp256k1 message cipher |
| Mining | the Epic node calls `build_coinbase` on `/v2/foreign` (ADR 0046) |
| Files | V3 JSON (ADR 0015) |

The wire fixes no crate, module or type name, the internal slate model (ADR 0002), or any
exchange between two LEPIC wallets. Between two LEPIC wallets an S1 is otherwise a V2 JSON slate
with a marker, and a direct HTTP or Tor exchange would be plain JSON with no sealing, schema or
error codes of its own.

LEPIC needs two things. The Epic layer is named and kept apart, so that nothing in the core leans
on a legacy shape. A native protocol carries slates between LEPIC wallets: compact, sealed and
versioned independently of the Epic bytes.

## Decision

### Epic compatibility is an isolated layer

Everything that exists because stock `epic-wallet` speaks it is called legacy.

- `lepic-legacy-rpc` is the `/v2/foreign` JSON-RPC server and client.
- `lepic-legacy-slate` holds the V2 and V3 JSON codecs and the LEPIC marker codecs. The marker
  exists because legacy slates carry LEPIC facts (RFC 0002 §5).
- `lepic-transport` and `lepic-methods` have a `legacy` cargo feature, on by default. Without it
  they build with no legacy crate, the default codec registries decode nothing, and no method is
  found in the registry (ADR 0051).
- `cargo xtask no-legacy` builds the crates listed in `xtask/src/no_legacy.rs` with default
  features off, one package at a time, and fails when one depends on a `lepic-legacy-*`
  crate. `cargo xtask check` runs it. `lepic-wallet` and `lepic-epicbox` are not on the list:
  the wallet stores slates as V3 JSON, and Epicbox slates are V2 or V3 JSON.
- Epic's names stay where bytes are: the JSON-RPC method names, `foreign_api_version`,
  `supported_slate_versions`, `/v2/foreign` and the V2 and V3 field names.
- Stored ids never change. The `transport` and `codec` columns hold `http`, `tor`, `epicbox`,
  `file`, `legacy-v2` and `legacy-v3`; the native codec is the one id `lepic.v1`.
- `POST /v2/foreign` is in the OpenAPI document under the `legacy` tag (ADR 0050).

Receiving V2 and V3 JSON on every method, the Epicbox frames and cipher, `build_coinbase` on
`/v2/foreign`, and HTTP and Tor sends to stock listeners stay. Exchanges depend on them, and no
native protocol replaces them.

### One native slate

`lepic.v1` is a compact binary slate in the crate `lepic-native-slate`. Its layout follows grin's
V4 slate where RFC 0001 had no reason to differ: an explicit kernel-features byte, a block header
version that must match the fork table at the slate's height, and an extension tail. A proposal
(S1, I1) carries no inputs or outputs and an answer leaves out the initiator's message, so each
slate has one encoding. It names every field in a JSON view for tools (`lepic epictx open`). Its
layout is §5.10. LEPIC does not read or write age recipients or slatepack markers.

A native slate always travels sealed, never alone, apart from the raw in-person code below. A
sealed slate is an RFC 0002 envelope with body type `0A` (§5.3 to §5.9), one envelope for every
sealed message. Padding is inside the seal, with a 768-byte floor (`PADDING_FLOOR`, §5.7). The
suite byte leaves room for a post-quantum suite later (§5.4).

The seal key is a LEPIC namespace key (ADR 0033), `lepic-wallet seal key v1`, separate from every
proof key, with a context of account, network and kind. A listener advertises its own seal key. No
signing key is converted. Other namespace labels the native flows add: `epic1 seal key v1`,
`epic1 proof key v1`, `epic1 indexed proof key v1`, `reply mailbox v1`, `post key v1` and
`link mailbox v1` (§5.2, Appendix A). A restore from the phrase gives them all back.

Text and files:

- The text form is EPICTX: the markers `BEGINEPICTX.` and `ENDEPICTX.`, for files and
  copy-paste only. Other envelope bodies (pairing, notices) keep `BEGINEPICSEALED.`.
- One extension, `.epictx`, for every stage; the stage is read from inside. A reply is named after
  the file it answers: the stem, then `-reply`, then `.epictx` (§5.11, §5.12).
- A stock `saved_txs` file of the same extension is read by content and shown as not a payment
  file.

### Ways a native slate goes

Which way a payment goes depends on what the sender already knows (§3.1).

| Route | Condition |
|---|---|
| Paired contact's mailbox | `native_direct` is on and the contact's pairing features claim `NATIVE_SLATES` (marker bit 7). Never through a private pairing. |
| An HTTP or Tor listener | `native_direct` is on, the caller does not ask for legacy, and the listener's `check_version` answer advertises the endpoint. |
| A payments address over Epicbox | `native_direct` is on and the peer claimed `NATIVE_SLATES` and is a LEPIC wallet seen lately (ADR 0016). A stock listener never acknowledges a message that is not a slate and loses its queue to one. |
| An epic1 address | The payer holds an epic1 link. The payee has no contact, key or Epicbox address to start from. |
| In person | A code shown on one screen and scanned on the other. |
| A file to an unknown receiver | The marked V3 file with a one-time reply key; a LEPIC receiver answers sealed. |

`native_direct` is a `WalletConfig` and host-policy value (ADR 0036). It is off unless the host
sets it (`native_direct` in the CLI, the `LEPIC_NATIVE_DIRECT` environment variable). With it off a
wallet sends what it sent before native slates existed, and it claims no `NATIVE_SLATES` bit in a
pairing or a contact update. A wallet reads native slates whatever its setting, and an answer
takes the format of its request.

### One code, one identity

No code serves both legacy and LEPIC. The default receive code is the plain Epicbox link, which
every wallet reads. The epic1 address is a separate code.

An epic1 address holds two keys and nothing else: the payment-proof key and the seal key, kept
apart, in bech32m with a version byte first (§5.13, `lepic-epic1`; 115 characters on mainnet). It
names no mailbox or domain. The transport sits in the link, one field per method:
`epic:epic1…?epicbox=<mailbox>@<domain>&amount=…`. A link names at most 3 transports, and the
sender tries them in order (§5.14, `MAX_TRANSPORTS`). A stock wallet refuses an epic1 link. The
link mailbox is transport only and is never shown as the payee. The link mailbox keys have two
index spaces: 50 mailboxes for on-screen links, taken in turn, and 32 for printed links, fixed
until retired. A restore scans both in full.

An account has numbered epic1 addresses, index 0 first: one per shop, per invoice or for one
payment. The index is not in the address, and the address format does not change. Index 0 keeps
the keys of earlier builds (`seal key v1` kind 00 and `epic1 proof key v1`); indexes 1 and above
use `epic1 seal key v1` and `epic1 indexed proof key v1`, with the index at the end of the context
(ADR 0033). The onion, web and Epicbox seal keys do not change.

- Envelopes to an epic1 keep the zero hint. A hint the sender can derive from the address would
  be the same on every message to it and would let a relay pick out every payment to it.
- A link mailbox is recorded with the index it was issued for and opened with that index's key.
  Files, transaction text and the direct listener try the issued indexes of every account in
  turn, the most recent payment's index first, and stop at the first key that opens. The direct
  listener does so only where the host switched epic1 on for that socket kind (off for the onion
  and the web socket by default).
- The wallet keeps the highest index issued per account and the index each payment came to. A
  restore tries 50 indexes past the highest one known (`RESTORE_GAP`). A restored install issues
  no new address until the host makes it the one that issues (`epic1 issue-here`), so two
  installs on one phrase do not hand one index to two payers. LEPIC sets no limit on addresses.
- The wallet, the CLI and `serve` issue the next address, give the address at an index, and list
  the issued ones. A received transaction shows its index.

An epic1 send sets a TTL of 1,440 blocks when the caller sets none (`EPIC1_TTL_BLOCKS`). An
accepted post is not final: the send stays open until the payee answers or the user cancels, and
the host may post the same sealed S1 to the link's next transport (§5.14).

### The native direct endpoint

A LEPIC listener serves the `/v1/peer` routes of `lepic-peer` beside `/v2/foreign`, on the same
port and onion. The crate moves envelope bytes only and implements no wallet trait.

- `GET /v1/peer` describes the endpoint: protocol, formats, network and the seal key.
- `POST /v1/peer/slates` takes a type `0A` envelope as `application/vnd.lepic.epictx`, at most
  `MAX_ENVELOPE_LEN` (69,632 bytes, 68 KiB). `200` answers with the reply envelope, sealed to the
  sender's one-time reply key. A repeated slate gets the same reply (`MAX_CACHED_REPLIES`, 64).
- Errors are RFC 9457 problems with a closed list of codes: `not_ready` (503, `Retry-After`),
  `refused` (422), `too_large` (413), `rate_limited` (429) and `unsupported_format` (415).
- An I1 is never taken here. An invoice needs the payer's consent, so it travels between paired
  contacts or in a code the payer scans (§6.10).
- The advertised key is the seal key of the listener that accepted the connection: one for the
  onion, one for the plain web address, never the epic1 key. The socket chooses it and the `Host`
  header never does, so the advert links neither listener to the other nor to the payments
  identity.
- On plain HTTP the seal gives what `/v2/foreign` never had: a passive observer sees no amounts.
  Over Tor the onion authenticates the listener.

The listener's limits (ADR 0017) apply to both dialects.

### Discovery, pinning and downgrade

A LEPIC listener adds a `lepic` key to its `check_version` answer: `protocol`, `formats`, `path`
and `seal` (`lepic_peer::Advert`). Stock senders read only their two keys, and LEPIC's decoder
ignores unknown keys, so neither changes behaviour. A LEPIC sender that reads the advert posts
to the endpoint. One that does not falls back to `receive_tx`. No extra round trip is made.

The first native exchange that succeeds pins the advertised key for the sending account and the
listener's origin. After that:

- a send to the pinned origin that cannot go native stops with an error, and LEPIC reports it. A
  missing advert or any error from the endpoint is not a reason to fall back. It never retries
  over `/v2/foreign` by itself;
- a different key at a pinned address is a different wallet. The send stops and LEPIC reports it.

On plain HTTP an attacker can strip the advert from a first contact. The sender then sends
legacy, which is what it did before native slates, so a first contact is no worse. A pin removes
the risk afterwards, as HSTS does for HTTPS.

### Versions

Two axes, as in grin: `protocol`, the shape of the endpoint (`/v1`; an additive change keeps it,
a break takes `/v2`), and `formats`, the slate encodings. Protocol 1 has no feature bits. The
bits of the LEPIC marker (`lepic-transport` `marker::features`) are claims without parity, and
`NATIVE_SLATES` is bit 7.

### The port

The method stays how a slate travels; the format is per transaction and is chosen before the
engine encodes (ADR 0051). The port has two additive fields: `Sending.peer: Option<PeerFormats>`,
the formats the receiver's endpoint reads, and `SenderFacts.format`, so `encode_reply` answers in
the format it was asked in. The engine stores the exact wire bytes of each stage with their codec
id and converts only at the edge, never format to format. A resend uses the stored bytes, so a
transaction keeps its first format for its whole life.

### In person

An in-person code carries one slate shown on one screen and scanned by the other wallet. The
first code always carries a one-time reply key, and every answer is sealed to it. The payee shows
an I1 (a paypoint starts), or a payer shows an S1. The code is raw `lepic.v1` bytes, or the binary
envelope in `ur:epic-slate` payload version 2 (§5.18). It names a reply mailbox on the wallet's
own relay when the wallet is online; the answer is posted there, so one scan completes a payment.
Offline, the answer is shown as an animated code.

LEPIC never finalizes an in-person answer by itself, in either direction. It keeps at most
`MAX_ANSWERS_PER_CODE` (16) different answers per code, stores each answer that checks with a
check code, reports it with `Event::InPersonAnswer`, flags two answers with the same code, and
finalizes only when the host asks. The check code is four digits of the answering party's public excess (§6.7).
Raw `lepic.v1` is read only from a scan; file and paste paths refuse it.

An in-person code takes a TTL from the host. A caller that passes none gets 30 blocks
(`IN_PERSON_TTL_BLOCKS`), and LEPIC refuses a TTL at or under the 10-block margin
(`INVOICE_TTL_MARGIN_BLOCKS`).

### What the core leaves to the host

LEPIC is the core. Limits, prompts and policy live in the host. LEPIC reports facts and acts
when the host says so.

- A relay named by untrusted input (a scanned code, a link, a reply record) passes the host rule
  (`lepic-transport` `host_rule`, §5.14, Appendix B.2). LEPIC refuses loopback and unspecified
  addresses itself, on the addresses it resolved and connects to. It reports a local-network
  address and a public one with their class, and posts only when the host says so. Whether to
  ask the user about an unknown relay, answer through Tor, or accept a local-network address is
  the host's.
- A relay domain in an epic1 link, tag `09` or record `02` follows Epicbox's address rule: labels
  of letters and digits, no hyphens (`lepic-epic1` `relay`, Appendix B.2). An Epicbox relay checks
  both addresses of every post and refuses one with a hyphen. An earlier decision allowed hyphens
  and was reversed on 2026-11-10.
- A changed seal key at a pinned peer, a slate too large to seal, and an epic1 send with no answer
  reach the host as errors or events. The host decides what the user sees.
- The check-code confirmation of an in-person answer is the host's.

## Consequences

- The core does not depend on Epic's shapes; the no-legacy build keeps it that way.
- Epic compatibility on the receive side is kept whole. What can go later is LEPIC's own sending
  choices.
- Two direct protocols share one listener, with one set of limits.
- An installed wallet keeps every address, contact, pending transaction and setting. A transaction
  in flight finishes in the format it started in. Saved addresses keep their meaning: the native
  endpoint sits behind the same address. Older LEPIC builds never see native bytes, because they
  do not advertise and so get legacy.
- Native keys come from the seed, so a restore needs no migration.
- A printed static code lets its relay link every payment made to its one mailbox. Codes shown on
  screen rotate the mailbox.
- A payer who scans a code in person can be raced by someone who saw the code, because the reply key
  and mailbox are in it. LEPIC reports every answer and finalizes none. The check code and the
  host's confirmation make the race visible. A sticker over a printed code, and check-code
  grinding, remain residual risks (RFC 0003 §10).

## Alternatives considered

- **Keep the layout and document it.** Nothing stops legacy shapes from leaking back into the
  engine, and "foreign" stays the core's word.
- **Native only, as grin 5.0.** It removes HTTP(S) sends to stock wallets, which breaks exchange
  deposits and every stock user.
- **A separate method id for native.** The user would pick a protocol and one address would need
  two entries. The format belongs to the peer.
- **Native as JSON.** It is readable, but the slate grows back to legacy size and encryption makes
  the body opaque anyway.
- **A separate port for the endpoint.** One more port to open, publish and firewall, and the onion
  needs a second port. Paths on one listener cost nothing.
- **An advert in the Epicbox address.** The anchored address pattern rejects it in stock wallets.
- **A relay extension for epic1 mailboxes.** A stock Epicbox server holds mailboxes for secp256k1
  keys, and the link mailbox keys are such keys derived from the seed, so no relay changes.
- **A link with an Epicbox address and an epic1 beside it.** Nothing in the link binds the two, so
  a genuine Epicbox address beside someone else's epic1 would pay that someone.
- **age recipients and slatepack markers.** They need converted keys, or a second armour.

## Related

- ADR 0002: slate model.
- ADR 0003: transport format policy.
- ADR 0016: Epicbox notices and the "LEPIC lately" rule.
- ADR 0017: direct transactions over HTTP.
- ADR 0033: keys and domains.
- ADR 0036: host policy.
- ADR 0044: the onion key.
- ADR 0050: the wallet API.
- ADR 0051: transaction methods in one crate.
- RFC 0001: slate format.
- RFC 0002: contact pairing.
- RFC 0003: EPICTX.
