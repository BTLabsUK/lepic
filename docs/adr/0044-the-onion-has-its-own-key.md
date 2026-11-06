# 0044 The onion has its own key

Status: accepted
Date: 2026-11-06

## Context

ADR 0018 made the wallet's onion the payment-proof address in onion form: the Ed25519 key whose
seed is the secret of `m/0/1/0`, the key that also gives the Epicbox address. Anyone who knows a
wallet's onion therefore knows its Epicbox address and its payment-proof address, and the other
way round: one public value links the wallet's Tor and Epicbox identities. The Tor/Epicbox split
research chose option A: the onion gets a key of its own, and Epicbox and the proof address stay
where stock wallets expect them.

An installed wallet already published the old onion, and senders may have saved it: the GUI
wallet's contacts, `epic-wallet` users, and LEPIC wallets that paid it. A restore from the phrase
must still give back every address the wallet answers at.

## Decision

- The onion key is a LEPIC namespace key (ADR 0033): the keyed BLAKE2b-256 of the seed over the
  label `lepic-wallet onion key v1` with no context. The 32 bytes are the Ed25519 seed; tor gets
  the key expanded as ADR 0018 says. `Wallet::onion_key` returns it, `lepic tor address` and the
  binding's `onion_address` show its onion, and `tor listen` and `start_tor` publish it.
- The Epicbox address and the payment-proof address stay at `m/0/1/0`, as in `epic-wallet`.
- A payment proof is signed with the key of the address the slate came to. `ReceiveRequest`
  carries `proof_key`: `Payments` (the default: Epicbox, HTTP, files) or `Onion` (a slate that
  came to the onion). A proof whose receiver address is not that key's public key is refused
  with `ForeignProofAddress`, as before; so a slate sent to the onion that asks for a proof to
  the payment-proof address is refused, and the sender learns nothing that links the two. The
  sender's own proof address stays the payment-proof key.
- The previous onion, the one LEPIC 0.3.1 and earlier, the GUI wallet and `epic-wallet` publish,
  stays available as a key: `Wallet::previous_onion_key`, `lepic tor address --previous` and the
  binding's `previous_onion_address`. Publishing it is a host choice (ADR 0036), off unless the
  host asks:
  - the binding's `HostPolicy::publish_previous_onion`, default false: when true, `start_tor`
    with `publish_onion` adds the previous onion as well, behind a listener of its own whose
    proofs are signed with the payment-proof key, and removes it at `stop_tor`;
  - `lepic tor listen --previous-onion` does the same in the CLI; without it only the onion is
    published.
  Epic Wallet does not publish the previous onion: it has few users, who are told of the new
  address, and publishing it would keep the two identities linked. The lookup stays.

## Consequences

- An updated install shows a new onion. The old address stops working for that install, and
  anyone who saved it needs the new one, unless the host publishes the previous onion; then
  those senders still reach it and their proofs verify as before.
- A restore from the phrase gives the same onion and the same previous onion, so both addresses
  come back.
- Pairing never carries the wallet's own onion (RFC 0002 carries only relay onions), so no
  contact record changes. Onion contacts imported from GUI profiles name other wallets' onions,
  which those wallets publish as before.
- The GUI wallet and `epic-wallet` on the same phrase still publish the previous onion. If both
  run with the previous onion published, tor serves whichever published last, as with two
  installs of one phrase before.
- A wallet with tor and the previous onion runs two onion services and two loopback listeners.
- Nothing public links the onion to the Epicbox or payment-proof address. The previous onion is
  the payment-proof address in onion form, so while it is published, it links the two as before.
- Vectors: `testdata/vectors/keys/onion_key_seed32` and `onion_key_seed16`.

## Alternatives considered

- Keep one key (ADR 0018): no migration, but the Tor and Epicbox identities stay linked.
- A new BIP32 path: ADR 0033 puts no new LEPIC key on a BIP32 path.
- Move the Epicbox and proof addresses instead: stock wallets send to them, and every wallet on
  the phrase drains that mailbox, so they cannot move.
- Sign every proof with the payment-proof key: a slate sent to the onion could then ask for a
  proof to the payment-proof address and link the two.
- Publish the previous onion by default for a period: senders who saved it keep working, but
  the two identities stay linked for that period, which is what this change removes.
