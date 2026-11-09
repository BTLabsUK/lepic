# ADR 0044: The onion has its own key

Status: accepted

## Context

A wallet that receives over Tor needs an onion address. The `epic-wallet` onion is the payment-proof
address in onion form: the Ed25519 key whose seed is the address secret of `m/0/1/0`, the key that
also gives the Epicbox address. One public value, the onion, then names the wallet's Tor, Epicbox and
payment-proof identities together.

LEPIC wants a Tor identity that gives neither of the others away, a restore from the phrase that
returns every address the wallet answers at, and Epicbox and proof addresses where other wallets
expect them. Senders may have saved the payment-proof onion in a GUI wallet's contacts, in
`epic-wallet`, or in another LEPIC wallet.

## Decision

### The onion key

The onion key is a LEPIC namespace key (ADR 0033): the keyed BLAKE2b-256 of the seed over the label
`lepic-wallet onion key v1`, with no context (`namespace::ONION_KEY_LABEL`). The 32 bytes are the
Ed25519 seed. It is on no BIP32 path. `lepic-tor` expands the seed into the form tor takes (ADR
0018).

`Wallet::onion_key` returns it as an `OnionKey`: the seed, wiped on drop and never printed, and the
public key. `lepic tor address`, the binding's `onion_address`, `lepic tor listen` and `start_tor`
use it.

The Epicbox address and the payment-proof address are at `m/0/1/0`, as in `epic-wallet`.

### The key of a proof

`ReceiveRequest.proof_key` names the key that signs a payment proof the slate asks for:

- `Payments`, the default: the payment-proof key. For Epicbox, HTTP, files and the previous onion.
- `Onion`: the onion key. For a slate that came to the onion.
- `Epic1`: the epic1 proof key of the receiving account (ADR 0052). For a slate that came to the
  account's epic1 address.

A proof whose receiver address is not that key's public key is refused with
`ReceiveError::ForeignProofAddress`. A slate sent to the onion that asks for a proof to the
payment-proof address is refused, so the sender learns nothing that links the two. The wallet's own
proof address as a sender is the payment-proof key. The CLI's onion listener and the binding's onion
listener use `Onion`.

### The previous onion

The payment-proof address in onion form, which `epic-wallet address` prints, is the previous onion.
It stays available as a key:

- `Wallet::previous_onion_key` returns the address key of account `m/0/0`, index 0, as the seed and
  the payment-proof public key.
- `lepic tor address --previous` and the binding's `previous_onion_address` show its onion.

Publishing it is a host choice (ADR 0036), off unless the host asks:

- The binding's `HostPolicy::publish_previous_onion` is false by default. When true, `start_tor`
  with `publish_onion` adds the previous onion once the onion is published. It has a listener of its
  own (socket `previous-onion.sock`, `PREVIOUS_ONION_SOCKET`) whose proofs use `Payments`. It goes
  away at `stop_tor`. The event stream reports only the onion; a previous onion that cannot be added
  is logged.
- `lepic tor listen --previous-onion` does the same in the CLI. Without it only the onion is
  published.

A host that leaves the previous onion off keeps the Tor and Epicbox identities apart.

### Vectors

`testdata/vectors/keys/onion_key_seed32.json` and `onion_key_seed16.json` pin the key.

## Consequences

- A wallet shows its onion address, which differs from `epic-wallet`'s for the same phrase. A sender
  that saved the payment-proof onion reaches the wallet only while the host publishes the previous
  onion, and its proofs verify then.
- A restore from the phrase gives the same onion and the same previous onion.
- Pairing carries relay onions only (RFC 0002), so no contact record holds the wallet's own onion.
  Onion contacts imported from GUI profiles name other wallets' onions.
- The GUI wallet or `epic-wallet` on the same phrase publishes the previous onion. If a LEPIC host
  publishes it too, tor serves whichever published last, as with two installs of one phrase.
- A wallet with tor and the previous onion runs two onion services and two loopback listeners.
- While the previous onion is published it is the payment-proof address in onion form, so it links
  the Tor and payment-proof identities. The onion links to neither.

## Alternatives considered

- One key (ADR 0018): no migration, and the Tor and Epicbox identities stay linked.
- A new BIP32 path: ADR 0033 puts no LEPIC key on a BIP32 path.
- Move the Epicbox and proof addresses instead: other wallets send to them, and every wallet on the
  phrase drains that mailbox, so they cannot move.
- Sign every proof with the payment-proof key: a slate sent to the onion could then ask for a proof
  to the payment-proof address and link the two.
- Publish the previous onion by default: saved addresses keep working, and the identities stay
  linked.

## Related

- ADR 0018: Tor through a bundled tor child process.
- ADR 0033: keys and domains.
- ADR 0036: host policy.
