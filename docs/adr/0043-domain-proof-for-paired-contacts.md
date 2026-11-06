# 0043 Domain proof for paired contacts

Status: accepted
Date: 2026-11-06

Extends RFC 0002 (envelope extension `83`, section 6.3) and 0033 (registry rows).

## Context

A service paired with a wallet is shown by the name it chose. The council of 2026-11-04 (item K6)
asked for a way for a service to show where it runs, and decided under option B that core does no
domain check: the app applies relay moves and any domain verification stays outside core. On
2026-11-06 the owner reversed option B for the domain proof only. Core now carries the proof and
checks it; it still fetches nothing.

## Decision

A contact may claim a domain with a signature, and a host checks the claim against a file the
domain publishes.

Attestation message, signed with Ed25519 by the domain key:

```
"epic-domain/1" || net (1 byte: 00 mainnet, 01 floonet) || sig_key (32) || issued_at (u64 BE, seconds) || domain
```

`sig_key` is the pairing's Ed25519 verifying key, the one in the card.

Extension `83`, in a reply, a confirm and a contact update (the card takes no extensions):
`issued_at (8, u64 BE) || signature (64) || domain (1 to 253 bytes)`. A malformed value reads as
absent and never fails the envelope.

Domain normalization: ASCII only, lowercased, one trailing dot removed. Labels are 1 to 63
characters of `a-z`, `0-9` and `-`, not starting or ending with `-`. At least one dot; 1 to 253
bytes in all.

Domain key: `HKDF-SHA256(salt = "epic-domain/1", ikm = contact root, info = "sign" || net)`, 32
bytes used as an Ed25519 seed, for each account and network.

File at `https://<domain>/.well-known/epic-wallet.json`, at most 4,096 bytes:

```json
{"version":1,"networks":{"mainnet":{"domain_keys":["<hex 32>"]},"floonet":{"domain_keys":["<hex 32>"]}},"relays":["host:port"]}
```

`relays` is optional and informational. At most 8 keys per network. Unknown members are ignored.

`verify(domain, file, claim, sig_key, net)` answers `Proven` when the file parses, the network's
`domain_keys` lists a key whose signature over the message checks, and the claim's domain equals
the domain asked about. Otherwise it answers `Refused` with one of `FileTooLarge`,
`FileMalformed`, `UnsupportedVersion`, `NetworkAbsent`, `DomainMismatch`, `NoKeyMatches`. A file
that lists the key only under the other network is `NetworkAbsent`.

### What core does

Crypto and wire only. It derives the key, signs and parses the claim, and carries it in the three
envelopes. It stores exactly what it received in two nullable contact columns (schema 14,
`peer_domain` and `peer_domain_attestation`, the whole `83` value) and in optional backup fields.
It has no fetch, no timer and no policy. A claim missing from a contact update clears the stored
one. `verify` is a pure function on bytes the host hands it.

### What hosts do

- CLI services derive the key, write the file and attach the claim: `lepic profile domain
  show|file|attach` with the `domain` setting (`LEPIC_DOMAIN`, `--domain`).
- The app fetches `https://<domain>/.well-known/epic-wallet.json` with HTTPS only, no redirects
  and a 4 KiB cap, through its network rules (Tor when on). It calls verify and keeps the status
  `Claimed`, `Proven` or `Refused` itself, rechecking on its own schedule. A fetch that fails
  leaves the status `Claimed`. It shows a proven domain quietly. Its one predicate,
  "domain-backed", is a proven domain or the built-in BT Labs key, and it gates relay-move
  consent.

The pairing state "Verified" keeps its meaning, the short authentication string. The domain
status is host state and is never in core.

## Consequences

- LEPIC b6f5003f and older ignore `83` as an unknown extension above `80` and keep pairing with
  the new version in both directions.
- Schema 13 stores migrate to 14 with null columns, and v1 backups load without the new fields.
- Verification state is never in core, so a restored store carries the claim as received and the
  app checks it again.
- The key is bound to the recovery phrase. A service that restores from its phrase gets the same
  key; a seed change means a new key and a republished file, and contacts see `Refused` until
  then.
- `PairingExtras` gains the claim and is `Clone`, not `Copy`.
- Registry rows in 0033: the derived key and the tag `epic-domain/1`. Vector:
  `pairing/domain.json`.

## Alternatives considered

- A random key kept in a file: another secret to back up, more CLI surface; refused.
- Fetching the file in core: refused by K6; core has no network access beyond its ports, and the
  host owns redirects, Tor and timeouts.
