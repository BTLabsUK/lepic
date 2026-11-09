# ADR 0043: Domain proof for paired contacts

Status: accepted

## Context

A service paired with a wallet is shown by the name it chose, which the service picks freely. A
service needs a way to show where it runs, so that the app can show a name tied to a domain. The
proof is a signature that a host checks against a file the domain publishes. Core carries and
checks the signature, and fetches nothing. The app applies relay moves (ADR 0039), and the domain
verification and its policy stay outside core.

## Decision

A contact may claim a domain with a signature. A host checks the claim against a file the domain
publishes.

### The attestation

The domain key signs this message with Ed25519:

```
"epic-domain/1" || net (1 byte: 00 mainnet, 01 floonet) || sig_key (32) || issued_at (u64 BE, seconds) || domain
```

`sig_key` is the pairing's Ed25519 verifying key, the one in the card. The claim is therefore
bound to one network and one pairing.

Extension `0x83` carries it in a reply, a confirm and a contact update; the card takes no
extensions. The value is `issued_at (8) || signature (64) || domain (1 to 253 bytes)`. A malformed
value reads as absent and never fails the envelope. RFC 0002 6.3 describes the extension.

### The domain name

ASCII only, lowercased, one trailing dot removed. Labels are 1 to 63 characters of `a-z`, `0-9`
and `-`, not starting or ending with `-`. At least one dot, 1 to 253 bytes in all
(`DomainName::new` in `lepic-seal/src/domain.rs`).

### The domain key

`HKDF-SHA256(salt = "epic-domain/1", ikm = contact root, info = "sign" || net)` gives 32 bytes
used as an Ed25519 seed (`lepic-wallet-contacts/src/key_schedule.rs`). The key is bound to the
recovery phrase: a wallet restored from its phrase has the same key.

### The well-known file

A domain serves the file at `https://<domain>/.well-known/epic-wallet.json`, at most 4,096 bytes
(`DOMAIN_FILE_MAX`):

```json
{"version":1,"networks":{"mainnet":{"domain_keys":["<hex 32>"]},"floonet":{"domain_keys":["<hex 32>"]}},"relays":["host:port"]}
```

`relays` is optional and informational. A network lists at most 8 keys. Unknown members are
ignored.

### Verification

`verify(domain, file, claim, sig_key, network)` in `lepic-wallet-contacts/src/domain.rs` answers
`Proven` when the file parses, lists keys for the network, the claim names `domain`, and one listed
key signed the claim. Otherwise it answers `Refused` with `FileTooLarge`, `FileMalformed`,
`UnsupportedVersion`, `NetworkAbsent`, `DomainMismatch` or `NoKeyMatches`. A file that lists the
key only under the other network is `NetworkAbsent`.

### What core does

Core does crypto and wire. It derives the key, signs and parses the claim, and carries it in the
three envelopes. It stores what it received in two nullable contact columns (`peer_domain` and
`peer_domain_attestation`, the whole `0x83` value) and in optional backup fields. It has no
fetch, no timer and no policy. An envelope that carries no claim replaces the stored claim with
none. `verify` is a pure function on bytes the host hands it.

### What hosts do

- A CLI service derives the key, writes the file and attaches the claim: `lepic profile domain
  show|file|attach` with the `domain` setting (`LEPIC_DOMAIN`, `--domain`). Pairings made while
  `domain` is set carry the claim by themselves; `attach` is for earlier pairings.
- An app fetches the file over HTTPS only, without redirects and with a 4 KiB cap, through its own
  network rules. It calls `verify` and keeps the status `Claimed`, `Proven` or `Refused`, checking
  again on its own schedule. A fetch that fails leaves the status `Claimed`.

The pairing state "Verified" keeps its meaning, the short authentication string. The domain status
is host state and is never in core.

## Consequences

- A build that does not know `0x83` ignores it as an unknown extension above `0x80` and keeps
  pairing in both directions.
- Verification state is never in core, so a restored store carries the claim as received and the
  app checks it again.
- A service that changes its seed gets a new key and republishes the file; contacts see `Refused`
  until then.
- `PairingExtras` carries the claim and is `Clone`, not `Copy`.
- The vector file is `pairing/domain.json`.

## Alternatives considered

- A random key kept in a file: another secret to back up and more CLI surface.
- Fetching the file in core: core has no network access beyond its ports, and the host owns
  redirects, Tor and timeouts.

## Related

- ADR 0033: key and domain registry, the derived key and the tag `epic-domain/1`.
- RFC 0002: contact pairing.
