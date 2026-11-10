# Follow-ups

Planned work that is decided but not built yet. Each row says what the code should do and when it
is built. A row leaves this page in the change that builds it.

## Pins and the direct client

| Planned behaviour | Built with |
|---|---|
| Accepting a changed peer key pins the key the user was shown (`accept_peer_key(origin, shown_key)`); if the listener now shows another key, the wallet asks again | The pin work |
| A legacy send to a pinned origin checks the pin as a native send does, and the changed-key error no longer suggests a legacy retry | The pin work |
| Pins stay per account (ADR 0052); the app may show them wallet-wide | The pin work, if the app asks |
| One canonical origin form: IPv6 literals in canonical text, and the default port applied the same way when parsing and when sending | The single relay and host type (ADR 0054) |
| The direct reply cache is keyed by slate id and stage and bounded per peer, so an honest retry that re-seals gets the stored answer | Direct protocol 2 |
| The advert lists every protocol the listener serves | Direct protocol 2 |

## Mailboxes and in-person codes

| Planned behaviour | Built with |
|---|---|
| The epic1 refusal store keeps the newest refusal per slate and reports when it is full | Native state tables |
| A mailbox drain rotates its order between cycles and reports a mailbox it could not empty | ADR 0054's carrier interface |
| In person: both colliding answers are flagged, and `closed` is documented as built | In-person app work |
| In person: a code's reply mailbox is drained directly, and drain failures reach the app | In-person app work |
| In person: the app can read back open codes and stored answers after a restart | In-person app work |
| In person: answers kept per code are bounded by distinct answer keys, oldest dropped first | In-person app work |
| RFC 0003 6.7 and Appendix A name the answering party's public excess | Next RFC 0003 edit |

## Native state and checks

| Planned behaviour | Built with |
|---|---|
| Native protocol state (links, payments, answers, in-person codes, refusals, index counters) in real tables with a schema version and expiry, in place of JSON rows under setting prefixes | The next schema version, before ADR 0054 code |
| A CI check freezes the vectors of every key label that a release has issued (a `frozen` column in the ADR 0033 table) | The first release that ships numbered epic1 addresses |
| A `kind()` on every engine error, mapped once for the CLI and the FFI | When the engine error enums next change shape |
| FFI `epic1_pay` takes a caller-chosen `slate_id`, as the wallet API does | When the app retries payments |
| Per-route scopes for TLS clients of the wallet API, beyond the socket-only routes | The API scopes work |
| `NativeV1Codec` is removed (unused) | The next clean-up |
