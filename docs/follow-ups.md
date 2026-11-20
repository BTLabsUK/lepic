# Follow-ups

Planned work that is decided but not built yet. Each row says what the code should do and when it
is built. A row leaves this page in the change that builds it.

## Mailboxes and in-person codes

| Planned behaviour | Built with |
|---|---|
| The epic1 refusal store keeps the newest refusal per slate and reports when it is full | Native state tables |
| In person: both colliding answers are flagged, and `closed` is documented as built | In-person app work |
| In person: a code's reply mailbox is read directly, and read failures reach the app | In-person app work |
| In person: the app can read back open codes and stored answers after a restart | In-person app work |
| In person: answers kept per code are bounded by distinct answer keys, oldest dropped first | In-person app work |
| RFC 0003 6.7 and Appendix A name the answering party's public excess | Next RFC 0003 edit |

## Native state and checks

| Planned behaviour | Built with |
|---|---|
| Native protocol state (links, payments, answers, in-person codes, refusals, index counters) in real tables with a schema version and expiry, in place of JSON rows under setting prefixes | The next schema version |
| A CI check freezes the vectors of every key label that a release has issued (a `frozen` column in the ADR 0033 table) | The first release that ships numbered epic1 addresses |
| A `kind()` on every engine error, mapped once for the CLI and the FFI | When the engine error enums next change shape |
| FFI `epic1_pay` takes a caller-chosen `slate_id`, as the wallet API does | When the app retries payments |
| Per-route scopes for TLS clients of the wallet API, beyond the socket-only routes | The API scopes work |
