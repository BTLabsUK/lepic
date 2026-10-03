# 0015 The file method writes V3; Epicbox stays V2

Status: accepted
Date: 2026-10-03
Supersedes: the file row of the policy table in ADR 0003. The rest of ADR 0003 stands.

## Context

`epic-wallet` `v4.0.2` writes a slate file in the V3 shape only when the slate carries a TTL or a
payment proof, and in the V2 shape otherwise. Its Epicbox sender always uses the V2 shape. The
operator chose one fixed version per method for LEPIC: V2 over Epicbox, V3 in files. Other versions
come later through new codecs.

`epic-wallet` reads both V2 and V3 files (its file path accepts header version 2 or 3), so a V3 file
from LEPIC is accepted, and LEPIC accepts the V2 or V3 file an `epic-wallet` peer writes back.

## Decision

| Transport | Accepts | New slate | Reply |
|---|---|---|---|
| Epicbox | V2 and V3 shapes | V2 shape | shape of the inbound slate, header echoed |
| File | V2 and V3 | V3, header `3/3/<b>` | V3, header `3/3/<b>` |

## Consequences

- LEPIC's file output no longer matches `epic-wallet`'s bytes for slates without TTL or payment
  proof. Compatibility is shown by the differential and interop suites (`epic-wallet` reads every
  LEPIC file and LEPIC finalizes every reply), not by byte equality with upstream's V2 files.
- Payment proofs and TTL can travel in files; over Epicbox they still return `Unrepresentable`.
