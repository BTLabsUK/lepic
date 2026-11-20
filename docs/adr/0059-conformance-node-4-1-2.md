# ADR 0059: Conformance and vectors on epic v4.1.2

Status: accepted
Date: 2026-11-14

## Context

ADR 0038 moved the interop stacks and `upstream.toml` to `epic` `v4.1.2` and left the conformance
workspace and the golden vectors on `v4.1.0`, because `epic-wallet` `v4.1.0`, the latest wallet
release, asks for the node crates at `v4.1.0` and a second spelling would build two copies.

That left LEPIC's reference code one node release behind the network. Between `v4.1.0`
(`82fa7e81`) and `v4.1.2` (`bd3a8c8c`) the crates the reference wallet links change as follows:
`core`, `keychain` and `util` only in their version numbers; `api` in its auth, router and mining
handlers; `chain` in header validation (`pipe.rs`) and `chain.rs`; `p2p` in peer handling.
None of these is a path LEPIC ports.

## Decision

- The conformance workspace links `epic` `v4.1.2` at `bd3a8c8c5e957e57574364326dfb17051d0096ae`
  and `epic-wallet` `v4.1.0` at `845b3fcf4df12ed0139929c62157015447a9d063`.
- `epic-wallet`'s own node dependencies are moved to the same `v4.1.2` copy with
  `[patch."https://github.com/EpicCash/epic"]`. Cargo refuses a patch whose source equals the
  patched one, and it treats `github.com/EpicCash/epic` with or without `.git` or a trailing slash
  as one source, so the node crates come from `https://www.github.com/EpicCash/epic`, which
  GitHub serves as the same repository. The workspace links one copy of each node crate.
- The vectors record the repository as `https://github.com/EpicCash/epic`; the generator drops the
  `www.` when it reads the lockfile.
- The golden vectors are regenerated with `cargo xtask vectors generate`. Against `v4.1.0` they
  differ only in the recorded node commit and in the node's user agent (`MW/Epic 4.1.2`) that the
  engine vectors capture from the reference node.

This supersedes the conformance line of ADR 0038 and the node row of ADR 0020's table.

## Consequences

- Conformance, vectors, interop and `upstream.toml` all name the node release the network runs.
- The `www.github.com` spelling depends on GitHub keeping that host as an alias. If it stops, the
  conformance build fails at fetch, visibly; the fix is any other spelling Cargo does not
  canonicalise to `github.com/EpicCash/epic` (a mirror, or an `ssh://` URL).
- When `epic-wallet` publishes a release that asks for the current node tag, the patch goes and
  the workspace dependencies return to the plain spelling.
- An upstream watch compares EpicCash tags and branches with these pins.

## Alternatives considered

- Stay on `v4.1.0` (ADR 0038): the reference code lags the network for no gain.
- Two copies of the node crates: the reference wallet's types and the workspace's would not
  unify, and the vectors would come from a mix.
- Vendor the node crates: a copy of upstream to maintain for a version-number change.

## Related

- ADR 0009: conformance workspace.
- ADR 0020: reference wallet and node.
- ADR 0038: interop node at `epic` `v4.1.2`.
