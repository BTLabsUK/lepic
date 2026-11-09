# Contributing

LEPIC takes contributions from people and AI tools under the same rules. Open issues and pull
requests at [github.com/BTLabsUK/lepic](https://github.com/BTLabsUK/lepic).

## Before you start

1. Read `README.md` and [docs/architecture.md](docs/architecture.md) for the goals, non-goals and
   crate layout.
2. Read [docs/rules.md](docs/rules.md). It holds the rules for Rust code, compatibility, testing
   and security that every change follows.
3. Read the ADRs in `docs/adr/` and the notes in `docs/compat/` that bear on the change.
4. Find or open the issue for the change.

## Making a change

- One change per branch. Name it `<type>/<slug>`, for example `feat/legacy-v3-codec`. A branch
  named `<type>/<letter>-<two digits>-<slug>`, for example `feat/s-02-legacy-v3-codec`, makes the
  hook require a `Refs: S-02` footer on every commit.
- One logical change per commit. Keep formatting, renames and refactors apart from behaviour
  changes, and stage files by name.
- Every commit builds and passes `cargo xtask check`.
- A change to a wire format, key, proof or storage layout comes with golden vectors. See
  [docs/compat/](docs/compat/) and [testdata/vectors/README.md](testdata/vectors/README.md).
- Logging follows [docs/logging.md](docs/logging.md): one field vocabulary, and secrets are never
  logged.

## The check

`cargo xtask check` is the gate. It runs, in order:

1. `cargo fmt --check`
2. `cargo clippy` over the workspace with `-D warnings`, and over `lepic-ffi` without default
   features
3. `cargo test --workspace --locked`
4. `cargo deny check`
5. the xtask gates `deps-check`, `ci-lint`, `repo-lint`, `lockfiles`, `vectors verify` and
   `no-legacy`

It stops at the first failing step. It needs `cargo-deny` installed.

- Run it from a git checkout. The repository gates list files through `git`, so they fail in an
  unpacked source archive.
- The `lockfiles` gate runs `cargo fetch --locked` for `conformance/`, `fuzz/` and
  `interop/probe/`, so the first run needs network access. A change to a product dependency must
  update those lockfiles in the same commit.

`.github/workflows/ci.yml` runs `cargo xtask check`, the fuzz targets' build
(`cargo xtask fuzz --build`), `actionlint` with `cargo xtask ci-lint`, and `cargo test --locked`
in `conformance/`. The conformance workspace builds the reference node and wallet, which need
CMake, a C++ compiler, libclang and the OpenSSL headers. `.github/workflows/mobile.yml` builds the
mobile libraries. The scenarios in `interop/` run against live nodes and wallets, outside CI.
See [interop/README.md](interop/README.md).

## Commit messages

```text
<type>(<scope>)[!]: <description>

<body: what the change does and why, wrapped at 72 columns>

Refs: <task id, when the branch name has one>
BREAKING CHANGE: <what breaks and how to migrate>
Signed-off-by: Full Name <name@example.com>
```

- Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`, `revert`.
- Scopes: `primitives`, `crypto`, `keychain`, `slate`, `seal`, `contact`, `node`, `store`,
  `transport`, `methods`, `epicbox`, `wallet`, `telemetry`, `ffi`, `cli`, `xtask`, `conformance`,
  `fuzz`, `interop`, `deps`, `ci`, `docs`, `repo`. Leave the scope out only when a change spans
  the whole repository.
- Description: imperative mood, first word lowercase, no trailing period. The subject line is at
  most 72 characters.
- Body: separated from the subject by a blank line. Say why the change exists and what it
  affects, including any effect on wire formats, stored data or the public API. Lines wrap at 72
  characters; lines with a URL are exempt.
- A breaking change has `!` after the scope and a `BREAKING CHANGE:` footer.
- Describe the correction, never an attack. Leave out private finding ids and exploit detail.
- `fixup!`, `squash!` and `amend!` subjects pass the local hook so a branch can be reworked. The
  pull request check refuses them, so squash them before review.

## The commit-message hook

`.githooks/commit-msg` enforces these rules. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

`.github/workflows/commit-lint.yml` runs the same script on the pull request title and on each
commit. It takes the script from the base branch, so a pull request cannot relax the rules it is
checked against. A commit by Dependabot or `github-actions[bot]` in a pull request opened by that
bot is skipped.

## Developer Certificate of Origin

`Signed-off-by` certifies the [DCO 1.1](https://developercertificate.org/): you wrote the change or
have the right to submit it under the project license. Add it with `git commit -s`.
