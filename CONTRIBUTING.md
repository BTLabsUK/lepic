# Contributing

LEPIC takes contributions under the rules set out on this page.

The source lives at [github.com/BTLabsUK/lepic](https://github.com/BTLabsUK/lepic): open
issues and pull requests there.

## Before you start

1. Read `README.md` and `docs/architecture.md` for goals, non-goals and the crate layout, and
   `docs/rules.md` for the hard rules and the rules for Rust code, compatibility, testing and
   security that every change follows.
2. Find or open the issue for the change on GitHub.
3. Read the ADRs and `docs/compat/` pages that bear on it.

## Making a change

- One change per branch: `<type>/<slug>`, for example `feat/legacy-v3-codec`. A branch named after
  a task id (`feat/s-02-legacy-v3-codec`) needs a `Refs: S-02` footer on its commits.
- Commits follow Conventional Commits with a DCO sign-off (`git commit -s`), as described under
  "Commit messages" below.
- Every commit builds and passes `cargo xtask check`. Run it from a git checkout: its repository
  gates and their tests list files through `git`, so they fail in an unpacked source archive. It
  also reads the `conformance/` and `fuzz/` lockfiles, which needs their dependencies fetched once,
  with network.
- Each commit holds one logical change. Keep formatting, renames and refactors apart from behaviour
  changes, and stage files by name.
- Changes to wire formats, keys, proofs or storage need golden vectors (`docs/compat/`).
- Logging follows `docs/logging.md`: one field vocabulary, and secrets never logged.

## Commit messages

```
<type>(<scope>)[!]: <description>

<body: what changed and why, wrapped at 72 columns>

Refs: <task-id, when the branch names one>
BREAKING CHANGE: <what breaks and how to migrate>
Signed-off-by: Full Name <email>
```

- Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`, `revert`.
- Scopes: `primitives`, `crypto`, `keychain`, `slate`, `contact`, `node`, `store`, `transport`,
  `epicbox`, `wallet`, `telemetry`, `ffi`, `cli`, `xtask`, `conformance`, `fuzz`, `interop`, `deps`,
  `ci`, `docs`, `repo`. Omit the scope only when a change spans the whole repository.
- Description: imperative mood, lowercase first word, no trailing period. The whole subject line is
  at most 72 characters.
- Body: why the change exists and what it affects, including any effect on wire formats, stored
  data or the public API. A breaking change gets `!` after the scope and a `BREAKING CHANGE:` footer.
- Describe the correction, never an attack. No private finding IDs or exploit detail.

## Enabling the local commit-message check

The repository ships a `commit-msg` hook that rejects malformed messages. Enable it once per clone:

```
git config core.hooksPath .githooks
```

Maintainers run the same check before a merge, so a skipped hook only moves the failure later.

## Developer Certificate of Origin

By adding `Signed-off-by` you certify the [DCO 1.1](https://developercertificate.org/): you wrote the
change or have the right to submit it under the project license.
