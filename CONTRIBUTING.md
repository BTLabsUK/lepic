# Contributing

LEPIC takes contributions under the rules below.

## Before you start

1. Read `README.md` and `docs/architecture.md` for goals, non-goals and the crate layout.
2. Open an issue or pick an open one.
3. Read the ADRs and `docs/compat/` pages the task names.

## Making a change

- One task per branch: `<type>/<task-id>-<slug>`, for example `feat/s-02-legacy-v3-codec`.
- Commits follow Conventional Commits with a `Refs: <task-id>` footer and a DCO sign-off
  (`git commit -s`). The full rules are in `CONTRIBUTING.md`.
- Every commit builds and passes `cargo xtask check`. Run it from a git checkout: its repository
  gates and their tests list files through `git`, so they fail in an unpacked source archive. It
  also reads the `conformance/` and `fuzz/` lockfiles, which needs their dependencies fetched once,
  with network.
- Changes to wire formats, keys, proofs or storage need golden vectors (`docs/rules.md`).

## Enabling the local commit-message check

The repository ships a `commit-msg` hook that rejects malformed messages. Enable it once per clone:

```
git config core.hooksPath .githooks
```

CI runs the same check, so a skipped hook only moves the failure later.

## Developer Certificate of Origin

By adding `Signed-off-by` you certify the [DCO 1.1](https://developercertificate.org/): you wrote the
change or have the right to submit it under the project license.
