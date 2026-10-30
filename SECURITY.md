# Security policy

## Reporting a vulnerability

Do not open a public issue. Email **support@btlabs.uk**, or open a *confidential* issue on GitLab
(New issue, then tick "Turn on confidentiality"); only the maintainers can see it. The GitHub
repository, [BTLabsUK/lepic](https://github.com/BTLabsUK/lepic), is a read-only mirror: do not
report vulnerabilities there.

Include the affected version or commit, what an attacker controls, what happens, and the smallest
reproduction you have.

## Scope

In scope: anything that can lose or lock funds, leak keys or wallet data, make the wallet accept an
invalid transaction, or crash it from untrusted input (node responses, relay messages, slates, files).

Issues in the Epic Cash node, the reference wallet or the Epicbox relay belong to those projects. If
you find one through LEPIC, report it to them privately and tell us only what we need to protect
LEPIC users.

## Supported versions

LEPIC is pre-1.0. Only the latest release receives fixes.
