# Security policy

Report a vulnerability by email to **support@btlabs.uk**. Do not open a public issue or a pull
request in [BTLabsUK/lepic](https://github.com/BTLabsUK/lepic) for it.

## What to include

- The affected version or commit.
- What the attacker controls.
- What happens as a result.
- The smallest reproduction you have.

## Scope

In scope: anything in LEPIC that can

- lose or lock funds,
- leak keys or wallet data,
- make the wallet accept an invalid transaction, or
- crash it from untrusted input: node answers, relay messages, slates and files.

A problem in the Epic Cash node, the reference wallet or the Epicbox relay belongs to those
projects. If you find one through LEPIC, report it to them privately. Tell BT Labs only what is
needed to protect LEPIC users.

## Supported versions

LEPIC is pre-1.0. Only the latest release receives fixes.
