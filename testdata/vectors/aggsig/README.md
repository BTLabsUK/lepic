# aggsig vectors

Written by `conformance/vectors/src/primitives/aggsig.rs` (task G-02) from `core/src/libtx/aggsig.rs` of the Epic node at the commit in `upstream`.
Deterministic: all keys and nonces are fixed test values passed in, so `cargo xtask vectors generate
--area aggsig` reproduces the files byte for byte.

Signatures are the 64-byte compact form, public keys the 33-byte compressed form.

## Two-party flow

`two_party_plain` and `two_party_height_locked` follow the call order of `epic-wallet` v4.0.2's
slate code:

1. The sender subtracts the offset from its excess (`sender_excess_split`); that is the key it signs
   with and publishes.
2. The nonce sum and public excess sum are the sums of both parties' public nonces and public
   excesses.
3. Each party signs with `calculate_partial_sig(excess, nonce, nonce_sum, Some(excess_sum),
   kernel_sig_msg)`; the other side checks it with `verify_partial_sig`.
4. `add_signatures(partials, nonce_sum)` gives `final_sig`, checked with `verify_completed_sig`
   against the excess sum.
5. `kernel_excess` is `commit(0, sender_excess_split + receiver_excess)`; as a public key it equals
   the public excess sum. The kernel built from it verifies, and `kernel_serialized_v2` is its
   layout.

`expected.checks` are `aggsig::verify_single` calls with their arguments and result. `kind` is
`partial` (`is_partial = true`, as `verify_partial_sig`) or `completed` (`is_partial = false`, the
rule kernel and participant-message verification apply). `completed` is not upstream's
`verify_completed_sig`, which passes `is_partial = true`; `completed_and_kernel_rules` records
that function. A null `pub_nonce_sum` or
`pubkey_sum` means `None`. The rejected cases cover a partial checked against the wrong key, against
a nonce sum missing the other party's nonce, against another message, and without the true key sum;
a final signature checked against another message or key; a partial passed off as final; and
partials aggregated over the wrong nonce sum.

`expected.commit_checks` are `verify_single_from_commit` calls: the final signature against the
kernel excess, against another message, and against another commitment.

## Single signer

`single_signer_message` signs BLAKE2b-256 of a text with `sign_single(msg, key, Some(nonce),
Some(pubkey))`, as participant messages are signed; the nonce is the `[1; 32]` `epic-wallet` uses
in test-RNG mode. `single_signer_without_pubkey_in_challenge` signs with `None` for the challenge
key. Each file's `checks` verify the signature as signed, and reject another message, another key,
and the other challenge-key choice.

## Completed and kernel rules

`completed_and_kernel_rules` separates the two ways upstream checks a finished signature. Each case
records three verdicts with the public key as both key and challenge key: `partial` from
`verify_partial_sig` against `nonce_sum`, `completed` from upstream's `verify_completed_sig`, which
compares the nonce's X coordinate only, and `kernel` from `verify_single_from_commit` against
`commit(0, key)`, which also requires a square Y, as the node does for kernels.

`share_over_negated_nonce` and `negated_share_over_nonce` are one-party shares from
`calculate_partial_sig` whose nonce sum is the negation of the nonce used. They verify as partials
and pass `completed`, but fail `kernel`. `complete_signature` is `sign_single` with the nonce and
passes all three; `complete_signature_other_message` checks it against another message and fails
all three.
