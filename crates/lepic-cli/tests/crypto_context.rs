// SPDX-License-Identifier: Apache-2.0
//! The first `run` of a process blinds the secp256k1 context. The context is created once per
//! process, so this binary holds only this test.

mod support;

use support::{TestHost, run_in};

#[test]
fn the_first_command_randomizes_the_crypto_context() {
    assert!(!lepic_wallet::crypto_context_is_randomized());
    let outcome = run_in(&TestHost::new(), &["--version"], Vec::new(), "");
    assert_eq!(outcome.code, 0, "{outcome:?}");
    assert!(lepic_wallet::crypto_context_is_randomized());
}
