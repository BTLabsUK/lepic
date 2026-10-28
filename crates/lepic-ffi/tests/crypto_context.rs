// SPDX-License-Identifier: Apache-2.0
//! `RustLib.init()` blinds the secp256k1 context. The context is created once per process, so
//! this binary holds only this test.

#[test]
fn init_app_randomizes_the_crypto_context() {
    assert!(!lepic_wallet::crypto_context_is_randomized());
    lepic_ffi::api::runtime::init_app();
    assert!(lepic_wallet::crypto_context_is_randomized());
}
