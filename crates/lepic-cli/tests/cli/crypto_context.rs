// SPDX-License-Identifier: Apache-2.0
//! The first `run` of a process blinds the secp256k1 context. The context is created once per
//! process, and the other tests of this binary run commands too, so the check runs in a child
//! process that runs this test alone.

use std::process::Command;

use crate::support;
use support::{TestHost, run_in};

const CHILD: &str = "LEPIC_TEST_CRYPTO_CONTEXT_CHILD";

#[test]
fn the_first_command_randomizes_the_crypto_context() {
    if std::env::var_os(CHILD).is_none() {
        let name = concat!(
            module_path!(),
            "::the_first_command_randomizes_the_crypto_context"
        );
        // `module_path!()` starts with the test crate's name; the test filter does not.
        let name = name.split_once("::").map_or(name, |(_, rest)| rest);
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}");
        assert!(
            stdout.contains("1 passed"),
            "the child ran no test: {stdout}"
        );
        return;
    }
    assert!(!lepic_wallet::crypto_context_is_randomized());
    let outcome = run_in(&TestHost::new(), &["--version"], Vec::new(), "");
    assert_eq!(outcome.code, 0, "{outcome:?}");
    assert!(lepic_wallet::crypto_context_is_randomized());
}
