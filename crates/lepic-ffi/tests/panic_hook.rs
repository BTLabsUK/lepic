// SPDX-License-Identifier: Apache-2.0
//! The panic hook `RustLib.init()` installs keeps panic messages out of stderr. The hook is
//! process-wide, so the test runs itself again as a child process and reads the child's stderr.

use std::process::Command;

const CHILD: &str = "LEPIC_PANIC_HOOK_CHILD";
const TEST: &str = "the_panic_hook_reports_where_but_not_what";

#[test]
fn the_panic_hook_reports_where_but_not_what() {
    if std::env::var_os(CHILD).is_some() {
        lepic_ffi::api::runtime::init_app();
        let caught = std::panic::catch_unwind(|| panic!("payload-that-must-not-print"));
        assert!(caught.is_err());
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("payload-that-must-not-print"), "{stderr}");
    assert!(stderr.contains("lepic panicked at "), "{stderr}");
    assert!(stderr.contains("panic_hook.rs"), "{stderr}");
}

const EARLIER_TEST: &str = "a_hook_installed_before_is_replaced_not_called";

/// A hook installed before `init_app` would receive the payload too, so it is not called.
#[test]
fn a_hook_installed_before_is_replaced_not_called() {
    if std::env::var_os(CHILD).is_some() {
        std::panic::set_hook(Box::new(|info| {
            eprintln!(
                "earlier hook saw {:?}",
                info.payload().downcast_ref::<&str>()
            );
        }));
        lepic_ffi::api::runtime::init_app();
        let caught = std::panic::catch_unwind(|| panic!("payload-that-must-not-print"));
        assert!(caught.is_err());
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", EARLIER_TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("earlier hook"), "{stderr}");
    assert!(!stderr.contains("payload-that-must-not-print"), "{stderr}");
    assert!(stderr.contains("lepic panicked at "), "{stderr}");
}
