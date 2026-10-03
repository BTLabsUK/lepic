//! Declares the cfg flutter_rust_bridge's attributes test for, so the compiler accepts it.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(frb_expand)");
}
