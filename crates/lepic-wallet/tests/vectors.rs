//! Golden vector replays of the engine (docs/rules.md): `cargo xtask vectors verify` runs exactly
//! this target.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

#[path = "receive/harness.rs"]
mod receive_harness;
#[path = "receive/vectors.rs"]
mod receive_vectors;
mod selection_vectors;
mod support;
