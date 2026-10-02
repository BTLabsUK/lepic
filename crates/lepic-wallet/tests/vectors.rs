//! Golden vector replay for the engine (`testdata/vectors/engine`).

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

mod selection_vectors;
