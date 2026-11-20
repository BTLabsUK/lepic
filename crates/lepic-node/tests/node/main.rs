// SPDX-License-Identifier: Apache-2.0
//! The integration tests of `lepic-node`, built as one test binary: every file below was once a
//! binary of its own, and each of those linked the whole crate again. Run one former file by
//! its module name, `cargo nextest run -p lepic-node -E 'test(/^<module>::/)'`.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in the
// shared helpers that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;

mod decode;
mod fixtures;
mod header;
mod http;
mod live;
mod mock;
mod plausibility;
