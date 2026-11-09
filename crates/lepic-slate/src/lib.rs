// SPDX-License-Identifier: Apache-2.0
//! Slate domain model, the codec trait and the codec registry. The legacy JSON codecs live in
//! `lepic-legacy-slate` (ADR 0052).

pub mod codec;
pub mod error;
pub mod model;
pub mod origin;
pub mod registry;
pub mod role;
pub mod stage;
pub mod ur_slate;
pub mod validate;
