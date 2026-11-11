// SPDX-License-Identifier: Apache-2.0
//! `Relay`, `Peer` and `Profile`.

use serde::{Deserialize, Serialize};

/// The home relay and the connection to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Relay {}

/// A LEPIC wallet whose native endpoint this wallet pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Peer {
    pub(crate) origin: String,
}

/// What this wallet tells its contacts about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Profile {}
