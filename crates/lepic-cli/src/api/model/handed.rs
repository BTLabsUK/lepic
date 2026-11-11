// SPDX-License-Identifier: Apache-2.0
//! `Inspection` and `OpenResult`: anything a user is handed, read and acted on.

use serde::{Deserialize, Serialize};

/// What a text, file or QR code is, and what opening it would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Inspection {}

/// What opening it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OpenResult {}
