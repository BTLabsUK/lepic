// SPDX-License-Identifier: Apache-2.0
//! The pairing code of an invite and the invite id derived from it (RFC 0002 7.1). The id is the
//! hint of a pairing reply, so it lives with the envelope.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::{first8, sha256};

const ID_DOMAIN: &[u8] = b"epic-pair/1 id";

/// The secret code of an invite. Wiped on drop and never printed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingCode([u8; 16]);

impl PairingCode {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn expose_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

/// `H("epic-pair/1 id" || code)[0..8]`: names an invite and is the hint of its replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InviteId([u8; 8]);

impl InviteId {
    pub fn from_code(code: &PairingCode) -> Self {
        Self(first8(&sha256(&[ID_DOMAIN, code.expose_bytes()])))
    }

    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}
