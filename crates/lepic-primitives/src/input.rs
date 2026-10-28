// Portions Copyright 2019 The Grin Developers
// Ported from EpicCash/epic core/src/core/transaction.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Transaction inputs, equal in encoding and hash to the node's `Input`.

use lepic_crypto::Commitment;

use crate::hash::DefaultHashable;
use crate::output::{OutputFeatures, OutputIdentifier};
use crate::ser::{Readable, Reader, SerError, Writeable, Writer};

/// A reference to the output being spent: its features and commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Input {
    pub features: OutputFeatures,
    pub commitment: Commitment,
}

impl Input {
    pub const fn new(features: OutputFeatures, commitment: Commitment) -> Self {
        Self {
            features,
            commitment,
        }
    }

    pub const fn is_coinbase(&self) -> bool {
        self.features.is_coinbase()
    }

    pub const fn identifier(&self) -> OutputIdentifier {
        OutputIdentifier::new(self.features, self.commitment)
    }
}

impl From<OutputIdentifier> for Input {
    fn from(identifier: OutputIdentifier) -> Self {
        Self::new(identifier.features, identifier.commitment)
    }
}

impl Writeable for Input {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.features.write(writer);
        self.commitment.write(writer);
    }
}

impl Readable for Input {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        Ok(Self {
            features: OutputFeatures::read(reader)?,
            commitment: Commitment::read(reader)?,
        })
    }
}

impl DefaultHashable for Input {}
