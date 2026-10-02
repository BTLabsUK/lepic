//! Transaction outputs, equal in encoding and hash to the node's `Output`, `OutputFeatures` and
//! `OutputIdentifier`.

use lepic_crypto::{Commitment, RangeProof};

use crate::hash::DefaultHashable;
use crate::ser::{Readable, Reader, SerError, SerializationMode, Writeable, Writer};

/// Whether an output is an ordinary payment or a block reward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputFeatures {
    Plain,
    Coinbase,
}

impl OutputFeatures {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Plain => 0,
            Self::Coinbase => 1,
        }
    }

    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Plain),
            1 => Some(Self::Coinbase),
            _ => None,
        }
    }

    pub const fn is_coinbase(self) -> bool {
        matches!(self, Self::Coinbase)
    }
}

impl Writeable for OutputFeatures {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_u8(self.as_u8());
    }
}

impl Readable for OutputFeatures {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        Self::from_u8(reader.read_u8()?).ok_or(SerError::Invalid {
            type_name: "output features",
        })
    }
}

/// A new coin: its features, its commitment and the range proof for that commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub features: OutputFeatures,
    pub commitment: Commitment,
    pub proof: RangeProof,
}

impl Output {
    pub fn new(features: OutputFeatures, commitment: Commitment, proof: RangeProof) -> Self {
        Self {
            features,
            commitment,
            proof,
        }
    }

    pub fn identifier(&self) -> OutputIdentifier {
        OutputIdentifier::new(self.features, self.commitment)
    }

    pub fn is_coinbase(&self) -> bool {
        self.features.is_coinbase()
    }
}

// The hash covers features and commitment only; the proof is committed to separately.
impl Writeable for Output {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.features.write(writer);
        self.commitment.write(writer);
        if writer.serialization_mode() != SerializationMode::Hash {
            self.proof.write(writer);
        }
    }
}

impl Readable for Output {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        Ok(Self {
            features: OutputFeatures::read(reader)?,
            commitment: Commitment::read(reader)?,
            proof: RangeProof::read(reader)?,
        })
    }
}

impl DefaultHashable for Output {}

/// What identifies an unspent output: features and commitment. Its hash equals the hash of the
/// matching [`Output`] and of an input that spends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutputIdentifier {
    pub features: OutputFeatures,
    pub commitment: Commitment,
}

impl OutputIdentifier {
    pub const fn new(features: OutputFeatures, commitment: Commitment) -> Self {
        Self {
            features,
            commitment,
        }
    }
}

impl Writeable for OutputIdentifier {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.features.write(writer);
        self.commitment.write(writer);
    }
}

impl Readable for OutputIdentifier {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        Ok(Self {
            features: OutputFeatures::read(reader)?,
            commitment: Commitment::read(reader)?,
        })
    }
}

impl DefaultHashable for OutputIdentifier {}
