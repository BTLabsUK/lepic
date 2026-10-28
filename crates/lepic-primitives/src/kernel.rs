// Portions Copyright 2019 The Grin Developers
// Ported from EpicCash/epic core/src/core/transaction.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Transaction kernels, equal in encoding, hash and signature message to the node's `TxKernel`
//! and `KernelFeatures`.

use lepic_crypto::{Commitment, Message, Signature};

use crate::amount::{Fee, Height};
use crate::hash::{DefaultHashable, Hashed};
use crate::ser::{
    ProtocolVersion, Readable, Reader, SerError, SerializationMode, Writeable, Writer,
};

const PLAIN: u8 = 0;
const COINBASE: u8 = 1;
const HEIGHT_LOCKED: u8 = 2;

const INVALID: SerError = SerError::Invalid {
    type_name: "kernel features",
};

/// The kind of a kernel and the values its signature commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelFeatures {
    Plain { fee: Fee },
    Coinbase,
    HeightLocked { fee: Fee, lock_height: Height },
}

impl KernelFeatures {
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Plain { .. } => PLAIN,
            Self::Coinbase => COINBASE,
            Self::HeightLocked { .. } => HEIGHT_LOCKED,
        }
    }

    /// Coinbase kernels carry no fee.
    pub const fn fee(&self) -> Fee {
        match self {
            Self::Plain { fee } | Self::HeightLocked { fee, .. } => *fee,
            Self::Coinbase => Fee::ZERO,
        }
    }

    pub const fn lock_height(&self) -> Option<Height> {
        match self {
            Self::HeightLocked { lock_height, .. } => Some(*lock_height),
            Self::Plain { .. } | Self::Coinbase => None,
        }
    }

    /// The message a kernel's excess signs: BLAKE2b-256 of the feature byte, followed by the fee
    /// and lock height for the variants that have them.
    pub fn signature_message(&self) -> Message {
        let feature = self.as_u8();
        let hash = match self {
            Self::Plain { fee } => (feature, fee.value()).hash(),
            Self::Coinbase => feature.hash(),
            Self::HeightLocked { fee, lock_height } => {
                (feature, fee.value(), lock_height.value()).hash()
            }
        };
        Message::from(*hash.as_bytes())
    }

    // Version 1 writes fee and lock height for every variant, as zero where unused.
    fn write_v1<W: Writer + ?Sized>(&self, writer: &mut W) {
        let (fee, lock_height) = match self {
            Self::Plain { fee } => (*fee, Height::ZERO),
            Self::Coinbase => (Fee::ZERO, Height::ZERO),
            Self::HeightLocked { fee, lock_height } => (*fee, *lock_height),
        };
        writer.write_u8(self.as_u8());
        fee.write(writer);
        lock_height.write(writer);
    }

    fn write_v2<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_u8(self.as_u8());
        match self {
            Self::Plain { fee } => fee.write(writer),
            Self::Coinbase => {}
            Self::HeightLocked { fee, lock_height } => {
                fee.write(writer);
                lock_height.write(writer);
            }
        }
    }

    fn read_v1(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        let feature = reader.read_u8()?;
        let fee = Fee::read(reader)?;
        let lock_height = Height::read(reader)?;
        match feature {
            PLAIN if lock_height == Height::ZERO => Ok(Self::Plain { fee }),
            COINBASE if fee == Fee::ZERO && lock_height == Height::ZERO => Ok(Self::Coinbase),
            HEIGHT_LOCKED => Ok(Self::HeightLocked { fee, lock_height }),
            _ => Err(INVALID),
        }
    }

    fn read_v2(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        match reader.read_u8()? {
            PLAIN => Ok(Self::Plain {
                fee: Fee::read(reader)?,
            }),
            COINBASE => Ok(Self::Coinbase),
            HEIGHT_LOCKED => Ok(Self::HeightLocked {
                fee: Fee::read(reader)?,
                lock_height: Height::read(reader)?,
            }),
            _ => Err(INVALID),
        }
    }
}

// Kernels always hash their version 1 layout, whatever version they are written in.
impl Writeable for KernelFeatures {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        if writer.serialization_mode() == SerializationMode::Hash
            || writer.protocol_version() <= ProtocolVersion::V1
        {
            self.write_v1(writer);
        } else {
            self.write_v2(writer);
        }
    }
}

impl Readable for KernelFeatures {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        if reader.protocol_version() <= ProtocolVersion::V1 {
            Self::read_v1(reader)
        } else {
            Self::read_v2(reader)
        }
    }
}

/// The proof that a transaction balances: its excess commitment and a signature by that excess
/// over the feature message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxKernel {
    pub features: KernelFeatures,
    pub excess: Commitment,
    pub excess_sig: Signature,
}

impl TxKernel {
    pub const fn new(features: KernelFeatures, excess: Commitment, excess_sig: Signature) -> Self {
        Self {
            features,
            excess,
            excess_sig,
        }
    }

    pub fn signature_message(&self) -> Message {
        self.features.signature_message()
    }

    pub const fn is_coinbase(&self) -> bool {
        matches!(self.features, KernelFeatures::Coinbase)
    }
}

impl Writeable for TxKernel {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.features.write(writer);
        self.excess.write(writer);
        self.excess_sig.write(writer);
    }
}

impl Readable for TxKernel {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        Ok(Self {
            features: KernelFeatures::read(reader)?,
            excess: Commitment::read(reader)?,
            excess_sig: Signature::read(reader)?,
        })
    }
}

impl DefaultHashable for TxKernel {}
