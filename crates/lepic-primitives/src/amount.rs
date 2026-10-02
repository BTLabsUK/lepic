//! Amounts, fees and heights as distinct types with checked arithmetic.

use thiserror::Error;

use crate::ser::{Readable, Reader, SerError, Writeable, Writer};

/// Base units in one EPIC.
pub const EPIC_BASE: u64 = 100_000_000;

/// Base units in one thousandth of an EPIC, the default base fee per unit of weight.
pub const MILLI_EPIC: u64 = EPIC_BASE / 1_000;

/// Base units in one millionth of an EPIC.
pub const MICRO_EPIC: u64 = MILLI_EPIC / 1_000;

/// An arithmetic result that does not fit the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ArithmeticError {
    #[error("arithmetic overflow")]
    Overflow,
    #[error("arithmetic underflow")]
    Underflow,
}

macro_rules! base_unit_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(u64);

        impl $name {
            pub const ZERO: Self = Self(0);

            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn value(self) -> u64 {
                self.0
            }

            pub fn checked_add(self, other: Self) -> Result<Self, ArithmeticError> {
                self.0
                    .checked_add(other.0)
                    .map(Self)
                    .ok_or(ArithmeticError::Overflow)
            }

            pub fn checked_sub(self, other: Self) -> Result<Self, ArithmeticError> {
                self.0
                    .checked_sub(other.0)
                    .map(Self)
                    .ok_or(ArithmeticError::Underflow)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl Writeable for $name {
            fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
                writer.write_u64(self.0);
            }
        }

        impl Readable for $name {
            fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
                reader.read_u64().map(Self)
            }
        }
    };
}

base_unit_type!(
    /// A quantity of coin in base units.
    Amount
);

base_unit_type!(
    /// A transaction fee in base units.
    Fee
);

impl Fee {
    pub const fn to_amount(self) -> Amount {
        Amount(self.0)
    }
}

/// A block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Height(u64);

impl Height {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub fn checked_add_blocks(self, blocks: u64) -> Result<Self, ArithmeticError> {
        self.0
            .checked_add(blocks)
            .map(Self)
            .ok_or(ArithmeticError::Overflow)
    }

    pub fn checked_sub_blocks(self, blocks: u64) -> Result<Self, ArithmeticError> {
        self.0
            .checked_sub(blocks)
            .map(Self)
            .ok_or(ArithmeticError::Underflow)
    }
}

impl std::fmt::Display for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Writeable for Height {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_u64(self.0);
    }
}

impl Readable for Height {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        reader.read_u64().map(Self)
    }
}
