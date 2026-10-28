// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2018 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic core/src/ser.rs (Apache-2.0); see NOTICE and upstream.toml.

//! Big-endian binary serialization, byte-compatible with the Epic node's `core::ser`.
//!
//! Reading works on a byte slice and never allocates more than a caller-supplied maximum, so a
//! decoder fed hostile input does bounded work and returns a [`SerError`] instead of panicking.

use thiserror::Error;

/// Largest single byte read, matching the node's `BinReader`, which refuses longer reads.
pub const MAX_READ_LEN: usize = 100_000;

/// Largest item count [`Reader::read_multi`] accepts, matching the node's `read_multi`.
pub const MAX_MULTI_COUNT: usize = 1_000_000;

/// Failure to decode a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SerError {
    #[error("input truncated: needed {needed} bytes, {available} available")]
    Truncated { needed: usize, available: usize },
    #[error("length {len} exceeds the maximum {max}")]
    TooLarge { len: u64, max: usize },
    #[error("{remaining} trailing bytes after the value")]
    TrailingBytes { remaining: usize },
    #[error("unexpected byte {found:#04x}, expected {expected:#04x}")]
    UnexpectedByte { expected: u8, found: u8 },
    #[error("invalid encoding of {type_name}")]
    Invalid { type_name: &'static str },
    #[error("items are not sorted by hash")]
    NotSorted,
    #[error("items contain a duplicate hash")]
    Duplicate,
}

/// Serialization protocol version. Some types, kernels in particular, encode differently per
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    pub const V1: Self = Self(1);
    pub const V2: Self = Self(2);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Whether a writer needs the full encoding or only the part that defines the value's hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationMode {
    Full,
    Hash,
}

/// Sink for encoded values. Integers are written big-endian.
pub trait Writer {
    fn serialization_mode(&self) -> SerializationMode;

    fn protocol_version(&self) -> ProtocolVersion;

    fn write_fixed_bytes(&mut self, bytes: &[u8]);

    fn write_u8(&mut self, n: u8) {
        self.write_fixed_bytes(&[n]);
    }

    fn write_u16(&mut self, n: u16) {
        self.write_fixed_bytes(&n.to_be_bytes());
    }

    fn write_u32(&mut self, n: u32) {
        self.write_fixed_bytes(&n.to_be_bytes());
    }

    fn write_i32(&mut self, n: i32) {
        self.write_fixed_bytes(&n.to_be_bytes());
    }

    fn write_u64(&mut self, n: u64) {
        self.write_fixed_bytes(&n.to_be_bytes());
    }

    fn write_i64(&mut self, n: i64) {
        self.write_fixed_bytes(&n.to_be_bytes());
    }

    /// Writes the bytes after a `u64` length prefix.
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u64(bytes.len() as u64);
        self.write_fixed_bytes(bytes);
    }
}

/// A value with a binary encoding. Encoding cannot fail: every value of a type is encodable.
pub trait Writeable {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W);
}

/// A value that can be decoded from untrusted bytes.
pub trait Readable: Sized {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError>;
}

/// Writer that collects the full encoding in memory.
#[derive(Debug, Clone)]
pub struct VecWriter {
    bytes: Vec<u8>,
    version: ProtocolVersion,
}

impl VecWriter {
    pub fn new(version: ProtocolVersion) -> Self {
        Self {
            bytes: Vec::new(),
            version,
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Writer for VecWriter {
    fn serialization_mode(&self) -> SerializationMode {
        SerializationMode::Full
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    fn write_fixed_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
}

/// Cursor over untrusted input. Every read checks the remaining length first.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    input: &'a [u8],
    version: ProtocolVersion,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8], version: ProtocolVersion) -> Self {
        Self { input, version }
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub fn remaining(&self) -> usize {
        self.input.len()
    }

    /// Fails with [`SerError::TrailingBytes`] unless all input was consumed.
    pub fn finish(self) -> Result<(), SerError> {
        match self.input.len() {
            0 => Ok(()),
            remaining => Err(SerError::TrailingBytes { remaining }),
        }
    }

    /// Reads exactly `len` bytes, refusing more than [`MAX_READ_LEN`].
    pub fn read_fixed_bytes(&mut self, len: usize) -> Result<&'a [u8], SerError> {
        if len > MAX_READ_LEN {
            return Err(SerError::TooLarge {
                len: len as u64,
                max: MAX_READ_LEN,
            });
        }
        let (head, rest) = self
            .input
            .split_at_checked(len)
            .ok_or(SerError::Truncated {
                needed: len,
                available: self.input.len(),
            })?;
        self.input = rest;
        Ok(head)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], SerError> {
        let (head, rest) = self
            .input
            .split_first_chunk::<N>()
            .ok_or(SerError::Truncated {
                needed: N,
                available: self.input.len(),
            })?;
        self.input = rest;
        Ok(*head)
    }

    pub fn read_u8(&mut self) -> Result<u8, SerError> {
        self.read_array().map(u8::from_be_bytes)
    }

    pub fn read_u16(&mut self) -> Result<u16, SerError> {
        self.read_array().map(u16::from_be_bytes)
    }

    pub fn read_u32(&mut self) -> Result<u32, SerError> {
        self.read_array().map(u32::from_be_bytes)
    }

    pub fn read_i32(&mut self) -> Result<i32, SerError> {
        self.read_array().map(i32::from_be_bytes)
    }

    pub fn read_u64(&mut self) -> Result<u64, SerError> {
        self.read_array().map(u64::from_be_bytes)
    }

    pub fn read_i64(&mut self) -> Result<i64, SerError> {
        self.read_array().map(i64::from_be_bytes)
    }

    /// Reads a `u64` length prefix and that many bytes. The length is checked against `max`,
    /// [`MAX_READ_LEN`] and the remaining input before anything is read.
    pub fn read_bytes_len_prefix(&mut self, max: usize) -> Result<&'a [u8], SerError> {
        let len = self.read_u64()?;
        let len = bounded_len(len, max)?;
        self.read_fixed_bytes(len)
    }

    /// Consumes one byte and fails unless it equals `expected`.
    pub fn expect_u8(&mut self, expected: u8) -> Result<(), SerError> {
        let found = self.read_u8()?;
        if found == expected {
            Ok(())
        } else {
            Err(SerError::UnexpectedByte { expected, found })
        }
    }

    /// Reads `count` consecutive items. The count is checked against `max`,
    /// [`MAX_MULTI_COUNT`] and the remaining input before any allocation.
    pub fn read_multi<T: Readable>(&mut self, count: u64, max: usize) -> Result<Vec<T>, SerError> {
        let count = bounded_count(count, max)?;
        // Every encoded item occupies at least one byte, so a count above the remaining input
        // cannot succeed and must not size the allocation.
        if count > self.input.len() {
            return Err(SerError::Truncated {
                needed: count,
                available: self.input.len(),
            });
        }
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(T::read(self)?);
        }
        Ok(items)
    }
}

fn bounded_len(len: u64, max: usize) -> Result<usize, SerError> {
    let max = max.min(MAX_READ_LEN);
    usize::try_from(len)
        .ok()
        .filter(|len| *len <= max)
        .ok_or(SerError::TooLarge { len, max })
}

fn bounded_count(count: u64, max: usize) -> Result<usize, SerError> {
    let max = max.min(MAX_MULTI_COUNT);
    usize::try_from(count)
        .ok()
        .filter(|count| *count <= max)
        .ok_or(SerError::TooLarge { len: count, max })
}

/// Encodes `value` in full.
pub fn ser_vec<T: Writeable + ?Sized>(value: &T, version: ProtocolVersion) -> Vec<u8> {
    let mut writer = VecWriter::new(version);
    value.write(&mut writer);
    writer.into_bytes()
}

/// Decodes exactly one `T` from `bytes`, rejecting trailing bytes. This is the pure entry point
/// for fuzzing every `Readable` type.
pub fn deserialize<T: Readable>(bytes: &[u8], version: ProtocolVersion) -> Result<T, SerError> {
    let mut reader = Reader::new(bytes, version);
    let value = T::read(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

impl Writeable for ProtocolVersion {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write_u32(self.0);
    }
}

impl Readable for ProtocolVersion {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        reader.read_u32().map(Self)
    }
}

macro_rules! impl_int {
    ($int:ty, $write:ident, $read:ident) => {
        impl Writeable for $int {
            fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
                writer.$write(*self);
            }
        }

        impl Readable for $int {
            fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
                reader.$read()
            }
        }
    };
}

impl_int!(u8, write_u8, read_u8);
impl_int!(u16, write_u16, read_u16);
impl_int!(u32, write_u32, read_u32);
impl_int!(i32, write_i32, read_i32);
impl_int!(u64, write_u64, read_u64);
impl_int!(i64, write_i64, read_i64);

impl<T: Writeable + ?Sized> Writeable for &T {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        (**self).write(writer);
    }
}

// Sequences carry no count of their own; the enclosing type writes it, as the node does.
impl<T: Writeable> Writeable for [T] {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        for item in self {
            item.write(writer);
        }
    }
}

impl<T: Writeable> Writeable for Vec<T> {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.as_slice().write(writer);
    }
}

macro_rules! impl_tuple {
    ($($name:ident: $index:tt),+) => {
        impl<$($name: Writeable),+> Writeable for ($($name,)+) {
            fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
                $(self.$index.write(writer);)+
            }
        }

        impl<$($name: Readable),+> Readable for ($($name,)+) {
            fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
                Ok(($($name::read(reader)?,)+))
            }
        }
    };
}

impl_tuple!(A: 0, B: 1);
impl_tuple!(A: 0, B: 1, C: 2);
impl_tuple!(A: 0, B: 1, C: 2, D: 3);
