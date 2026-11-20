// SPDX-License-Identifier: Apache-2.0
//! Reading fixed-width big-endian fields off the front of the input.

use crate::error::NativeError;

pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn take(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<&'a [u8], NativeError> {
        let (taken, rest) = self
            .rest
            .split_at_checked(len)
            .ok_or(NativeError::Truncated { field })?;
        self.rest = rest;
        Ok(taken)
    }

    pub(crate) fn array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<&'a [u8; N], NativeError> {
        let (taken, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(NativeError::Truncated { field })?;
        self.rest = rest;
        Ok(taken)
    }

    pub(crate) fn u8(&mut self, field: &'static str) -> Result<u8, NativeError> {
        self.array::<1>(field).map(|[byte]| *byte)
    }

    pub(crate) fn u16(&mut self, field: &'static str) -> Result<u16, NativeError> {
        self.array(field).map(|bytes| u16::from_be_bytes(*bytes))
    }

    pub(crate) fn u64(&mut self, field: &'static str) -> Result<u64, NativeError> {
        self.array(field).map(|bytes| u64::from_be_bytes(*bytes))
    }

    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.rest
    }
}
