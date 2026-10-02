//! Transactions and transaction bodies, equal in encoding and hash to the node's `Transaction`
//! and `TransactionBody`, with the checks the node runs when it reads one.
//!
//! Range proofs, kernel signatures and kernel sums are not checked here; decoding a
//! transaction proves only that it is well formed.

use std::cmp::Ordering;

use thiserror::Error;

use crate::amount::{ArithmeticError, Fee, Height};
use crate::crypto_ser::BlindingFactor;
use crate::fee::BodyCounts;
use crate::hash::{DefaultHashable, Hash, Hashed};
use crate::input::Input;
use crate::kernel::TxKernel;
use crate::output::Output;
use crate::params::{MAX_BLOCK_WEIGHT, MAX_TX_WEIGHT};
use crate::ser::{MAX_MULTI_COUNT, ProtocolVersion, Readable, Reader, SerError, Writeable, Writer};

/// One of the three lists in a transaction body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPart {
    Inputs,
    Outputs,
    Kernels,
}

impl std::fmt::Display for BodyPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Inputs => "inputs",
            Self::Outputs => "outputs",
            Self::Kernels => "kernels",
        })
    }
}

/// A transaction that is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TxError {
    #[error("transaction encoding is invalid")]
    Encoding(#[from] SerError),
    #[error("{part} are not sorted by hash")]
    NotSorted { part: BodyPart },
    #[error("{part} contain a duplicate")]
    Duplicate { part: BodyPart },
    #[error("transaction weight {weight} exceeds the limit {max}")]
    TooHeavy { weight: u64, max: u64 },
    #[error("an input spends an output of the same transaction")]
    CutThrough,
    #[error("transaction contains a coinbase output")]
    CoinbaseOutput,
    #[error("transaction contains a coinbase kernel")]
    CoinbaseKernel,
}

impl TxError {
    fn into_ser_error(self) -> SerError {
        match self {
            Self::Encoding(error) => error,
            Self::NotSorted { .. } => SerError::NotSorted,
            Self::Duplicate { .. } => SerError::Duplicate,
            Self::TooHeavy { .. }
            | Self::CutThrough
            | Self::CoinbaseOutput
            | Self::CoinbaseKernel => SerError::Invalid {
                type_name: "transaction",
            },
        }
    }
}

/// Inputs, outputs and kernels. Each list is expected in increasing hash order without
/// duplicates; [`TransactionBody::new`] sorts, [`TransactionBody::from_parts`] keeps the order
/// it is given so that a malformed body can be represented and rejected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionBody {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    kernels: Vec<TxKernel>,
}

impl TransactionBody {
    pub fn new(inputs: Vec<Input>, outputs: Vec<Output>, kernels: Vec<TxKernel>) -> Self {
        let mut body = Self::from_parts(inputs, outputs, kernels);
        body.sort();
        body
    }

    pub fn from_parts(inputs: Vec<Input>, outputs: Vec<Output>, kernels: Vec<TxKernel>) -> Self {
        Self {
            inputs,
            outputs,
            kernels,
        }
    }

    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    pub fn kernels(&self) -> &[TxKernel] {
        &self.kernels
    }

    pub fn into_parts(self) -> (Vec<Input>, Vec<Output>, Vec<TxKernel>) {
        (self.inputs, self.outputs, self.kernels)
    }

    pub fn counts(&self) -> BodyCounts {
        BodyCounts::new(
            count(self.inputs.len()),
            count(self.outputs.len()),
            count(self.kernels.len()),
        )
    }

    /// Sorts each list by hash, the order the node requires.
    pub fn sort(&mut self) {
        self.inputs.sort_by_cached_key(Hashed::hash);
        self.outputs.sort_by_cached_key(Hashed::hash);
        self.kernels.sort_by_cached_key(Hashed::hash);
    }

    /// Sum of the kernel fees.
    pub fn fee(&self) -> Result<Fee, ArithmeticError> {
        self.kernels.iter().try_fold(Fee::ZERO, |total, kernel| {
            total.checked_add(kernel.features.fee())
        })
    }

    /// Highest kernel lock height, or zero when no kernel is height-locked.
    pub fn lock_height(&self) -> Height {
        self.kernels
            .iter()
            .filter_map(|kernel| kernel.features.lock_height())
            .max()
            .unwrap_or(Height::ZERO)
    }

    pub fn verify_sorted(&self) -> Result<(), TxError> {
        verify_sorted_and_unique(&self.inputs, BodyPart::Inputs)?;
        verify_sorted_and_unique(&self.outputs, BodyPart::Outputs)?;
        verify_sorted_and_unique(&self.kernels, BodyPart::Kernels)
    }

    /// Fails when an input spends an output of the same body. Expects sorted lists.
    pub fn verify_cut_through(&self) -> Result<(), TxError> {
        let mut inputs = self.inputs.iter().map(Hashed::hash).peekable();
        let mut outputs = self.outputs.iter().map(Hashed::hash).peekable();
        while let (Some(input), Some(output)) = (inputs.peek(), outputs.peek()) {
            match input.cmp(output) {
                Ordering::Less => {
                    inputs.next();
                }
                Ordering::Greater => {
                    outputs.next();
                }
                Ordering::Equal => return Err(TxError::CutThrough),
            }
        }
        Ok(())
    }

    /// Transactions may not create coinbase outputs or kernels.
    pub fn verify_features(&self) -> Result<(), TxError> {
        if self.outputs.iter().any(Output::is_coinbase) {
            return Err(TxError::CoinbaseOutput);
        }
        if self.kernels.iter().any(TxKernel::is_coinbase) {
            return Err(TxError::CoinbaseKernel);
        }
        Ok(())
    }

    /// The weight limit for a transaction, which leaves room for the coinbase in a block.
    pub fn verify_tx_weight(&self) -> Result<(), TxError> {
        let weight = self.counts().weight_as_block();
        if weight > MAX_TX_WEIGHT {
            return Err(TxError::TooHeavy {
                weight,
                max: MAX_TX_WEIGHT,
            });
        }
        Ok(())
    }

    fn read_checked(reader: &mut Reader<'_>) -> Result<Self, TxError> {
        let counts = BodyCounts::new(reader.read_u64()?, reader.read_u64()?, reader.read_u64()?);
        // Checked before reading any item, so hostile counts cannot drive the work.
        let weight = counts.weight_as_block();
        if weight > MAX_BLOCK_WEIGHT {
            return Err(SerError::TooLarge {
                len: weight,
                // Only reported in the error; the comparison above is in u64.
                max: usize::try_from(MAX_BLOCK_WEIGHT).unwrap_or(usize::MAX),
            }
            .into());
        }
        let inputs = reader.read_multi(counts.inputs, MAX_MULTI_COUNT)?;
        let outputs = reader.read_multi(counts.outputs, MAX_MULTI_COUNT)?;
        let kernels = reader.read_multi(counts.kernels, MAX_MULTI_COUNT)?;
        let body = Self::from_parts(inputs, outputs, kernels);
        body.verify_sorted()?;
        Ok(body)
    }
}

/// Converts a collection length. Lengths of in-memory collections always fit `u64`.
fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn verify_sorted_and_unique<T: Hashed>(items: &[T], part: BodyPart) -> Result<(), TxError> {
    let hashes: Vec<Hash> = items.iter().map(Hashed::hash).collect();
    for pair in hashes.windows(2) {
        if let [previous, next] = pair {
            match previous.cmp(next) {
                Ordering::Less => {}
                Ordering::Equal => return Err(TxError::Duplicate { part }),
                Ordering::Greater => return Err(TxError::NotSorted { part }),
            }
        }
    }
    Ok(())
}

impl Writeable for TransactionBody {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        let counts = self.counts();
        writer.write_u64(counts.inputs);
        writer.write_u64(counts.outputs);
        writer.write_u64(counts.kernels);
        self.inputs.write(writer);
        self.outputs.write(writer);
        self.kernels.write(writer);
    }
}

/// Reads the counts, rejects them if they exceed the block weight limit, reads the items and
/// checks their order, as the node does.
impl Readable for TransactionBody {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        Self::read_checked(reader).map_err(TxError::into_ser_error)
    }
}

/// A transaction: an offset and a body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction {
    offset: BlindingFactor,
    body: TransactionBody,
}

impl Transaction {
    pub fn new(offset: BlindingFactor, body: TransactionBody) -> Self {
        Self { offset, body }
    }

    pub fn offset(&self) -> &BlindingFactor {
        &self.offset
    }

    pub fn body(&self) -> &TransactionBody {
        &self.body
    }

    pub fn into_parts(self) -> (BlindingFactor, TransactionBody) {
        (self.offset, self.body)
    }

    pub fn inputs(&self) -> &[Input] {
        self.body.inputs()
    }

    pub fn outputs(&self) -> &[Output] {
        self.body.outputs()
    }

    pub fn kernels(&self) -> &[TxKernel] {
        self.body.kernels()
    }

    pub fn fee(&self) -> Result<Fee, ArithmeticError> {
        self.body.fee()
    }

    pub fn lock_height(&self) -> Height {
        self.body.lock_height()
    }

    /// Fee weight, see [`BodyCounts::tx_weight`].
    pub fn weight(&self) -> u64 {
        self.body.counts().tx_weight()
    }

    /// The checks the node runs when it reads a transaction: weight, order, cut-through and
    /// features, in that order.
    pub fn verify_read(&self) -> Result<(), TxError> {
        self.body.verify_tx_weight()?;
        self.body.verify_sorted()?;
        self.body.verify_cut_through()?;
        self.body.verify_features()
    }

    /// Decodes exactly one transaction and runs [`Transaction::verify_read`], reporting which
    /// rule failed. This is the pure decode entry point for fuzzing.
    pub fn decode(bytes: &[u8], version: ProtocolVersion) -> Result<Self, TxError> {
        let mut reader = Reader::new(bytes, version);
        let transaction = Self::read_checked(&mut reader)?;
        reader.finish()?;
        Ok(transaction)
    }

    fn read_checked(reader: &mut Reader<'_>) -> Result<Self, TxError> {
        let offset = BlindingFactor::read(reader)?;
        let body = TransactionBody::read_checked(reader)?;
        let transaction = Self { offset, body };
        transaction.verify_read()?;
        Ok(transaction)
    }
}

impl Writeable for Transaction {
    fn write<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.offset.write(writer);
        self.body.write(writer);
    }
}

impl Readable for Transaction {
    fn read(reader: &mut Reader<'_>) -> Result<Self, SerError> {
        Self::read_checked(reader).map_err(TxError::into_ser_error)
    }
}

impl DefaultHashable for Transaction {}
