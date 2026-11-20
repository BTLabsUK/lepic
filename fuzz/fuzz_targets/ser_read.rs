// SPDX-License-Identifier: Apache-2.0
//! Binary reads of every transaction part, at both protocol versions.
//!
//! Input: one byte choosing the type (see `TYPES`), one byte choosing the protocol version (odd
//! is version 1, even is version 2), then the encoding. `cargo xtask fuzz` writes seeds in this layout.

#![no_main]

use lepic_crypto::{Commitment, PublicKey, RangeProof, Signature};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::hash::Hash;
use lepic_primitives::input::Input;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::{Output, OutputFeatures, OutputIdentifier};
use lepic_primitives::ser::{ProtocolVersion, Readable, Writeable, deserialize, ser_vec};
use lepic_primitives::tx::{Transaction, TransactionBody};
use libfuzzer_sys::fuzz_target;

type Check = fn(&[u8], ProtocolVersion);

/// Index order is the seed layout `cargo xtask fuzz` writes; append, never reorder.
const TYPES: [Check; 14] = [
    reads_canonically::<Transaction>,
    reads_canonically::<TransactionBody>,
    reads_canonically::<TxKernel>,
    reads_canonically::<KernelFeatures>,
    reads_canonically::<Input>,
    reads_canonically::<Output>,
    reads_canonically::<OutputIdentifier>,
    reads_canonically::<OutputFeatures>,
    reads_canonically::<Commitment>,
    reads_canonically::<PublicKey>,
    reads_canonically::<Signature>,
    reads_canonically::<RangeProof>,
    reads_canonically::<BlindingFactor>,
    reads_canonically::<Hash>,
];

/// Whatever a read accepts, writing it at the same version gives back the same bytes, so two
/// peers never disagree about what a hash or signature covers.
fn reads_canonically<T: Readable + Writeable>(bytes: &[u8], version: ProtocolVersion) {
    if let Ok(value) = deserialize::<T>(bytes, version) {
        assert_eq!(
            ser_vec(&value, version),
            bytes,
            "{} at {version:?} does not write back what it read",
            std::any::type_name::<T>()
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let [selector, version, bytes @ ..] = data else {
        return;
    };
    let version = if version % 2 == 1 {
        ProtocolVersion::V1
    } else {
        ProtocolVersion::V2
    };
    if let Some(check) = TYPES.get(usize::from(*selector) % TYPES.len()) {
        check(bytes, version);
    }
});
