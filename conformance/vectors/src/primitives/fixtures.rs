// SPDX-License-Identifier: Apache-2.0
//! Fixed test values and the JSON shapes shared by the primitives and aggsig areas.

use epic_core::core::transaction::{
    Input, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel,
};
use epic_core::ser;
use epic_util::secp::key::{PublicKey, SecretKey};
use epic_util::secp::{ContextFlag, Secp256k1, Signature};
use serde::Serialize;

use crate::{Error, hex};

/// A check the generator makes on upstream output. A failure means the case does not show what it
/// claims to show, so no vector is written.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct Unexpected(&'static str);

pub(crate) fn unexpected(step: &'static str) -> Error {
    Error::reference(step)(Unexpected(step))
}

pub(crate) fn ensure(holds: bool, step: &'static str) -> Result<(), Error> {
    if holds { Ok(()) } else { Err(unexpected(step)) }
}

pub(crate) fn secp() -> Secp256k1 {
    Secp256k1::with_caps(ContextFlag::Commit)
}

pub(crate) fn secret(secp: &Secp256k1, bytes: &[u8; 32]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(secp, bytes).map_err(Error::reference("fixed secret key"))
}

pub(crate) fn public(secp: &Secp256k1, key: &SecretKey) -> Result<PublicKey, Error> {
    PublicKey::from_secret_key(secp, key).map_err(Error::reference("public key"))
}

pub(crate) fn public_hex(secp: &Secp256k1, key: &PublicKey) -> String {
    hex(key.serialize_vec(secp, true))
}

/// The 64-byte compact form, as JSON slates carry it. Binary layouts carry `to_raw_data`.
pub(crate) fn sig_hex(secp: &Secp256k1, sig: &Signature) -> String {
    hex(sig.serialize_compact(secp))
}

pub(crate) fn ser_error_name(error: &ser::Error) -> String {
    match error {
        ser::Error::IOErr(_, kind) => format!("IOErr({kind:?})"),
        other => format!("{other:?}"),
    }
}

pub(crate) fn output_features(features: OutputFeatures) -> &'static str {
    match features {
        OutputFeatures::Plain => "Plain",
        OutputFeatures::Coinbase => "Coinbase",
    }
}

#[derive(Serialize)]
pub(crate) struct Features {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lock_height: Option<String>,
}

impl From<&KernelFeatures> for Features {
    fn from(features: &KernelFeatures) -> Features {
        match *features {
            KernelFeatures::Plain { fee } => Features {
                kind: "Plain",
                fee: Some(fee.to_string()),
                lock_height: None,
            },
            KernelFeatures::Coinbase => Features {
                kind: "Coinbase",
                fee: None,
                lock_height: None,
            },
            KernelFeatures::HeightLocked { fee, lock_height } => Features {
                kind: "HeightLocked",
                fee: Some(fee.to_string()),
                lock_height: Some(lock_height.to_string()),
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct InputJson {
    features: &'static str,
    commit: String,
}

impl From<&Input> for InputJson {
    fn from(input: &Input) -> InputJson {
        InputJson {
            features: output_features(input.features),
            commit: hex(input.commit),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct OutputJson {
    features: &'static str,
    commit: String,
    proof: String,
}

impl From<&Output> for OutputJson {
    fn from(output: &Output) -> OutputJson {
        OutputJson {
            features: output_features(output.features),
            commit: hex(output.commit),
            proof: hex(output.proof.bytes()),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct KernelJson {
    features: Features,
    excess: String,
    excess_sig: String,
}

impl KernelJson {
    pub(crate) fn new(secp: &Secp256k1, kernel: &TxKernel) -> KernelJson {
        KernelJson {
            features: Features::from(&kernel.features),
            excess: hex(kernel.excess),
            excess_sig: sig_hex(secp, &kernel.excess_sig),
        }
    }
}

/// A transaction as its parts, in the order the transaction holds them.
#[derive(Serialize)]
pub(crate) struct TransactionJson {
    offset: String,
    inputs: Vec<InputJson>,
    outputs: Vec<OutputJson>,
    kernels: Vec<KernelJson>,
}

impl TransactionJson {
    pub(crate) fn new(secp: &Secp256k1, tx: &Transaction) -> TransactionJson {
        TransactionJson {
            offset: hex(&tx.offset),
            inputs: tx.inputs().iter().map(InputJson::from).collect(),
            outputs: tx.outputs().iter().map(OutputJson::from).collect(),
            kernels: tx
                .kernels()
                .iter()
                .map(|kernel| KernelJson::new(secp, kernel))
                .collect(),
        }
    }
}
