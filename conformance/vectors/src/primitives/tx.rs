// SPDX-License-Identifier: Apache-2.0
//! Binary layouts of the crypto types and of every transaction part: output and kernel features,
//! inputs, outputs and kernels, at protocol versions 1 and 2, with their hashes and kernel
//! signature messages.

use epic_core::core::hash::Hashed;
use epic_core::core::transaction::{
    Input, KernelFeatures, Output, OutputFeatures, OutputIdentifier, TxKernel,
};
use epic_core::libtx::aggsig;
use epic_core::ser::{self, ProtocolVersion, Readable, Writeable};
use epic_keychain::BlindingFactor;
use epic_util::secp::Message;
use serde::Serialize;

use super::AREA;
use super::build::{Coin, CoinJson, OutputSpec, OutputSpecJson, signed_kernel};
use super::fixtures::{
    Features, ensure, output_features, public, public_hex, secp, secret, ser_error_name, sig_hex,
};
use crate::{Error, Pins, Rendered, hex, render};

#[derive(Serialize)]
struct NoInputs {}

#[derive(Serialize)]
struct Cases<T> {
    cases: Vec<T>,
}

fn ser_at<T: Writeable>(thing: &T, version: u32) -> Result<String, Error> {
    ser::ser_vec(thing, ProtocolVersion(version))
        .map(hex)
        .map_err(Error::reference("serialization"))
}

fn deserialize<T: Readable>(bytes: &[u8], version: u32) -> Result<T, ser::Error> {
    ser::deserialize::<T>(&mut &bytes[..], ProtocolVersion(version))
}

const VALUE: u64 = 1_500_000_000;
const BLIND: u8 = 0x41;
const SIG_KEY: [u8; 32] = [0x42; 32];
const SIG_NONCE: [u8; 32] = [0x43; 32];
const SIG_TEXT: &[u8] = b"lepic crypto types";

#[derive(Serialize)]
struct CryptoInputs {
    output: OutputSpecJson,
    sig_key: String,
    sig_nonce: String,
    /// The signed message is BLAKE2b-256 of this text.
    sig_text: String,
}

/// Each `*_ser` field is the binary layout; the others are the forms JSON carries.
#[derive(Serialize)]
struct CryptoExpected {
    commitment: String,
    commitment_ser: String,
    blinding_factor_ser: String,
    public_key: String,
    public_key_ser: String,
    sig_msg: String,
    signature_compact: String,
    signature_ser: String,
    range_proof: String,
    range_proof_ser: String,
}

fn crypto_types(pins: &Pins) -> Result<Rendered, Error> {
    let secp = secp();
    let spec = OutputSpec::new(Coin::plain(VALUE, BLIND));
    let output = spec.output(&secp)?;
    let blind = BlindingFactor::from_secret_key(secret(&secp, &spec.coin.blind)?);
    let sig_key = secret(&secp, &SIG_KEY)?;
    let public_key = public(&secp, &sig_key)?;
    let digest = SIG_TEXT.to_vec().hash();
    let msg = Message::from_slice(digest.as_bytes()).map_err(Error::reference("message"))?;
    let nonce = secret(&secp, &SIG_NONCE)?;
    let sig = aggsig::sign_single(&secp, &msg, &sig_key, Some(&nonce), Some(&public_key))
        .map_err(Error::reference("signature"))?;
    ensure(
        aggsig::verify_single(
            &secp,
            &sig,
            &msg,
            None,
            &public_key,
            Some(&public_key),
            false,
        ),
        "crypto types signature verifies",
    )?;
    output
        .verify_proof()
        .map_err(Error::reference("range proof verification"))?;

    let inputs = CryptoInputs {
        output: OutputSpecJson::from(&spec),
        sig_key: hex(SIG_KEY),
        sig_nonce: hex(SIG_NONCE),
        sig_text: String::from_utf8_lossy(SIG_TEXT).into_owned(),
    };
    let expected = CryptoExpected {
        commitment: hex(output.commit),
        commitment_ser: ser_at(&output.commit, 2)?,
        blinding_factor_ser: ser_at(&blind, 2)?,
        public_key: public_hex(&secp, &public_key),
        public_key_ser: ser_at(&public_key, 2)?,
        sig_msg: hex(msg),
        signature_compact: sig_hex(&secp, &sig),
        signature_ser: ser_at(&sig, 2)?,
        range_proof: hex(output.proof.bytes()),
        range_proof_ser: ser_at(&output.proof, 2)?,
    };
    render(AREA, "crypto_types", &pins.node, inputs, expected)
}

#[derive(Serialize)]
struct OutputFeaturesCase {
    byte: String,
    /// The decoded features, or the upstream error.
    outcome: String,
}

fn output_features_cases() -> Vec<OutputFeaturesCase> {
    [0u8, 1, 2, 0xff]
        .into_iter()
        .map(|byte| OutputFeaturesCase {
            byte: hex([byte]),
            outcome: match deserialize::<OutputFeatures>(&[byte], 2) {
                Ok(features) => output_features(features).to_owned(),
                Err(error) => ser_error_name(&error),
            },
        })
        .collect()
}

const KERNEL_FEATURES: &[KernelFeatures] = &[
    KernelFeatures::Plain { fee: 0 },
    KernelFeatures::Plain { fee: 1 },
    KernelFeatures::Plain { fee: 800_000 },
    KernelFeatures::Plain { fee: u64::MAX },
    KernelFeatures::Coinbase,
    KernelFeatures::HeightLocked {
        fee: 800_000,
        lock_height: 0,
    },
    KernelFeatures::HeightLocked {
        fee: 800_000,
        lock_height: 1,
    },
    KernelFeatures::HeightLocked {
        fee: 800_000,
        lock_height: 1_000_000,
    },
    KernelFeatures::HeightLocked {
        fee: u64::MAX,
        lock_height: u64::MAX,
    },
];

#[derive(Serialize)]
struct KernelFeaturesCase {
    features: Features,
    serialized_v1: String,
    serialized_v2: String,
    sig_msg: String,
}

fn kernel_features_cases() -> Result<Vec<KernelFeaturesCase>, Error> {
    KERNEL_FEATURES
        .iter()
        .map(|features| {
            let msg = features
                .kernel_sig_msg()
                .map_err(Error::reference("kernel signature message"))?;
            Ok(KernelFeaturesCase {
                features: Features::from(features),
                serialized_v1: ser_at(features, 1)?,
                serialized_v2: ser_at(features, 2)?,
                sig_msg: hex(msg),
            })
        })
        .collect()
}

/// Exactly one of `features` and `error` is set.
#[derive(Serialize)]
struct DecodeCase {
    protocol_version: u32,
    bytes: String,
    features: Option<Features>,
    error: Option<String>,
}

fn kernel_features_bytes(feature: u8, fee: Option<u64>, lock_height: Option<u64>) -> Vec<u8> {
    let mut bytes = vec![feature];
    for value in [fee, lock_height].into_iter().flatten() {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn kernel_features_decodes() -> Vec<DecodeCase> {
    let v1 = [
        kernel_features_bytes(0, Some(10), Some(0)),
        kernel_features_bytes(0, Some(10), Some(5)),
        kernel_features_bytes(1, Some(0), Some(0)),
        kernel_features_bytes(1, Some(1), Some(0)),
        kernel_features_bytes(1, Some(0), Some(1)),
        kernel_features_bytes(2, Some(10), Some(100)),
        kernel_features_bytes(2, Some(10), Some(0)),
        kernel_features_bytes(3, Some(0), Some(0)),
        kernel_features_bytes(0, Some(10), None),
    ];
    let v2 = [
        kernel_features_bytes(0, Some(10), None),
        kernel_features_bytes(1, None, None),
        kernel_features_bytes(2, Some(10), Some(100)),
        kernel_features_bytes(3, None, None),
        kernel_features_bytes(0, None, None),
        kernel_features_bytes(2, Some(10), None),
    ];
    let cases = v1
        .into_iter()
        .map(|bytes| (1, bytes))
        .chain(v2.into_iter().map(|bytes| (2, bytes)));
    cases
        .map(|(protocol_version, bytes)| {
            let decoded = deserialize::<KernelFeatures>(&bytes, protocol_version);
            DecodeCase {
                protocol_version,
                bytes: hex(&bytes),
                features: decoded.as_ref().ok().map(Features::from),
                error: decoded.as_ref().err().map(ser_error_name),
            }
        })
        .collect()
}

#[derive(Serialize)]
struct InputCase {
    input: CoinJson,
    commit: String,
    serialized_v1: String,
    serialized_v2: String,
    hash: String,
}

fn input_cases() -> Result<Vec<InputCase>, Error> {
    let secp = secp();
    [OutputFeatures::Plain, OutputFeatures::Coinbase]
        .into_iter()
        .map(|features| {
            let coin = Coin {
                features,
                ..Coin::plain(VALUE, BLIND)
            };
            let input: Input = coin.input(&secp)?;
            Ok(InputCase {
                input: CoinJson::from(&coin),
                commit: hex(input.commit),
                serialized_v1: ser_at(&input, 1)?,
                serialized_v2: ser_at(&input, 2)?,
                hash: hex(input.hash()),
            })
        })
        .collect()
}

/// `hash` covers features and commitment only; the proof is committed to separately.
#[derive(Serialize)]
struct OutputCase {
    output: OutputSpecJson,
    commit: String,
    proof: String,
    serialized_v1: String,
    serialized_v2: String,
    hash: String,
    identifier_serialized: String,
    identifier_hash: String,
}

fn output_cases() -> Result<Vec<OutputCase>, Error> {
    let secp = secp();
    [
        (OutputFeatures::Plain, VALUE, BLIND),
        (OutputFeatures::Coinbase, VALUE, BLIND),
        (OutputFeatures::Plain, 0, 0x44),
        (OutputFeatures::Plain, 1, 0x45),
        (OutputFeatures::Plain, u64::MAX, 0x46),
    ]
    .into_iter()
    .map(|(features, value, blind)| {
        let spec = OutputSpec::new(Coin {
            features,
            ..Coin::plain(value, blind)
        });
        let output: Output = spec.output(&secp)?;
        output
            .verify_proof()
            .map_err(Error::reference("output range proof"))?;
        let identifier = OutputIdentifier::from_output(&output);
        Ok(OutputCase {
            output: OutputSpecJson::from(&spec),
            commit: hex(output.commit),
            proof: hex(output.proof.bytes()),
            serialized_v1: ser_at(&output, 1)?,
            serialized_v2: ser_at(&output, 2)?,
            hash: hex(output.hash()),
            identifier_serialized: ser_at(&identifier, 2)?,
            identifier_hash: hex(identifier.hash()),
        })
    })
    .collect()
}

#[derive(Serialize)]
struct KernelCase {
    features: Features,
    excess_blind: String,
    nonce: String,
    excess: String,
    sig_msg: String,
    excess_sig: String,
    serialized_v1: String,
    serialized_v2: String,
    /// Kernels hash their protocol version 1 layout whatever version the writer speaks.
    hash: String,
}

fn kernel_cases() -> Result<Vec<KernelCase>, Error> {
    let secp = secp();
    let features = [
        KernelFeatures::Plain { fee: 800_000 },
        KernelFeatures::Coinbase,
        KernelFeatures::HeightLocked {
            fee: 800_000,
            lock_height: 1_000_000,
        },
    ];
    features
        .into_iter()
        .zip([0x47u8, 0x48, 0x49])
        .map(|(features, key)| {
            let excess_blind = [key; 32];
            let nonce = [key ^ 0x80; 32];
            let kernel: TxKernel = signed_kernel(&secp, features, &excess_blind, &nonce)?;
            kernel
                .verify()
                .map_err(Error::reference("kernel verification"))?;
            Ok(KernelCase {
                features: Features::from(&features),
                excess_blind: hex(excess_blind),
                nonce: hex(nonce),
                excess: hex(kernel.excess),
                sig_msg: hex(kernel
                    .msg_to_sign()
                    .map_err(Error::reference("kernel signature message"))?),
                excess_sig: sig_hex(&secp, &kernel.excess_sig),
                serialized_v1: ser_at(&kernel, 1)?,
                serialized_v2: ser_at(&kernel, 2)?,
                hash: hex(kernel.hash()),
            })
        })
        .collect()
}

pub(super) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    Ok(vec![
        crypto_types(pins)?,
        render(
            AREA,
            "output_features",
            &pins.node,
            NoInputs {},
            Cases {
                cases: output_features_cases(),
            },
        )?,
        render(
            AREA,
            "kernel_features",
            &pins.node,
            NoInputs {},
            Cases {
                cases: kernel_features_cases()?,
            },
        )?,
        render(
            AREA,
            "kernel_features_decode",
            &pins.node,
            NoInputs {},
            Cases {
                cases: kernel_features_decodes(),
            },
        )?,
        render(
            AREA,
            "inputs",
            &pins.node,
            NoInputs {},
            Cases {
                cases: input_cases()?,
            },
        )?,
        render(
            AREA,
            "outputs",
            &pins.node,
            NoInputs {},
            Cases {
                cases: output_cases()?,
            },
        )?,
        render(
            AREA,
            "kernels",
            &pins.node,
            NoInputs {},
            Cases {
                cases: kernel_cases()?,
            },
        )?,
    ])
}
