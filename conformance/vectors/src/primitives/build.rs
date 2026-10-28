// SPDX-License-Identifier: Apache-2.0
//! Builds inputs, outputs, kernels and whole transactions from fixed blinding factors and nonces,
//! so every commitment, range proof and signature regenerates byte for byte.

use epic_core::core::transaction::{
    Input, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel,
};
use epic_core::libtx::aggsig;
use epic_keychain::BlindingFactor;
use epic_util::secp::Secp256k1;
use epic_util::secp::pedersen::{Commitment, RangeProof};
use serde::Serialize;

use super::fixtures::{output_features, public, secret};
use crate::{Error, hex};

/// A coin: an input being spent, or the commitment part of an output.
#[derive(Clone, Copy)]
pub(crate) struct Coin {
    pub(crate) features: OutputFeatures,
    pub(crate) value: u64,
    pub(crate) blind: [u8; 32],
}

/// An output and the two nonces its Bulletproof is built from.
#[derive(Clone, Copy)]
pub(crate) struct OutputSpec {
    pub(crate) coin: Coin,
    pub(crate) rewind_nonce: [u8; 32],
    pub(crate) private_nonce: [u8; 32],
}

/// A single-kernel transaction. The kernel excess is the output blinds minus the input blinds
/// minus the offset, signed by one signer with a fixed nonce.
pub(crate) struct TxSpec {
    pub(crate) inputs: Vec<Coin>,
    pub(crate) outputs: Vec<OutputSpec>,
    pub(crate) features: KernelFeatures,
    pub(crate) offset: [u8; 32],
    pub(crate) kernel_nonce: [u8; 32],
}

impl Coin {
    pub(crate) fn plain(value: u64, blind: u8) -> Coin {
        Coin {
            features: OutputFeatures::Plain,
            value,
            blind: [blind; 32],
        }
    }

    pub(crate) fn commit(&self, secp: &Secp256k1) -> Result<Commitment, Error> {
        secp.commit(self.value, secret(secp, &self.blind)?)
            .map_err(Error::reference("commitment"))
    }

    pub(crate) fn input(&self, secp: &Secp256k1) -> Result<Input, Error> {
        Ok(Input::new(self.features, self.commit(secp)?))
    }
}

impl OutputSpec {
    /// Nonces are derived from the blind byte so a case lists one byte per output.
    pub(crate) fn new(coin: Coin) -> OutputSpec {
        let tag = coin.blind[0];
        OutputSpec {
            coin,
            rewind_nonce: [tag ^ 0x0f; 32],
            private_nonce: [tag ^ 0xf0; 32],
        }
    }

    pub(crate) fn proof(&self, secp: &Secp256k1) -> Result<RangeProof, Error> {
        Ok(secp.bullet_proof(
            self.coin.value,
            secret(secp, &self.coin.blind)?,
            secret(secp, &self.rewind_nonce)?,
            secret(secp, &self.private_nonce)?,
            None,
            None,
        ))
    }

    pub(crate) fn output(&self, secp: &Secp256k1) -> Result<Output, Error> {
        Ok(Output {
            features: self.coin.features,
            commit: self.coin.commit(secp)?,
            proof: self.proof(secp)?,
        })
    }
}

/// Signs a kernel the way `TxKernel::verify` checks it: the excess public key is also the key
/// committed to in the challenge.
pub(crate) fn signed_kernel(
    secp: &Secp256k1,
    features: KernelFeatures,
    excess_blind: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<TxKernel, Error> {
    let blind = secret(secp, excess_blind)?;
    let nonce = secret(secp, nonce)?;
    let public_blind = public(secp, &blind)?;
    let msg = features
        .kernel_sig_msg()
        .map_err(Error::reference("kernel signature message"))?;
    let excess_sig = aggsig::sign_single(secp, &msg, &blind, Some(&nonce), Some(&public_blind))
        .map_err(Error::reference("kernel signature"))?;
    let excess = secp
        .commit(0, blind)
        .map_err(Error::reference("kernel excess"))?;
    Ok(TxKernel {
        features,
        excess,
        excess_sig,
    })
}

impl TxSpec {
    pub(crate) fn excess_blind(&self, secp: &Secp256k1) -> Result<[u8; 32], Error> {
        let positive = self
            .outputs
            .iter()
            .map(|output| secret(secp, &output.coin.blind))
            .collect::<Result<Vec<_>, _>>()?;
        let mut negative = self
            .inputs
            .iter()
            .map(|input| secret(secp, &input.blind))
            .collect::<Result<Vec<_>, _>>()?;
        negative.push(secret(secp, &self.offset)?);
        let sum = secp
            .blind_sum(positive, negative)
            .map_err(Error::reference("excess blinding factor"))?;
        Ok(sum.0)
    }

    pub(crate) fn kernel(&self, secp: &Secp256k1) -> Result<TxKernel, Error> {
        signed_kernel(
            secp,
            self.features,
            &self.excess_blind(secp)?,
            &self.kernel_nonce,
        )
    }

    /// The transaction with inputs, outputs and kernels in upstream's sorted order.
    pub(crate) fn build(&self, secp: &Secp256k1) -> Result<Transaction, Error> {
        let inputs = self
            .inputs
            .iter()
            .map(|coin| coin.input(secp))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = self
            .outputs
            .iter()
            .map(|output| output.output(secp))
            .collect::<Result<Vec<_>, _>>()?;
        let offset = BlindingFactor::from_secret_key(secret(secp, &self.offset)?);
        Ok(Transaction::new(inputs, outputs, vec![self.kernel(secp)?]).with_offset(offset))
    }
}

#[derive(Serialize)]
pub(crate) struct CoinJson {
    features: &'static str,
    value: String,
    blind: String,
}

impl From<&Coin> for CoinJson {
    fn from(coin: &Coin) -> CoinJson {
        CoinJson {
            features: output_features(coin.features),
            value: coin.value.to_string(),
            blind: hex(coin.blind),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct OutputSpecJson {
    features: &'static str,
    value: String,
    blind: String,
    rewind_nonce: String,
    private_nonce: String,
}

impl From<&OutputSpec> for OutputSpecJson {
    fn from(spec: &OutputSpec) -> OutputSpecJson {
        OutputSpecJson {
            features: output_features(spec.coin.features),
            value: spec.coin.value.to_string(),
            blind: hex(spec.coin.blind),
            rewind_nonce: hex(spec.rewind_nonce),
            private_nonce: hex(spec.private_nonce),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct TxSpecJson {
    inputs: Vec<CoinJson>,
    outputs: Vec<OutputSpecJson>,
    kernel_features: super::fixtures::Features,
    offset: String,
    kernel_nonce: String,
}

impl From<&TxSpec> for TxSpecJson {
    fn from(spec: &TxSpec) -> TxSpecJson {
        TxSpecJson {
            inputs: spec.inputs.iter().map(CoinJson::from).collect(),
            outputs: spec.outputs.iter().map(OutputSpecJson::from).collect(),
            kernel_features: super::fixtures::Features::from(&spec.features),
            offset: hex(spec.offset),
            kernel_nonce: hex(spec.kernel_nonce),
        }
    }
}
