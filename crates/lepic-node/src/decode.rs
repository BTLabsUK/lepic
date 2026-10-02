//! Pure decoders for node response bodies: JSON-RPC framing, then strict validation against
//! the request that was made. The client uses them, and so can fuzz targets.

use std::collections::BTreeSet;

use lepic_crypto::Commitment;
use lepic_primitives::amount::Height;

use crate::api::{LocatedKernel, NodeVersion, OutputLocation, PmmrIndices, Tip, UnspentOutputs};
use crate::error::{NodeError, RejectionKind};
use crate::rpc::decode_response;
use crate::wire::{
    WireLocatedKernel, WireOutput, WireOutputListing, WireTip, WireVersion,
    validate_output_locations,
};

pub fn version(body: &[u8]) -> Result<NodeVersion, NodeError> {
    const METHOD: &str = "get_version";
    decode_response::<WireVersion>(METHOD, body)?.validate(METHOD)
}

pub fn tip(body: &[u8]) -> Result<Tip, NodeError> {
    const METHOD: &str = "get_tip";
    decode_response::<WireTip>(METHOD, body)?.validate(METHOD)
}

/// `Ok(None)` when the node answered `NotFound`.
pub fn kernel(
    body: &[u8],
    excess: &Commitment,
    min_height: Option<Height>,
    max_height: Option<Height>,
) -> Result<Option<LocatedKernel>, NodeError> {
    const METHOD: &str = "get_kernel";
    match decode_response::<WireLocatedKernel>(METHOD, body) {
        Ok(kernel) => kernel
            .validate(METHOD, excess, min_height, max_height)
            .map(Some),
        Err(NodeError::Rejected { rejection, .. }) if rejection.kind == RejectionKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub fn outputs(
    body: &[u8],
    requested: &BTreeSet<Commitment>,
) -> Result<Vec<OutputLocation>, NodeError> {
    const METHOD: &str = "get_outputs";
    let outputs = decode_response::<Vec<WireOutput>>(METHOD, body)?;
    validate_output_locations(METHOD, outputs, requested)
}

pub fn unspent_outputs(
    body: &[u8],
    start_index: u64,
    end_index: Option<u64>,
    max: u64,
) -> Result<UnspentOutputs, NodeError> {
    const METHOD: &str = "get_unspent_outputs";
    decode_response::<WireOutputListing>(METHOD, body)?.validate_unspent(
        METHOD,
        start_index,
        end_index,
        max,
    )
}

pub fn pmmr_indices(body: &[u8]) -> Result<PmmrIndices, NodeError> {
    const METHOD: &str = "get_pmmr_indices";
    Ok(decode_response::<WireOutputListing>(METHOD, body)?.into_pmmr_indices())
}

pub fn push_transaction(body: &[u8]) -> Result<(), NodeError> {
    decode_response::<()>("push_transaction", body)
}
