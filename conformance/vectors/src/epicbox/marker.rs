// SPDX-License-Identifier: Apache-2.0
//! The LEPIC marker with feature bits on a V2 S1 sent over Epicbox: the plain S1 of the slates
//! area with `"lepic":{"version":1,"f":<bits>}` as its last key, as RFC 0002 and the marker's
//! description define it. The generator checks that the Epicbox listener of `epic-wallet`
//! decodes the marked text to the same V2 slate as the plain one, so a stock receiver answers a
//! marked S1 as it answers any other.

use epic_wallet_libwallet::{Slate, SlateVersion, VersionedSlate};
use serde::Serialize;

use super::{CheckFailed, render};
use crate::{Error, Rendered, Upstream};

const PLAIN_S1: &str =
    include_str!("../../../../testdata/vectors/slates/send_epicbox_plain_s1_v2.json");

/// LEPIC's own bits: the marker (bit 0) and the address proof (bit 2), and with both host bits.
const FEATURES: [u32; 2] = [0b101, 0b11_0101];

#[derive(Serialize)]
struct Inputs {
    plain_s1: String,
    features: u32,
}

#[derive(Serialize)]
struct Expected {
    json: String,
}

fn plain_json() -> Result<String, Error> {
    let vector: serde_json::Value = serde_json::from_str(PLAIN_S1)?;
    vector
        .pointer("/expected/json")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::reference("plain s1")(CheckFailed::Plaintext))
}

fn decode(text: &str) -> Result<(SlateVersion, String), Error> {
    let versioned: VersionedSlate = serde_json::from_str(text)?;
    let version = versioned.version();
    let slate: Slate = versioned.into();
    let again = VersionedSlate::into_version(slate, SlateVersion::V2);
    Ok((version, serde_json::to_string(&again)?))
}

pub(super) fn generate(wallet: &Upstream) -> Result<Vec<Rendered>, Error> {
    let plain = plain_json()?;
    let (plain_version, plain_decoded) = decode(&plain)?;
    let body = plain
        .strip_suffix('}')
        .ok_or_else(|| Error::reference("plain s1")(CheckFailed::Plaintext))?;
    let mut vectors = Vec::new();
    for features in FEATURES {
        let json = format!("{body},\"lepic\":{{\"version\":1,\"f\":{features}}}}}");
        let (version, decoded) = decode(&json)?;
        if version != plain_version || decoded != plain_decoded {
            return Err(Error::reference("marked s1")(CheckFailed::Plaintext));
        }
        let name = format!("marker_s1_v2_features_{features}");
        vectors.push(render(
            &name,
            wallet,
            Inputs {
                plain_s1: plain.clone(),
                features,
            },
            Expected { json },
        )?);
    }
    Ok(vectors)
}
