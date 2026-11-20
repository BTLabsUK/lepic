// SPDX-License-Identifier: Apache-2.0
//! Primitives and aggsig areas: binary layouts, hashes, kernel signature messages, weights, fees,
//! chain parameters, transaction validation outcomes and the two-party signature flow, computed by
//! the node code with fixed keys and nonces so every file regenerates byte for byte.

mod aggsig;
mod build;
mod chain;
mod fixtures;
mod hash;
mod ser;
mod tx;
mod validate;

use epic_core::global::{self, ChainTypes};

use crate::{Error, Pins, Rendered, chain_type_guard};

const AREA: &str = "primitives";
const AGGSIG_AREA: &str = "aggsig";

pub(crate) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    // Weight limits read the chain type; every case except the per-network ones runs on mainnet.
    let _chain_type = chain_type_guard();
    global::set_mining_mode(ChainTypes::Mainnet);
    let mut rendered = ser::generate(pins)?;
    rendered.extend(hash::generate(pins)?);
    rendered.extend(tx::generate(pins)?);
    rendered.extend(chain::generate(pins)?);
    rendered.extend(validate::generate(pins)?);
    Ok(rendered)
}

pub(crate) fn generate_aggsig(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    aggsig::generate(pins)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{DEFAULT_OUT, LOCKFILE};

    fn assert_matches_committed(
        area: &str,
        vectors: Vec<Rendered>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = Path::new(DEFAULT_OUT).join(area);
        let mut committed: Vec<String> = std::fs::read_dir(&dir)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .filter_map(|path| Some(path.file_stem()?.to_str()?.to_owned()))
            .collect();
        committed.sort();
        let mut produced: Vec<String> = vectors.iter().map(|v| v.name.clone()).collect();
        produced.sort();
        assert_eq!(committed, produced, "{}", dir.display());
        for vector in vectors {
            let path = dir.join(format!("{}.json", vector.name));
            assert_eq!(std::fs::read(&path)?, vector.bytes, "{}", path.display());
        }
        Ok(())
    }

    #[test]
    fn regenerated_primitives_vectors_match_committed_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        assert_matches_committed(AREA, generate(&pins)?)
    }

    #[test]
    fn regenerated_aggsig_vectors_match_committed_files() -> Result<(), Box<dyn std::error::Error>>
    {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        assert_matches_committed(AGGSIG_AREA, generate_aggsig(&pins)?)
    }
}
