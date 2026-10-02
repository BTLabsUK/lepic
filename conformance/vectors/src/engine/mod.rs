//! Engine area: output selection, and the node responses of restore and refresh sessions on an
//! upstream in-process test chain, with the wallet state upstream ends in.
//!
//! Every case drives an upstream `epic-wallet` v4.0.2 instance through its public API. Restore
//! and refresh cases record each JSON-RPC exchange between upstream's `HTTPNodeClient` and the
//! node's own foreign API handlers, then replay the recording into a second upstream wallet that
//! starts from the same state and must reach the same end state.

mod chain;
mod history;
mod node;
mod selection;
mod wallet;

use crate::{Error, LOCKFILE, Pins, Rendered, Upstream, git_source};

const AREA: &str = "engine";

#[derive(Debug, thiserror::Error)]
pub(crate) enum Failure {
    #[error("upstream wallet call failed")]
    Wallet(#[source] epic_wallet_libwallet::Error),
    #[error("upstream call failed")]
    Upstream(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("scratch i/o failed")]
    Io(#[source] std::io::Error),
    #[error("arithmetic overflow while building a case")]
    Overflow,
    #[error("upstream wallet could not reach the node during {0}")]
    NodeUnreachable(&'static str),
    #[error("test chain story failed: {0}")]
    Story(&'static str),
    #[error("replay of {case} diverged from the recording: {detail}")]
    Replay { case: String, detail: String },
    #[error("selection case {case} did not behave as its description says: {detail}")]
    Selection { case: &'static str, detail: String },
    #[error("vector rendering failed")]
    Render(#[source] Box<Error>),
}

impl Failure {
    pub(crate) fn upstream<E: std::error::Error + Send + Sync + 'static>(error: E) -> Failure {
        Failure::Upstream(Box::new(error))
    }

    /// For upstream errors that implement only `Debug`.
    pub(crate) fn described<E: std::fmt::Debug>(error: E) -> Failure {
        Failure::Upstream(format!("{error:?}").into())
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure::Render(Box::new(error))
    }
}

pub(crate) fn generate(_pins: &Pins) -> Result<Vec<Rendered>, Error> {
    // The cases run wallet code, which pins the node commit it links in its own lockfile.
    let wallet = git_source(LOCKFILE, "epic_wallet_libwallet")?;
    let mut vectors = selection::generate(&wallet).map_err(Error::reference("engine selection"))?;
    vectors.extend(history::generate(&wallet).map_err(Error::reference("engine history"))?);
    Ok(vectors)
}

fn render<I: serde::Serialize, E: serde::Serialize>(
    name: &str,
    upstream: &Upstream,
    inputs: I,
    expected: E,
) -> Result<Rendered, Failure> {
    Ok(crate::render(AREA, name, upstream, inputs, expected)?)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::DEFAULT_OUT;

    #[test]
    fn regenerated_vectors_match_committed_files() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        for vector in generate(&pins)? {
            let path = Path::new(DEFAULT_OUT)
                .join(AREA)
                .join(format!("{}.json", vector.name));
            assert_eq!(std::fs::read(&path)?, vector.bytes, "{}", path.display());
        }
        Ok(())
    }
}
