//! Recorded node sessions in the exchange format of `testdata/vectors/README.md`, served as a
//! fixed node state.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

use super::Answer;
use crate::rpc::FOREIGN_ENDPOINT;

/// A recording that cannot be served.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FixtureError {
    #[error("recording is not valid json")]
    Json(#[source] serde_json::Error),
    #[error("recording has no exchanges")]
    NoExchanges,
    #[error("recorded {method} exchange has an unexpected shape")]
    Shape { method: String },
    #[error("recorded unspent output listing does not cover its whole window")]
    IncompleteListing,
}

#[derive(Debug, Clone, Deserialize)]
struct Exchange {
    endpoint: String,
    method: String,
    #[serde(default)]
    params: Value,
    response: Value,
}

#[derive(Debug, Default)]
struct Listing {
    first_index: u64,
    highest_index: u64,
    outputs: BTreeMap<u64, Value>,
}

/// A recorded session. Exchanges other than `get_outputs` and `get_unspent_outputs` are served
/// by equal endpoint, method and params, any number of times.
#[derive(Debug)]
pub struct Recording {
    exact: Vec<Exchange>,
    outputs: BTreeMap<String, Option<Value>>,
    listing: Option<Listing>,
}

impl Recording {
    /// Accepts a golden vector (exchanges under `expected.exchanges`) or a node fixture
    /// (exchanges at the top level).
    pub fn parse(json: &str) -> Result<Self, FixtureError> {
        let document: Value = serde_json::from_str(json).map_err(FixtureError::Json)?;
        let exchanges = document
            .pointer("/expected/exchanges")
            .or_else(|| document.get("exchanges"))
            .cloned()
            .ok_or(FixtureError::NoExchanges)?;
        let exchanges: Vec<Exchange> =
            serde_json::from_value(exchanges).map_err(FixtureError::Json)?;
        if exchanges.is_empty() {
            return Err(FixtureError::NoExchanges);
        }
        let mut recording = Self {
            exact: Vec::new(),
            outputs: BTreeMap::new(),
            listing: None,
        };
        for exchange in exchanges {
            match exchange.method.as_str() {
                "get_outputs" => recording.add_outputs(&exchange)?,
                "get_unspent_outputs" => recording.add_listing(&exchange)?,
                _ => recording.exact.push(exchange),
            }
        }
        Ok(recording)
    }

    fn add_outputs(&mut self, exchange: &Exchange) -> Result<(), FixtureError> {
        let shape = || FixtureError::Shape {
            method: exchange.method.clone(),
        };
        let requested = exchange
            .params
            .get(0)
            .and_then(Value::as_array)
            .ok_or_else(shape)?;
        let found = exchange
            .response
            .pointer("/result/Ok")
            .and_then(Value::as_array)
            .ok_or_else(shape)?;
        for commit in requested {
            let commit = commit.as_str().ok_or_else(shape)?.to_ascii_lowercase();
            let output = found
                .iter()
                .find(|output| {
                    output
                        .get("commit")
                        .and_then(Value::as_str)
                        .is_some_and(|found| found.eq_ignore_ascii_case(&commit))
                })
                .cloned();
            self.outputs.insert(commit, output);
        }
        Ok(())
    }

    fn add_listing(&mut self, exchange: &Exchange) -> Result<(), FixtureError> {
        let shape = || FixtureError::Shape {
            method: exchange.method.clone(),
        };
        let start = exchange
            .params
            .get(0)
            .and_then(Value::as_u64)
            .ok_or_else(shape)?;
        let ok = exchange.response.pointer("/result/Ok").ok_or_else(shape)?;
        let highest = ok
            .get("highest_index")
            .and_then(Value::as_u64)
            .ok_or_else(shape)?;
        let last = ok
            .get("last_retrieved_index")
            .and_then(Value::as_u64)
            .ok_or_else(shape)?;
        if last != highest {
            return Err(FixtureError::IncompleteListing);
        }
        let outputs = ok
            .get("outputs")
            .and_then(Value::as_array)
            .ok_or_else(shape)?;
        let listing = self.listing.get_or_insert_with(|| Listing {
            first_index: start,
            ..Listing::default()
        });
        listing.first_index = listing.first_index.min(start);
        listing.highest_index = listing.highest_index.max(highest);
        for output in outputs {
            let index = output
                .get("mmr_index")
                .and_then(Value::as_u64)
                .ok_or_else(shape)?;
            listing.outputs.insert(index, output.clone());
        }
        Ok(())
    }

    pub(super) fn answer(&self, method: &str, params: &Value) -> Answer {
        match method {
            "get_outputs" => self.answer_outputs(params),
            "get_unspent_outputs" => self.answer_unspent(params),
            _ => self
                .exact
                .iter()
                .find(|exchange| {
                    exchange.endpoint == FOREIGN_ENDPOINT
                        && exchange.method == method
                        && exchange.params == *params
                })
                .map_or(
                    Answer::Violation("no recorded exchange matches"),
                    |exchange| Answer::Response(exchange.response.clone()),
                ),
        }
    }

    fn answer_outputs(&self, params: &Value) -> Answer {
        let Some(requested) = params.get(0).and_then(Value::as_array) else {
            return Answer::Violation("get_outputs without a commitment list");
        };
        let mut found = Vec::new();
        for commit in requested {
            let Some(commit) = commit.as_str() else {
                return Answer::Violation("get_outputs with a commitment that is not a string");
            };
            match self.outputs.get(&commit.to_ascii_lowercase()) {
                Some(Some(output)) => found.push(output.clone()),
                Some(None) => {}
                None => return Answer::Violation("get_outputs for a commitment never recorded"),
            }
        }
        Answer::Ok(Value::Array(found))
    }

    fn answer_unspent(&self, params: &Value) -> Answer {
        let Some(listing) = &self.listing else {
            return Answer::Violation("no unspent output listing recorded");
        };
        let start = params.get(0).and_then(Value::as_u64);
        let end = params.get(1).map(Value::as_u64);
        let max = params.get(2).and_then(Value::as_u64);
        let (Some(start), Some(end), Some(max)) = (start, end, max) else {
            return Answer::Violation("get_unspent_outputs with unexpected params");
        };
        let end = end.unwrap_or(listing.highest_index);
        if start < listing.first_index || end > listing.highest_index {
            return Answer::Violation("get_unspent_outputs window outside the recorded listing");
        }
        Answer::Ok(window(&listing.outputs, start, end, max))
    }
}

/// The node's answer to `get_unspent_outputs` over a complete listing: at most `max` outputs
/// in `start..=end`, with `last_retrieved_index` at the last one returned when `max` cut the
/// window short.
pub(super) fn window(outputs: &BTreeMap<u64, Value>, start: u64, end: u64, max: u64) -> Value {
    let take = usize::try_from(max).unwrap_or(usize::MAX);
    let mut selected = Vec::new();
    let mut last_retrieved = end;
    if start <= end {
        let mut in_window = outputs.range(start..=end);
        for (index, output) in in_window.by_ref().take(take) {
            selected.push(output.clone());
            last_retrieved = *index;
        }
        if in_window.next().is_none() {
            last_retrieved = end;
        }
    }
    json!({
        "highest_index": end,
        "last_retrieved_index": last_retrieved,
        "outputs": selected,
    })
}
