//! The JSON-RPC node client, generic over how requests reach a node.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures_util::stream::{self, StreamExt, TryStreamExt};
use lepic_crypto::Commitment;
use lepic_primitives::amount::Height;
use lepic_primitives::tx::Transaction;
use serde_json::{Value, json};
use tracing::{Instrument, Span, debug, info_span, warn};

use crate::api::{
    LocatedKernel, NodeApi, NodeVersion, OutputLocation, PmmrIndices, Propagation, Tip,
    UnspentOutputs,
};
use crate::decode;
use crate::error::{ErrorChain, FieldProblem, NodeError};
use crate::plausible;
use crate::rpc::{FOREIGN_ENDPOINT, encode_request};
use crate::wire::WireTransaction;

/// Delivers one serialized JSON-RPC request to a node and returns the response body.
///
/// Implementations bound what they read; the client validates what it gets.
pub trait RpcTransport: Send + Sync {
    fn post(
        &self,
        endpoint: &'static str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, NodeError>> + Send;

    /// The node host, for logs. Never carries credentials.
    fn node_label(&self) -> &str;
}

/// Retries for reads that failed in a way repeating may fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total tries, including the first. One means no retry.
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl RetryPolicy {
    pub const NONE: Self = Self {
        max_attempts: 1,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
    };

    fn backoff_before(&self, attempt: u32) -> Duration {
        let doublings = attempt.saturating_sub(2).min(16);
        self.initial_backoff
            .saturating_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
            .min(self.max_backoff)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(4),
        }
    }
}

/// How the client spreads and repeats work. Transport limits (sizes, timeouts) live with the
/// transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallPolicy {
    pub retry: RetryPolicy,
    /// Commitments per `get_outputs` request. Upstream uses 500.
    pub outputs_per_request: usize,
    /// `get_outputs` requests in flight at once.
    pub max_concurrent_requests: usize,
}

impl Default for CallPolicy {
    fn default() -> Self {
        Self {
            retry: RetryPolicy::default(),
            outputs_per_request: 500,
            max_concurrent_requests: 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Idempotency {
    Read,
    Write,
}

/// A [`NodeApi`] over any [`RpcTransport`].
///
/// The client remembers the highest tip it accepted. A later tip implausibly far above it is
/// refused with [`NodeError::ImplausibleTip`], and outputs or kernels in blocks above it are
/// refused unless a fresh tip covers them. Clones share what was seen.
#[derive(Debug, Clone)]
pub struct NodeClient<T> {
    transport: T,
    policy: CallPolicy,
    highest_tip: Arc<Mutex<Option<SeenTip>>>,
}

#[derive(Debug, Clone, Copy)]
struct SeenTip {
    height: Height,
    first_seen: Instant,
}

impl<T: RpcTransport> NodeClient<T> {
    pub fn new(transport: T, policy: CallPolicy) -> Self {
        Self {
            transport,
            policy,
            highest_tip: Arc::new(Mutex::new(None)),
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn seen_tip(&self) -> MutexGuard<'_, Option<SeenTip>> {
        self.highest_tip
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    async fn fetch_tip(&self) -> Result<Tip, NodeError> {
        let body = self
            .call("get_tip", &Value::Null, Idempotency::Read)
            .await?;
        let tip = decode::tip(&body)?;
        self.accept_tip(tip.height)?;
        Ok(tip)
    }

    // A lower tip is accepted without becoming the reference: a reorganisation or a node that is
    // slightly behind reports one honestly, and keeping the higher reference keeps the bound
    // from being walked down and then up again.
    fn accept_tip(&self, reported: Height) -> Result<(), NodeError> {
        let now = Instant::now();
        let mut seen = self.seen_tip();
        if let Some(previous) = *seen {
            let elapsed = now.saturating_duration_since(previous.first_seen);
            if reported > plausible::max_tip_after(previous.height, elapsed) {
                return Err(NodeError::ImplausibleTip {
                    previous: previous.height,
                    reported,
                });
            }
            if reported <= previous.height {
                return Ok(());
            }
        }
        *seen = Some(SeenTip {
            height: reported,
            first_seen: now,
        });
        Ok(())
    }

    /// Refuses a block height above the tip. A height above the remembered tip may come from a
    /// block found since, so the tip is asked for again before refusing.
    async fn ensure_not_above_tip(
        &self,
        method: &'static str,
        field: &'static str,
        highest: Option<Height>,
    ) -> Result<(), NodeError> {
        let Some(highest) = highest else {
            return Ok(());
        };
        let covered = |client: &Self| client.seen_tip().is_some_and(|tip| highest <= tip.height);
        if covered(self) {
            return Ok(());
        }
        self.fetch_tip().await?;
        if covered(self) {
            return Ok(());
        }
        Err(NodeError::invalid(method, field, FieldProblem::AboveTip))
    }

    /// Posts one request and returns the response body, retrying transient failures of reads.
    async fn call(
        &self,
        method: &'static str,
        params: &Value,
        idempotency: Idempotency,
    ) -> Result<Vec<u8>, NodeError> {
        let span = call_span(method, self.transport.node_label());
        self.call_with_retries(method, params, idempotency)
            .instrument(span)
            .await
    }

    async fn call_with_retries(
        &self,
        method: &'static str,
        params: &Value,
        idempotency: Idempotency,
    ) -> Result<Vec<u8>, NodeError> {
        let body = encode_request(method, params)?;
        let max_attempts = match idempotency {
            Idempotency::Read => self.policy.retry.max_attempts.max(1),
            Idempotency::Write => 1,
        };
        let mut attempt = 1;
        loop {
            let started = Instant::now();
            let outcome = self.transport.post(FOREIGN_ENDPOINT, body.clone()).await;
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match outcome {
                Ok(response) => {
                    debug!(attempt, elapsed_ms, "node call answered");
                    return Ok(response);
                }
                Err(error) if error.is_transient() && attempt < max_attempts => {
                    warn!(attempt, elapsed_ms, error = %ErrorChain(&error), "node call failed, retrying");
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(self.policy.retry.backoff_before(attempt)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn get_outputs_chunk(
        &self,
        chunk: &[Commitment],
    ) -> Result<Vec<OutputLocation>, NodeError> {
        let hex: Vec<String> = chunk.iter().map(Commitment::to_hex).collect();
        let params = json!([hex, null, null, false, false]);
        let body = self.call("get_outputs", &params, Idempotency::Read).await?;
        let requested: BTreeSet<Commitment> = chunk.iter().copied().collect();
        decode::outputs(&body, &requested)
    }
}

// Span names must be literals; naming each span after its method keeps the method out of the
// field vocabulary.
fn call_span(method: &str, node: &str) -> Span {
    match method {
        "get_version" => info_span!("get_version", node),
        "get_tip" => info_span!("get_tip", node),
        "get_kernel" => info_span!("get_kernel", node),
        "get_outputs" => info_span!("get_outputs", node),
        "get_unspent_outputs" => info_span!("get_unspent_outputs", node),
        "get_pmmr_indices" => info_span!("get_pmmr_indices", node),
        "push_transaction" => info_span!("push_transaction", node),
        _ => info_span!("node_call", node),
    }
}

impl<T: RpcTransport> NodeApi for NodeClient<T> {
    async fn get_version(&self) -> Result<NodeVersion, NodeError> {
        let body = self
            .call("get_version", &Value::Null, Idempotency::Read)
            .await?;
        decode::version(&body)
    }

    async fn get_tip(&self) -> Result<Tip, NodeError> {
        self.fetch_tip().await
    }

    async fn get_kernel(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> Result<Option<LocatedKernel>, NodeError> {
        const METHOD: &str = "get_kernel";
        let params = json!([
            excess.to_hex(),
            min_height.map(Height::value),
            max_height.map(Height::value),
        ]);
        let body = self.call(METHOD, &params, Idempotency::Read).await?;
        let kernel = decode::kernel(&body, excess, min_height, max_height)?;
        let height = kernel.as_ref().map(|located| located.height);
        self.ensure_not_above_tip(METHOD, "height", height).await?;
        Ok(kernel)
    }

    async fn get_outputs(
        &self,
        commitments: &[Commitment],
    ) -> Result<Vec<OutputLocation>, NodeError> {
        let unique: Vec<Commitment> = commitments
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let chunk_size = self.policy.outputs_per_request.max(1);
        let concurrency = self.policy.max_concurrent_requests.max(1);
        let requests: Vec<_> = unique
            .chunks(chunk_size)
            .map(|chunk| self.get_outputs_chunk(chunk))
            .collect();
        let chunks: Vec<Vec<OutputLocation>> = stream::iter(requests)
            .buffer_unordered(concurrency)
            .try_collect()
            .await?;
        let outputs: Vec<OutputLocation> = chunks.into_iter().flatten().collect();
        let highest = outputs.iter().map(|output| output.height).max();
        self.ensure_not_above_tip("get_outputs", "block_height", highest)
            .await?;
        Ok(outputs)
    }

    async fn get_unspent_outputs(
        &self,
        start_index: u64,
        end_index: Option<u64>,
        max: u64,
    ) -> Result<UnspentOutputs, NodeError> {
        const METHOD: &str = "get_unspent_outputs";
        let params = json!([start_index, end_index, max, true]);
        let body = self.call(METHOD, &params, Idempotency::Read).await?;
        let page = decode::unspent_outputs(&body, start_index, end_index, max)?;
        let highest = page.outputs.iter().map(|output| output.height).max();
        self.ensure_not_above_tip(METHOD, "block_height", highest)
            .await?;
        Ok(page)
    }

    async fn get_pmmr_indices(
        &self,
        start_height: Height,
        end_height: Option<Height>,
    ) -> Result<PmmrIndices, NodeError> {
        let params = json!([start_height.value(), end_height.map(Height::value)]);
        let body = self
            .call("get_pmmr_indices", &params, Idempotency::Read)
            .await?;
        decode::pmmr_indices(&body)
    }

    async fn push_transaction(
        &self,
        transaction: &Transaction,
        propagation: Propagation,
    ) -> Result<(), NodeError> {
        const METHOD: &str = "push_transaction";
        let fluff = propagation == Propagation::Fluff;
        let transaction =
            serde_json::to_value(WireTransaction::from(transaction)).map_err(|source| {
                NodeError::EncodeRequest {
                    method: METHOD,
                    source,
                }
            })?;
        let params = Value::Array(vec![transaction, Value::Bool(fluff)]);
        let body = self.call(METHOD, &params, Idempotency::Write).await?;
        decode::push_transaction(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let policy = RetryPolicy {
            max_attempts: 6,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(350),
        };
        let waits: Vec<_> = (2..=5)
            .map(|attempt| policy.backoff_before(attempt))
            .collect();
        assert_eq!(
            waits,
            [100, 200, 350, 350].map(Duration::from_millis).to_vec()
        );
    }
}
