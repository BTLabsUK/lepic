//! The scripted node of `mock` builds, which the Dart package tests drive through
//! `crate::api::testing`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use lepic_keychain::proof::create_output;
use lepic_keychain::{Identifier, Keychain, ProofBuilder, SwitchCommitment};
use lepic_node::mock::{ChainOutput, ChainState, MockNode};
use lepic_node::{
    CallPolicy, LocatedKernel, NodeClient, NodeError, NodeVersion, RetryPolicy, RpcTransport, Tip,
};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::params::Network;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::node::{Node, NodeBackend};

/// How often a request to a stalled node checks whether the node answers again.
const STALL_POLL: Duration = Duration::from_millis(10);

#[derive(Clone)]
pub(crate) struct MockBackend {
    node: MockNode,
    panic_next: Arc<AtomicBool>,
    unreachable: Arc<AtomicBool>,
    stalled: Arc<AtomicBool>,
    stalled_calls: Arc<AtomicU64>,
    lose_post_reply: Arc<AtomicBool>,
}

impl MockBackend {
    pub(crate) fn new(height: u64) -> Result<Self, WalletError> {
        let hash = Hash::from_slice(&[0; 32]).map_err(|_| invalid("block hash"))?;
        let chain = ChainState::new(
            NodeVersion {
                node_version: "4.0.4".to_owned(),
                block_header_version: 7,
            },
            Tip {
                height: Height::new(height),
                last_block_pushed: hash,
            },
        );
        Ok(Self {
            node: MockNode::from_chain(chain),
            panic_next: Arc::default(),
            unreachable: Arc::default(),
            stalled: Arc::default(),
            stalled_calls: Arc::default(),
            lose_post_reply: Arc::default(),
        })
    }

    pub(crate) fn client(&self) -> Node {
        NodeClient::new(
            NodeBackend::Mock(self.clone()),
            CallPolicy {
                retry: RetryPolicy::NONE,
                ..CallPolicy::default()
            },
        )
    }

    // The point of this hook is a panic inside an engine operation, so the binding's panic
    // boundary can be tested from Dart.
    #[allow(clippy::panic)]
    pub(crate) async fn post(
        &self,
        endpoint: &'static str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, NodeError> {
        if self.panic_next.swap(false, Ordering::SeqCst) {
            panic!("mock node asked to panic");
        }
        if self.unreachable.load(Ordering::SeqCst) {
            return Err(NodeError::Connect(Box::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused,
            ))));
        }
        if self.stalled.load(Ordering::SeqCst) {
            self.stalled_calls.fetch_add(1, Ordering::SeqCst);
            while self.stalled.load(Ordering::SeqCst) {
                tokio::time::sleep(STALL_POLL).await;
            }
        }
        let is_post = contains(&body, b"push_transaction");
        let reply = self.node.post(endpoint, body).await;
        if is_post && self.lose_post_reply.swap(false, Ordering::SeqCst) {
            return Err(NodeError::Connect(Box::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            ))));
        }
        reply
    }

    pub(crate) fn node_label(&self) -> &str {
        self.node.node_label()
    }

    pub(crate) fn panic_on_next_call(&self) {
        self.panic_next.store(true, Ordering::SeqCst);
    }

    pub(crate) fn set_unreachable(&self, unreachable: bool) {
        self.unreachable.store(unreachable, Ordering::SeqCst);
    }

    pub(crate) fn set_stalled(&self, stalled: bool) {
        self.stalled.store(stalled, Ordering::SeqCst);
    }

    /// Node requests that waited on a stalled node, counted when they start waiting.
    pub(crate) fn stalled_calls(&self) -> u64 {
        self.stalled_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn lose_next_post_reply(&self) {
        self.lose_post_reply.store(true, Ordering::SeqCst);
    }

    pub(crate) fn height(&self) -> u64 {
        let mut height = 0;
        self.node
            .update_chain(|chain| height = chain.tip.height.value());
        height
    }

    pub(crate) fn set_height(&self, height: u64) {
        self.node
            .update_chain(|chain| chain.tip.height = Height::new(height));
    }

    pub(crate) fn pushed_count(&self) -> usize {
        self.node.pushed_transactions().len()
    }

    /// Puts every transaction pushed so far into the node's transaction pool.
    pub(crate) fn pool_pushed(&self) {
        let pushed = self.node.pushed_transactions();
        self.node.update_chain(|chain| chain.pool = pushed);
    }

    /// Adds a plain output of `amount` for key `m/0/0/<child>` of the wallet with `phrase`, mined
    /// in the tip block.
    pub(crate) fn fund(
        &self,
        phrase: &str,
        network: Network,
        amount: u64,
        child: u32,
    ) -> Result<(), WalletError> {
        let keychain =
            Keychain::from_mnemonic(phrase, network).map_err(|_| invalid("recovery phrase"))?;
        let id = Identifier::new(3, [0, 0, child, 0]).map_err(|_| invalid("key path"))?;
        let builder = ProofBuilder::new(&keychain).map_err(|_| invalid("proof builder"))?;
        let output = create_output(&keychain, &builder, amount, &id, SwitchCommitment::Regular)
            .map_err(|_| invalid("output"))?;
        self.node.update_chain(|chain| {
            let mmr_index = next_mmr_index(chain);
            chain.outputs.push(ChainOutput {
                commitment: output.commitment,
                features: output.features,
                proof: output.proof,
                height: chain.tip.height,
                mmr_index,
                spent: false,
            });
        });
        Ok(())
    }

    /// Mines every transaction pushed so far into the tip block: spends their inputs and adds
    /// their outputs and kernels.
    pub(crate) fn mine_pushed(&self) {
        let pushed = self.node.pushed_transactions();
        self.node.update_chain(|chain| {
            let height = chain.tip.height;
            for transaction in &pushed {
                for input in transaction.inputs() {
                    for output in &mut chain.outputs {
                        if output.commitment == input.commitment {
                            output.spent = true;
                        }
                    }
                }
                for output in transaction.outputs() {
                    if chain
                        .outputs
                        .iter()
                        .any(|known| known.commitment == output.commitment)
                    {
                        continue;
                    }
                    let mmr_index = next_mmr_index(chain);
                    chain.outputs.push(ChainOutput {
                        commitment: output.commitment,
                        features: output.features,
                        proof: output.proof.clone(),
                        height,
                        mmr_index,
                        spent: false,
                    });
                }
                for kernel in transaction.kernels() {
                    if chain.kernels.iter().any(|known| known.kernel == *kernel) {
                        continue;
                    }
                    let mmr_index = u64::try_from(chain.kernels.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                    chain.kernels.push(LocatedKernel {
                        kernel: *kernel,
                        height,
                        mmr_index,
                    });
                }
            }
        });
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn next_mmr_index(chain: &ChainState) -> u64 {
    chain
        .outputs
        .iter()
        .map(|output| output.mmr_index)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn invalid(what: &str) -> WalletError {
    WalletError::new(
        WalletErrorKind::InvalidArgument,
        format!("mock chain rejected the {what}"),
    )
}
