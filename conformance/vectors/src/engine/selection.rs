//! Output selection cases: a stated UTXO set in an upstream wallet, then upstream's fee estimate
//! and upstream's send-slate selection for one request.
//!
//! The node is a fixed answer, not a chain: it reports the case's tip, and reports exactly the
//! case's on-chain outputs (status `Unspent` or `Locked`) as present. Upstream refreshes those
//! before selecting, so this keeps the stated UTXO set unchanged through the refresh.

use std::collections::HashMap;
use std::sync::Arc;

use epic_core::core::Transaction;
use epic_core::libtx::tx_fee;
use epic_keychain::Identifier;
use epic_util::Mutex;
use epic_util::secp::pedersen::Commitment;
use epic_wallet_libwallet::api_impl::owner;
use epic_wallet_libwallet::{
    Error as WalletError, InitTxArgs, NodeClient, NodeStatus, NodeVersionInfo, OutputData,
    OutputStatus, PoolEntry,
};
use serde::Serialize;

use super::chain::{ScratchDir, use_test_chain_settings};
use super::wallet::UpstreamWallet;
use super::{Failure, render};
use crate::{Rendered, Upstream, hex};

const EPIC: u64 = 100_000_000;
const MNEMONIC_ENTROPY: [u8; 32] = [0x5e; 32];

#[derive(Clone, Copy, Debug)]
enum Status {
    Unspent,
    Unconfirmed,
    Locked,
}

impl Status {
    fn upstream(self) -> OutputStatus {
        match self {
            Status::Unspent => OutputStatus::Unspent,
            Status::Unconfirmed => OutputStatus::Unconfirmed,
            Status::Locked => OutputStatus::Locked,
        }
    }

    fn on_chain(self) -> bool {
        matches!(self, Status::Unspent | Status::Locked)
    }
}

#[derive(Clone, Copy)]
struct Utxo {
    value: u64,
    height: u64,
    coinbase: bool,
    status: Status,
}

const fn plain(value: u64, height: u64) -> Utxo {
    Utxo {
        value,
        height,
        coinbase: false,
        status: Status::Unspent,
    }
}

const fn coinbase(value: u64, height: u64) -> Utxo {
    Utxo {
        value,
        height,
        coinbase: true,
        status: Status::Unspent,
    }
}

const fn with_status(utxo: Utxo, status: Status) -> Utxo {
    Utxo { status, ..utxo }
}

struct Case {
    name: &'static str,
    description: &'static str,
    tip: u64,
    utxos: &'static [Utxo],
    amount: u64,
    minimum_confirmations: u64,
    max_outputs: u32,
    num_change_outputs: u32,
    use_all: bool,
}

const MIXED: &[Utxo] = &[
    plain(5 * EPIC, 3),
    plain(EPIC, 4),
    plain(3 * EPIC, 5),
    plain(10 * EPIC, 6),
];

const SINGLE: &[Utxo] = &[plain(4 * EPIC, 2)];

const YOUNG: &[Utxo] = &[
    plain(2 * EPIC, 17),
    plain(EPIC, 18),
    plain(3 * EPIC, 19),
    plain(4 * EPIC, 20),
];

const COINBASE: &[Utxo] = &[coinbase(8 * EPIC, 10), coinbase(7 * EPIC, 18)];

const UNAVAILABLE: &[Utxo] = &[
    with_status(plain(EPIC, 5), Status::Locked),
    with_status(plain(2 * EPIC, 6), Status::Unconfirmed),
    plain(6 * EPIC, 7),
];

const MANY_SMALL: &[Utxo] = &[
    plain(EPIC, 2),
    plain(2 * EPIC, 3),
    plain(3 * EPIC, 4),
    plain(4 * EPIC, 5),
    plain(5 * EPIC, 6),
];

const EQUAL: &[Utxo] = &[plain(2 * EPIC, 4), plain(2 * EPIC, 3), plain(2 * EPIC, 5)];

const CASES: &[Case] = &[
    Case {
        name: "selection_smallest",
        description: "Smallest first, as many as the amount needs, one change output.",
        tip: 20,
        utxos: MIXED,
        amount: 2 * EPIC,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_all",
        description: "The \"all\" strategy spends every eligible output.",
        tip: 20,
        utxos: MIXED,
        amount: 2 * EPIC,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: true,
    },
    Case {
        name: "selection_exact_no_change",
        description: "The input covers amount plus the one-input, one-output fee exactly, so no \
                      change output is built.",
        tip: 20,
        utxos: SINGLE,
        amount: 4 * EPIC - FEE_1_IN_1_OUT,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_three_change_outputs",
        description: "Change split over three outputs; the last takes the remainder.",
        tip: 20,
        utxos: MIXED,
        amount: 2 * EPIC + 1,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 3,
        use_all: false,
    },
    Case {
        name: "selection_minimum_confirmations",
        description: "With ten blocks of confirmations required, only outputs at or below height \
                      11 at tip 20 are eligible.",
        tip: 20,
        utxos: &[
            plain(2 * EPIC, 17),
            plain(EPIC, 18),
            plain(9 * EPIC, 11),
            plain(3 * EPIC, 12),
        ],
        amount: 2 * EPIC,
        minimum_confirmations: 10,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_not_enough_confirmed",
        description: "Every output is too young for the required confirmations.",
        tip: 20,
        utxos: YOUNG,
        amount: EPIC,
        minimum_confirmations: 10,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_coinbase_maturity",
        description: "A coinbase output whose lock height is above the tip is not eligible, even \
                      though it is smaller.",
        tip: 20,
        utxos: COINBASE,
        amount: EPIC,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_locked_and_unconfirmed_excluded",
        description: "Locked outputs and unconfirmed outputs are not eligible with one required \
                      confirmation.",
        tip: 20,
        utxos: UNAVAILABLE,
        amount: EPIC / 2,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: true,
    },
    Case {
        name: "selection_unconfirmed_with_zero_confirmations",
        description: "With zero required confirmations an unconfirmed plain output is eligible; a \
                      locked one still is not.",
        tip: 20,
        utxos: UNAVAILABLE,
        amount: EPIC / 2,
        minimum_confirmations: 0,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: true,
    },
    Case {
        name: "selection_max_outputs_window",
        description: "With at most two inputs, the first window of two consecutive outputs by \
                      value that covers the amount is used.",
        tip: 20,
        utxos: MANY_SMALL,
        amount: 6 * EPIC,
        minimum_confirmations: 1,
        max_outputs: 2,
        num_change_outputs: 1,
        use_all: true,
    },
    Case {
        name: "selection_max_outputs_exceeded",
        description: "No window of two covers the amount, so selection goes past the maximum, \
                      smallest first.",
        tip: 20,
        utxos: MANY_SMALL,
        amount: 10 * EPIC,
        minimum_confirmations: 1,
        max_outputs: 2,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_fee_needs_another_input",
        description: "The input covers the amount but not amount plus fee, so a second input is \
                      selected.",
        tip: 20,
        utxos: &[plain(4 * EPIC, 2), plain(EPIC, 3)],
        amount: 4 * EPIC,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_not_enough_funds",
        description: "The eligible total is below amount plus fee.",
        tip: 20,
        utxos: MIXED,
        amount: 19 * EPIC,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
    Case {
        name: "selection_equal_values",
        description: "Outputs of equal value keep the order upstream stores them in, which is the \
                      order they were added.",
        tip: 20,
        utxos: EQUAL,
        amount: 3 * EPIC,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        use_all: false,
    },
];

/// The fee of a transaction with one input, one output and one kernel; cross-checked against
/// upstream's `tx_fee` before any case runs.
const FEE_1_IN_1_OUT: u64 = 400_000;

#[derive(Serialize)]
struct UtxoInput {
    index: usize,
    n_child: u32,
    key_id: String,
    commit: String,
    value: String,
    height: String,
    lock_height: String,
    is_coinbase: bool,
    status: String,
}

#[derive(Serialize)]
struct Inputs {
    description: &'static str,
    mnemonic: String,
    tip_height: String,
    coinbase_maturity: String,
    utxos: Vec<UtxoInput>,
    amount: String,
    minimum_confirmations: String,
    max_outputs: u32,
    num_change_outputs: u32,
    strategy: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Selected {
        amount: String,
        fee: String,
        total: String,
        inputs: Vec<usize>,
        change: Vec<Change>,
    },
    NotEnoughFunds {
        available: String,
        needed: String,
    },
}

#[derive(Serialize)]
struct Change {
    n_child: u32,
    key_id: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Estimate {
    Estimated { total: String, fee: String },
    NotEnoughFunds { available: String, needed: String },
}

#[derive(Serialize)]
struct Expected {
    estimate: Estimate,
    send: Outcome,
}

pub(crate) fn generate(upstream: &Upstream) -> Result<Vec<Rendered>, Failure> {
    let _chain_type = crate::chain_type_guard();
    let scratch = ScratchDir::new("engine-selection")?;
    use_test_chain_settings(scratch.path());
    if tx_fee(1, 1, 1, None) != FEE_1_IN_1_OUT {
        return Err(Failure::Selection {
            case: "selection_exact_no_change",
            detail: format!("upstream fee is {}", tx_fee(1, 1, 1, None)),
        });
    }
    let mnemonic = epic_keychain::mnemonic::from_entropy(&MNEMONIC_ENTROPY.to_vec())
        .map_err(Failure::described)?;
    CASES
        .iter()
        .map(|case| run(upstream, &scratch, &mnemonic, case))
        .collect()
}

fn run(
    upstream: &Upstream,
    scratch: &ScratchDir,
    mnemonic: &str,
    case: &Case,
) -> Result<Rendered, Failure> {
    let node = StaticNode::new(case.tip);
    let wallet = UpstreamWallet::restore(&scratch.path().join(case.name), mnemonic, node.clone())?;
    let utxos = store_utxos(&wallet, &node, case)?;
    let args = InitTxArgs {
        amount: case.amount,
        minimum_confirmations: case.minimum_confirmations,
        max_outputs: case.max_outputs,
        num_change_outputs: case.num_change_outputs,
        selection_strategy_is_use_all: case.use_all,
        ..Default::default()
    };

    let estimate_args = InitTxArgs {
        estimate_only: Some(true),
        ..args.clone()
    };
    // Selection draws nothing the vectors record, so the test RNG and its process-wide slate
    // counter are not used here.
    let estimate = match wallet.with(|w| owner::init_send_tx(&mut *w, None, estimate_args, false)) {
        Ok(slate) => Estimate::Estimated {
            total: slate.amount.to_string(),
            fee: slate.fee.to_string(),
        },
        Err(Failure::Wallet(WalletError::NotEnoughFunds {
            available, needed, ..
        })) => Estimate::NotEnoughFunds {
            available: available.to_string(),
            needed: needed.to_string(),
        },
        Err(other) => return Err(other),
    };

    let send = match wallet.with(|w| {
        let slate = owner::init_send_tx(&mut *w, None, args, false)?;
        let context = w.get_private_context(None, slate.id.as_bytes(), 0)?;
        Ok((slate, context))
    }) {
        Ok((slate, context)) => {
            let inputs = context
                .input_ids
                .iter()
                .map(|(key_id, _, _)| index_of(&utxos, key_id, case.name))
                .collect::<Result<Vec<_>, _>>()?;
            let change = context
                .output_ids
                .iter()
                .map(|(key_id, _, value)| Change {
                    n_child: key_id.to_path().last_path_index(),
                    key_id: key_id.to_hex(),
                    value: value.to_string(),
                })
                .collect();
            let total = context
                .input_ids
                .iter()
                .try_fold(0u64, |sum, (_, _, value)| sum.checked_add(*value))
                .ok_or(Failure::Overflow)?;
            Outcome::Selected {
                amount: slate.amount.to_string(),
                fee: slate.fee.to_string(),
                total: total.to_string(),
                inputs,
                change,
            }
        }
        Err(Failure::Wallet(WalletError::NotEnoughFunds {
            available, needed, ..
        })) => Outcome::NotEnoughFunds {
            available: available.to_string(),
            needed: needed.to_string(),
        },
        Err(other) => return Err(other),
    };
    wallet.close()?;

    let inputs = Inputs {
        description: case.description,
        mnemonic: mnemonic.to_owned(),
        tip_height: case.tip.to_string(),
        coinbase_maturity: epic_core::global::coinbase_maturity().to_string(),
        utxos,
        amount: case.amount.to_string(),
        minimum_confirmations: case.minimum_confirmations.to_string(),
        max_outputs: case.max_outputs,
        num_change_outputs: case.num_change_outputs,
        strategy: if case.use_all { "all" } else { "smallest" },
    };
    render(case.name, upstream, inputs, Expected { estimate, send })
}

/// Stores the case's outputs in the wallet in list order, each under the next derivation index,
/// and tells the node which of them are on chain.
fn store_utxos(
    wallet: &UpstreamWallet<StaticNode>,
    node: &StaticNode,
    case: &Case,
) -> Result<Vec<UtxoInput>, Failure> {
    let maturity = epic_core::global::coinbase_maturity();
    let mut stored = Vec::new();
    for (index, utxo) in case.utxos.iter().enumerate() {
        let lock_height = if utxo.coinbase {
            utxo.height.checked_add(maturity).ok_or(Failure::Overflow)?
        } else {
            0
        };
        let mmr_index = u64::try_from(index)
            .ok()
            .and_then(|i| i.checked_add(1))
            .ok_or(Failure::Overflow)?;
        let output = wallet.with(|w| {
            let key_id = w.next_child(None)?;
            let commit = w.calc_commit_for_cache(None, utxo.value, &key_id)?;
            let output = OutputData {
                root_key_id: w.parent_key_id(),
                n_child: key_id.to_path().last_path_index(),
                key_id,
                commit,
                mmr_index: utxo.status.on_chain().then_some(mmr_index),
                value: utxo.value,
                status: utxo.status.upstream(),
                height: utxo.height,
                lock_height,
                is_coinbase: utxo.coinbase,
                tx_log_entry: None,
            };
            let mut batch = w.batch(None)?;
            batch.save(output.clone())?;
            batch.commit()?;
            Ok(output)
        })?;
        let commit = output.commit.clone().unwrap_or_default();
        if utxo.status.on_chain() {
            node.add_on_chain(&commit, utxo.height, mmr_index)?;
        }
        stored.push(UtxoInput {
            index,
            n_child: output.n_child,
            key_id: output.key_id.to_hex(),
            commit,
            value: output.value.to_string(),
            height: output.height.to_string(),
            lock_height: output.lock_height.to_string(),
            is_coinbase: output.is_coinbase,
            status: format!("{:?}", output.status),
        });
    }
    Ok(stored)
}

fn index_of(
    utxos: &[UtxoInput],
    key_id: &Identifier,
    case: &'static str,
) -> Result<usize, Failure> {
    let wanted = key_id.to_hex();
    utxos
        .iter()
        .find(|u| u.key_id == wanted)
        .map(|u| u.index)
        .ok_or_else(|| Failure::Selection {
            case,
            detail: format!("selected an output that is not in the case: {wanted}"),
        })
}

/// A node that knows only a tip height and a fixed set of on-chain outputs.
#[derive(Clone)]
struct StaticNode {
    tip: u64,
    on_chain: Arc<Mutex<HashMap<String, (u64, u64)>>>,
}

impl StaticNode {
    fn new(tip: u64) -> StaticNode {
        StaticNode {
            tip,
            on_chain: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn add_on_chain(&self, commit: &str, height: u64, mmr_index: u64) -> Result<(), Failure> {
        if commit.is_empty() {
            return Err(Failure::Selection {
                case: "store_utxos",
                detail: "upstream did not cache an output commitment".to_owned(),
            });
        }
        self.on_chain
            .lock()
            .insert(commit.to_owned(), (height, mmr_index));
        Ok(())
    }

    fn unsupported<T>(call: &str) -> Result<T, WalletError> {
        Err(WalletError::ClientCallback(format!(
            "{call} is not part of a selection case"
        )))
    }
}

impl NodeClient for StaticNode {
    fn node_url(&self) -> &str {
        "static"
    }
    fn set_node_url(&mut self, _node_url: &str) {}
    fn node_api_secret(&self) -> Option<String> {
        None
    }
    fn set_node_api_secret(&mut self, _node_api_secret: Option<String>) {}
    fn post_tx(&self, _tx: &Transaction, _fluff: bool) -> Result<(), WalletError> {
        StaticNode::unsupported("post_tx")
    }
    fn post_tx_tor(&self, _tx: &Transaction, _tor_url: &str) -> Result<(), WalletError> {
        StaticNode::unsupported("post_tx_tor")
    }
    fn get_mempool(&self) -> Result<Vec<PoolEntry>, WalletError> {
        StaticNode::unsupported("get_mempool")
    }
    fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
        None
    }
    fn get_chain_tip(&self) -> Result<(u64, String), WalletError> {
        Ok((self.tip, hex([0u8; 32])))
    }
    fn get_kernel(
        &mut self,
        _excess: &Commitment,
        _min_height: Option<u64>,
        _max_height: Option<u64>,
    ) -> Result<Option<(epic_core::core::TxKernel, u64, u64)>, WalletError> {
        StaticNode::unsupported("get_kernel")
    }
    fn get_outputs_from_node(
        &self,
        wallet_outputs: Vec<Commitment>,
    ) -> Result<HashMap<Commitment, (String, u64, u64)>, WalletError> {
        let on_chain = self.on_chain.lock();
        Ok(wallet_outputs
            .into_iter()
            .filter_map(|commit| {
                let key = hex(commit.0);
                on_chain
                    .get(&key)
                    .map(|(height, mmr)| (commit, (key.clone(), *height, *mmr)))
            })
            .collect())
    }
    fn get_node_status(&self) -> Result<NodeStatus, WalletError> {
        // Upstream refuses to refresh unless the node reports itself synced.
        serde_json::from_value(serde_json::json!({
            "protocol_version": 1,
            "user_agent": "static",
            "connections": 0,
            "tip": {
                "height": self.tip,
                "last_block_pushed": hex([0u8; 32]),
                "prev_block_to_last": hex([0u8; 32]),
                "total_difficulty": {},
            },
            "sync_status": "no_sync",
        }))
        .map_err(|e| WalletError::ClientCallback(e.to_string()))
    }
    fn get_outputs_by_pmmr_index(
        &self,
        _start_height: u64,
        _end_height: Option<u64>,
        _max_outputs: u64,
    ) -> Result<
        (
            u64,
            u64,
            Vec<(
                Commitment,
                epic_util::secp::pedersen::RangeProof,
                bool,
                u64,
                u64,
            )>,
        ),
        WalletError,
    > {
        StaticNode::unsupported("get_outputs_by_pmmr_index")
    }
    fn height_range_to_pmmr_indices(
        &self,
        _start_height: u64,
        _end_height: Option<u64>,
    ) -> Result<(u64, u64), WalletError> {
        StaticNode::unsupported("height_range_to_pmmr_indices")
    }
    fn get_onion_addresses(&self) -> Result<Vec<String>, WalletError> {
        StaticNode::unsupported("get_onion_addresses")
    }
}
