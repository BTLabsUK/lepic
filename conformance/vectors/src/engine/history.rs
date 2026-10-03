//! Restore and refresh cases on one upstream test chain built in a fixed order.
//!
//! Two upstream wallets share the chain: a miner, which takes most block rewards and trades with
//! the subject, and the subject, whose restore and refresh sessions are recorded. Every random
//! choice upstream would make is pinned: wallets come from fixed mnemonics, coinbase outputs and
//! slates are built in upstream's test mode, and blocks are spaced by upstream's test helper.

use epic_core::core::hash::Hashed;
use epic_core::core::{BlockHeader, Transaction};
use epic_core::global;
use epic_core::libtx::{proof::LegacyProofBuilder, reward};
use epic_keychain::mnemonic;
use epic_wallet_impls::HTTPNodeClient;
use epic_wallet_libwallet::api_impl::{foreign, owner};
use epic_wallet_libwallet::{BlockFees, InitTxArgs};
use serde::Serialize;

use super::chain::{ScratchDir, TestChain, use_test_chain_settings};
use super::node::{Exchange, NodeServer, ReplayReport, is_false};
use super::wallet::{UpstreamWallet, WalletState, copy_dir};
use super::{Failure, render};
use crate::{Rendered, Upstream, hex};

type Wallet = UpstreamWallet<HTTPNodeClient>;

const MINER_ENTROPY: [u8; 32] = [0x4d; 32];
const SUBJECT_ENTROPY: [u8; 32] = [0x53; 32];

/// Amounts in the smallest unit; one EPIC is 10^8. Each is below one block reward, so the
/// sender's "smallest" selection takes a single input.
const MINER_TO_SUBJECT_CONFIRMED: u64 = 300_000_000;
const SUBJECT_TO_MINER: u64 = 100_000_000;
const MINER_TO_SUBJECT_REORGANISED: u64 = 200_000_000;
const MINER_TO_SUBJECT_WHILE_BEHIND: u64 = 150_000_000;

/// How far below the subject's last refresh the lagging node's tip is.
const NODE_LAG_BLOCKS: u64 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Miner,
    Subject,
}

impl Who {
    fn label(self) -> &'static str {
        match self {
            Who::Miner => "miner",
            Who::Subject => "subject",
        }
    }
}

/// One block of the test chain, as the vectors describe it.
#[derive(Debug, Clone, Serialize)]
struct BlockNote {
    height: String,
    hash: String,
    reward_to: &'static str,
    proof_builder: &'static str,
    transactions: Vec<&'static str>,
    /// For a fork block, the height of the block the fork grew from.
    fork_of: Option<String>,
    /// The block was on the chain, and a longer fork replaced it.
    orphaned: bool,
}

/// A transaction of the story, as the vectors describe it.
#[derive(Debug, Clone, Serialize)]
struct TxNote {
    name: &'static str,
    from: &'static str,
    to: &'static str,
    amount: String,
    fee: String,
    kernel_excess: String,
}

#[derive(Serialize)]
struct Chain<'a> {
    chain_type: &'static str,
    coinbase_maturity: String,
    blocks: &'a [BlockNote],
    transactions: &'a [TxNote],
}

#[derive(Serialize)]
struct Subject {
    mnemonic: String,
    password: &'static str,
    keychain: &'static str,
}

#[derive(Serialize)]
struct SessionInputs<'a> {
    description: &'static str,
    subject: &'a Subject,
    chain: Chain<'a>,
    session: &'static str,
    before: Option<WalletState>,
    /// Present when the node served `chain` only up to this height, as a node that has not
    /// synced further.
    #[serde(skip_serializing_if = "Option::is_none")]
    node_tip: Option<String>,
}

#[derive(Serialize)]
struct SessionExpected {
    exchanges: Vec<Exchange>,
    after: WalletState,
    /// Upstream's update returned `false`, its report that it could not reach the node, after
    /// the recorded exchanges.
    #[serde(skip_serializing_if = "is_false")]
    node_unreachable: bool,
}

struct Story {
    // Field order is drop order: servers and wallets let go of the chain before the scratch
    // directory that holds it is removed.
    server: NodeServer,
    miner: Wallet,
    subject: Wallet,
    chain: TestChain,
    blocks: Vec<BlockNote>,
    txs: Vec<TxNote>,
    subject_mnemonic: String,
    /// The height the node serves the chain up to, when it serves a prefix.
    node_tip: Option<u64>,
    scratch: ScratchDir,
}

/// A recorded session, before it is rendered.
struct Session {
    name: &'static str,
    description: &'static str,
    session: &'static str,
    before: Option<WalletState>,
    node_tip: Option<u64>,
    blocks: Vec<BlockNote>,
    txs: Vec<TxNote>,
    exchanges: Vec<Exchange>,
    after: WalletState,
    node_unreachable: bool,
}

pub(crate) fn generate(upstream: &Upstream) -> Result<Vec<Rendered>, Failure> {
    let _chain_type = crate::chain_type_guard();
    let scratch = ScratchDir::new("engine-history")?;
    use_test_chain_settings(scratch.path());
    let mut story = Story::new(scratch)?;
    let mut sessions = Vec::new();

    // Rewards to the miner, then two subject coinbase outputs, one per proof builder.
    for _ in 0..4 {
        story.reward(Who::Miner, &[])?;
    }
    story.reward(Who::Subject, &[])?;
    story.legacy_reward_to_subject()?;
    story.reward(Who::Miner, &[])?;
    story.reward(Who::Miner, &[])?;
    story.refresh_subject()?;

    let tx = story.transfer(Who::Miner, "received", MINER_TO_SUBJECT_CONFIRMED)?;
    story.reward(Who::Miner, &[("received", &tx)])?;
    sessions.push(story.refresh_session(
        "refresh_confirmed",
        "The subject received a transaction that has since been mined; the refresh confirms its \
         output and its transaction log entry.",
    )?);

    let tx = story.transfer(Who::Subject, "sent", SUBJECT_TO_MINER)?;
    story.reward(Who::Miner, &[("sent", &tx)])?;
    sessions.push(story.refresh_session(
        "refresh_spent",
        "The subject sent a transaction that has since been mined; the refresh marks its input \
         spent, confirms its change output and marks the transaction sent.",
    )?);

    let fork_point = story.chain.head()?;
    let tx = story.transfer(Who::Miner, "reorganised", MINER_TO_SUBJECT_REORGANISED)?;
    story.reward(Who::Miner, &[("reorganised", &tx)])?;
    story.refresh_subject()?;
    story.fork_to_miner(&fork_point, 2)?;
    sessions.push(story.refresh_session(
        "refresh_reorganised",
        "The subject saw a received transaction confirmed, then a longer fork without it became \
         the chain; the refresh no longer finds the output.",
    )?);

    // An immature coinbase output at the tip, then one more block.
    story.reward(Who::Subject, &[])?;
    story.reward(Who::Miner, &[])?;
    sessions.push(story.restore_session(
        "restore_full_scan",
        "A new wallet created from the subject's mnemonic runs its first update, which scans the \
         whole chain: coinbase outputs from both proof builders, a received output that was spent, \
         the change of the spend, an output lost to the reorganisation, and an immature coinbase.",
    )?);

    // The node falls behind the subject's last refresh. It serves the whole chain again while the
    // subject receives a transaction mined above the lagging tip, falls behind again, and then
    // catches up.
    story.refresh_subject()?;
    let lagging_tip = story
        .chain
        .head()?
        .height
        .checked_sub(NODE_LAG_BLOCKS)
        .ok_or(Failure::Overflow)?;
    let lagging = story
        .chain
        .prefix(&story.scratch.path().join("lagging"), lagging_tip)?;
    story.serve_prefix(&lagging)?;
    sessions.push(story.refresh_session(
        "refresh_node_behind",
        "The subject last refreshed at the chain's tip. The node now holds the chain only up to \
         two blocks below that; the refresh runs against the lower tip.",
    )?);
    story.serve_chain();
    let tx = story.transfer(Who::Miner, "while_behind", MINER_TO_SUBJECT_WHILE_BEHIND)?;
    story.reward(Who::Miner, &[("while_behind", &tx)])?;
    story.serve_prefix(&lagging)?;
    sessions.push(story.refresh_session(
        "refresh_node_behind_pending_receive",
        "As refresh_node_behind, after the subject received a transaction built and mined at \
         heights above the node's tip; the refresh runs against the lower tip.",
    )?);
    story.serve_chain();
    sessions.push(story.refresh_session(
        "refresh_node_caught_up",
        "After refresh_node_behind_pending_receive, the node holds the whole chain again, one \
         block above the subject's last complete refresh; the refresh confirms the transaction \
         received meanwhile.",
    )?);

    let subject = Subject {
        mnemonic: story.subject_mnemonic.clone(),
        password: "",
        keychain: "mainnet",
    };
    let mut vectors = Vec::new();
    for s in sessions {
        let inputs = SessionInputs {
            description: s.description,
            subject: &subject,
            chain: Chain {
                chain_type: "AutomatedTesting",
                coinbase_maturity: global::coinbase_maturity().to_string(),
                blocks: &s.blocks,
                transactions: &s.txs,
            },
            session: s.session,
            before: s.before,
            node_tip: s.node_tip.map(|height| height.to_string()),
        };
        let expected = SessionExpected {
            exchanges: s.exchanges,
            after: s.after,
            node_unreachable: s.node_unreachable,
        };
        vectors.push(render(s.name, upstream, inputs, expected)?);
    }
    Ok(vectors)
}

impl Story {
    fn new(scratch: ScratchDir) -> Result<Story, Failure> {
        let chain = TestChain::new(&scratch.path().join("chain"))?;
        let server = NodeServer::live(chain.chain().clone()).map_err(Failure::Io)?;
        let miner_mnemonic = phrase(&MINER_ENTROPY)?;
        let subject_mnemonic = phrase(&SUBJECT_ENTROPY)?;
        let miner = Wallet::restore(
            &scratch.path().join("miner"),
            &miner_mnemonic,
            client(&server)?,
        )?;
        let subject = Wallet::restore(
            &scratch.path().join("subject"),
            &subject_mnemonic,
            client(&server)?,
        )?;
        Ok(Story {
            server,
            miner,
            subject,
            chain,
            blocks: Vec::new(),
            txs: Vec::new(),
            subject_mnemonic,
            node_tip: None,
            scratch,
        })
    }

    fn wallet(&self, who: Who) -> &Wallet {
        match who {
            Who::Miner => &self.miner,
            Who::Subject => &self.subject,
        }
    }

    fn next_height(&self) -> Result<u64, Failure> {
        self.chain
            .head()?
            .height
            .checked_add(1)
            .ok_or(Failure::Overflow)
    }

    /// Mines a block whose reward the wallet builds in upstream's test mode.
    fn reward(&mut self, who: Who, txs: &[(&'static str, &Transaction)]) -> Result<(), Failure> {
        let height = self.next_height()?;
        let fees = txs
            .iter()
            .try_fold(0u64, |sum, (_, tx)| sum.checked_add(tx.fee()))
            .ok_or(Failure::Overflow)?;
        let block_fees = BlockFees {
            fees,
            key_id: None,
            height,
        };
        let coinbase = self
            .wallet(who)
            .with(|w| foreign::build_coinbase(&mut *w, None, &block_fees, true))?;
        let refs: Vec<&Transaction> = txs.iter().map(|(_, tx)| *tx).collect();
        self.chain.mine(&refs, coinbase.output, coinbase.kernel);
        self.note(
            who,
            "current",
            txs.iter().map(|(name, _)| *name).collect(),
            None,
        )
    }

    /// Mines a block whose reward output the subject's keychain proves with the legacy builder,
    /// as wallets did before the current builder existed. The subject's database does not learn
    /// of it; only scanning finds it.
    fn legacy_reward_to_subject(&mut self) -> Result<(), Failure> {
        let height = self.next_height()?;
        let keychain = self.subject.with(|w| w.keychain(None))?;
        let key_id = self.subject.with(|w| w.next_child(None))?;
        let builder = LegacyProofBuilder::new(&keychain);
        let (output, kernel) = reward::output(&keychain, &builder, &key_id, 0, true, height)
            .map_err(Failure::upstream)?;
        self.chain.mine(&[], output, kernel);
        self.note(Who::Subject, "legacy", Vec::new(), None)
    }

    /// Mines `count` blocks rewarding the miner on top of `fork_point`, which must make the fork
    /// the longest chain.
    fn fork_to_miner(&mut self, fork_point: &BlockHeader, count: usize) -> Result<(), Failure> {
        let mut prev = fork_point.clone();
        for _ in 0..count {
            let height = prev.height.checked_add(1).ok_or(Failure::Overflow)?;
            let block_fees = BlockFees {
                fees: 0,
                key_id: None,
                height,
            };
            let coinbase = self
                .miner
                .with(|w| foreign::build_coinbase(&mut *w, None, &block_fees, true))?;
            let block = self
                .chain
                .mine_fork_block(&prev, &[], coinbase.output, coinbase.kernel)?;
            self.note_block(
                &block,
                Who::Miner,
                "current",
                Vec::new(),
                Some(fork_point.height.to_string()),
            );
            prev = block;
        }
        let head = self.chain.head()?;
        if head.hash() != prev.hash() {
            return Err(Failure::Story("the fork did not become the chain"));
        }
        let replaced = self.blocks.iter_mut().filter(|b| {
            b.fork_of.is_none() && b.height.parse::<u64>().is_ok_and(|h| h > fork_point.height)
        });
        for block in replaced {
            block.orphaned = true;
        }
        Ok(())
    }

    fn note(
        &mut self,
        who: Who,
        builder: &'static str,
        transactions: Vec<&'static str>,
        fork_of: Option<String>,
    ) -> Result<(), Failure> {
        let head = self.chain.head()?;
        self.note_block(&head, who, builder, transactions, fork_of);
        Ok(())
    }

    fn note_block(
        &mut self,
        header: &BlockHeader,
        who: Who,
        builder: &'static str,
        transactions: Vec<&'static str>,
        fork_of: Option<String>,
    ) {
        self.blocks.push(BlockNote {
            height: header.height.to_string(),
            hash: header.hash().to_hex(),
            reward_to: who.label(),
            proof_builder: builder,
            transactions,
            fork_of,
            orphaned: false,
        });
    }

    /// A full send: the sender selects with the "smallest" strategy and one change output, the
    /// receiver signs, the sender locks and finalizes. Nothing is posted; the caller mines it.
    fn transfer(
        &mut self,
        from: Who,
        name: &'static str,
        amount: u64,
    ) -> Result<Transaction, Failure> {
        let (sender, receiver) = match from {
            Who::Miner => (&self.miner, &self.subject),
            Who::Subject => (&self.subject, &self.miner),
        };
        let args = InitTxArgs {
            amount,
            minimum_confirmations: 1,
            max_outputs: 500,
            num_change_outputs: 1,
            selection_strategy_is_use_all: false,
            ..Default::default()
        };
        let slate = sender.with(|w| owner::init_send_tx(&mut *w, None, args, true))?;
        let slate = receiver
            .with(|w| foreign::receive_tx(&mut *w, None, &slate, None, None, None, true))?;
        sender.with(|w| owner::tx_lock_outputs(&mut *w, None, &slate, 0, None))?;
        let slate = sender.with(|w| owner::finalize_tx(&mut *w, None, &slate))?;
        let kernel = slate
            .tx
            .kernels()
            .first()
            .map(|k| hex(k.excess.0))
            .unwrap_or_default();
        self.txs.push(TxNote {
            name,
            from: from.label(),
            to: match from {
                Who::Miner => Who::Subject.label(),
                Who::Subject => Who::Miner.label(),
            },
            amount: amount.to_string(),
            fee: slate.fee.to_string(),
            kernel_excess: kernel,
        });
        Ok(slate.tx)
    }

    /// Makes the node answer from `prefix`, a copy of the chain up to a lower height.
    fn serve_prefix(&mut self, prefix: &TestChain) -> Result<(), Failure> {
        self.node_tip = Some(prefix.head()?.height);
        self.server.serve(prefix.chain().clone());
        Ok(())
    }

    /// Makes the node answer from the whole chain again.
    fn serve_chain(&mut self) {
        self.node_tip = None;
        self.server.serve(self.chain.chain().clone());
    }

    /// An unrecorded refresh, to move the subject's state forward between cases.
    fn refresh_subject(&self) -> Result<(), Failure> {
        refresh(&self.subject, "a setup refresh")
    }

    /// Records the subject's refresh, then replays it into a copy of the subject's wallet taken
    /// just before.
    fn refresh_session(
        &mut self,
        name: &'static str,
        description: &'static str,
    ) -> Result<Session, Failure> {
        let before = self.subject.state()?;
        let replica_dir = self.scratch.path().join(format!("replica-{name}"));
        self.subject.close()?;
        copy_dir(self.subject.dir(), &replica_dir)?;
        self.subject = Wallet::reopen(self.subject.dir(), client(&self.server)?)?;

        self.server.start_recording();
        let reached = update(&self.subject)?;
        let exchanges = self.server.stop_recording();
        let after = self.subject.state()?;

        let replay = NodeServer::replay(exchanges.clone()).map_err(Failure::Io)?;
        let replica = Wallet::reopen(&replica_dir, client(&replay)?)?;
        check_replay(name, &replay, &replica, reached, &after)?;

        let mut session =
            self.session(name, description, "refresh", Some(before), exchanges, after);
        session.node_unreachable = !reached;
        Ok(session)
    }

    /// Records a new wallet's first update from the subject's mnemonic, then replays it into
    /// another new wallet from the same mnemonic.
    fn restore_session(
        &mut self,
        name: &'static str,
        description: &'static str,
    ) -> Result<Session, Failure> {
        let restored = Wallet::restore(
            &self.scratch.path().join(format!("restored-{name}")),
            &self.subject_mnemonic,
            client(&self.server)?,
        )?;
        self.server.start_recording();
        refresh(&restored, name)?;
        let exchanges = self.server.stop_recording();
        let after = restored.state()?;
        restored.close()?;

        let replay = NodeServer::replay(exchanges.clone()).map_err(Failure::Io)?;
        let replica = Wallet::restore(
            &self.scratch.path().join(format!("replica-{name}")),
            &self.subject_mnemonic,
            client(&replay)?,
        )?;
        check_replay(name, &replay, &replica, true, &after)?;

        Ok(self.session(name, description, "restore", None, exchanges, after))
    }

    fn session(
        &self,
        name: &'static str,
        description: &'static str,
        session: &'static str,
        before: Option<WalletState>,
        exchanges: Vec<Exchange>,
        after: WalletState,
    ) -> Session {
        Session {
            name,
            description,
            session,
            before,
            node_tip: self.node_tip,
            blocks: self.blocks.clone(),
            txs: self.txs.clone(),
            exchanges,
            after,
            node_unreachable: false,
        }
    }
}

/// The update the CLI and the owner API run before showing balances and outputs. Returns
/// `false` where upstream reports that it could not reach the node.
fn update(wallet: &Wallet) -> Result<bool, Failure> {
    owner::update_wallet_state(wallet.instance(), None, &None, false).map_err(Failure::Wallet)
}

fn refresh(wallet: &Wallet, during: &'static str) -> Result<(), Failure> {
    if update(wallet)? {
        Ok(())
    } else {
        Err(Failure::NodeUnreachable(during))
    }
}

/// Runs the replica's update against a replay server and checks it against the recording.
fn check_replay(
    name: &str,
    replay: &NodeServer,
    replica: &Wallet,
    reached: bool,
    recorded: &WalletState,
) -> Result<(), Failure> {
    let (replayed_reached, replayed) = replay_into(replica)?;
    if replayed_reached != reached {
        return Err(Failure::Replay {
            case: name.to_owned(),
            detail: format!(
                "update reached the node: recorded {reached}, replayed {replayed_reached}"
            ),
        });
    }
    verify_replay(
        name,
        &replay.replay_report(),
        &serde_json::to_value(&replayed).map_err(Failure::upstream)?,
        &serde_json::to_value(recorded).map_err(Failure::upstream)?,
    )
}

fn replay_into(replica: &Wallet) -> Result<(bool, WalletState), Failure> {
    let reached = update(replica)?;
    let replayed = replica.state()?;
    replica.close()?;
    Ok((reached, replayed))
}

/// A replay matches when every request found a recorded answer, every recorded answer was asked
/// for, and the wallet ended in the recorded state.
fn verify_replay(
    name: &str,
    report: &ReplayReport,
    replayed: &serde_json::Value,
    recorded: &serde_json::Value,
) -> Result<(), Failure> {
    let diverged = |detail: String| Failure::Replay {
        case: name.to_owned(),
        detail,
    };
    if !report.unexpected.is_empty() {
        return Err(diverged(format!(
            "requests without a recorded response: {:?}",
            report.unexpected
        )));
    }
    if report.unused != 0 {
        return Err(diverged(format!(
            "{} recorded exchanges were not requested",
            report.unused
        )));
    }
    if replayed != recorded {
        return Err(diverged(format!(
            "end state differs: recorded {recorded}, replayed {replayed}"
        )));
    }
    Ok(())
}

fn client(server: &NodeServer) -> Result<HTTPNodeClient, Failure> {
    HTTPNodeClient::new(server.url(), None).map_err(Failure::Wallet)
}

fn phrase(entropy: &[u8; 32]) -> Result<String, Failure> {
    mnemonic::from_entropy(&entropy.to_vec()).map_err(Failure::described)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::Value;

    use super::*;
    use crate::DEFAULT_OUT;

    fn committed(name: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let path = Path::new(DEFAULT_OUT)
            .join(super::super::AREA)
            .join(format!("{name}.json"));
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    fn exchanges(vector: &Value) -> Result<Vec<Exchange>, Box<dyn std::error::Error>> {
        Ok(serde_json::from_value(
            vector["expected"]["exchanges"].clone(),
        )?)
    }

    /// Replays a committed restore vector into a new upstream wallet, from the file alone.
    fn replay_restore_file(
        vector: &Value,
        exchanges: Vec<Exchange>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _chain_type = crate::chain_type_guard();
        let scratch = ScratchDir::new("engine-replay-test")?;
        use_test_chain_settings(scratch.path());
        let mnemonic = vector["inputs"]["subject"]["mnemonic"]
            .as_str()
            .ok_or("vector has no mnemonic")?;
        let replay = NodeServer::replay(exchanges)?;
        let replica = Wallet::restore(&scratch.path().join("replica"), mnemonic, client(&replay)?)?;
        let (reached, replayed) = replay_into(&replica)?;
        if !reached {
            return Err(Failure::NodeUnreachable("a replay").into());
        }
        verify_replay(
            "restore_full_scan",
            &replay.replay_report(),
            &serde_json::to_value(&replayed)?,
            &vector["expected"]["after"],
        )?;
        Ok(())
    }

    #[test]
    fn committed_restore_vector_replays_through_upstream_client()
    -> Result<(), Box<dyn std::error::Error>> {
        let vector = committed("restore_full_scan")?;
        replay_restore_file(&vector, exchanges(&vector)?)
    }

    #[test]
    fn replay_detects_an_output_missing_from_the_recording()
    -> Result<(), Box<dyn std::error::Error>> {
        let vector = committed("restore_full_scan")?;
        let mut exchanges = exchanges(&vector)?;
        let listing = exchanges
            .iter_mut()
            .find(|e| e.method == "get_unspent_outputs")
            .ok_or("no get_unspent_outputs exchange")?;
        let outputs = listing.response["result"]["Ok"]["outputs"]
            .as_array_mut()
            .ok_or("no outputs in the listing")?;
        let subject_commits: Vec<&str> = vector["expected"]["after"]["outputs"]
            .as_array()
            .ok_or("no outputs")?
            .iter()
            .filter_map(|o| o["commit"].as_str())
            .collect();
        let before = outputs.len();
        outputs.retain(|o| o["commit"].as_str() != subject_commits.first().copied());
        assert_eq!(outputs.len() + 1, before);
        let result = replay_restore_file(&vector, exchanges);
        let error = result
            .err()
            .ok_or("a tampered recording replayed cleanly")?;
        assert!(
            matches!(
                error.downcast_ref::<Failure>(),
                Some(Failure::Replay { .. })
            ),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn replay_detects_a_request_the_recording_lacks() -> Result<(), Box<dyn std::error::Error>> {
        let vector = committed("restore_full_scan")?;
        let mut exchanges = exchanges(&vector)?;
        exchanges.retain(|e| e.method != "get_pmmr_indices");
        let result = replay_restore_file(&vector, exchanges);
        let error = result
            .err()
            .ok_or("a truncated recording replayed cleanly")?;
        assert!(
            matches!(
                error.downcast_ref::<Failure>(),
                Some(Failure::Replay { .. } | Failure::NodeUnreachable(_) | Failure::Wallet(_))
            ),
            "{error}"
        );
        Ok(())
    }
}
