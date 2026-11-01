// SPDX-License-Identifier: Apache-2.0
//! One run of a differential case: an upstream miner and an upstream peer, plus a subject that
//! is either a LEPIC wallet or, in the reference run, an upstream wallet from the same mnemonic,
//! all on one in-process test chain. A run records what every wallet reports at each
//! checkpoint and the transaction the chain mined.

// Each test target compiles this module and uses only part of it.
#![allow(dead_code)]

pub mod compare;
pub mod faults;
pub mod lepic;
pub mod node;
pub mod scenario;
pub mod soak;
pub mod upstream;
pub mod view;

use std::path::{Path, PathBuf};

use epic_core::core::Transaction;

use self::lepic::LepicParty;
use self::node::TestNode;
use self::upstream::UpstreamParty;
use self::view::PartyView;

/// One EPIC in the smallest unit.
pub const EPIC: u64 = 100_000_000;
/// What the miner pays the peer and the subject before a case starts.
const FUNDING: u64 = 20 * EPIC;
/// The amount every case moves.
pub const AMOUNT: u64 = 3 * EPIC;
/// Blocks of confirmation after which `epic-wallet info` counts an output as spendable.
const SPENDABLE_AFTER: usize = 10;
/// Blocks mined before the first funding, so the miner holds mature rewards.
const MATURE_REWARDS: usize = 6;
pub const TTL_BLOCKS: u64 = 40;

const MINER_ENTROPY: [u8; 32] = [0x11; 32];
const PEER_ENTROPY: [u8; 32] = [0x22; 32];
const SUBJECT_ENTROPY: [u8; 32] = [0x33; 32];

/// How an upstream wallet writes slate files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlateShape {
    /// As the file method writes them: the V2 shape unless the slate needs V3.
    FileMethod,
    /// Always the V3 shape, as wallets that write V3 files produce, and as `epic-wallet`'s file
    /// method reads them.
    V3,
    /// The V3 shape with `version` and `orig_version` 3, as LEPIC's file method writes every
    /// slate (ADR 0015).
    V3Header3,
}

/// How a paying wallet chooses its inputs and change, as `epic-wallet`'s `InitTxArgs` says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spend {
    pub minimum_confirmations: u64,
    /// Spend every eligible output instead of as few of the smallest as cover the amount.
    pub use_all: bool,
    pub change_outputs: u32,
}

impl Default for Spend {
    /// What the CLI passes as `-c 1` with its other defaults.
    fn default() -> Spend {
        Spend {
            minimum_confirmations: 1,
            use_all: false,
            change_outputs: 1,
        }
    }
}

/// What an initiating sender asks for.
#[derive(Debug, Clone)]
pub struct Offer {
    pub amount: u64,
    pub ttl_blocks: Option<u64>,
    pub message: Option<String>,
    pub proof_to: Option<[u8; 32]>,
    pub spend: Spend,
}

/// How a payer pays an invoice.
#[derive(Debug, Clone)]
pub struct Pay {
    pub amount: u64,
    pub ttl_blocks: Option<u64>,
    pub message: Option<String>,
    pub spend: Spend,
}

/// One output the miner pays a party before a case starts, mined in its own block and followed
/// by `gap_blocks` empty ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Funding {
    pub to: Who,
    pub amount: u64,
    pub gap_blocks: usize,
}

/// The chain a case starts on: the fundings in order, then `settle_blocks` empty blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub fundings: Vec<Funding>,
    pub settle_blocks: usize,
}

impl Setup {
    /// One output for each party, spendable by `epic-wallet info`'s count when the case starts.
    pub fn standard() -> Setup {
        let funding = |to| Funding {
            to,
            amount: FUNDING,
            gap_blocks: 0,
        };
        Setup {
            fundings: vec![funding(Who::Peer), funding(Who::Subject)],
            settle_blocks: SPENDABLE_AFTER,
        }
    }

    /// The tip once the miner's rewards matured: the height the first funding builds on.
    pub const MINED_FIRST: u64 = MATURE_REWARDS as u64;

    /// The height of each funding output, in order, and the tip when the case starts.
    pub fn heights(&self) -> (Vec<u64>, u64) {
        let mut tip = Self::MINED_FIRST;
        let mut heights = Vec::with_capacity(self.fundings.len());
        for funding in &self.fundings {
            tip += 1;
            heights.push(tip);
            tip += funding.gap_blocks as u64;
        }
        (heights, tip + self.settle_blocks as u64)
    }
}

/// A wallet that takes part in a file exchange. Each step reads and writes slate files as the
/// wallet's file method does.
pub trait Party {
    fn mnemonic(&self) -> &str;
    /// Writes S1 to `out` and locks the inputs. Returns the slate id.
    fn send(&mut self, out: &Path, offer: &Offer) -> String;
    /// Reads S1 from `input` and writes S2 to `out`. Returns the slate id.
    fn receive(&mut self, input: &Path, out: &Path, message: Option<&str>) -> String;
    /// Reads S2, finalizes and posts the transaction.
    fn finalize_and_post(&mut self, input: &Path);
    /// Writes I1 to `out`. Returns the slate id.
    fn issue_invoice(&mut self, out: &Path, amount: u64, message: Option<&str>) -> String;
    /// Reads I1 from `input`, writes I2 to `out` and locks the inputs. Returns the slate id.
    fn pay_invoice(&mut self, input: &Path, out: &Path, pay: &Pay) -> String;
    /// Reads I2, finalizes and posts the transaction.
    fn finalize_invoice_and_post(&mut self, input: &Path);
    /// Cancels the transaction of `slate_id`, as `epic-wallet cancel` does.
    fn cancel(&mut self, slate_id: &str);
    fn refresh(&mut self);
    /// Balance, outputs and, when a slate id is given, its transaction log entry.
    fn view(&mut self, slate_id: Option<&str>) -> PartyView;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    Lepic,
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    Peer,
    Subject,
}

pub struct Checkpoint {
    pub label: &'static str,
    pub peer: PartyView,
    pub subject: PartyView,
}

/// The parts of a mined transaction that do not depend on randomness: every commitment comes
/// from keys both runs derive alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinedShape {
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub kernels: Vec<String>,
}

impl MinedShape {
    fn of(tx: &Transaction) -> MinedShape {
        let mut inputs: Vec<String> = tx.body.inputs.iter().map(|i| hex(&i.commit.0)).collect();
        let mut outputs: Vec<String> = tx.body.outputs.iter().map(|o| hex(&o.commit.0)).collect();
        inputs.sort();
        outputs.sort();
        let kernels = tx
            .body
            .kernels
            .iter()
            .map(|k| format!("{:?}", k.features))
            .collect();
        MinedShape {
            inputs,
            outputs,
            kernels,
        }
    }
}

/// The wallet under test: LEPIC, or in the reference run an upstream wallet in its place.
enum Subject {
    Lepic(Box<LepicParty>),
    Reference(UpstreamParty),
}

pub struct World {
    // Wallets go before the node and the directory, so they close first.
    miner: UpstreamParty,
    peer: UpstreamParty,
    subject: Subject,
    node: TestNode,
    files: PathBuf,
    pub checkpoints: Vec<Checkpoint>,
    pub mined: Vec<Transaction>,
    _scratch: ScratchDir,
}

impl World {
    /// A fresh chain with mature miner rewards, and a peer and subject funded by the miner over
    /// the file method with one output each.
    pub fn start(label: &str, kind: SubjectKind, peer_writes: SlateShape) -> World {
        World::start_with(label, kind, peer_writes, &Setup::standard())
    }

    /// A fresh chain with mature miner rewards, on which the miner pays the peer and the
    /// subject the outputs `setup` lists, over the file method.
    pub fn start_with(
        label: &str,
        kind: SubjectKind,
        peer_writes: SlateShape,
        setup: &Setup,
    ) -> World {
        let scratch = ScratchDir::new(label);
        let dir = scratch.path();
        node::use_test_chain_settings(dir);
        let node = TestNode::start(&dir.join("chain"));
        let miner = UpstreamParty::restore(
            "miner",
            &dir.join("miner"),
            &phrase(&MINER_ENTROPY),
            node.url(),
            SlateShape::FileMethod,
        );
        let peer = UpstreamParty::restore(
            "peer",
            &dir.join("peer"),
            &phrase(&PEER_ENTROPY),
            node.url(),
            peer_writes,
        );
        let subject = match kind {
            SubjectKind::Lepic => Subject::Lepic(Box::new(LepicParty::restore(
                "subject",
                &phrase(&SUBJECT_ENTROPY),
                node.url(),
                7,
            ))),
            // The reference writes files as LEPIC's file method does, so the runs differ only in
            // the wallet, not in what the peer reads.
            SubjectKind::Reference => Subject::Reference(UpstreamParty::restore(
                "subject",
                &dir.join("subject"),
                &phrase(&SUBJECT_ENTROPY),
                node.url(),
                SlateShape::V3Header3,
            )),
        };
        let files = dir.join("files");
        std::fs::create_dir_all(&files).unwrap();
        let mut world = World {
            miner,
            peer,
            subject,
            node,
            files,
            checkpoints: Vec::new(),
            mined: Vec::new(),
            _scratch: scratch,
        };
        world.mine(MATURE_REWARDS);
        world.miner.refresh();
        for (index, funding) in setup.fundings.iter().enumerate() {
            world.fund(index, funding);
        }
        world.mine(setup.settle_blocks);
        world.refresh_all();
        world.mined.clear();
        world
    }

    fn fund(&mut self, index: usize, funding: &Funding) {
        let s1 = self.file(&format!("fund-{index}.tx"));
        let s2 = self.file(&format!("fund-{index}.tx.response"));
        let offer = Offer {
            amount: funding.amount,
            ttl_blocks: None,
            message: None,
            proof_to: None,
            spend: Spend::default(),
        };
        self.miner.send(&s1, &offer);
        self.party(funding.to).receive(&s1, &s2, None);
        self.miner.finalize_and_post(&s2);
        self.mine(1);
        self.miner.refresh();
        self.mine(funding.gap_blocks);
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.files.join(name)
    }

    pub fn party(&mut self, who: Who) -> &mut dyn Party {
        match who {
            Who::Peer => &mut self.peer,
            Who::Subject => match &mut self.subject {
                Subject::Lepic(lepic) => &mut **lepic,
                Subject::Reference(upstream) => upstream,
            },
        }
    }

    /// The LEPIC subject, in the LEPIC run.
    pub fn lepic(&mut self) -> Option<&mut LepicParty> {
        match &mut self.subject {
            Subject::Lepic(lepic) => Some(&mut **lepic),
            Subject::Reference(_) => None,
        }
    }

    pub fn mnemonic(&self, who: Who) -> String {
        match who {
            Who::Peer => self.peer.mnemonic().to_owned(),
            Who::Subject => match &self.subject {
                Subject::Lepic(lepic) => lepic.mnemonic().to_owned(),
                Subject::Reference(upstream) => upstream.mnemonic().to_owned(),
            },
        }
    }

    /// The payment proof address of a party, as the upstream wallet of its mnemonic derives it.
    pub fn proof_address(&self, who: Who) -> [u8; 32] {
        match who {
            Who::Peer => self.peer.proof_address(),
            Who::Subject => {
                let dir = self._scratch.path().join("proof-address");
                let shadow = UpstreamParty::restore(
                    "shadow",
                    &dir,
                    &self.mnemonic(Who::Subject),
                    self.node.url(),
                    SlateShape::FileMethod,
                );
                shadow.proof_address()
            }
        }
    }

    /// Mines `blocks` blocks rewarding the miner; the first holds every pooled transaction.
    pub fn mine(&mut self, blocks: usize) {
        for _ in 0..blocks {
            let height = self.node.next_height();
            let reward = self.miner.coinbase(height, self.node.total_fees());
            self.mined.extend(self.node.mine(reward));
        }
    }

    pub fn pool_len(&self) -> usize {
        self.node.pool_len()
    }

    pub fn height(&self) -> u64 {
        self.node.height()
    }

    pub fn refresh_all(&mut self) {
        self.miner.refresh();
        self.peer.refresh();
        self.party(Who::Subject).refresh();
    }

    /// Refreshes both parties, then records what they report about `slate_id`.
    pub fn checkpoint(&mut self, label: &'static str, slate_id: &str) {
        self.peer.refresh();
        self.party(Who::Subject).refresh();
        let peer = self.peer.view(Some(slate_id));
        let subject = self.party(Who::Subject).view(Some(slate_id));
        self.checkpoints.push(Checkpoint {
            label,
            peer,
            subject,
        });
    }

    pub fn kernel_height(&self, tx: &Transaction) -> Option<u64> {
        let kernel = tx.body.kernels.first()?;
        self.node.kernel_height(&kernel.excess)
    }

    pub fn mined_shapes(&self) -> Vec<MinedShape> {
        self.mined.iter().map(MinedShape::of).collect()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn phrase(entropy: &[u8; 32]) -> String {
    epic_keychain::mnemonic::from_entropy(&entropy.to_vec()).unwrap()
}

/// A directory under the system temporary directory, removed on drop.
struct ScratchDir(tempfile::TempDir);

impl ScratchDir {
    fn new(label: &str) -> ScratchDir {
        ScratchDir(
            tempfile::Builder::new()
                .prefix(&format!("lepic-differential-{label}-"))
                .tempdir()
                .unwrap(),
        )
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}
