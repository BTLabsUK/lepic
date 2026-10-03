//! One run of a differential case: an upstream miner and an upstream peer, plus a subject that
//! is either a LEPIC wallet or, in the reference run, an upstream wallet from the same mnemonic,
//! all on one in-process test chain. A run records what every wallet reports at each
//! checkpoint and the transaction the chain mined.

pub mod lepic;
pub mod node;
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
}

/// What an initiating sender asks for.
#[derive(Debug, Clone)]
pub struct Offer {
    pub amount: u64,
    pub ttl_blocks: Option<u64>,
    pub message: Option<String>,
    pub proof_to: Option<[u8; 32]>,
}

/// How a payer pays an invoice.
#[derive(Debug, Clone)]
pub struct Pay {
    pub amount: u64,
    pub ttl_blocks: Option<u64>,
    pub message: Option<String>,
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

pub struct World {
    // Wallets go before the node and the directory, so they close first.
    miner: UpstreamParty,
    peer: UpstreamParty,
    subject: Box<dyn Party>,
    node: TestNode,
    files: PathBuf,
    pub checkpoints: Vec<Checkpoint>,
    pub mined: Vec<Transaction>,
    _scratch: ScratchDir,
}

impl World {
    /// A fresh chain with mature miner rewards, and a peer and subject funded by the miner over
    /// the file method.
    pub fn start(label: &str, kind: SubjectKind, peer_writes: SlateShape) -> World {
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
        let subject: Box<dyn Party> = match kind {
            SubjectKind::Lepic => Box::new(LepicParty::restore(
                "subject",
                &phrase(&SUBJECT_ENTROPY),
                node.url(),
                7,
            )),
            // LEPIC writes as the file method does, so its reference does too.
            SubjectKind::Reference => Box::new(UpstreamParty::restore(
                "subject",
                &dir.join("subject"),
                &phrase(&SUBJECT_ENTROPY),
                node.url(),
                SlateShape::FileMethod,
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
        world.mine(6);
        world.miner.refresh();
        world.fund(Who::Peer);
        world.fund(Who::Subject);
        world.mine(SPENDABLE_AFTER);
        world.refresh_all();
        world.mined.clear();
        world
    }

    fn fund(&mut self, who: Who) {
        let s1 = self.file(&format!("fund-{who:?}.tx"));
        let s2 = self.file(&format!("fund-{who:?}.tx.response"));
        let offer = Offer {
            amount: FUNDING,
            ttl_blocks: None,
            message: None,
            proof_to: None,
        };
        self.miner.send(&s1, &offer);
        self.party(who).receive(&s1, &s2, None);
        self.miner.finalize_and_post(&s2);
        self.mine(1);
        self.miner.refresh();
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.files.join(name)
    }

    pub fn party(&mut self, who: Who) -> &mut dyn Party {
        match who {
            Who::Peer => &mut self.peer,
            Who::Subject => &mut *self.subject,
        }
    }

    pub fn mnemonic(&self, who: Who) -> String {
        match who {
            Who::Peer => self.peer.mnemonic().to_owned(),
            Who::Subject => self.subject.mnemonic().to_owned(),
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
        self.subject.refresh();
    }

    /// Refreshes both parties, then records what they report about `slate_id`.
    pub fn checkpoint(&mut self, label: &'static str, slate_id: &str) {
        self.peer.refresh();
        self.subject.refresh();
        let peer = self.peer.view(Some(slate_id));
        let subject = self.subject.view(Some(slate_id));
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
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> ScratchDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lepic-differential-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _absent = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        ScratchDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}
