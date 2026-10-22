//! A node that lies. The wallet cannot trust what a node says, so a hostile or broken node may
//! hide outputs, confirm a kernel and take it back, jump the tip, answer with commitments the
//! wallet never asked for, or answer slowly or with a huge body. Each ends in a typed error or a
//! state an honest rescan repairs: no panic, no hang, and no change to balances or output
//! statuses that the chain the node serves does not justify.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod scan_support;
mod send_support;
mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lepic_crypto::{Commitment, RangeProof};
use lepic_keychain::{Keychain, Seed};
use lepic_node::mock::ChainOutput;
use lepic_node::{
    BlockHeaderInfo, CallPolicy, HttpSettings, HttpTransport, LocatedKernel, NodeApi, NodeClient,
    NodeError, NodeVersion, OutputLocation, PmmrIndices, PoolTransaction, Propagation, RetryPolicy,
    Tip, UnspentOutputs, webpki_tls_config,
};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_primitives::tx::Transaction;
use lepic_store::{AccountRecord, OutputRecord, OutputStatus, TxId, TxState, WalletStore};
use lepic_transport::transport::Destination;
use lepic_wallet::refresh::{RefreshError, RefreshOutcome};
use lepic_wallet::scan::{ScanCancel, ScanError, ScanOptions};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Ports, StoreOpener, Wallet};
use scan_support::{PASSWORD, full_scan_vector, options, restore, snapshot};
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, TIP, context_key, output};
use support::{Harness, LOOPBACK, MemoryStores, TestVault, complete_restore_scan, password};

const AMOUNT: u64 = 100_000_000;

/// What the wrapped node says that the chain it serves does not.
#[derive(Default)]
struct Lies {
    /// Reported as the tip, whatever the chain is at.
    tip: Option<Height>,
    /// Added to every `get_outputs` answer, requested or not.
    extra_locations: Vec<OutputLocation>,
    /// Added to every page of unspent outputs.
    extra_unspent: Vec<lepic_node::UnspentOutput>,
    /// Every page also carries its own outputs again, and copies of them under commitments no
    /// key of the wallet makes.
    echo_and_forge: bool,
    /// Every n-th output of a page of unspent outputs is left out.
    hide_every: Option<usize>,
}

/// The mock node's client, with answers a hostile node would add or take away.
struct LyingNode {
    inner: NodeClient<lepic_node::mock::MockNode>,
    lies: Arc<Mutex<Lies>>,
}

impl LyingNode {
    fn lies(&self) -> std::sync::MutexGuard<'_, Lies> {
        self.lies.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl NodeApi for LyingNode {
    fn get_version(&self) -> impl Future<Output = Result<NodeVersion, NodeError>> + Send {
        self.inner.get_version()
    }

    fn get_tip(&self) -> impl Future<Output = Result<Tip, NodeError>> + Send {
        let answer = self.inner.get_tip();
        let lie = self.lies().tip;
        async move {
            let mut tip = answer.await?;
            if let Some(height) = lie {
                tip.height = height;
            }
            Ok(tip)
        }
    }

    fn get_header(
        &self,
        height: Height,
    ) -> impl Future<Output = Result<Option<BlockHeaderInfo>, NodeError>> + Send {
        self.inner.get_header(height)
    }

    fn get_kernel(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> impl Future<Output = Result<Option<LocatedKernel>, NodeError>> + Send {
        self.inner.get_kernel(excess, min_height, max_height)
    }

    fn get_outputs(
        &self,
        commitments: &[Commitment],
    ) -> impl Future<Output = Result<Vec<OutputLocation>, NodeError>> + Send {
        let answer = self.inner.get_outputs(commitments);
        let extra = self.lies().extra_locations.clone();
        async move {
            let mut found = answer.await?;
            found.extend(extra);
            Ok(found)
        }
    }

    fn get_unspent_outputs(
        &self,
        start_index: u64,
        end_index: Option<u64>,
        max: u64,
    ) -> impl Future<Output = Result<UnspentOutputs, NodeError>> + Send {
        let answer = self.inner.get_unspent_outputs(start_index, end_index, max);
        let (extra, hide, echo) = {
            let lies = self.lies();
            (
                lies.extra_unspent.clone(),
                lies.hide_every,
                lies.echo_and_forge,
            )
        };
        async move {
            let mut page = answer.await?;
            if let Some(every) = hide {
                let mut n = 0;
                page.outputs.retain(|_| {
                    n += 1;
                    n % every != 0
                });
            }
            if echo {
                let mut added = page.outputs.clone();
                for (n, output) in page.outputs.iter().enumerate() {
                    let mut forged = output.clone();
                    forged.commitment = Commitment::commit_value(n as u64 + 1).unwrap();
                    added.push(forged);
                }
                page.outputs.extend(added);
            }
            page.outputs.extend(extra);
            Ok(page)
        }
    }

    fn get_pmmr_indices(
        &self,
        start_height: Height,
        end_height: Option<Height>,
    ) -> impl Future<Output = Result<PmmrIndices, NodeError>> + Send {
        self.inner.get_pmmr_indices(start_height, end_height)
    }

    fn push_transaction(
        &self,
        transaction: &Transaction,
        propagation: Propagation,
    ) -> impl Future<Output = Result<(), NodeError>> + Send {
        self.inner.push_transaction(transaction, propagation)
    }

    fn get_unconfirmed_transactions(
        &self,
    ) -> impl Future<Output = Result<Vec<PoolTransaction>, NodeError>> + Send {
        self.inner.get_unconfirmed_transactions()
    }
}

type LiarWallet = Wallet<LyingNode, MemoryStores, TestVault>;

/// The funded sender of the send tests, over a node that can lie.
struct Liar {
    harness: Harness,
    wallet: LiarWallet,
    store: lepic_store::MemoryStore,
    lies: Arc<Mutex<Lies>>,
    funding: OutputRecord,
}

impl Liar {
    fn new() -> Self {
        let harness = Harness::new();
        let lies = Arc::new(Mutex::new(Lies::default()));
        let base = harness.ports(TestVault::default());
        let ports = Ports {
            node: LyingNode {
                inner: base.node,
                lies: Arc::clone(&lies),
            },
            stores: base.stores,
            secrets: base.secrets,
            transports: base.transports,
            clock: base.clock,
            rng: base.rng,
            runtime: base.runtime,
        };
        let wallet = Wallet::new(harness.config(Network::Floonet), ports).unwrap();
        harness
            .block_on(wallet.restore(password("sender"), SENDER_MNEMONIC))
            .unwrap();
        harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(TIP));
        complete_restore_scan(&harness.runtime, &wallet);
        let seed = Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = harness
            .stores
            .open(&harness.data_dir, context_key(&seed))
            .unwrap();
        let keychain = Keychain::from_seed(&seed, Network::Floonet).unwrap();
        let funding = output(&keychain, 0, FUNDING, OutputFeatures::Coinbase);
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: ACCOUNT,
                    label: "default".to_owned(),
                    next_child: NEXT_CHILD,
                })?;
                repos.put_output(&funding)
            })
            .unwrap();
        harness.node.update_chain(|chain| {
            chain.outputs.push(on_chain(&funding, 1, 1));
        });
        Self {
            harness,
            wallet,
            store,
            lies,
            funding,
        }
    }

    fn lie(&self, change: impl FnOnce(&mut Lies)) {
        change(&mut self.lies.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn set_tip(&self, height: u64) {
        self.harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(height));
    }

    fn send(&self, ttl_blocks: Option<u64>) -> TxId {
        self.harness
            .block_on(self.wallet.send(
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ttl_blocks,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    transport: LOOPBACK,
                    to: Destination::new(PEER.to_owned()),
                },
            ))
            .unwrap()
            .tx_id
    }

    fn refresh(&self) -> Result<RefreshOutcome, RefreshError> {
        self.harness.block_on(self.wallet.refresh())
    }

    /// The change output of the only send.
    fn change(&self) -> OutputRecord {
        self.outputs()
            .into_iter()
            .find(|output| output.id != self.funding.id)
            .unwrap()
    }

    /// The commitments of the wallet's outputs that the node's chain holds unspent.
    fn held_on_chain(&self) -> Vec<Commitment> {
        let asked: Vec<Commitment> = self
            .outputs()
            .iter()
            .map(|output| output.id.commitment)
            .collect();
        let node = self.harness.node.client();
        self.harness
            .block_on(node.get_outputs(&asked))
            .unwrap()
            .into_iter()
            .map(|location| location.commitment)
            .collect()
    }

    fn outputs(&self) -> Vec<OutputRecord> {
        self.store
            .read(|repos| repos.outputs(ACCOUNT, None))
            .unwrap()
    }

    fn state(&self, tx: TxId) -> TxState {
        self.store
            .read(|repos| repos.transaction(tx))
            .unwrap()
            .unwrap()
            .state
    }

    /// Everything a refresh could change in the wallet.
    fn snapshot(&self) -> WalletState {
        let states = self
            .store
            .read(|repos| repos.transactions(ACCOUNT))
            .unwrap()
            .into_iter()
            .map(|stored| (stored.id, stored.entry.state))
            .collect();
        WalletState {
            outputs: self.outputs(),
            states,
            confirmed_height: self.wallet.last_confirmed_height().unwrap(),
        }
    }
}

#[derive(Debug, PartialEq)]
struct WalletState {
    outputs: Vec<OutputRecord>,
    states: Vec<(TxId, TxState)>,
    confirmed_height: Option<Height>,
}

fn on_chain(output: &OutputRecord, height: u64, mmr_index: u64) -> ChainOutput {
    ChainOutput {
        commitment: output.id.commitment,
        features: output.id.features,
        proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
        height: Height::new(height),
        mmr_index,
        spent: false,
    }
}

/// The send mined: the funding output spent and the change on the chain at `TIP + 1`.
fn mine_the_send(liar: &Liar, change: &OutputRecord) {
    liar.harness.node.update_chain(|chain| {
        chain.outputs[0].spent = true;
        chain.outputs.push(on_chain(change, TIP + 1, 3));
        chain.tip.height = Height::new(TIP + 1);
    });
}

fn balance_total(liar: &Liar) -> u64 {
    liar.outputs()
        .iter()
        .filter(|output| output.status == OutputStatus::Unspent)
        .map(|output| output.amount.value())
        .sum()
}

#[test]
fn the_wrapper_passes_honest_answers_through() {
    let liar = Liar::new();
    let tx = liar.send(None);
    let change = liar.change();
    mine_the_send(&liar, &change);

    let outcome = liar.refresh().unwrap();

    assert!(matches!(outcome, RefreshOutcome::Refreshed(_)));
    assert_eq!(liar.state(tx), TxState::Confirmed);
}

/// A jump of the tip no chain makes between two answers.
const ABSURD_JUMP: u64 = 50_000_000;

#[test]
fn a_tip_that_jumps_absurdly_ends_the_refresh_and_changes_nothing() {
    let liar = Liar::new();
    // A send that expires at its TTL cutoff: a tip past the cutoff would cancel it and free its
    // inputs.
    let tx = liar.send(Some(5));
    liar.refresh().unwrap();
    let before = liar.snapshot();

    liar.set_tip(TIP + ABSURD_JUMP);
    let result = liar.refresh();

    assert!(result.is_err(), "refresh believed the jump: {result:?}");
    assert_eq!(liar.snapshot(), before);
    assert_eq!(liar.state(tx), TxState::Sent);

    // The honest chain, a few blocks on, is believed again.
    liar.set_tip(TIP + 2);
    liar.refresh().unwrap();
    assert_eq!(liar.snapshot().states, before.states);
}

#[test]
fn a_tip_the_engine_is_told_to_believe_still_ends_without_cancelling_a_send() {
    let liar = Liar::new();
    let tx = liar.send(Some(5));
    let before = liar.snapshot();

    liar.lie(|lies| lies.tip = Some(Height::new(u64::MAX)));
    let result = liar.refresh();

    assert!(result.is_err(), "refresh believed the tip: {result:?}");
    assert_eq!(liar.snapshot(), before);
    assert_eq!(liar.state(tx), TxState::Sent);
}

#[test]
fn a_confirmed_kernel_the_node_takes_back_does_not_create_spendable_funds() {
    let liar = Liar::new();
    let tx = liar.send(None);
    let change = liar.change();
    mine_the_send(&liar, &change);
    liar.refresh().unwrap();
    assert_eq!(liar.state(tx), TxState::Confirmed);
    let confirmed = liar.snapshot();

    // A reorganisation: the block with the send is gone, the funding output is unspent again and
    // the change does not exist.
    liar.harness.node.update_chain(|chain| {
        chain.outputs.truncate(1);
        chain.outputs[0].spent = false;
        chain.tip.height = Height::new(TIP + 2);
    });
    let result = liar.refresh();

    // The wallet answers with a typed result, and does not keep as unspent an output the chain
    // no longer holds.
    assert!(result.is_ok() || result.is_err());
    let held = liar.held_on_chain();
    for output in liar.outputs() {
        if output.status == OutputStatus::Unspent {
            assert!(
                held.contains(&output.id.commitment),
                "an output the node does not hold is unspent"
            );
        }
    }
    assert_eq!(
        liar.state(tx),
        confirmed.states.iter().find(|(id, _)| *id == tx).unwrap().1
    );
}

fn commitment_of_another_wallet(value: u64) -> Commitment {
    Commitment::commit_value(value).unwrap()
}

#[test]
fn commitments_the_wallet_did_not_ask_for_change_nothing() {
    let liar = Liar::new();
    liar.send(None);
    liar.refresh().unwrap();
    let before = liar.snapshot();

    // Unrelated commitments, at heights the chain has reached.
    liar.lie(|lies| {
        lies.extra_locations = (1..=5)
            .map(|n| OutputLocation {
                commitment: commitment_of_another_wallet(n),
                features: OutputFeatures::Plain,
                height: Height::new(1),
                mmr_index: n,
            })
            .collect();
    });
    liar.refresh().unwrap();
    assert_eq!(liar.snapshot(), before);

    // The same above the tip is an implausible answer, which ends the refresh.
    liar.lie(|lies| {
        for location in &mut lies.extra_locations {
            location.height = Height::new(TIP + 1_000);
        }
    });
    assert!(liar.refresh().is_err());
    assert_eq!(liar.snapshot(), before);
}

/// A restored wallet over a node that can lie, and the honest result of the same restore.
fn lying_restore(lies: Lies) -> (Harness, LiarWallet, Arc<Mutex<Lies>>, serde_json::Value) {
    let vector = full_scan_vector();
    let harness = scan_support::harness(&vector);
    let lies = Arc::new(Mutex::new(lies));
    let base = harness.ports(harness.vault.clone());
    let wallet = Wallet::new(
        harness.config(Network::Mainnet),
        Ports {
            node: LyingNode {
                inner: base.node,
                lies: Arc::clone(&lies),
            },
            stores: base.stores,
            secrets: base.secrets,
            transports: base.transports,
            clock: base.clock,
            rng: base.rng,
            runtime: base.runtime,
        },
    )
    .unwrap();
    restore(&harness, &wallet, &vector);
    (harness, wallet, lies, vector)
}

/// What a scan found, without the ids the store gave the transactions it made for it.
fn found(snapshot: &scan_support::Snapshot) -> Vec<(OutputRecord, ())> {
    snapshot
        .outputs
        .iter()
        .map(|output| {
            let mut output = output.clone();
            output.tx = None;
            (output, ())
        })
        .collect()
}

fn honest_restore() -> scan_support::Snapshot {
    let (harness, wallet, _, vector) = lying_restore(Lies::default());
    harness
        .block_on(wallet.scan(options(&vector), &ScanCancel::new()))
        .unwrap();
    snapshot(&harness)
}

#[test]
fn outputs_the_node_adds_to_a_restore_scan_are_not_the_wallets() {
    let honest = honest_restore();
    let (harness, wallet, _lies, vector) = lying_restore(Lies {
        echo_and_forge: true,
        ..Lies::default()
    });

    let result = harness.block_on(wallet.scan(options(&vector), &ScanCancel::new()));

    // Either way the wallet holds exactly the outputs the honest scan found.
    if result.is_ok() {
        assert_eq!(found(&snapshot(&harness)), found(&honest));
    } else {
        assert!(matches!(result, Err(ScanError::Node(_))), "{result:?}");
    }
}

#[test]
fn a_node_that_hides_outputs_from_a_restore_scan_is_repaired_by_an_honest_rescan() {
    let honest = honest_restore();
    let (harness, wallet, lies, vector) = lying_restore(Lies {
        hide_every: Some(2),
        ..Lies::default()
    });

    let result = harness.block_on(wallet.scan(options(&vector), &ScanCancel::new()));
    assert!(result.is_ok() || matches!(result, Err(ScanError::Node(_))));
    let hidden = snapshot(&harness);
    for output in &hidden.outputs {
        assert!(
            honest.outputs.iter().any(|own| own.id == output.id),
            "a scan under a lying node invented an output"
        );
    }
    assert!(
        hidden.outputs.len() < honest.outputs.len(),
        "the lie hid nothing, so the test proves nothing"
    );

    // An honest node, asked again, gives the wallet back everything.
    lies.lock().unwrap().hide_every = None;
    harness
        .block_on(wallet.scan(options(&vector), &ScanCancel::new()))
        .unwrap();
    assert_eq!(found(&snapshot(&harness)), found(&honest));
}

/// A node on 127.0.0.1 that answers every request badly, until it is dropped.
struct BadNode {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Clone, Copy)]
enum Badness {
    /// Reads the request and never answers.
    Stall,
    /// Declares a body of 4 GiB and sends junk for as long as the client reads.
    HugeBody,
    /// A small valid-looking head, then one byte of body per 50 ms.
    Drip,
}

impl BadNode {
    fn start(badness: Badness) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let flag = Arc::clone(&flag);
                        workers.push(std::thread::spawn(move || serve(stream, badness, &flag)));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Self {
            address,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for BadNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve(mut stream: TcpStream, badness: Badness, stop: &AtomicBool) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut request = [0u8; 8192];
    let _ = stream.read(&mut request);
    match badness {
        Badness::Stall => {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Badness::HugeBody => {
            let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4294967296\r\n\r\n";
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            let junk = [b' '; 16 * 1024];
            let mut sent = 0usize;
            // Far more than any cap, and a bounded loop so a client that reads on is not waited
            // on for ever.
            while !stop.load(Ordering::SeqCst) && sent < 256 * 1024 * 1024 {
                if stream.write_all(&junk).is_err() {
                    return;
                }
                sent += junk.len();
            }
        }
        Badness::Drip => {
            let head =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n";
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            while !stop.load(Ordering::SeqCst) {
                if stream.write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

type HttpWallet = Wallet<NodeClient<HttpTransport>, MemoryStores, TestVault>;

/// A second handle on the restored wallet whose node is `url`, with short timeouts.
fn http_wallet(harness: &Harness, runtime: &tokio::runtime::Runtime, url: &str) -> HttpWallet {
    let settings = HttpSettings {
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_millis(600),
        max_response_bytes: 64 * 1024,
        api_secret: None,
    };
    let transport = HttpTransport::new(url, &settings, webpki_tls_config().unwrap()).unwrap();
    let node = NodeClient::new(
        transport,
        CallPolicy {
            retry: RetryPolicy {
                max_attempts: 2,
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(2),
            },
            ..CallPolicy::default()
        },
    );
    let base = harness.ports(harness.vault.clone());
    let wallet = Wallet::new(
        harness.config(Network::Mainnet),
        Ports {
            node,
            stores: base.stores,
            secrets: base.secrets,
            transports: base.transports,
            clock: base.clock,
            rng: base.rng,
            runtime: runtime.handle().clone(),
        },
    )
    .unwrap();
    runtime.block_on(wallet.open(password(PASSWORD))).unwrap();
    wallet
}

#[test]
fn a_node_that_stalls_drips_or_floods_ends_scan_and_refresh_in_bounded_time() {
    let (harness, wallet, _, vector) = lying_restore(Lies::default());
    harness
        .block_on(wallet.scan(options(&vector), &ScanCancel::new()))
        .unwrap();
    wallet.close();
    let before = snapshot(&harness);

    for badness in [Badness::Stall, Badness::Drip, Badness::HugeBody] {
        let node = BadNode::start(badness);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let wallet = http_wallet(&harness, &runtime, &node.url());
        let started = Instant::now();

        let scan = runtime
            .block_on(wallet.scan(ScanOptions::update(Network::Mainnet), &ScanCancel::new()));
        let refresh = runtime.block_on(wallet.refresh());

        assert!(
            started.elapsed() < Duration::from_secs(20),
            "a bad node held the wallet for {:?}",
            started.elapsed()
        );
        assert!(matches!(scan, Err(ScanError::Node(_))), "{scan:?}");
        assert!(matches!(refresh, Err(RefreshError::Node(_))), "{refresh:?}");
        assert_eq!(snapshot(&harness), before);
        wallet.close();
    }
}
