//! Two upstream wallets on the upstream in-process test chain, wired the way the epic-wallet
//! controller tests wire them: a `WalletProxy` thread owns the chain and answers each wallet's
//! `LocalWalletClient`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use epic_core::core::Transaction;
use epic_core::global::{self, ChainTypes};
use epic_keychain::ExtKeychain;
use epic_util::secp::key::SecretKey;
use epic_util::{Mutex, ZeroingString};
use epic_wallet_impls::test_framework::{
    LocalWalletClient, WalletProxy, award_block_to_wallet, award_blocks_to_wallet,
};
use epic_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use epic_wallet_libwallet::{self as libwallet, NodeClient, WalletBackend, WalletInst};

use crate::Error;

type Lc = DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>;
type Proxy = WalletProxy<'static, Lc, LocalWalletClient, ExtKeychain>;
type Backend = dyn WalletBackend<'static, LocalWalletClient, ExtKeychain> + 'static;
pub(super) type Wallet =
    Arc<Mutex<Box<dyn WalletInst<'static, Lc, LocalWalletClient, ExtKeychain>>>>;
type Miner = Box<dyn Fn(&Wallet, &[&Transaction], usize) -> Result<(), libwallet::Error>>;

/// Wallets are opened without a keychain mask, as the upstream tests open them.
pub(super) const NO_MASK: Option<&SecretKey> = None;

pub(super) struct TestChain {
    pub(super) sender: Wallet,
    pub(super) receiver: Wallet,
    node: LocalWalletClient,
    mine: Miner,
    running: Arc<AtomicBool>,
    proxy: Option<JoinHandle<Result<(), libwallet::Error>>>,
    previous_chain_type: ChainTypes,
    scratch: ScratchDir,
}

impl TestChain {
    pub(super) fn start(
        label: &str,
        sender_mnemonic: &str,
        receiver_mnemonic: &str,
    ) -> Result<TestChain, Error> {
        let scratch = ScratchDir::create(label)?;
        let dir = scratch.path_str()?.to_owned();

        let previous_chain_type = global::CHAIN_TYPE.read().clone();
        global::set_mining_mode(ChainTypes::AutomatedTesting);
        // A path that does not exist makes the node fall back to its embedded foundation outputs.
        global::set_foundation_path(format!("{dir}/no-foundation-file.json"));

        let mut proxy: Proxy = WalletProxy::new(&dir);
        let sender = open_wallet(&mut proxy, &dir, "sender", sender_mnemonic)?;
        let receiver = open_wallet(&mut proxy, &dir, "receiver", receiver_mnemonic)?;
        let node = LocalWalletClient::new("node-control", proxy.tx.clone());
        proxy.add_wallet(
            "node-control",
            node.get_send_instance(),
            sender.clone(),
            None,
        );

        let chain = proxy.chain.clone();
        let mine: Miner = Box::new(move |wallet, txs, blocks| {
            if blocks == 0 {
                return Ok(());
            }
            award_block_to_wallet(&chain, txs.to_vec(), wallet.clone(), NO_MASK)?;
            award_blocks_to_wallet(
                &chain,
                wallet.clone(),
                NO_MASK,
                blocks.saturating_sub(1),
                false,
            )
        });
        let running = proxy.running.clone();
        let handle = std::thread::spawn(move || proxy.run());

        Ok(TestChain {
            sender,
            receiver,
            node,
            mine,
            running,
            proxy: Some(handle),
            previous_chain_type,
            scratch,
        })
    }

    /// Mines `blocks` blocks whose rewards go to `wallet`; the first one includes `txs`.
    pub(super) fn mine(
        &self,
        wallet: &Wallet,
        txs: &[&Transaction],
        blocks: usize,
    ) -> Result<(), Error> {
        (self.mine)(wallet, txs, blocks).map_err(Error::reference("mining a test block"))
    }

    pub(super) fn scratch(&self) -> &Path {
        self.scratch.path()
    }

    pub(super) fn stop(mut self) -> Result<(), Error> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        let Some(handle) = self.proxy.take() else {
            return Ok(());
        };
        // The proxy checks the flag after answering a request, so one more request ends it.
        self.running.store(false, Ordering::Relaxed);
        let tip = self.node.get_chain_tip();
        let joined = handle.join();
        global::set_mining_mode(self.previous_chain_type.clone());
        tip.map_err(Error::reference("stopping the test chain"))?;
        match joined {
            Ok(result) => result.map_err(Error::reference("test chain proxy")),
            Err(_) => Err(Error::Reference {
                step: "test chain proxy",
                source: "proxy thread panicked".into(),
            }),
        }
    }
}

impl Drop for TestChain {
    fn drop(&mut self) {
        let _ignored = self.shutdown();
    }
}

fn open_wallet(proxy: &mut Proxy, dir: &str, name: &str, mnemonic: &str) -> Result<Wallet, Error> {
    let client = LocalWalletClient::new(name, proxy.tx.clone());
    let mut wallet: Box<dyn WalletInst<'static, Lc, LocalWalletClient, ExtKeychain>> = Box::new(
        DefaultWalletImpl::<LocalWalletClient>::new(client.clone())
            .map_err(Error::reference("wallet instance"))?,
    );
    let lc = wallet
        .lc_provider()
        .map_err(Error::reference("wallet lifecycle"))?;
    lc.set_top_level_directory(&format!("{dir}/{name}"))
        .map_err(Error::reference("wallet directory"))?;
    lc.create_wallet(
        None,
        Some(ZeroingString::from(mnemonic)),
        32,
        ZeroingString::from(""),
        false,
    )
    .map_err(Error::reference("wallet creation"))?;
    let mask = lc
        .open_wallet(None, ZeroingString::from(""), false, false)
        .map_err(Error::reference("wallet open"))?;
    let wallet = Arc::new(Mutex::new(wallet));
    proxy.add_wallet(name, client.get_send_instance(), wallet.clone(), mask);
    Ok(wallet)
}

/// Runs `f` on the wallet's backend, the way the upstream owner and foreign APIs do.
pub(super) fn with_backend<T>(
    wallet: &Wallet,
    step: &'static str,
    f: impl FnOnce(&mut Backend) -> Result<T, libwallet::Error>,
) -> Result<T, Error> {
    let mut lock = wallet.lock();
    let lc = lock.lc_provider().map_err(Error::reference(step))?;
    let backend = lc.wallet_inst().map_err(Error::reference(step))?;
    f(&mut **backend).map_err(Error::reference(step))
}

/// A per-process scratch directory for the chain and wallet databases, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create(label: &str) -> Result<ScratchDir, Error> {
        let path = std::env::temp_dir().join(format!(
            "lepic-vectors-slates-{}-{label}",
            std::process::id()
        ));
        let _absent = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).map_err(Error::io(&path))?;
        Ok(ScratchDir(path))
    }

    fn path_str(&self) -> Result<&str, Error> {
        self.0.to_str().ok_or_else(|| Error::Io {
            path: self.0.clone(),
            source: std::io::Error::other("scratch path is not utf-8"),
        })
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
