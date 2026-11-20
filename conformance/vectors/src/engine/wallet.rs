// SPDX-License-Identifier: Apache-2.0
//! Upstream wallets on disk, and the state the vectors record about them.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use epic_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use epic_util::{Mutex, ZeroingString};
use epic_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use epic_wallet_libwallet::{
    Error as WalletError, NodeClient, OutputData, TxLogEntry, WalletBackend, WalletInst,
};
use serde::Serialize;

use super::Failure;
use crate::hex;

/// Upstream wallets in these vectors use an empty password, as upstream's own tests do.
const PASSWORD: &str = "";

type Instance<C> = Arc<
    Mutex<Box<dyn WalletInst<'static, DefaultLCProvider<'static, C, ExtKeychain>, C, ExtKeychain>>>,
>;

/// An upstream `epic-wallet` instance: `DefaultLCProvider` over its sqlite backend, unlocked
/// without a keychain mask, talking to the node through `C`.
pub(crate) struct UpstreamWallet<C: NodeClient + 'static> {
    instance: Instance<C>,
    dir: PathBuf,
}

impl<C: NodeClient + 'static> UpstreamWallet<C> {
    /// Creates the wallet from a mnemonic, as `epic-wallet init -r` does, and opens it.
    pub(crate) fn restore(dir: &Path, mnemonic: &str, client: C) -> Result<Self, Failure> {
        let wallet = UpstreamWallet::with_client(dir, client)?;
        {
            let mut lock = wallet.instance.lock();
            let lc = lock.lc_provider().map_err(Failure::Wallet)?;
            lc.create_wallet(
                None,
                Some(ZeroingString::from(mnemonic)),
                32,
                ZeroingString::from(PASSWORD),
                false,
            )
            .map_err(Failure::Wallet)?;
        }
        wallet.open()?;
        Ok(wallet)
    }

    /// Opens an existing wallet directory with a different node client.
    pub(crate) fn reopen(dir: &Path, client: C) -> Result<Self, Failure> {
        let wallet = UpstreamWallet::with_client(dir, client)?;
        wallet.open()?;
        Ok(wallet)
    }

    fn with_client(dir: &Path, client: C) -> Result<Self, Failure> {
        let mut instance = Box::new(DefaultWalletImpl::<C>::new(client).map_err(Failure::upstream)?)
            as Box<
                dyn WalletInst<'static, DefaultLCProvider<'static, C, ExtKeychain>, C, ExtKeychain>,
            >;
        instance
            .lc_provider()
            .map_err(Failure::Wallet)?
            .set_top_level_directory(&dir.to_string_lossy())
            .map_err(Failure::Wallet)?;
        Ok(UpstreamWallet {
            instance: Arc::new(Mutex::new(instance)),
            dir: dir.to_path_buf(),
        })
    }

    fn open(&self) -> Result<(), Failure> {
        let mut lock = self.instance.lock();
        let lc = lock.lc_provider().map_err(Failure::Wallet)?;
        lc.open_wallet(None, ZeroingString::from(PASSWORD), false, false)
            .map_err(Failure::Wallet)?;
        Ok(())
    }

    pub(crate) fn close(&self) -> Result<(), Failure> {
        let mut lock = self.instance.lock();
        let lc = lock.lc_provider().map_err(Failure::Wallet)?;
        lc.close_wallet(None).map_err(Failure::Wallet)
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn instance(&self) -> Instance<C> {
        self.instance.clone()
    }

    /// Runs `f` on the open backend.
    pub(crate) fn with<R>(
        &self,
        f: impl FnOnce(&mut dyn WalletBackend<'static, C, ExtKeychain>) -> Result<R, WalletError>,
    ) -> Result<R, Failure> {
        let mut lock = self.instance.lock();
        let lc = lock.lc_provider().map_err(Failure::Wallet)?;
        let backend = lc.wallet_inst().map_err(Failure::Wallet)?;
        f(&mut **backend).map_err(Failure::Wallet)
    }

    pub(crate) fn state(&self) -> Result<WalletState, Failure> {
        self.with(|w| {
            let keychain = w.keychain(None)?;
            let parent = w.parent_key_id();
            let mut outputs = w
                .iter()
                .map(|o| OutputState::new(&keychain, &o))
                .collect::<Result<Vec<_>, _>>()?;
            outputs.sort_by(|a, b| {
                (a.n_child, &a.key_id, &a.mmr_index).cmp(&(b.n_child, &b.key_id, &b.mmr_index))
            });
            let mut transactions: Vec<TxState> = w.tx_log_iter().map(TxState::from).collect();
            transactions.sort_by_key(|t| t.id);
            let scanned = w.last_scanned_block()?;
            Ok(WalletState {
                outputs,
                transactions,
                last_confirmed_height: w.last_confirmed_height()?.to_string(),
                last_scanned_block: ScannedState {
                    height: scanned.height.to_string(),
                    hash: scanned.hash,
                    start_pmmr_index: scanned.start_pmmr_index.to_string(),
                    last_pmmr_index: scanned.last_pmmr_index.to_string(),
                },
                next_child_index: w.current_child_index(&parent)?,
                init_status: format!("{:?}", w.init_status()?),
            })
        })
    }
}

/// Everything about a wallet that a restore or refresh decides. Timestamps and slate ids are left
/// out: upstream takes them from the clock and from a process-wide counter.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct WalletState {
    pub(crate) outputs: Vec<OutputState>,
    pub(crate) transactions: Vec<TxState>,
    pub(crate) last_confirmed_height: String,
    pub(crate) last_scanned_block: ScannedState,
    pub(crate) next_child_index: u32,
    pub(crate) init_status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ScannedState {
    pub(crate) height: String,
    pub(crate) hash: String,
    pub(crate) start_pmmr_index: String,
    pub(crate) last_pmmr_index: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct OutputState {
    pub(crate) key_id: String,
    pub(crate) n_child: u32,
    pub(crate) commit: String,
    pub(crate) value: String,
    pub(crate) status: String,
    pub(crate) height: String,
    pub(crate) lock_height: String,
    pub(crate) is_coinbase: bool,
    pub(crate) mmr_index: Option<String>,
    pub(crate) tx_log_entry: Option<u32>,
}

impl OutputState {
    fn new(keychain: &ExtKeychain, o: &OutputData) -> Result<OutputState, WalletError> {
        let commit = match &o.commit {
            Some(commit) => commit.clone(),
            None => hex(keychain
                .commit(o.value, &o.key_id, &SwitchCommitmentType::Regular)?
                .0),
        };
        Ok(OutputState {
            key_id: o.key_id.to_hex(),
            n_child: o.n_child,
            commit,
            value: o.value.to_string(),
            status: format!("{:?}", o.status),
            height: o.height.to_string(),
            lock_height: o.lock_height.to_string(),
            is_coinbase: o.is_coinbase,
            mmr_index: o.mmr_index.map(|i| i.to_string()),
            tx_log_entry: o.tx_log_entry,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct TxState {
    pub(crate) id: u32,
    pub(crate) tx_type: String,
    pub(crate) confirmed: bool,
    pub(crate) confirmation_height: Option<String>,
    pub(crate) num_inputs: usize,
    pub(crate) num_outputs: usize,
    pub(crate) amount_credited: String,
    pub(crate) amount_debited: String,
    pub(crate) fee: Option<String>,
    pub(crate) ttl_cutoff_height: Option<String>,
    pub(crate) kernel_excess: Option<String>,
    pub(crate) kernel_lookup_min_height: Option<String>,
    pub(crate) has_slate_id: bool,
    pub(crate) public_addr: Option<String>,
}

impl From<TxLogEntry> for TxState {
    fn from(t: TxLogEntry) -> TxState {
        TxState {
            id: t.id,
            tx_type: format!("{:?}", t.tx_type),
            confirmed: t.confirmed,
            confirmation_height: t.confirmation_height.map(|h| h.to_string()),
            num_inputs: t.num_inputs,
            num_outputs: t.num_outputs,
            amount_credited: t.amount_credited.to_string(),
            amount_debited: t.amount_debited.to_string(),
            fee: t.fee.map(|f| f.to_string()),
            ttl_cutoff_height: t.ttl_cutoff_height.map(|h| h.to_string()),
            kernel_excess: t.kernel_excess.map(|k| hex(k.0)),
            kernel_lookup_min_height: t.kernel_lookup_min_height.map(|h| h.to_string()),
            has_slate_id: t.tx_slate_id.is_some(),
            public_addr: t.public_addr,
        }
    }
}

/// Copies a closed wallet directory, so a second instance can start from the same state.
pub(crate) fn copy_dir(from: &Path, to: &Path) -> Result<(), Failure> {
    std::fs::create_dir_all(to).map_err(Failure::Io)?;
    for entry in std::fs::read_dir(from).map_err(Failure::Io)? {
        let entry = entry.map_err(Failure::Io)?;
        let target = to.join(entry.file_name());
        if entry.file_type().map_err(Failure::Io)?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target).map_err(Failure::Io)?;
        }
    }
    Ok(())
}
