//! An upstream `epic-wallet` v4.1.0 party: `DefaultLCProvider` over its own sqlite backend,
//! talking to the test node through upstream's `HTTPNodeClient`, and driven the way the
//! `epic-wallet` CLI drives the file method (`controller/src/command.rs`).

use std::path::Path;
use std::sync::Arc;

use epic_core::core::{Output, TxKernel};
use epic_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use epic_util::{Mutex, ZeroingString};
use epic_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient, PathToSlate};
use epic_wallet_impls::{SlateGetter, SlatePutter};
use epic_wallet_libwallet::api_impl::{foreign, owner};
use epic_wallet_libwallet::{
    BlockFees, InitTxArgs, IssueInvoiceTxArgs, OutputStatus, Slate, SlateVersion, TxLogEntry,
    VersionedSlate, WalletBackend, WalletInst, address,
};

use super::view::{BalanceView, OutputView, PartyView, TxView};
use super::{Offer, Party, Pay, SlateShape, Spend, hex};

/// Upstream wallets use an empty password, as upstream's own tests do.
const PASSWORD: &str = "";
/// The CLI's default `max_outputs` for send and invoice payment.
const MAX_OUTPUTS: u32 = 500;
/// The confirmations `epic-wallet info` counts before an output is spendable, which LEPIC's
/// balance uses too.
const INFO_CONFIRMATIONS: u64 = 10;

type Instance = Arc<
    Mutex<
        Box<
            dyn WalletInst<
                    'static,
                    DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
                    HTTPNodeClient,
                    ExtKeychain,
                >,
        >,
    >,
>;

pub struct UpstreamParty {
    name: &'static str,
    instance: Instance,
    mnemonic: String,
    /// How this wallet writes slate files.
    writes: SlateShape,
}

impl UpstreamParty {
    /// Creates the wallet from a mnemonic, as `epic-wallet init -r` does, and opens it.
    pub fn restore(
        name: &'static str,
        dir: &Path,
        mnemonic: &str,
        node_url: &str,
        writes: SlateShape,
    ) -> UpstreamParty {
        let client = HTTPNodeClient::new(node_url, None).unwrap();
        let mut instance = Box::new(DefaultWalletImpl::<HTTPNodeClient>::new(client).unwrap())
            as Box<
                dyn WalletInst<
                        'static,
                        DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
                        HTTPNodeClient,
                        ExtKeychain,
                    >,
            >;
        let lc = instance.lc_provider().unwrap();
        lc.set_top_level_directory(&dir.to_string_lossy()).unwrap();
        lc.create_wallet(
            None,
            Some(ZeroingString::from(mnemonic)),
            32,
            ZeroingString::from(PASSWORD),
            false,
        )
        .unwrap();
        lc.open_wallet(None, ZeroingString::from(PASSWORD), false, false)
            .unwrap();
        UpstreamParty {
            name,
            instance: Arc::new(Mutex::new(instance)),
            mnemonic: mnemonic.to_owned(),
            writes,
        }
    }

    fn with<R>(
        &self,
        step: &str,
        f: impl FnOnce(
            &mut dyn WalletBackend<'static, HTTPNodeClient, ExtKeychain>,
        ) -> Result<R, epic_wallet_libwallet::Error>,
    ) -> R {
        let mut lock = self.instance.lock();
        let lc = lock.lc_provider().unwrap();
        let backend = lc.wallet_inst().unwrap();
        f(&mut **backend).unwrap_or_else(|e| panic!("{}: upstream {step} failed: {e}", self.name))
    }

    /// The reward of the next block, built as a mining node asks the wallet for it.
    pub fn coinbase(&self, height: u64, fees: u64) -> (Output, TxKernel) {
        let block_fees = BlockFees {
            fees,
            key_id: None,
            height,
        };
        let cb = self.with("build_coinbase", |w| {
            foreign::build_coinbase(&mut *w, None, &block_fees, false)
        });
        (cb.output, cb.kernel)
    }

    fn write(&self, path: &Path, slate: &Slate) {
        match self.writes {
            SlateShape::FileMethod => PathToSlate(path.to_path_buf()).put_tx(slate).unwrap(),
            SlateShape::V3 => {
                let versioned = VersionedSlate::into_version(slate.clone(), SlateVersion::V3);
                std::fs::write(path, serde_json::to_string(&versioned).unwrap()).unwrap();
            }
            SlateShape::V3Header3 => {
                let mut slate = slate.clone();
                slate.version_info.version = 3;
                slate.version_info.orig_version = 3;
                let versioned = VersionedSlate::into_version(slate, SlateVersion::V3);
                std::fs::write(path, serde_json::to_string(&versioned).unwrap()).unwrap();
            }
        }
    }

    /// Reads a slate file and checks its messages, as the CLI does before acting on it.
    fn read(&self, path: &Path) -> Slate {
        let slate = PathToSlate(path.to_path_buf())
            .get_tx()
            .unwrap_or_else(|e| panic!("{}: upstream could not read {path:?}: {e}", self.name));
        foreign::verify_slate_messages(&slate)
            .unwrap_or_else(|e| panic!("{}: messages in {path:?} do not verify: {e}", self.name));
        slate
    }

    fn post(&self, slate: &Slate) {
        self.with("post_tx", |w| {
            owner::post_tx(w.w2n_client(), &slate.tx, false)
        });
    }

    /// The payment proof address `epic-wallet` derives for the default account.
    pub fn proof_address(&self) -> [u8; 32] {
        self.with("proof address", |w| {
            let keychain = w.keychain(None)?;
            let secret = address::address_from_derivation_path(&keychain, &w.parent_key_id(), 0)?;
            Ok(address::ed25519_keypair(&secret)?.1.to_bytes())
        })
    }
}

fn send_args(
    amount: u64,
    ttl_blocks: Option<u64>,
    message: Option<&str>,
    spend: &Spend,
) -> InitTxArgs {
    InitTxArgs {
        src_acct_name: None,
        amount,
        minimum_confirmations: spend.minimum_confirmations,
        max_outputs: MAX_OUTPUTS,
        num_change_outputs: spend.change_outputs,
        selection_strategy_is_use_all: spend.use_all,
        message: message.map(str::to_owned),
        ttl_blocks,
        ..Default::default()
    }
}

impl Party for UpstreamParty {
    fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    fn send(&mut self, out: &Path, offer: &Offer) -> String {
        let mut args = send_args(
            offer.amount,
            offer.ttl_blocks,
            offer.message.as_deref(),
            &offer.spend,
        );
        args.payment_proof_recipient_address = offer
            .proof_to
            .map(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap());
        let s1 = self.with("init_send_tx", |w| {
            owner::init_send_tx(&mut *w, None, args, false)
        });
        self.write(out, &s1);
        let dest = out.to_string_lossy().into_owned();
        self.with("tx_lock_outputs", |w| {
            owner::tx_lock_outputs(&mut *w, None, &s1, 0, Some(dest))
        });
        s1.id.to_string()
    }

    fn receive(&mut self, input: &Path, out: &Path, message: Option<&str>) -> String {
        let s1 = self.read(input);
        let s2 = self.with("receive_tx", |w| {
            foreign::receive_tx(
                &mut *w,
                None,
                &s1,
                Some("default"),
                message.map(str::to_owned),
                None,
                false,
            )
        });
        self.write(out, &s2);
        s2.id.to_string()
    }

    fn finalize_and_post(&mut self, input: &Path) {
        let s2 = self.read(input);
        let s3 = self.with("finalize_tx", |w| owner::finalize_tx(&mut *w, None, &s2));
        self.post(&s3);
    }

    fn issue_invoice(&mut self, out: &Path, amount: u64, message: Option<&str>) -> String {
        let args = IssueInvoiceTxArgs {
            dest_acct_name: None,
            amount,
            message: message.map(str::to_owned),
            target_slate_version: None,
        };
        let i1 = self.with("issue_invoice_tx", |w| {
            owner::issue_invoice_tx(&mut *w, None, args, false)
        });
        self.write(out, &i1);
        i1.id.to_string()
    }

    fn pay_invoice(&mut self, input: &Path, out: &Path, pay: &Pay) -> String {
        let i1 = self.read(input);
        // Upstream pays the amount the invoice asks for.
        let args = send_args(0, pay.ttl_blocks, pay.message.as_deref(), &pay.spend);
        let i2 = self.with("process_invoice_tx", |w| {
            owner::process_invoice_tx(&mut *w, None, &i1, args, false)
        });
        self.write(out, &i2);
        let dest = out.to_string_lossy().into_owned();
        self.with("tx_lock_outputs", |w| {
            owner::tx_lock_outputs(&mut *w, None, &i2, 0, Some(dest))
        });
        i2.id.to_string()
    }

    fn finalize_invoice_and_post(&mut self, input: &Path) {
        let i2 = self.read(input);
        let i3 = self.with("finalize_invoice_tx", |w| {
            foreign::finalize_invoice_tx(&mut *w, None, &i2)
        });
        self.post(&i3);
    }

    fn cancel(&mut self, slate_id: &str) {
        let tx_id = self.with("find the transaction", |w| {
            Ok(w.tx_log_iter()
                .find(|t| t.tx_slate_id.is_some_and(|s| s.to_string() == slate_id))
                .map(|t| t.id))
        });
        let tx_id = tx_id.unwrap_or_else(|| panic!("{}: no transaction for {slate_id}", self.name));
        owner::cancel_tx(self.instance.clone(), None, &None, Some(tx_id), None)
            .unwrap_or_else(|e| panic!("{}: upstream cancel failed: {e}", self.name));
    }

    fn refresh(&mut self) {
        let reached = owner::update_wallet_state(self.instance.clone(), None, &None, false)
            .unwrap_or_else(|e| panic!("{}: upstream refresh failed: {e}", self.name));
        assert!(
            reached,
            "{}: upstream refresh did not reach the node",
            self.name
        );
    }

    fn view(&mut self, slate_id: Option<&str>) -> PartyView {
        let (_, info) = owner::retrieve_summary_info(
            self.instance.clone(),
            None,
            &None,
            false,
            INFO_CONFIRMATIONS,
        )
        .unwrap();
        let balance = BalanceView {
            total: info.total,
            spendable: info.amount_currently_spendable,
            awaiting_confirmation: info.amount_awaiting_confirmation,
            awaiting_finalization: info.amount_awaiting_finalization,
            immature: info.amount_immature,
            locked: info.amount_locked,
        };
        let (outputs, entries, tx) = self.with("view", |w| {
            let keychain = w.keychain(None)?;
            let mut outputs = Vec::new();
            for o in w.iter() {
                let commit = match &o.commit {
                    Some(commit) => commit.clone(),
                    None => hex(&keychain
                        .commit(o.value, &o.key_id, &SwitchCommitmentType::Regular)?
                        .0),
                };
                outputs.push(OutputView {
                    commit,
                    value: o.value,
                    status: output_status(&o.status),
                });
            }
            outputs.sort();
            let entry = slate_id.and_then(|id| {
                w.tx_log_iter()
                    .find(|t| t.tx_slate_id.is_some_and(|s| s.to_string() == id))
            });
            let tx = match entry {
                Some(entry) => {
                    let stored = w.get_stored_tx(&entry)?.is_some();
                    Some(tx_view(&entry, stored))
                }
                None => None,
            };
            Ok((outputs, w.tx_log_iter().count(), tx))
        });
        PartyView {
            balance,
            outputs,
            entries,
            tx,
        }
    }
}

fn output_status(status: &OutputStatus) -> &'static str {
    match status {
        OutputStatus::Unconfirmed => "Unconfirmed",
        OutputStatus::Unspent => "Unspent",
        OutputStatus::Locked => "Locked",
        OutputStatus::Spent => "Spent",
        OutputStatus::Deleted => "Deleted",
    }
}

fn tx_view(entry: &TxLogEntry, stored_tx: bool) -> TxView {
    let mut messages: Vec<String> = entry
        .messages
        .iter()
        .flat_map(|m| m.messages.iter())
        .filter_map(|m| m.message.clone())
        .collect();
    messages.sort();
    TxView {
        upstream_states: vec![(format!("{:?}", entry.tx_type), entry.confirmed)],
        amount_credited: entry.amount_credited,
        amount_debited: entry.amount_debited,
        fee: entry.fee,
        ttl_cutoff_height: Some(entry.ttl_cutoff_height),
        stored_tx: Some(stored_tx),
        messages: Some(messages),
        kernel_excess: Some(entry.kernel_excess.map(|k| hex(&k.0))),
    }
}
