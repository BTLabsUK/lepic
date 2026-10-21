//! The payer's side of an invoice once it has answered with an I2: the issuer can still post
//! the payment, so a cancel asks the node first and keeps the payment watched. And the payer
//! refuses an invoice whose kernel the chain could not take yet.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "invoice/harness.rs"]
mod harness;
mod support;

use harness::{ACCOUNT, FUNDING, ISSUER_MNEMONIC, PAYER_MNEMONIC, Party};
use lepic_node::mock::{ChainOutput, ChainState, MockNode};
use lepic_node::{LocatedKernel, NodeVersion, Tip};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::tx::Transaction;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{
    OutputRecord, OutputStatus, SlateStage, StoreError, StoredSlate, TxDirection, TxId, TxState,
    WalletStore,
};
use lepic_wallet::WalletError;
use lepic_wallet::chain::SLATE_LEAD_BLOCKS;
use lepic_wallet::invoice::{InvoiceError, PayRequest};
use lepic_wallet::selection::SelectionStrategy;
use serde_json::Value;
use uuid::Uuid;

const AMOUNT: u64 = 300_000_000;
const TIP: u64 = 4;

fn node() -> MockNode {
    MockNode::from_chain(ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(TIP),
            last_block_pushed: Hash::from_slice(&[0; 32]).unwrap(),
        },
    ))
}

fn request() -> PayRequest {
    PayRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..PayRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

/// `wire` with its JSON changed by `change`.
fn tampered(wire: &WireSlate, change: impl FnOnce(&mut Value)) -> WireSlate {
    let mut slate: Value = serde_json::from_str(wire.as_text().unwrap()).unwrap();
    change(&mut slate);
    WireSlate::text(MediaType::JSON, slate.to_string())
}

struct Invoice {
    node: MockNode,
    issuer: Party,
    payer: Party,
    slate_id: Uuid,
    i1: WireSlate,
}

impl Invoice {
    /// An invoice issued and delivered, and a payer holding one coinbase output at child 0.
    fn issued() -> Self {
        let node = node();
        let issuer = Party::new(ISSUER_MNEMONIC, &node);
        let issued = issuer.issue(AMOUNT, None).unwrap();
        let i1 = issuer.delivered().unwrap();
        let payer = Party::new(PAYER_MNEMONIC, &node);
        payer.fund(0, FUNDING);
        payer.set_next_child(1);
        Self {
            node,
            issuer,
            payer,
            slate_id: Uuid::from_bytes(*issued.slate_id.as_bytes()),
            i1,
        }
    }

    fn payment(&self) -> Option<(TxId, TxState)> {
        self.payer
            .read(|repos| repos.transaction_by_slate(self.slate_id, TxDirection::Outgoing))
            .map(|stored| (stored.id, stored.entry.state))
    }

    fn outputs(&self) -> Vec<OutputRecord> {
        self.payer.read(|repos| repos.outputs(ACCOUNT, None))
    }

    fn change(&self) -> Vec<OutputRecord> {
        self.outputs()
            .into_iter()
            .filter(|output| output.amount.value() != FUNDING)
            .collect()
    }

    /// The payment as the issuer posted it.
    fn posted(&self) -> Transaction {
        self.node.pushed_transactions()[0].clone()
    }

    fn mined_at(&self, height: u64) {
        let posted = self.posted();
        self.node.update_chain(|chain| {
            chain.tip.height = Height::new(height);
            for (position, output) in posted.outputs().iter().enumerate() {
                chain.outputs.push(ChainOutput {
                    commitment: output.commitment,
                    features: output.features,
                    proof: output.proof.clone(),
                    height: Height::new(height),
                    mmr_index: 2 + position as u64,
                    spent: false,
                });
            }
            chain.kernels.push(LocatedKernel {
                kernel: posted.kernels()[0],
                height: Height::new(height),
                mmr_index: 1,
            });
        });
    }
}

#[test]
fn a_payer_cancel_after_the_i2_keeps_a_watch_that_restores_a_payment_the_issuer_posts_later() {
    let invoice = Invoice::issued();
    let i2 = invoice.payer.pay(&invoice.i1, request()).unwrap().reply;
    let (tx_id, _) = invoice.payment().unwrap();
    let change_before = invoice.change();
    assert_eq!(change_before.len(), 1);

    invoice
        .payer
        .block_on(invoice.payer.wallet.cancel(tx_id))
        .unwrap();
    assert_eq!(invoice.payment(), Some((tx_id, TxState::Cancelled)));
    assert!(invoice.change().is_empty(), "the cancel drops the change");

    // The issuer still holds the I2, finalizes it, and the chain mines the I3.
    invoice.issuer.finalize(&i2).unwrap();
    invoice.mined_at(TIP + 1);
    invoice
        .payer
        .block_on(invoice.payer.wallet.refresh())
        .unwrap();

    assert_eq!(invoice.payment(), Some((tx_id, TxState::Confirmed)));
    let change = invoice.change();
    assert_eq!(change.len(), 1, "{change:?}");
    assert_eq!(change[0].id, change_before[0].id);
    assert_eq!(change[0].amount, change_before[0].amount);
    assert_eq!(change[0].status, OutputStatus::Unspent);
    assert_eq!(change[0].height, Height::new(TIP + 1));
}

#[test]
fn a_payer_cancel_after_the_i2_is_refused_while_the_node_pool_holds_the_issuers_post() {
    let invoice = Invoice::issued();
    let i2 = invoice.payer.pay(&invoice.i1, request()).unwrap().reply;
    let (tx_id, _) = invoice.payment().unwrap();
    invoice.issuer.finalize(&i2).unwrap();
    let posted = invoice.posted();
    invoice.node.update_chain(|chain| chain.pool.push(posted));
    let outputs = invoice.outputs();

    let error = invoice
        .payer
        .block_on(invoice.payer.wallet.cancel(tx_id))
        .unwrap_err();

    assert!(
        matches!(error, WalletError::InPool(id) if id == tx_id),
        "{error:?}"
    );
    assert_eq!(invoice.payment(), Some((tx_id, TxState::Sent)));
    assert_eq!(invoice.outputs(), outputs);
}

fn locked_at(wire: &WireSlate, height: u64) -> WireSlate {
    tampered(wire, |slate| {
        slate["lock_height"] = Value::String(height.to_string());
        let kernel = &mut slate["tx"]["body"]["kernels"][0];
        kernel["features"] = Value::String("HeightLocked".to_owned());
        kernel["lock_height"] = Value::String(height.to_string());
    })
}

#[test]
fn refuses_an_invoice_whose_kernel_is_locked_above_the_tip_and_stores_nothing() {
    let invoice = Invoice::issued();
    let outputs = invoice.outputs();
    let far = TIP + 1_000_000;

    let error = invoice
        .payer
        .pay(&locked_at(&invoice.i1, far), request())
        .unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::LockedUntil { lock_height, tip }
                if lock_height == Height::new(far) && tip == Height::new(TIP)
        ),
        "{error:?}"
    );
    assert_eq!(invoice.payment(), None);
    assert_eq!(invoice.outputs(), outputs);
    assert!(
        invoice
            .payer
            .read(|repos| repos.slates(invoice.slate_id))
            .is_empty()
    );
}

#[test]
fn refuses_an_invoice_locked_one_block_above_the_tip() {
    let invoice = Invoice::issued();

    let error = invoice
        .payer
        .pay(&locked_at(&invoice.i1, TIP + 1), request())
        .unwrap_err();

    assert!(
        matches!(error, InvoiceError::LockedUntil { .. }),
        "{error:?}"
    );
}

#[test]
fn pays_an_invoice_whose_lock_height_the_chain_has_reached() {
    let invoice = Invoice::issued();

    invoice
        .payer
        .pay(&locked_at(&invoice.i1, TIP), request())
        .unwrap();

    assert!(matches!(invoice.payment(), Some((_, TxState::Sent))));
}

/// `wire` with its slate height set to `height`.
fn created_at(wire: &WireSlate, height: u64) -> WireSlate {
    tampered(wire, |slate| {
        slate["height"] = Value::String(height.to_string());
    })
}

#[test]
fn refuses_an_invoice_created_above_the_tip_and_stores_nothing() {
    let invoice = Invoice::issued();
    let outputs = invoice.outputs();
    let ahead = TIP + SLATE_LEAD_BLOCKS + 1;

    let error = invoice
        .payer
        .pay(&created_at(&invoice.i1, ahead), request())
        .unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::AheadOfTip { height, tip }
                if height == Height::new(ahead) && tip == Height::new(TIP)
        ),
        "{error:?}"
    );
    assert_eq!(invoice.payment(), None);
    assert_eq!(invoice.outputs(), outputs);
    assert!(
        invoice
            .payer
            .read(|repos| repos.slates(invoice.slate_id))
            .is_empty()
    );
}

#[test]
fn pays_an_invoice_created_a_few_blocks_above_the_tip_at_its_own_height() {
    let invoice = Invoice::issued();

    let i2 = invoice
        .payer
        .pay(&created_at(&invoice.i1, TIP + SLATE_LEAD_BLOCKS), request())
        .unwrap()
        .slate;

    assert!(matches!(invoice.payment(), Some((_, TxState::Sent))));
    assert_eq!(i2.height(), Height::new(TIP));
}

#[test]
fn a_payment_stored_with_a_height_above_the_tip_can_be_cancelled() {
    let invoice = Invoice::issued();
    invoice.payer.pay(&invoice.i1, request()).unwrap();
    let (tx_id, _) = invoice.payment().unwrap();
    // As a database written before slate heights were checked may hold one: a copy of the
    // payment whose I2 has a height far above any chain.
    let id = Uuid::from_u128(7);
    let copy = invoice
        .payer
        .store()
        .write(|repos| {
            let mut entry = repos.transaction(tx_id)?.unwrap();
            let i2 = repos
                .slate(entry.slate_id.unwrap(), SlateStage::Invoice2)?
                .unwrap();
            let mut slate: Value = serde_json::from_slice(&i2.bytes).unwrap();
            slate["id"] = Value::String(id.to_string());
            slate["height"] = Value::String("1000000000000".to_owned());
            entry.slate_id = Some(id);
            let copy = repos.insert_transaction(&entry)?;
            repos.insert_slate(&StoredSlate {
                slate_id: id,
                stage: SlateStage::Invoice2,
                codec: i2.codec,
                bytes: slate.to_string().into_bytes(),
            })?;
            Ok::<_, StoreError>(copy)
        })
        .unwrap();

    invoice
        .payer
        .block_on(invoice.payer.wallet.cancel(copy))
        .unwrap();

    let state = invoice.payer.read(|repos| repos.transaction(copy));
    assert_eq!(state.unwrap().state, TxState::Cancelled);
}
