// SPDX-License-Identifier: Apache-2.0
//! Standard and invoice flows, each run as the epic-wallet CLI runs it for the file and Epicbox
//! methods (`controller/src/command.rs`, `impls/src/adapters/{file,epicbox}.rs`).

use std::path::{Path, PathBuf};

use epic_core::core::Transaction;
use epic_keychain::Keychain;
use epic_util::secp::key::PublicKey;
use epic_wallet_impls::{PathToSlate, SlateGetter, SlatePutter};
use epic_wallet_libwallet::api_impl::{foreign, owner};
use epic_wallet_libwallet::{
    EpicboxAddress, InitTxArgs, IssueInvoiceTxArgs, Slate, SlateVersion, VersionedSlate, address,
};

use super::harness::{NO_MASK, TestChain, Wallet, with_backend};
use crate::{Error, hex};

/// The CLI's `-c` option; every case uses one confirmation so the test chain stays short.
pub(super) const MINIMUM_CONFIRMATIONS: u64 = 1;
/// The CLI's default `max_outputs` for send and invoice processing.
const MAX_OUTPUTS: u32 = 500;
/// Upstream's default account, which the CLI passes to `receive_tx` on the file method.
const ACCOUNT: &str = "default";
const EPICBOX_DOMAIN: &str = "epicbox.epiccash.com";
const EPICBOX_PORT: u16 = 443;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Flow {
    Standard,
    Invoice,
}

impl Flow {
    pub(super) fn name(self) -> &'static str {
        match self {
            Flow::Standard => "standard",
            Flow::Invoice => "invoice",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Method {
    File,
    Epicbox,
}

impl Method {
    pub(super) fn name(self) -> &'static str {
        match self {
            Method::File => "file",
            Method::Epicbox => "epicbox",
        }
    }
}

/// One flow. In the standard flow the initiator is the sender; in the invoice flow it is the
/// issuer, and the payer responds.
pub(super) struct Case {
    pub(super) name: &'static str,
    pub(super) flow: Flow,
    pub(super) method: Method,
    pub(super) amount: u64,
    pub(super) initiator_message: Option<&'static str>,
    pub(super) responder_message: Option<&'static str>,
    pub(super) ttl_blocks: Option<u64>,
    pub(super) payment_proof: bool,
    pub(super) change_outputs: u32,
    /// Blocks mined to the sender on a fresh chain before the flow starts. The slate header's
    /// block version follows the tip height, so this picks it.
    pub(super) blocks_before: usize,
    pub(super) funding: Funding,
    /// A lock height the generator sets on upstream's S1 before writing it, as a wallet that
    /// builds height-locked slates would. Upstream itself always writes 0.
    pub(super) lock_height: Option<u64>,
}

/// What the sender (or payer) spends.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Funding {
    /// Its oldest mature coinbase output.
    Coinbase,
    /// The change output of a transaction mined just before the flow, so the input is `Plain`.
    Change,
}

impl Funding {
    pub(super) fn name(self) -> &'static str {
        match self {
            Funding::Coinbase => "coinbase",
            Funding::Change => "change",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Sender,
    Receiver,
    Issuer,
    Payer,
}

impl Role {
    pub(super) fn name(self) -> &'static str {
        match self {
            Role::Sender => "sender",
            Role::Receiver => "receiver",
            Role::Issuer => "issuer",
            Role::Payer => "payer",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Stage {
    S1,
    S2,
    S3,
    I1,
    I2,
    I3,
}

impl Stage {
    pub(super) fn name(self) -> &'static str {
        match self {
            Stage::S1 => "S1",
            Stage::S2 => "S2",
            Stage::S3 => "S3",
            Stage::I1 => "I1",
            Stage::I2 => "I2",
            Stage::I3 => "I3",
        }
    }
}

/// What a transport carried: the bytes the file method wrote, or the plaintext the Epicbox
/// method encrypted.
pub(super) struct Wire {
    pub(super) encoding: &'static str,
    pub(super) text: String,
}

/// A key the producing wallet used, as its derivation identifier and value.
#[derive(Clone, serde::Serialize)]
pub(super) struct KeyUse {
    pub(super) key_id: String,
    pub(super) mmr_index: Option<String>,
    pub(super) value: String,
}

#[derive(Clone, serde::Serialize)]
pub(super) struct RoleKeys {
    pub(super) role: &'static str,
    pub(super) inputs: Vec<KeyUse>,
    pub(super) outputs: Vec<KeyUse>,
}

pub(super) struct StageRecord {
    pub(super) stage: Stage,
    pub(super) producer: Role,
    /// The producer's slate after the stage, before any transport conversion.
    pub(super) slate: Slate,
    pub(super) wire: Option<Wire>,
    /// Keys of every party that has acted up to and including this stage.
    pub(super) keys: Vec<RoleKeys>,
}

pub(super) struct FlowRecord {
    pub(super) stages: Vec<StageRecord>,
    pub(super) final_tx: Transaction,
}

pub(super) fn run(chain: &TestChain, files: &Path, case: &Case) -> Result<FlowRecord, Error> {
    match (case.flow, case.method) {
        (Flow::Standard, Method::File) => standard_file(chain, files, case),
        (Flow::Standard, Method::Epicbox) => standard_epicbox(chain, case),
        (Flow::Invoice, _) => invoice_file(chain, files, case),
    }
}

/// Sends half of the sender's largest output to the receiver outside the test-RNG mode, so the
/// slate counter is untouched, and mines it. The sender is left with a smaller `Plain` change
/// output that the next flow selects first.
pub(super) fn fund_change_output(chain: &TestChain) -> Result<(), Error> {
    let largest = with_backend(&chain.sender, "sender outputs", |w| {
        Ok(w.iter().map(|out| out.value).max().unwrap_or(0))
    })?;
    let args = InitTxArgs {
        src_acct_name: None,
        amount: largest / 2,
        minimum_confirmations: MINIMUM_CONFIRMATIONS,
        max_outputs: MAX_OUTPUTS,
        num_change_outputs: 1,
        selection_strategy_is_use_all: false,
        ..Default::default()
    };
    let s1 = with_backend(&chain.sender, "funding init_send_tx", |w| {
        owner::init_send_tx(w, NO_MASK, args, false)
    })?;
    with_backend(&chain.sender, "funding tx_lock_outputs", |w| {
        owner::tx_lock_outputs(w, NO_MASK, &s1, 0, None)
    })?;
    let s2 = with_backend(&chain.receiver, "funding receive_tx", |w| {
        foreign::receive_tx(w, NO_MASK, &s1, None, None, None, false)
    })?;
    let s3 = with_backend(&chain.sender, "funding finalize_tx", |w| {
        owner::finalize_tx(w, NO_MASK, &s2)
    })?;
    chain.mine(&chain.sender, &[&s3.tx], 1)
}

fn send_args(chain: &TestChain, case: &Case) -> Result<InitTxArgs, Error> {
    let payment_proof_recipient_address = if case.payment_proof {
        Some(with_backend(
            &chain.receiver,
            "receiver proof address",
            |w| {
                let keychain = w.keychain(NO_MASK)?;
                let secret =
                    address::address_from_derivation_path(&keychain, &w.parent_key_id(), 0)?;
                Ok(address::ed25519_keypair(&secret)?.1)
            },
        )?)
    } else {
        None
    };
    Ok(InitTxArgs {
        src_acct_name: None,
        amount: case.amount,
        minimum_confirmations: MINIMUM_CONFIRMATIONS,
        max_outputs: MAX_OUTPUTS,
        num_change_outputs: case.change_outputs,
        selection_strategy_is_use_all: false,
        message: case.initiator_message.map(str::to_owned),
        ttl_blocks: case.ttl_blocks,
        payment_proof_recipient_address,
        ..Default::default()
    })
}

fn standard_file(chain: &TestChain, files: &Path, case: &Case) -> Result<FlowRecord, Error> {
    let args = send_args(chain, case)?;
    let mut s1 = with_backend(&chain.sender, "init_send_tx", |w| {
        owner::init_send_tx(w, NO_MASK, args, true)
    })?;
    if let Some(lock_height) = case.lock_height {
        s1.lock_height = lock_height;
        s1.update_kernel();
    }
    let sender_keys = context_keys(&chain.sender, Role::Sender, &s1, 0)?;
    let tx_path = files.join(format!("{}.tx", case.name));
    let s1_wire = put_file(&tx_path, &s1)?;
    let dest = path_string(&tx_path)?;
    with_backend(&chain.sender, "tx_lock_outputs", |w| {
        owner::tx_lock_outputs(w, NO_MASK, &s1, 0, Some(dest))
    })?;

    let incoming = get_file(&tx_path)?;
    foreign::verify_slate_messages(&incoming).map_err(Error::reference("verify messages"))?;
    let s2 = with_backend(&chain.receiver, "receive_tx", |w| {
        foreign::receive_tx(
            w,
            NO_MASK,
            &incoming,
            Some(ACCOUNT),
            case.responder_message.map(str::to_owned),
            None,
            true,
        )
    })?;
    let receiver_keys = log_keys(&chain.receiver, Role::Receiver, &s2)?;
    let response_path = PathBuf::from(format!("{}.response", tx_path.display()));
    let s2_wire = put_file(&response_path, &s2)?;

    let response = get_file(&response_path)?;
    owner::verify_slate_messages(&response).map_err(Error::reference("verify messages"))?;
    let s3 = with_backend(&chain.sender, "finalize_tx", |w| {
        owner::finalize_tx(w, NO_MASK, &response)
    })?;
    let s3_wire = put_file(&files.join(format!("{}.final", case.name)), &s3)?;

    let both = vec![sender_keys.clone(), receiver_keys];
    Ok(FlowRecord {
        final_tx: s3.tx.clone(),
        stages: vec![
            stage(
                Stage::S1,
                Role::Sender,
                s1,
                Some(s1_wire),
                vec![sender_keys],
            ),
            stage(Stage::S2, Role::Receiver, s2, Some(s2_wire), both.clone()),
            stage(Stage::S3, Role::Sender, s3, Some(s3_wire), both),
        ],
    })
}

/// The sender converts to the V2 shape before encrypting; the receiver replies in the shape it
/// received; the sender finalizes what it decrypted.
fn standard_epicbox(chain: &TestChain, case: &Case) -> Result<FlowRecord, Error> {
    let sender_address = epicbox_address(&chain.sender)?;
    let receiver_address = epicbox_address(&chain.receiver)?;
    let args = send_args(chain, case)?;
    let s1 = with_backend(&chain.sender, "init_send_tx", |w| {
        owner::init_send_tx(w, NO_MASK, args, true)
    })?;
    let sender_keys = context_keys(&chain.sender, Role::Sender, &s1, 0)?;
    let s1_plain = epicbox_plaintext(&VersionedSlate::into_version(s1.clone(), SlateVersion::V2))?;
    let as_sent: Slate = VersionedSlate::into_version(s1.clone(), SlateVersion::V2).into();
    with_backend(&chain.sender, "tx_lock_outputs", |w| {
        owner::tx_lock_outputs(w, NO_MASK, &as_sent, 0, Some(receiver_address))
    })?;

    let (version, incoming) = epicbox_decode(&s1_plain)?;
    let s2 = with_backend(&chain.receiver, "receive_tx", |w| {
        foreign::receive_tx(
            w,
            NO_MASK,
            &incoming,
            None,
            None,
            Some(sender_address),
            true,
        )
    })?;
    let receiver_keys = log_keys(&chain.receiver, Role::Receiver, &s2)?;
    let s2_plain = epicbox_plaintext(&VersionedSlate::into_version(s2.clone(), version))?;

    let (_, response) = epicbox_decode(&s2_plain)?;
    let s3 = with_backend(&chain.sender, "finalize_tx", |w| {
        owner::finalize_tx(w, NO_MASK, &response)
    })?;

    let both = vec![sender_keys.clone(), receiver_keys];
    Ok(FlowRecord {
        final_tx: s3.tx.clone(),
        stages: vec![
            stage(
                Stage::S1,
                Role::Sender,
                s1,
                Some(epicbox_wire(s1_plain)),
                vec![sender_keys],
            ),
            stage(
                Stage::S2,
                Role::Receiver,
                s2,
                Some(epicbox_wire(s2_plain)),
                both.clone(),
            ),
            stage(Stage::S3, Role::Sender, s3, None, both),
        ],
    })
}

/// Upstream has no invoice flow over Epicbox, so invoices use the file method.
fn invoice_file(chain: &TestChain, files: &Path, case: &Case) -> Result<FlowRecord, Error> {
    let issue = IssueInvoiceTxArgs {
        dest_acct_name: None,
        amount: case.amount,
        message: case.initiator_message.map(str::to_owned),
        target_slate_version: None,
    };
    let i1 = with_backend(&chain.receiver, "issue_invoice_tx", |w| {
        owner::issue_invoice_tx(w, NO_MASK, issue, true)
    })?;
    let issuer_keys = context_keys(&chain.receiver, Role::Issuer, &i1, 1)?;
    let invoice_path = files.join(format!("{}.invoice", case.name));
    let i1_wire = put_file(&invoice_path, &i1)?;

    let invoice = get_file(&invoice_path)?;
    owner::verify_slate_messages(&invoice).map_err(Error::reference("verify messages"))?;
    let pay = InitTxArgs {
        src_acct_name: None,
        amount: 0,
        minimum_confirmations: MINIMUM_CONFIRMATIONS,
        max_outputs: MAX_OUTPUTS,
        num_change_outputs: case.change_outputs,
        selection_strategy_is_use_all: false,
        message: case.responder_message.map(str::to_owned),
        ttl_blocks: case.ttl_blocks,
        ..Default::default()
    };
    let i2 = with_backend(&chain.sender, "process_invoice_tx", |w| {
        owner::process_invoice_tx(w, NO_MASK, &invoice, pay, true)
    })?;
    let payer_keys = context_keys(&chain.sender, Role::Payer, &i2, 0)?;
    let paid_path = files.join(format!("{}.paid", case.name));
    let i2_wire = put_file(&paid_path, &i2)?;
    let dest = path_string(&paid_path)?;
    with_backend(&chain.sender, "tx_lock_outputs", |w| {
        owner::tx_lock_outputs(w, NO_MASK, &i2, 0, Some(dest))
    })?;

    let paid = get_file(&paid_path)?;
    foreign::verify_slate_messages(&paid).map_err(Error::reference("verify messages"))?;
    let i3 = with_backend(&chain.receiver, "finalize_invoice_tx", |w| {
        foreign::finalize_invoice_tx(w, NO_MASK, &paid)
    })?;
    let i3_wire = put_file(&files.join(format!("{}.final", case.name)), &i3)?;

    let both = vec![issuer_keys.clone(), payer_keys];
    Ok(FlowRecord {
        final_tx: i3.tx.clone(),
        stages: vec![
            stage(
                Stage::I1,
                Role::Issuer,
                i1,
                Some(i1_wire),
                vec![issuer_keys],
            ),
            stage(Stage::I2, Role::Payer, i2, Some(i2_wire), both.clone()),
            stage(Stage::I3, Role::Issuer, i3, Some(i3_wire), both),
        ],
    })
}

fn stage(
    stage: Stage,
    producer: Role,
    slate: Slate,
    wire: Option<Wire>,
    keys: Vec<RoleKeys>,
) -> StageRecord {
    StageRecord {
        stage,
        producer,
        slate,
        wire,
        keys,
    }
}

fn put_file(path: &Path, slate: &Slate) -> Result<Wire, Error> {
    PathToSlate(path.to_path_buf())
        .put_tx(slate)
        .map_err(Error::reference("file method write"))?;
    let text = std::fs::read_to_string(path).map_err(Error::io(path))?;
    Ok(Wire {
        encoding: "file",
        text,
    })
}

fn get_file(path: &Path) -> Result<Slate, Error> {
    PathToSlate(path.to_path_buf())
        .get_tx()
        .map_err(Error::reference("file method read"))
}

fn path_string(path: &Path) -> Result<String, Error> {
    path.to_str().map(str::to_owned).ok_or_else(|| Error::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other("slate path is not utf-8"),
    })
}

fn epicbox_plaintext(slate: &VersionedSlate) -> Result<String, Error> {
    Ok(serde_json::to_string(slate)?)
}

fn epicbox_wire(text: String) -> Wire {
    Wire {
        encoding: "epicbox",
        text,
    }
}

/// The Epicbox listener parses with the untagged `VersionedSlate`, ignoring the header.
fn epicbox_decode(text: &str) -> Result<(SlateVersion, Slate), Error> {
    let versioned: VersionedSlate = serde_json::from_str(text)?;
    Ok((versioned.version(), versioned.into()))
}

fn epicbox_address(wallet: &Wallet) -> Result<String, Error> {
    with_backend(wallet, "epicbox address", |w| {
        let keychain = w.keychain(NO_MASK)?;
        let secret = address::address_from_derivation_path(&keychain, &w.parent_key_id(), 0)?;
        let public = PublicKey::from_secret_key(keychain.secp(), &secret)?;
        Ok(
            EpicboxAddress::new(public, Some(EPICBOX_DOMAIN.to_owned()), Some(EPICBOX_PORT))
                .to_string(),
        )
    })
}

/// The inputs and outputs the initiating or paying side recorded in its private context.
fn context_keys(
    wallet: &Wallet,
    role: Role,
    slate: &Slate,
    participant_id: usize,
) -> Result<RoleKeys, Error> {
    let context = with_backend(wallet, "private context", |w| {
        w.get_private_context(NO_MASK, slate.id.as_bytes(), participant_id)
    })?;
    let keys = |ids: &[(epic_keychain::Identifier, Option<u64>, u64)]| {
        ids.iter()
            .map(|(key_id, mmr_index, value)| KeyUse {
                key_id: key_id.to_hex(),
                mmr_index: mmr_index.map(|i| i.to_string()),
                value: value.to_string(),
            })
            .collect()
    };
    Ok(RoleKeys {
        role: role.name(),
        inputs: keys(&context.input_ids),
        outputs: keys(&context.output_ids),
    })
}

/// The receiver keeps no private context, so its output is found through the transaction log.
fn log_keys(wallet: &Wallet, role: Role, slate: &Slate) -> Result<RoleKeys, Error> {
    let outputs = with_backend(wallet, "receiver outputs", |w| {
        let entries: Vec<_> = w
            .tx_log_iter()
            .filter(|entry| entry.tx_slate_id == Some(slate.id))
            .map(|entry| (entry.id, entry.parent_key_id))
            .collect();
        Ok(w.iter()
            .filter(|out| {
                entries
                    .iter()
                    .any(|(id, parent)| out.tx_log_entry == Some(*id) && out.root_key_id == *parent)
            })
            .map(|out| KeyUse {
                key_id: out.key_id.to_hex(),
                mmr_index: out.mmr_index.map(|i| i.to_string()),
                value: out.value.to_string(),
            })
            .collect())
    })?;
    Ok(RoleKeys {
        role: role.name(),
        inputs: Vec::new(),
        outputs,
    })
}

pub(super) fn tx_hex(tx: &Transaction) -> Result<String, Error> {
    let bytes = epic_core::ser::ser_vec(tx, epic_core::ser::ProtocolVersion::local())
        .map_err(Error::reference("transaction serialization"))?;
    Ok(hex(bytes))
}
