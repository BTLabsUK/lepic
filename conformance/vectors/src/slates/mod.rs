// SPDX-License-Identifier: Apache-2.0
//! Slates area: the slate JSON upstream writes at every stage of the standard and invoice flows,
//! the exact bytes of the file method and the Epicbox plaintext, and upstream's parse outcome for
//! malformed slates. Every case runs two upstream wallets on a fresh in-process test chain in
//! test-RNG mode, so the area regenerates byte for byte.

mod flows;
mod harness;
mod malformed;

use serde::Serialize;

use crate::{Error, LOCKFILE, Pins, Rendered, Upstream, chain_type_guard, git_source, render};
use flows::{Case, Flow, FlowRecord, Funding, Method, Role, RoleKeys, StageRecord};
use harness::TestChain;

const AREA: &str = "slates";

// BIP-39 test-vector mnemonics, never real wallet material.
const SENDER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon art";
const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

const SENDER_MESSAGE: &str = "lepic vector: sender message";
const RECEIVER_MESSAGE: &str = "lepic vector: receiver message";
/// ASCII, and longer than the message length upstream keeps.
const LONG_MESSAGE: &str = concat!(
    "lepic vector: a message longer than upstream keeps. ",
    "0123456789012345678901234567890123456789012345678",
    "0123456789012345678901234567890123456789012345678",
    "0123456789012345678901234567890123456789012345678",
    "0123456789012345678901234567890123456789012345678",
    "0123456789012345678901234567890123456789012345678",
);

/// With four blocks the tip is below the test chain's first hard fork, so slates carry block
/// header version 6 as mainnet slates do today; with seven they carry 7.
const HEADER_6_BLOCKS: usize = 4;
const HEADER_7_BLOCKS: usize = 7;
const TTL_BLOCKS: u64 = 30;
/// One above the tip the slate is built at, so the final transaction is mined at its lock height.
const LOCK_HEIGHT: u64 = 5;

const fn case(name: &'static str, flow: Flow, method: Method, amount: u64) -> Case {
    Case {
        name,
        flow,
        method,
        amount,
        initiator_message: None,
        responder_message: None,
        ttl_blocks: None,
        payment_proof: false,
        change_outputs: 1,
        blocks_before: HEADER_6_BLOCKS,
        funding: Funding::Coinbase,
        lock_height: None,
    }
}

const STANDARD: Flow = Flow::Standard;
const INVOICE: Flow = Flow::Invoice;
const FILE: Method = Method::File;
const EPICBOX: Method = Method::Epicbox;

/// Order matters: upstream derives test-RNG slate ids from a process-wide counter, so each
/// case's id depends on how many cases ran before it in this process.
const CASES: &[Case] = &[
    case("send_file_plain", STANDARD, FILE, 100_000_000),
    Case {
        initiator_message: Some(SENDER_MESSAGE),
        responder_message: Some(RECEIVER_MESSAGE),
        ..case("send_file_messages", STANDARD, FILE, 110_000_000)
    },
    Case {
        initiator_message: Some(LONG_MESSAGE),
        responder_message: Some(LONG_MESSAGE),
        ..case("send_file_long_messages", STANDARD, FILE, 120_000_000)
    },
    Case {
        ttl_blocks: Some(TTL_BLOCKS),
        ..case("send_file_ttl", STANDARD, FILE, 130_000_000)
    },
    Case {
        payment_proof: true,
        ..case("send_file_payment_proof", STANDARD, FILE, 140_000_000)
    },
    Case {
        initiator_message: Some(SENDER_MESSAGE),
        responder_message: Some(RECEIVER_MESSAGE),
        ttl_blocks: Some(TTL_BLOCKS),
        payment_proof: true,
        ..case(
            "send_file_ttl_payment_proof_messages",
            STANDARD,
            FILE,
            150_000_000,
        )
    },
    Case {
        change_outputs: 3,
        ..case(
            "send_file_three_change_outputs",
            STANDARD,
            FILE,
            160_000_000,
        )
    },
    Case {
        funding: Funding::Change,
        ..case("send_file_plain_input", STANDARD, FILE, 170_000_000)
    },
    Case {
        blocks_before: HEADER_7_BLOCKS,
        ..case("send_file_header_7", STANDARD, FILE, 180_000_000)
    },
    case("send_epicbox_plain", STANDARD, EPICBOX, 200_000_000),
    Case {
        initiator_message: Some(SENDER_MESSAGE),
        ..case("send_epicbox_message", STANDARD, EPICBOX, 210_000_000)
    },
    Case {
        ttl_blocks: Some(TTL_BLOCKS),
        payment_proof: true,
        ..case(
            "send_epicbox_ttl_payment_proof",
            STANDARD,
            EPICBOX,
            220_000_000,
        )
    },
    Case {
        blocks_before: HEADER_7_BLOCKS,
        ..case("send_epicbox_header_7", STANDARD, EPICBOX, 230_000_000)
    },
    case("invoice_file_plain", INVOICE, FILE, 300_000_000),
    Case {
        initiator_message: Some(RECEIVER_MESSAGE),
        responder_message: Some(SENDER_MESSAGE),
        ..case("invoice_file_messages", INVOICE, FILE, 310_000_000)
    },
    Case {
        ttl_blocks: Some(TTL_BLOCKS),
        ..case("invoice_file_ttl", INVOICE, FILE, 320_000_000)
    },
    Case {
        blocks_before: HEADER_7_BLOCKS,
        ..case("invoice_file_header_7", INVOICE, FILE, 330_000_000)
    },
    Case {
        lock_height: Some(LOCK_HEIGHT),
        ..case("send_file_height_locked", STANDARD, FILE, 190_000_000)
    },
];

/// Upstream's counter is a `u8` with checked arithmetic in debug builds, so one process can
/// create at most 255 test-RNG slates. Every case creates exactly one.
const _: () = assert!(CASES.len() <= 255);

#[derive(Serialize)]
struct Options {
    amount: String,
    initiator_message: Option<&'static str>,
    responder_message: Option<&'static str>,
    ttl_blocks: Option<String>,
    payment_proof: bool,
    change_outputs: u32,
    minimum_confirmations: String,
    selection_strategy: &'static str,
    blocks_before: usize,
    funding: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    lock_height: Option<String>,
}

#[derive(Serialize)]
struct WalletInputs {
    role: &'static str,
    mnemonic: &'static str,
    account: &'static str,
    inputs: Vec<flows::KeyUse>,
    outputs: Vec<flows::KeyUse>,
}

#[derive(Serialize)]
struct StageInputs<'a> {
    case: &'a str,
    flow: &'static str,
    method: &'static str,
    stage: &'static str,
    producer: &'static str,
    encoding: &'static str,
    chain_type: &'static str,
    use_test_rng: bool,
    options: Options,
    wallets: Vec<WalletInputs>,
}

#[derive(Serialize)]
pub(super) struct Header {
    version: u64,
    orig_version: u64,
    block_header_version: u64,
}

#[derive(Serialize)]
struct FinalTx {
    json: String,
    serialized: String,
}

#[derive(Serialize)]
struct StageExpected {
    shape: &'static str,
    header: Header,
    slate_id: String,
    /// Values upstream drew at random. Empty: test-RNG mode fixes every one of them.
    randomized: Vec<&'static str>,
    json: String,
    final_tx: Option<FinalTx>,
}

pub(crate) fn generate(_pins: &Pins) -> Result<Vec<Rendered>, Error> {
    let _chain_type = chain_type_guard();
    let upstream = git_source(LOCKFILE, "epic_wallet_libwallet")?;
    let mut vectors = Vec::new();
    let mut flows = Vec::new();
    for case in CASES {
        let record = run_case(case)?;
        for stage in &record.stages {
            vectors.extend(render_stage(&upstream, case, &record, stage)?);
        }
        flows.push((case, record));
    }
    vectors.extend(malformed::generate(&upstream, &flows)?);
    Ok(vectors)
}

fn run_case(case: &Case) -> Result<FlowRecord, Error> {
    let chain = TestChain::start(case.name, SENDER_MNEMONIC, RECEIVER_MNEMONIC)?;
    chain.mine(&chain.sender, &[], case.blocks_before)?;
    if case.funding == Funding::Change {
        flows::fund_change_output(&chain)?;
    }
    let record = flows::run(&chain, chain.scratch(), case)?;
    // Mining the final transaction shows the upstream node accepts it.
    chain.mine(&chain.sender, &[&record.final_tx], 1)?;
    chain.stop()?;
    Ok(record)
}

fn render_stage(
    upstream: &Upstream,
    case: &Case,
    record: &FlowRecord,
    stage: &StageRecord,
) -> Result<Vec<Rendered>, Error> {
    use epic_wallet_libwallet::{SlateVersion, VersionedSlate};

    let mut encodings: Vec<(&'static str, String)> = Vec::new();
    if let Some(wire) = &stage.wire {
        encodings.push((wire.encoding, wire.text.clone()));
    }
    for (encoding, version) in [("v3", SlateVersion::V3), ("v2", SlateVersion::V2)] {
        let versioned = VersionedSlate::into_version(stage.slate.clone(), version);
        encodings.push((encoding, serde_json::to_string(&versioned)?));
    }

    let is_final = matches!(stage.stage, flows::Stage::S3 | flows::Stage::I3);
    let mut rendered = Vec::new();
    for (encoding, json) in encodings {
        let name = format!(
            "{}_{}_{encoding}",
            case.name,
            stage.stage.name().to_lowercase()
        );
        let inputs = StageInputs {
            case: case.name,
            flow: case.flow.name(),
            method: case.method.name(),
            stage: stage.stage.name(),
            producer: stage.producer.name(),
            encoding,
            chain_type: "AutomatedTesting",
            use_test_rng: true,
            options: options(case),
            wallets: stage.keys.iter().map(wallet_inputs).collect(),
        };
        let final_tx = if is_final {
            Some(FinalTx {
                json: serde_json::to_string(&record.final_tx)?,
                serialized: flows::tx_hex(&record.final_tx)?,
            })
        } else {
            None
        };
        let (shape, header) = shape_and_header(&json)?;
        let expected = StageExpected {
            shape,
            header,
            slate_id: stage.slate.id.to_string(),
            randomized: Vec::new(),
            json,
            final_tx,
        };
        rendered.push(render(AREA, &name, upstream, inputs, expected)?);
    }
    Ok(rendered)
}

fn options(case: &Case) -> Options {
    Options {
        amount: case.amount.to_string(),
        initiator_message: case.initiator_message,
        responder_message: case.responder_message,
        ttl_blocks: case.ttl_blocks.map(|b| b.to_string()),
        payment_proof: case.payment_proof,
        change_outputs: case.change_outputs,
        minimum_confirmations: flows::MINIMUM_CONFIRMATIONS.to_string(),
        selection_strategy: "smallest",
        blocks_before: case.blocks_before,
        funding: case.funding.name(),
        lock_height: case.lock_height.map(|height| height.to_string()),
    }
}

fn wallet_inputs(keys: &RoleKeys) -> WalletInputs {
    let mnemonic = if keys.role == Role::Sender.name() || keys.role == Role::Payer.name() {
        SENDER_MNEMONIC
    } else {
        RECEIVER_MNEMONIC
    };
    WalletInputs {
        role: keys.role,
        mnemonic,
        account: "default",
        inputs: keys.inputs.clone(),
        outputs: keys.outputs.clone(),
    }
}

/// Reads the shape and header from the emitted bytes themselves: the V3 shape is the one with
/// the `ttl_cutoff_height` key.
fn shape_and_header(json: &str) -> Result<(&'static str, Header), Error> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let shape = shape_of(&value).ok_or_else(|| Error::Reference {
        step: "reading the slate shape",
        source: "slate is not a JSON object".into(),
    })?;
    let header = header_of(&value).ok_or_else(|| Error::Reference {
        step: "reading the slate header",
        source: "version_info does not hold three numbers".into(),
    })?;
    Ok((shape, header))
}

/// The V3 shape is the object with the `ttl_cutoff_height` key; `None` when it is not an object.
pub(super) fn shape_of(value: &serde_json::Value) -> Option<&'static str> {
    let object = value.as_object()?;
    Some(if object.contains_key("ttl_cutoff_height") {
        "V3"
    } else {
        "V2"
    })
}

/// `None` when `version_info` or one of its numbers is missing.
pub(super) fn header_of(value: &serde_json::Value) -> Option<Header> {
    let info = value.get("version_info")?;
    let field = |name: &str| info.get(name).and_then(serde_json::Value::as_u64);
    Some(Header {
        version: field("version")?,
        orig_version: field("orig_version")?,
        block_header_version: field("block_header_version")?,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use super::*;
    use crate::DEFAULT_OUT;

    const CHILD: &str = "LEPIC_SLATES_VECTORS_CHILD";
    const THIS_TEST: &str = "slates::tests::regenerated_vectors_match_committed_files";

    /// Upstream keeps the chain type and the slate counter in process globals, so the comparison
    /// runs in a child process of its own and cannot disturb, or be disturbed by, other tests.
    #[test]
    fn regenerated_vectors_match_committed_files() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(CHILD).is_some() {
            return compare_with_committed_files();
        }
        let status = Command::new(std::env::current_exe()?)
            .args(["--exact", THIS_TEST, "--test-threads=1"])
            .env(CHILD, "1")
            .status()?;
        assert!(status.success(), "child generator run failed: {status}");
        Ok(())
    }

    fn compare_with_committed_files() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        let vectors = generate(&pins)?;
        let dir = Path::new(DEFAULT_OUT).join(AREA);
        for vector in &vectors {
            let path = dir.join(format!("{}.json", vector.name));
            let committed = std::fs::read_to_string(&path)?;
            let regenerated = String::from_utf8(vector.bytes.clone())?;
            assert_same_text(&committed, &regenerated, &path);
        }
        let committed = std::fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .count();
        assert_eq!(committed, vectors.len(), "stale files in {}", dir.display());
        Ok(())
    }

    /// Reports where the files first differ, with a little context, rather than two whole files
    /// of escaped JSON.
    fn assert_same_text(committed: &str, regenerated: &str, path: &Path) {
        let offset = committed
            .bytes()
            .zip(regenerated.bytes())
            .position(|(left, right)| left != right)
            .unwrap_or(committed.len().min(regenerated.len()));
        if offset == committed.len() && offset == regenerated.len() {
            return;
        }
        let window = |text: &str| {
            let from = offset.saturating_sub(40);
            let to = offset.saturating_add(40).min(text.len());
            String::from_utf8_lossy(text.as_bytes().get(from..to).unwrap_or_default()).into_owned()
        };
        panic!(
            "{} differs at byte {offset}\ncommitted:   ...{}...\nregenerated: ...{}...",
            path.display(),
            window(committed),
            window(regenerated)
        );
    }
}
