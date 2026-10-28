// SPDX-License-Identifier: Apache-2.0
//! Finalize logs in their own binary, for the reason `lifecycle_logs.rs` gives: finalize and a
//! later post log in their operation spans with the field vocabulary, and never log a key, the
//! seed or an amount above `debug`.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use lepic_keychain::{Identifier, Seed, SwitchCommitment};
use lepic_node::Propagation;
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::Amount;
use lepic_telemetry::{LogLevel, assert_no_secrets, capture};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, Sender, TIP};
use support::LOOPBACK;

const AMOUNT: u64 = 100_000_000;
const FEE: u64 = 800_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn finalize_and_post_log_in_their_spans_and_never_log_secrets_or_amounts() {
    let sender = Sender::new();
    let request = SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    };
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            request,
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let (s1, _) = sender.received().unwrap();
    let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
        .receive(
            FILE,
            s1.as_text().unwrap(),
            Some("receiver log test message"),
        )
        .unwrap()
        .reply;
    sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);

    let ((), captured) = capture(|| {
        let error = sender
            .harness
            .block_on(sender.wallet.finalize(LOOPBACK, &s2, Propagation::Stem))
            .unwrap_err();
        assert!(
            matches!(error, FinalizeError::NotPosted { .. }),
            "{error:?}"
        );
        sender
            .harness
            .block_on(sender.wallet.post(sent.tx_id, Propagation::Stem))
            .unwrap();
    });

    let seed = Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).unwrap();
    mac.update(b"lepic-wallet private context key v1");
    let context_key: [u8; 32] = mac.finalize_fixed().into();
    let change = FUNDING - AMOUNT - FEE;
    let input_key = sender
        .keychain
        .derive_key(
            FUNDING,
            &Identifier::new(3, [0, 0, 0, 0]).unwrap(),
            SwitchCommitment::Regular,
        )
        .unwrap();
    let change_key = sender
        .keychain
        .derive_key(
            change,
            &Identifier::new(3, [0, 0, NEXT_CHILD, 0]).unwrap(),
            SwitchCommitment::Regular,
        )
        .unwrap();
    let words: Vec<&str> = SENDER_MNEMONIC.split_whitespace().collect();
    let last_pair = words[words.len() - 2..].join(" ");
    let secrets: Vec<&[u8]> = vec![
        seed.expose_bytes(),
        &context_key,
        input_key.expose_bytes(),
        change_key.expose_bytes(),
        last_pair.as_bytes(),
        b"receiver log test message",
    ];
    assert_no_secrets(&captured.records, &secrets).unwrap();

    let amounts = [AMOUNT.to_string(), FUNDING.to_string(), change.to_string()];
    for record in &captured.records {
        if record.level <= LogLevel::Info {
            let text = record.to_string();
            for amount in &amounts {
                assert!(!text.contains(amount.as_str()), "{record}");
            }
        }
        assert_eq!(record.field("wallet"), Some("test"), "{record}");
    }

    let tx_id = sent.tx_id.to_string();
    let finalized = captured
        .records
        .iter()
        .find(|record| record.message == "slate finalized")
        .unwrap_or_else(|| panic!("no \"slate finalized\": {:?}", captured.records));
    assert!(finalized.spans.contains(&"finalize"), "{finalized}");
    assert_eq!(
        finalized.field("tx_id"),
        Some(tx_id.as_str()),
        "{finalized}"
    );
    assert_eq!(
        finalized.field("slate_id"),
        Some(sent.slate_id.to_string().as_str()),
        "{finalized}"
    );
    assert_eq!(finalized.field("stage"), Some("S2"), "{finalized}");
    assert_eq!(
        finalized.field("transport"),
        Some(LOOPBACK.as_str()),
        "{finalized}"
    );
    let posted = captured
        .records
        .iter()
        .find(|record| record.message == "transaction posted")
        .unwrap_or_else(|| panic!("no \"transaction posted\": {:?}", captured.records));
    assert!(posted.spans.contains(&"post"), "{posted}");
    assert_eq!(posted.field("tx_id"), Some(tx_id.as_str()), "{posted}");
}
