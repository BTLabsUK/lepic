// SPDX-License-Identifier: Apache-2.0
//! The log test runs in its own binary, as `tests/lifecycle_logs.rs` explains: send, a failed
//! delivery, resend and cancel log in their operation spans with the field vocabulary, and
//! never log a key, the seed or an amount above `debug`.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod send_support;
mod support;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use lepic_keychain::{Identifier, Seed, SwitchCommitment};
use lepic_primitives::amount::Amount;
use lepic_telemetry::{LogLevel, assert_no_secrets, capture};
use lepic_transport::transport::Destination;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, Sender};
use support::LOOPBACK;

const AMOUNT: u64 = 100_000_000;

fn to(destination: &str) -> Delivery {
    Delivery::Deliver {
        to: Destination::new(destination.to_owned()),
    }
}

#[test]
fn send_and_cancel_log_in_their_spans_and_never_log_secrets_or_amounts() {
    let sender = Sender::new();
    let method = sender.harness.method();
    let request = SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        message: Some("lepic log test message".to_owned()),
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    };
    let ((sent, tx_id), captured) = capture(|| {
        let error = sender
            .harness
            .block_on(sender.wallet.send(&method, request, to("nobody")))
            .unwrap_err();
        let SendError::Undelivered {
            tx_id, slate_id, ..
        } = error
        else {
            panic!("{error:?}");
        };
        sender
            .harness
            .block_on(sender.wallet.resend(&method, tx_id, to(PEER)))
            .unwrap();
        sender
            .harness
            .block_on(sender.wallet.cancel(tx_id))
            .unwrap();
        (slate_id, tx_id)
    });

    let seed = Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).unwrap();
    mac.update(b"lepic-wallet private context key v1");
    let context_key: [u8; 32] = mac.finalize_fixed().into();
    let change = FUNDING - AMOUNT - 800_000;
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
        b"lepic log test message",
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

    let slate_id = sent.to_string();
    let tx_id = tx_id.to_string();
    for (message, span) in [
        ("slate created", "send"),
        ("slate sent", "resend"),
        ("transaction cancelled", "cancel"),
    ] {
        let record = captured
            .records
            .iter()
            .find(|record| record.message == message && record.spans.contains(&span))
            .unwrap_or_else(|| panic!("no {message:?} in span {span:?}: {:?}", captured.records));
        assert_eq!(record.field("tx_id"), Some(tx_id.as_str()), "{record}");
        if span != "cancel" {
            assert_eq!(
                record.field("slate_id"),
                Some(slate_id.as_str()),
                "{record}"
            );
            assert_eq!(
                record.field("transport"),
                Some(LOOPBACK.as_str()),
                "{record}"
            );
            assert_eq!(record.field("stage"), Some("S1"), "{record}");
        }
    }
}
