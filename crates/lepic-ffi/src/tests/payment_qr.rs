// SPDX-License-Identifier: Apache-2.0
//! Payment files as QR codes through the binding: sends and invoices whose slates go by their
//! deflated-text codes through the version 1 reader of earlier LEPIC releases and finalize, and
//! in-person codes and answers refused by the payment-file reader.

use super::contact::{EPIC, World};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::in_person::in_person_qr_parts;
use crate::api::types::ContactRelayMode;
use crate::api::wallet::{decode_ur_slate, encode_ur_slate};
use lepic_wallet::slate::ur_slate::{decode_ur_slate as read_version_1, encode_ur_slate_split};

/// The fragment and single-code limits the app passes.
const APP_FRAGMENT: u32 = 107;
const APP_SINGLE: u32 = 124;

/// The slate text the parts of `json`'s code read back as through the version 1 reader, the
/// one LEPIC releases before 0.5.0 read payment codes with. The code is the one the app writes:
/// deflated text at the app's limits.
fn by_text_code(json: &str) -> String {
    let parts = encode_ur_slate(json.to_owned(), APP_FRAGMENT, Some(APP_SINGLE)).unwrap();
    assert_eq!(
        parts,
        encode_ur_slate_split(json, APP_SINGLE as usize, APP_FRAGMENT as usize).unwrap()
    );
    let read = read_version_1(&parts).unwrap();
    assert!(read.is_complete());
    let text = read.json.unwrap();
    assert_eq!(text, json);
    text
}

#[tokio::test]
async fn a_send_and_an_invoice_go_by_text_codes_an_earlier_release_reads() {
    let mut world = World::new();
    let sender = world.funded().await;
    let receiver = world.wallet().await;
    let s1 = sender
        .create_send_slate(EPIC, 1, Some("lunch".to_owned()), None)
        .await
        .unwrap();
    let s2 = receiver
        .receive_slate(by_text_code(&s1.json))
        .await
        .unwrap();
    let finalized = sender
        .finalize_and_post(by_text_code(&s2.json))
        .await
        .unwrap();
    assert_eq!(finalized.tx_id, s1.tx_id);
    let s3 = sender.finished_payment(s1.tx_id).await.unwrap();
    by_text_code(&s3);

    let i1 = receiver
        .issue_invoice_slate(2 * EPIC, Some("order 17".to_owned()))
        .await
        .unwrap();
    let payer = world.funded().await;
    let i2 = payer
        .pay_invoice_slate(
            by_text_code(&i1.json),
            2 * EPIC,
            1,
            Some("paid".to_owned()),
            None,
        )
        .await
        .unwrap();
    let finalized = receiver
        .finalize_and_post(by_text_code(&i2.json))
        .await
        .unwrap();
    assert_eq!(finalized.slate_id, i1.slate_id);
}

#[tokio::test]
async fn a_code_of_deflated_text_reads_as_the_text() {
    let mut world = World::new();
    let sender = world.funded().await;
    let s1 = sender.create_send_slate(EPIC, 1, None, None).await.unwrap();
    let parts = encode_ur_slate_split(&s1.json, 80, 64).unwrap();
    let read = decode_ur_slate(parts).unwrap();
    assert_eq!(read.json.as_deref(), Some(s1.json.as_str()));
}

#[tokio::test]
async fn in_person_codes_and_answers_are_refused_by_the_payment_reader() {
    let mut world = World::new();
    let sender = world.funded().await;
    let receiver = world.wallet().await;
    let code = sender
        .in_person_send(EPIC, 1, None, None, None, ContactRelayMode::Offline)
        .await
        .unwrap();
    let reply = receiver
        .in_person_receive(code.bytes.clone(), None, ContactRelayMode::Offline)
        .await
        .unwrap();
    for bytes in [code.bytes, reply.envelope] {
        let parts = in_person_qr_parts(bytes, APP_FRAGMENT, None).unwrap();
        assert_eq!(kind(decode_ur_slate(parts)), WalletErrorKind::ForeignUrCode);
    }
}
