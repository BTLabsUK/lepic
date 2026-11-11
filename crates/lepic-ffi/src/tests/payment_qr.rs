// SPDX-License-Identifier: Apache-2.0
//! Payment files as QR codes through the binding: sends and invoices whose slates go by their
//! deflated-text codes through the version 1 reader of earlier LEPIC releases, and by their
//! `lepic.v1` codes, and finalize; codes written as deflated text still reading; and in-person
//! codes and payment codes each refused by the other's reader.

use super::contact::{EPIC, World};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::in_person::{in_person_qr_parts, in_person_qr_read};
use crate::api::types::{Chain, ContactRelayMode};
use crate::api::wallet::{decode_ur_slate, encode_ur_slate};
use lepic_wallet::slate::ur_slate::{decode_ur_slate as read_version_1, encode_ur_slate_split};

const FRAGMENT: u32 = 125;
const SINGLE: u32 = 160;

/// The fragment and single-code limits the app passes.
const APP_FRAGMENT: u32 = 107;
const APP_SINGLE: u32 = 124;

/// The slate text the parts of `json`'s text code read back as through the version 1 reader,
/// the one LEPIC releases before 0.5.0 read payment codes with. The code is the one the app
/// writes: deflated text at the app's limits.
fn by_text_code(json: &str) -> String {
    let parts = encode_ur_slate(
        json.to_owned(),
        Chain::Floonet,
        false,
        APP_FRAGMENT,
        Some(APP_SINGLE),
    )
    .unwrap();
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

/// The slate text the parts of `json`'s code read back as, after checking the code went as
/// `lepic.v1` bytes: fewer parts than its deflated text needs.
fn by_code(json: &str) -> String {
    let parts = encode_ur_slate(
        json.to_owned(),
        Chain::Floonet,
        true,
        FRAGMENT,
        Some(SINGLE),
    )
    .unwrap();
    let text_parts = encode_ur_slate_split(json, SINGLE as usize, FRAGMENT as usize).unwrap();
    assert!(
        parts.len() < text_parts.len(),
        "{} vs {}",
        parts.len(),
        text_parts.len()
    );
    let read = decode_ur_slate(parts).unwrap();
    assert!(read.complete);
    let text = read.json.unwrap();
    assert!(text.len() < json.len(), "{text}");
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
async fn a_send_goes_by_its_codes_and_posts() {
    let mut world = World::new();
    let sender = world.funded().await;
    let receiver = world.wallet().await;
    let s1 = sender
        .create_send_slate(EPIC, 1, Some("lunch".to_owned()), None)
        .await
        .unwrap();
    let s2 = receiver.receive_slate(by_code(&s1.json)).await.unwrap();
    let finalized = sender.finalize_and_post(by_code(&s2.json)).await.unwrap();
    assert_eq!(finalized.tx_id, s1.tx_id);
    let finished = sender.finished_payment(s1.tx_id).await.unwrap();
    let read = decode_ur_slate(
        encode_ur_slate(
            finished.clone(),
            Chain::Floonet,
            true,
            FRAGMENT,
            Some(SINGLE),
        )
        .unwrap(),
    )
    .unwrap();
    let (kept, sent) = (
        crate::api::wallet::inspect_slate(read.json.unwrap(), Chain::Floonet).unwrap(),
        crate::api::wallet::inspect_slate(finished, Chain::Floonet).unwrap(),
    );
    assert_eq!(
        (kept.stage, kept.slate_id, kept.amount, kept.fee),
        (sent.stage, sent.slate_id, sent.amount, sent.fee)
    );
}

#[tokio::test]
async fn an_invoice_goes_by_its_codes_and_posts() {
    let mut world = World::new();
    let shop = world.wallet().await;
    let payer = world.funded().await;
    let i1 = shop
        .issue_invoice_slate(2 * EPIC, Some("order 17".to_owned()))
        .await
        .unwrap();
    let paid = payer
        .pay_invoice_slate(
            by_code(&i1.json),
            2 * EPIC,
            1,
            Some("paid".to_owned()),
            None,
        )
        .await
        .unwrap();
    let finalized = shop.finalize_and_post(by_code(&paid.json)).await.unwrap();
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

/// The S1 file of the slate vectors.
fn vector_s1() -> String {
    let path = format!(
        "{}/../../testdata/vectors/slates/send_file_plain_s1_file.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vector["expected"]["json"].as_str().unwrap().to_owned()
}

#[test]
fn text_lepic_v1_cannot_carry_goes_as_deflated_text() {
    let json = r#"{"note":"not a slate"}"#.to_owned();
    let parts =
        encode_ur_slate(json.clone(), Chain::Floonet, true, FRAGMENT, Some(SINGLE)).unwrap();
    assert_eq!(decode_ur_slate(parts).unwrap().json, Some(json));
}

#[tokio::test]
async fn in_person_and_payment_codes_are_refused_by_each_others_reader() {
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
        let parts = in_person_qr_parts(bytes, FRAGMENT, None).unwrap();
        assert_eq!(kind(decode_ur_slate(parts)), WalletErrorKind::ForeignUrCode);
    }
    let parts = encode_ur_slate(vector_s1(), Chain::Floonet, true, FRAGMENT, Some(SINGLE)).unwrap();
    assert_eq!(
        kind(in_person_qr_read(parts)),
        WalletErrorKind::InvalidSlate
    );
}
