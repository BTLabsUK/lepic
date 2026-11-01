// SPDX-License-Identifier: Apache-2.0
//! One envelope of each type, a card and an invite, sealed with a fixed RNG. The snapshot pins
//! the wire bytes and text forms, and `cargo xtask fuzz` seeds the corpora from it.

// Helpers outside `#[test]` functions are test code too and may unwrap, index and panic.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{ScriptedRng, Side, to_hex};
use lepic_contact::{
    Commitment, ConfirmBody, ConfirmCode, ContactKind, ContactName, Content, EncSecretKey, Invite,
    InviteFields, MessageType, Network, Nonce, PairingCode, PairingLink, Purpose, Reference,
    RelayHost, ReplyBody, Sas, SealedEnvelope, armor, pairing_envelope_link, seal, seal_confirm,
    seal_reply,
};
use serde_json::{Value, json};

const NET: Network = Network::Floonet;

fn envelope_entry(name: &str, envelope: &[u8], key: &EncSecretKey) -> Value {
    let sealed = SealedEnvelope::decode(envelope, NET).unwrap();
    let opened = sealed.open(key).unwrap();
    json!({
        "name": name,
        "type": format!("{:?}", opened.content.kind),
        "signed": opened.sender.is_some(),
        "hint": to_hex(sealed.hint().as_bytes()),
        "bytes": to_hex(envelope),
        "armored": armor(envelope),
    })
}

#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn samples() {
    let (alice, bob) = (Side::new(1), Side::new(11));
    let card_a = alice.card("Alice", NET);
    let card_b = bob.card("Bob", NET);
    let na = Nonce::from_bytes([0xa1; 16]);
    let nb = Nonce::from_bytes([0xb2; 16]);
    let invite = Invite::new(
        NET,
        InviteFields {
            kind: ContactKind::Person,
            name: ContactName::new("Alice").unwrap(),
            expires: 1_800_000_000,
            code: PairingCode::from_bytes([0xc0; 16]),
            commit: Commitment::new(&na, &card_a),
            enc_key: alice.enc_pk(),
            home_relay: RelayHost::new("epicbox.example.org").unwrap(),
            service_inbox: None,
            onion: None,
            link: None,
            mailbox_key: None,
        },
    )
    .unwrap();
    let reply_key = EncSecretKey::from_bytes([0x42; 32]);

    let mut slate = Content::new(
        MessageType::Slate,
        br#"{"version_info":{"version":3,"orig_version":3,"block_header_version":6}}"#.to_vec(),
    );
    slate.reply_key = Some(reply_key.public_key());
    let anonymous_slate = seal(
        NET,
        &bob.enc_pk(),
        bob_card_rule(&card_b),
        &slate,
        None,
        &mut ScriptedRng::seeded(1),
    )
    .unwrap();

    let mut answer = Content::new(MessageType::Slate, br#"{"sta":"S2"}"#.to_vec());
    answer.purpose = Some(Purpose::Payment);
    let reply_slate = seal(
        NET,
        &reply_key.public_key(),
        lepic_contact::HintRule::ReplyKey,
        &answer,
        None,
        &mut ScriptedRng::seeded(2),
    )
    .unwrap();

    let mut notice = Content::new(
        MessageType::Notice,
        br#"{"lepic":1,"type":"declined","slate_id":"0436430c-2b02-624c-2032-570501212b00"}"#
            .to_vec(),
    );
    notice.purpose = Some(Purpose::DepositRequest);
    notice.reference = Some(Reference::new("dep-0042").unwrap());
    notice.expires = Some(1_800_000_600);
    let signed_notice = seal(
        NET,
        &bob.enc_pk(),
        bob_card_rule(&card_b),
        &notice,
        Some(&alice.sig),
        &mut ScriptedRng::seeded(3),
    )
    .unwrap();

    let reply = seal_reply(
        &invite,
        &ReplyBody {
            code: invite.fields().code.clone(),
            nonce: nb.clone(),
            confirm_code: ConfirmCode::from_bytes([0xcc; 16]),
            card: card_b.clone(),
        },
        &mut ScriptedRng::seeded(4),
    )
    .unwrap();

    let confirm = seal_confirm(
        &card_b,
        &ConfirmBody {
            nonce: na.clone(),
            card: card_a.clone(),
        },
        &alice.sig,
        &mut ScriptedRng::seeded(5),
    )
    .unwrap();

    let mut update = Content::new(MessageType::ContactUpdate, Vec::new());
    update.card = Some(card_a.clone());
    let contact_update = seal(
        NET,
        &bob.enc_pk(),
        bob_card_rule(&card_b),
        &update,
        Some(&alice.sig),
        &mut ScriptedRng::seeded(6),
    )
    .unwrap();

    let sas = Sas::compute(NET, &card_a, &card_b, &na, &nb);
    let samples = json!({
        "envelopes": [
            envelope_entry("anonymous_slate_with_reply_key", &anonymous_slate, &bob.enc),
            envelope_entry("slate_to_reply_key", &reply_slate, &reply_key),
            envelope_entry("signed_notice", &signed_notice, &bob.enc),
            envelope_entry("pairing_reply", &reply, &alice.enc),
            envelope_entry("pairing_confirm", &confirm, &bob.enc),
            envelope_entry("signed_contact_update", &contact_update, &bob.enc),
        ],
        "links": {
            "contact": card_a.to_link(),
            "pair": invite.to_link(),
            "pair_reply": pairing_envelope_link(PairingLink::Reply, &reply),
            "pair_confirm": pairing_envelope_link(PairingLink::Confirm, &confirm),
        },
        "cards": [to_hex(card_a.as_bytes()), to_hex(card_b.as_bytes())],
        "invite": to_hex(invite.as_bytes()),
        "sas": {
            "bytes": to_hex(sas.as_bytes()),
            "symbols": sas.symbols().unwrap().iter().map(|s| format!("{} {}", s.emoji, s.name)).collect::<Vec<_>>(),
        },
    });
    insta::assert_snapshot!(serde_json::to_string_pretty(&samples).unwrap());
}

fn bob_card_rule(card: &lepic_contact::ContactCard) -> lepic_contact::HintRule<'_> {
    card.hint_rule()
}
