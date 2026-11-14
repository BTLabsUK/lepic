// SPDX-License-Identifier: Apache-2.0
// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use lepic_crypto::EcdsaSignature;
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::{
    ClientFrame, Domain, EpicboxAddress, FrameError, MAX_CHALLENGE_LEN, MAX_FRAME_LEN,
    MAX_FRAME_TYPE_LEN, MAX_RELAY_MESSAGE_ID_LEN, Network, Nonce, PROTOCOL_VERSION, RelayErrorKind,
    RelayFrame, RelayMessageId, Salt, SignedMessage, SlateFrame, WalletMode, verify_text,
};
use proptest::prelude::*;

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_array([byte; 32]).unwrap()
}

fn address(byte: u8, port: Option<u16>) -> EpicboxAddress {
    EpicboxAddress::new(
        PublicKey::from_secret_key(&secret(byte)).unwrap(),
        Network::Mainnet,
        Domain::parse("relay.example.org").unwrap(),
        port,
    )
}

fn relay(text: &str) -> RelayFrame {
    RelayFrame::from_json(text).unwrap()
}

fn msg_id(text: &str) -> RelayMessageId {
    RelayMessageId::parse(text).unwrap()
}

fn slate_with_message_id(id: &str) -> String {
    serde_json::json!({
        "type": "Slate",
        "from": "a",
        "str": "s",
        "signature": "30",
        "challenge": "",
        "epicboxmsgid": id,
        "ver": "3.0.0",
    })
    .to_string()
}

#[test]
fn client_frames_serialize_in_upstream_shape() {
    let own = address(1, None);
    let key = secret(1);
    insta::assert_snapshot!(
        ClientFrame::client_details("4.0.2", WalletMode::Listener).to_json().unwrap(),
        @r#"{"type":"ClientDetails","wallet_version":"4.0.2","wallet_mode":"listener","protocol_version":"3.0.0"}"#
    );
    insta::assert_snapshot!(
        ClientFrame::client_details("4.0.2", WalletMode::Send).to_json().unwrap(),
        @r#"{"type":"ClientDetails","wallet_version":"4.0.2","wallet_mode":"send","protocol_version":"3.0.0"}"#
    );
    insta::assert_snapshot!(
        ClientFrame::subscribe(&own, "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc", &key)
            .unwrap()
            .to_json()
            .unwrap(),
        @r#"{"type":"Subscribe","address":"esYTimgooNuxKXdEEXJk3fbXoy2HWyyY2CaRXYU8Z8B7fSPyz6YL","ver":"3.0.0","signature":"304402207aa124804523b62e52206f7711254c8756e6780a124b504d106c3b68b6b2864e02207dc6396ecf47517cdffa1a3932325dfe2b8dbcda563611097b3d407bbcb4bda2"}"#
    );
    insta::assert_snapshot!(
        ClientFrame::made(&address(2, None), &msg_id("Rk4pW7nZ2cT9sLb3XyQ6vH1mJ8dG5fUa"), &secret(2))
            .unwrap()
            .to_json()
            .unwrap(),
        @r#"{"type":"Made","address":"esWtu4BwqC58U5YtffP4sVJ7SWV88uYdn3okpEdiv1dFHnYMh6oj","signature":"30440220112df76ccb6a023902de1757ea950f206486bbb49971a485e115f5040ce9de0702207d8e1bf6aa61e42001c7b12d4ce497518a34fdec52bacbfa01e630a521e202a7","ver":"3.0.0","epicboxmsgid":"Rk4pW7nZ2cT9sLb3XyQ6vH1mJ8dG5fUa"}"#
    );
    insta::assert_snapshot!(
        ClientFrame::unsubscribe(&own).to_json().unwrap(),
        @r#"{"type":"Unsubscribe","address":"esYTimgooNuxKXdEEXJk3fbXoy2HWyyY2CaRXYU8Z8B7fSPyz6YL"}"#
    );
    insta::assert_snapshot!(
        ClientFrame::GetVersion.to_json().unwrap(),
        @r#"{"type":"GetVersion"}"#
    );
}

#[test]
fn post_slate_carries_display_addresses_and_the_signature_over_str() {
    let from = address(1, None);
    let to = address(2, Some(13420));
    let message = SignedMessage::seal(
        "{}",
        &to,
        &secret(1),
        Salt::from([1; 8]),
        Nonce::from([2; 12]),
    )
    .unwrap();
    let ClientFrame::PostSlate {
        from: from_text,
        to: to_text,
        str,
        signature,
    } = ClientFrame::post_slate(&from, &to, &message)
    else {
        panic!("not a PostSlate frame");
    };
    assert_eq!(from_text, from.to_string());
    assert_eq!(to_text, to.to_string());
    assert!(to_text.ends_with(":13420"));
    assert_eq!(str, message.str);
    let signature = EcdsaSignature::from_der_hex(&signature).unwrap();
    assert_eq!(verify_text(&str, &signature, from.public_key()), Ok(()));
}

#[test]
fn decodes_every_relay_frame_the_public_relay_sends() {
    assert_eq!(
        relay(r#"{"type":"Challenge","str":"abc"}"#),
        RelayFrame::Challenge {
            str: "abc".to_owned()
        }
    );
    assert_eq!(relay(r#"{"type":"Ok"}"#), RelayFrame::Ok);
    assert_eq!(
        relay(r#"{"type":"Error","kind":"InvalidSignature","description":"Invalid signature."}"#),
        RelayFrame::Error {
            kind: RelayErrorKind::InvalidSignature,
            description: "Invalid signature.".to_owned()
        }
    );
    assert_eq!(
        relay(r#"{"type":"GetVersion","str":"3.0.0"}"#),
        RelayFrame::GetVersion {
            str: "3.0.0".to_owned()
        }
    );
    assert_eq!(
        relay(
            r#"{"type":"Slate","from":"a@b","str":"{}","signature":"30","challenge":"","epicboxmsgid":"id1","ver":"3.0.0"}"#
        ),
        RelayFrame::Slate(SlateFrame {
            from: "a@b".to_owned(),
            str: "{}".to_owned(),
            signature: "30".to_owned(),
            challenge: String::new(),
            epicboxmsgid: Some(msg_id("id1")),
            ver: Some(PROTOCOL_VERSION.to_owned()),
        })
    );
}

#[test]
fn decodes_slate_without_message_id_from_an_unversioned_subscription() {
    let RelayFrame::Slate(slate) =
        relay(r#"{"type":"Slate","from":"a","str":"s","signature":"30","challenge":"c"}"#)
    else {
        panic!("not a Slate frame");
    };
    assert_eq!(slate.epicboxmsgid, None);
    assert_eq!(slate.ver, None);
}

#[test]
fn keeps_error_kinds_it_does_not_know() {
    assert_eq!(
        relay(r#"{"type":"Error","kind":"RateLimited","description":""}"#),
        RelayFrame::Error {
            kind: RelayErrorKind::Other("RateLimited".to_owned()),
            description: String::new()
        }
    );
}

#[test]
fn ignores_unknown_fields() {
    assert_eq!(relay(r#"{"type":"Ok","extra":1}"#), RelayFrame::Ok);
    assert_eq!(
        relay(r#"{"type":"Challenge","str":"c","extra":[1,2]}"#),
        RelayFrame::Challenge {
            str: "c".to_owned()
        }
    );
}

#[test]
fn tolerates_unknown_frame_types() {
    assert_eq!(
        relay(r#"{"type":"Stats","clients":4}"#),
        RelayFrame::Unknown {
            type_name: "Stats".to_owned()
        }
    );
}

#[test]
fn bounds_the_names_of_unknown_frame_types() {
    let long = "T".repeat(MAX_FRAME_TYPE_LEN + 1);
    let RelayFrame::Unknown { type_name } = relay(&format!(r#"{{"type":"{long}"}}"#)) else {
        panic!("not an unknown frame");
    };
    assert_eq!(type_name, format!("{}...", &long[..MAX_FRAME_TYPE_LEN]));

    assert_eq!(
        relay(r#"{"type":"a\nb\u0000c é"}"#),
        RelayFrame::Unknown {
            type_name: "a?b?c??".to_owned()
        }
    );
    assert!(matches!(
        ClientFrame::from_json(&format!(r#"{{"type":"{long}"}}"#)),
        Err(FrameError::UnknownClientType { type_name }) if type_name.len() == MAX_FRAME_TYPE_LEN + 3
    ));
}

#[test]
fn bounds_relay_error_kinds_it_does_not_know() {
    let long = "K".repeat(MAX_FRAME_TYPE_LEN + 1);
    let frame = relay(&format!(
        r#"{{"type":"Error","kind":"{long}","description":"d"}}"#
    ));
    assert_eq!(
        frame,
        RelayFrame::Error {
            kind: RelayErrorKind::Other(format!("{}...", &long[..MAX_FRAME_TYPE_LEN])),
            description: "d".to_owned()
        }
    );
    assert_eq!(
        RelayErrorKind::from("bad\nkind".to_owned()),
        RelayErrorKind::Other("bad?kind".to_owned())
    );
}

#[test]
fn a_known_type_name_with_escapes_is_still_known() {
    assert_eq!(relay(r#"{"type":"\u004fk"}"#), RelayFrame::Ok);
}

#[test]
fn reads_the_type_wherever_it_is_in_the_frame() {
    assert_eq!(
        relay(r#"{"str":"c","x":{"type":"Ok"},"type":"Challenge"}"#),
        RelayFrame::Challenge {
            str: "c".to_owned()
        }
    );
}

#[test]
fn rejects_a_frame_with_two_types() {
    assert!(matches!(
        RelayFrame::from_json(r#"{"type":"Ok","type":"Challenge","str":"c"}"#),
        Err(FrameError::Json(_))
    ));
}

#[test]
fn tolerates_non_json_keepalive_text() {
    for text in ["pong", "ping", "", "  pong\n", "[1]", "42"] {
        assert_eq!(relay(text), RelayFrame::Keepalive, "{text:?}");
    }
}

#[test]
fn rejects_truncated_json_object() {
    assert!(matches!(
        RelayFrame::from_json(r#"{"type":"Challenge""#),
        Err(FrameError::Json(_))
    ));
}

#[test]
fn rejects_object_without_a_string_type() {
    for text in [r#"{"str":"c"}"#, r#"{"type":5}"#, r#"{"type":null}"#] {
        assert!(
            matches!(RelayFrame::from_json(text), Err(FrameError::MissingType)),
            "{text}"
        );
    }
}

#[test]
fn rejects_known_type_with_missing_fields() {
    assert!(matches!(
        RelayFrame::from_json(r#"{"type":"Challenge"}"#),
        Err(FrameError::Fields { type_name, .. }) if type_name == "Challenge"
    ));
    assert!(matches!(
        RelayFrame::from_json(r#"{"type":"Slate","from":"a","str":"s","signature":"30"}"#),
        Err(FrameError::Fields { type_name, .. }) if type_name == "Slate"
    ));
}

#[test]
fn rejects_challenge_outside_the_relay_format() {
    for text in [
        r#"{"type":"Challenge","str":"{\"destination\":{}}"}"#,
        r#"{"type":"Challenge","str":""}"#,
        r#"{"type":"Challenge","str":"has space"}"#,
        r#"{"type":"Challenge","str":"0436430c2b02624c2032570501212b03"}"#,
        r#"{"type":"Challenge","str":"0436430c-2b02-624c-2032-570501212b03"}"#,
        r#"{"type":"Challenge","str":"0436430C-2B02-624C-2032-570501212B03"}"#,
    ] {
        assert!(
            matches!(RelayFrame::from_json(text), Err(FrameError::Challenge)),
            "{text}"
        );
    }
    let long = format!(
        r#"{{"type":"Challenge","str":"{}"}}"#,
        "a".repeat(MAX_CHALLENGE_LEN + 1)
    );
    assert!(matches!(
        RelayFrame::from_json(&long),
        Err(FrameError::Challenge)
    ));
}

#[test]
fn accepts_challenges_in_the_relay_format() {
    for challenge in [
        "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc",
        "Rk4pW7nZ2cT9sLb3XyQ6vH1mJ8dG5fUa",
        "Rk4p_W7nZ2cT9sLb3-yQ6vH1mJ8dG5fU",
        "mock-challenge-1",
        "0436430c2b02624c2032570501212b0g",
        "0436430C2B02624C2032570501212B03",
    ] {
        let text = format!(r#"{{"type":"Challenge","str":"{challenge}"}}"#);
        assert_eq!(
            RelayFrame::from_json(&text).unwrap(),
            RelayFrame::Challenge {
                str: challenge.to_owned()
            }
        );
    }
    let longest = "a".repeat(MAX_CHALLENGE_LEN);
    assert!(ClientFrame::subscribe(&address(1, None), &longest, &secret(1)).is_ok());
}

#[test]
fn refuses_to_sign_a_challenge_outside_the_relay_format() {
    for challenge in [r#"{"str":"x"}"#, "0436430c2b02624c2032570501212b03"] {
        assert!(matches!(
            ClientFrame::subscribe(&address(1, None), challenge, &secret(1)),
            Err(FrameError::Challenge)
        ));
    }
}

#[test]
fn rejects_known_type_with_mistyped_fields() {
    assert!(matches!(
        RelayFrame::from_json(r#"{"type":"Challenge","str":7}"#),
        Err(FrameError::Fields { .. })
    ));
    assert!(matches!(
        RelayFrame::from_json(
            r#"{"type":"Slate","from":"a","str":"s","signature":"30","challenge":"","epicboxmsgid":1}"#
        ),
        Err(FrameError::Fields { .. })
    ));
}

#[test]
fn accepts_relay_message_ids_up_to_the_limit() {
    for id in [
        "Rk4pW7nZ2cT9sLb3XyQ6vH1mJ8dG5fUa",
        "a",
        "local-1",
        "under_score",
        &"x".repeat(MAX_RELAY_MESSAGE_ID_LEN),
    ] {
        let RelayFrame::Slate(slate) = relay(&slate_with_message_id(id)) else {
            panic!("not a Slate frame");
        };
        assert_eq!(slate.epicboxmsgid.unwrap().as_str(), id);
    }
}

#[test]
fn rejects_slate_with_an_oversized_or_unsafe_message_id_as_malformed() {
    let oversized = "x".repeat(MAX_RELAY_MESSAGE_ID_LEN + 1);
    for id in [
        oversized.as_str(),
        "",
        "has space",
        "local:1",
        "caf\u{e9}",
        "line\nbreak",
        "a/b",
    ] {
        assert!(
            matches!(
                RelayFrame::from_json(&slate_with_message_id(id)),
                Err(FrameError::Fields { type_name, .. }) if type_name == "Slate"
            ),
            "accepted {id:?}"
        );
    }
}

#[test]
fn relay_message_id_parse_enforces_the_same_rules() {
    assert!(RelayMessageId::parse("abc-_09").is_ok());
    assert!(RelayMessageId::parse(&"x".repeat(MAX_RELAY_MESSAGE_ID_LEN + 1)).is_err());
    assert!(RelayMessageId::parse("é").is_err());
}

#[test]
fn rejects_frame_over_the_length_limit_before_parsing() {
    let text = format!(
        "{{\"type\":\"Challenge\",\"str\":\"{}\"}}",
        "a".repeat(MAX_FRAME_LEN)
    );
    assert!(matches!(
        RelayFrame::from_json(&text),
        Err(FrameError::TooLong {
            max: MAX_FRAME_LEN,
            ..
        })
    ));
    assert!(matches!(
        RelayFrame::from_json(&"p".repeat(MAX_FRAME_LEN + 1)),
        Err(FrameError::TooLong { .. })
    ));
    assert!(matches!(
        ClientFrame::from_json(&text),
        Err(FrameError::TooLong { .. })
    ));
}

#[test]
fn relay_side_rejects_unknown_client_frame_types() {
    assert!(matches!(
        ClientFrame::from_json(r#"{"type":"Shutdown"}"#),
        Err(FrameError::UnknownClientType { type_name }) if type_name == "Shutdown"
    ));
    assert!(matches!(
        ClientFrame::from_json("pong"),
        Err(FrameError::Json(_))
    ));
    for text in ["[1]", "42", r#""Ok""#, "null"] {
        assert!(
            matches!(ClientFrame::from_json(text), Err(FrameError::MissingType)),
            "{text}"
        );
    }
}

#[test]
fn relay_side_rejects_unknown_wallet_mode() {
    assert!(matches!(
        ClientFrame::from_json(
            r#"{"type":"ClientDetails","wallet_version":"1","wallet_mode":"miner","protocol_version":"3.0.0"}"#
        ),
        Err(FrameError::Fields { type_name, .. }) if type_name == "ClientDetails"
    ));
}

#[test]
fn relay_side_rejects_known_client_type_with_missing_fields() {
    assert!(matches!(
        ClientFrame::from_json(r#"{"type":"Subscribe","address":"a"}"#),
        Err(FrameError::Fields { type_name, .. }) if type_name == "Subscribe"
    ));
}

fn wire_text() -> impl Strategy<Value = String> {
    any::<String>()
}

fn relay_frame() -> impl Strategy<Value = RelayFrame> {
    let kind = prop_oneof![
        Just(RelayErrorKind::UnknownError),
        Just(RelayErrorKind::InvalidRequest),
        Just(RelayErrorKind::InvalidSignature),
        Just(RelayErrorKind::InvalidChallenge),
        Just(RelayErrorKind::TooManySubscriptions),
        "[a-z]{1,8}".prop_map(RelayErrorKind::Other),
    ];
    prop_oneof![
        "[A-Za-z0-9_-]{1,31}".prop_map(|str| RelayFrame::Challenge { str }),
        Just(RelayFrame::Ok),
        (kind, wire_text()).prop_map(|(kind, description)| RelayFrame::Error { kind, description }),
        (
            wire_text(),
            wire_text(),
            wire_text(),
            wire_text(),
            proptest::option::of("[A-Za-z0-9_-]{1,64}".prop_map(|id| msg_id(&id))),
            proptest::option::of(wire_text()),
        )
            .prop_map(|(from, str, signature, challenge, epicboxmsgid, ver)| {
                RelayFrame::Slate(SlateFrame {
                    from,
                    str,
                    signature,
                    challenge,
                    epicboxmsgid,
                    ver,
                })
            }),
        wire_text().prop_map(|str| RelayFrame::GetVersion { str }),
    ]
}

fn client_frame() -> impl Strategy<Value = ClientFrame> {
    let mode = prop_oneof![Just(WalletMode::Listener), Just(WalletMode::Send)];
    prop_oneof![
        (wire_text(), mode, wire_text()).prop_map(
            |(wallet_version, wallet_mode, protocol_version)| ClientFrame::ClientDetails {
                wallet_version,
                wallet_mode,
                protocol_version,
                ext: None,
            }
        ),
        (wire_text(), wire_text(), wire_text()).prop_map(|(address, ver, signature)| {
            ClientFrame::Subscribe {
                address,
                ver,
                signature,
            }
        }),
        (wire_text(), wire_text(), wire_text(), wire_text()).prop_map(
            |(from, to, str, signature)| ClientFrame::PostSlate {
                from,
                to,
                str,
                signature,
            }
        ),
        (wire_text(), wire_text(), wire_text(), wire_text()).prop_map(
            |(address, signature, ver, epicboxmsgid)| ClientFrame::Made {
                address,
                signature,
                ver,
                epicboxmsgid,
            }
        ),
        wire_text().prop_map(|address| ClientFrame::Unsubscribe { address }),
        Just(ClientFrame::GetVersion),
    ]
}

proptest! {
    #[test]
    fn relay_frames_round_trip(frame in relay_frame()) {
        let text = frame.to_json().unwrap().unwrap();
        prop_assert_eq!(RelayFrame::from_json(&text).unwrap(), frame);
    }

    #[test]
    fn client_frames_round_trip(frame in client_frame()) {
        let text = frame.to_json().unwrap();
        prop_assert_eq!(ClientFrame::from_json(&text).unwrap(), frame);
    }

    #[test]
    fn relay_decoder_never_panics(text in any::<String>()) {
        let _ = RelayFrame::from_json(&text);
    }
}
