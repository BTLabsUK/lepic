//! Receive against the G-03 slate vectors: each S1 received with the recorded randomness yields
//! the recorded S2 in every encoding.

use lepic_primitives::params::Network;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::error::{EncodeError, Unrepresentable};
use lepic_slate::stage::Stage;
use lepic_store::WalletStore;

use crate::receive_harness::*;

#[test]
fn each_g03_s1_received_with_the_recorded_randomness_yields_the_g03_s2() {
    let base_fee = Network::Floonet.params().default_base_fee();
    let (v3, v2) = (V3JsonCodec::new(base_fee), V2JsonCodec::new(base_fee));
    let cases = standard_cases();
    assert!(cases.len() >= 12, "only {} standard cases", cases.len());
    let mut checked_v2 = 0;
    for case in &cases {
        let (s1, transport) = delivered_s1(case);
        let s2_v3 = vector(&format!("{case}_s2_v3"));
        let method = text(&s2_v3["inputs"]["method"]);
        let receiver = Receiver::new(&receiver_mnemonic(&s2_v3), slate_height(&s1));
        let key_id = receiver_output_key(&s2_v3);
        receiver.reserve_up_to(key_id);

        let received = receiver
            .receive(transport, &json(&s1), responder_message(&s2_v3).as_deref())
            .unwrap_or_else(|error| panic!("{case}: {error:?}"));

        assert_eq!(received.slate.stage(), Stage::S2, "{case}");
        let stored_key = receiver
            .store()
            .read(|repos| repos.outputs_of_transaction(received.tx_id))
            .unwrap()[0]
            .key_id;
        assert_eq!(stored_key.0, key_id.to_bytes(), "{case}: output key");
        let expected_reply = json(&vector(&format!("{case}_s2_{method}")));
        assert_eq!(
            received.reply.as_text().unwrap(),
            expected_reply,
            "{case}: {method} reply"
        );
        assert_eq!(
            encode_as(&v3, &received.slate).unwrap().as_text().unwrap(),
            json(&s2_v3),
            "{case}: v3"
        );
        let v2_name = format!("{case}_s2_v2");
        match encode_as(&v2, &received.slate) {
            Ok(encoded) => {
                assert_eq!(
                    encoded.as_text().unwrap(),
                    json(&vector(&v2_name)),
                    "{case}: v2"
                );
                checked_v2 += 1;
            }
            // Upstream drops TTL and payment proof when it converts to V2; LEPIC refuses.
            Err(EncodeError::Unrepresentable {
                what: Unrepresentable::TimeToLive | Unrepresentable::PaymentProof,
                ..
            }) => assert!(has_vector(&v2_name), "{case}"),
            Err(error) => panic!("{case}: v2 {error:?}"),
        }
    }
    assert!(checked_v2 > 0);
}
