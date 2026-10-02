//! Epicbox frames in both directions, and the path a pushed `Slate` frame takes in the client:
//! sender address, signature over `str`, then decryption for our key.

#![no_main]

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::{ClientFrame, Domain, EpicboxAddress, Network, ReceivedMessage, RelayFrame};
use libfuzzer_sys::fuzz_target;

/// The receiver key of the Epicbox message vectors, so seeded `Slate` frames open.
const OWN_SECRET: [u8; 32] = [2; 32];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(frame) = ClientFrame::from_json(text) {
        let written = match frame.to_json() {
            Ok(written) => written,
            Err(error) => panic!("an accepted client frame does not write: {error}"),
        };
        assert_eq!(ClientFrame::from_json(&written).ok(), Some(frame));
    }
    let Ok(frame) = RelayFrame::from_json(text) else {
        return;
    };
    match frame.to_json() {
        Ok(Some(written)) => assert_eq!(RelayFrame::from_json(&written).ok(), Some(frame.clone())),
        Ok(None) => {}
        Err(error) => panic!("an accepted relay frame does not write: {error}"),
    }
    if let RelayFrame::Slate(slate) = frame {
        open_for_us(&slate.from, &slate.str, &slate.signature);
    }
});

fn open_for_us(from: &str, str: &str, signature: &str) {
    let Ok(own_secret) = SecretKey::from_array(OWN_SECRET) else {
        panic!("the own secret is a valid key");
    };
    let Ok(own_key) = PublicKey::from_secret_key(&own_secret) else {
        panic!("a valid secret has a public key");
    };
    for network in [Network::Mainnet, Network::Floonet] {
        let own = EpicboxAddress::new(own_key, network, Domain::default(), None);
        if let Ok(message) = ReceivedMessage::open(from, str, signature, &own, &own_secret) {
            assert_eq!(message.sender.network(), network);
        }
    }
}
