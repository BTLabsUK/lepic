// SPDX-License-Identifier: Apache-2.0
//! Pairing invites, their `epiccash://pair/1/` link, and the reply and confirm bodies.

#![no_main]

use lepic_contact::{Confirm, Invite, Network, PairingLink, ReplyBody, pairing_envelope_from_link};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for network in [Network::Mainnet, Network::Floonet] {
        if let Ok(invite) = Invite::decode(data, network) {
            assert_eq!(
                invite.as_bytes(),
                data,
                "an invite keeps the bytes it was read from"
            );
            assert_eq!(
                Invite::from_link(&invite.to_link(), network).as_ref(),
                Ok(&invite)
            );
        }
        if let Ok(reply) = ReplyBody::decode(data, network) {
            assert_eq!(reply.encode().as_slice(), data);
        }
        match Confirm::decode(data, network) {
            Ok(Confirm::Accepted(body)) => assert_eq!(body.encode(), data),
            Ok(Confirm::Refused(_)) => assert_eq!(data.len(), 1, "a refusal is one status byte"),
            Err(_) => {}
        }
        if let Ok(text) = std::str::from_utf8(data) {
            if let Ok(invite) = Invite::from_link(text, network) {
                assert_eq!(
                    Invite::decode(invite.as_bytes(), network).as_ref(),
                    Ok(&invite)
                );
            }
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = pairing_envelope_from_link(text, PairingLink::Reply);
        let _ = pairing_envelope_from_link(text, PairingLink::Confirm);
    }
});
