// SPDX-License-Identifier: Apache-2.0
//! Contact cards: binary bytes and the `epiccash://contact/1/` link.

#![no_main]

use lepic_contact::{ContactCard, Network};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for network in [Network::Mainnet, Network::Floonet] {
        if let Ok(card) = ContactCard::decode(data, network) {
            assert_eq!(
                card.as_bytes(),
                data,
                "a card keeps the bytes it was read from"
            );
            let link = card.to_link();
            assert_eq!(ContactCard::from_link(&link, network).as_ref(), Ok(&card));
        }
        if let Ok(text) = std::str::from_utf8(data) {
            if let Ok(card) = ContactCard::from_link(text, network) {
                assert_eq!(
                    ContactCard::decode(card.as_bytes(), network).as_ref(),
                    Ok(&card)
                );
            }
        }
    }
});
