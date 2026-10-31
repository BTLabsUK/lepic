// SPDX-License-Identifier: Apache-2.0
//! The contact list of a `.wfeh` history payload a user restores from (RFC 0002 10.5), imported
//! into an empty store.

#![no_main]

use lepic_primitives::params::Network;
use lepic_store::{CARD_KEY_LEN, ContactKind, PeerCard};
use libfuzzer_sys::fuzz_target;

/// Takes any bytes for a card whose keys are its first bytes, so the import goes on past the
/// cards to the records. The wallet decodes and verifies cards with `lepic-contact` instead,
/// which the `contact_card` target covers.
fn read_card(bytes: &[u8]) -> Option<PeerCard> {
    let key = |offset: usize| {
        let mut key = [0u8; CARD_KEY_LEN];
        for (slot, byte) in key.iter_mut().zip(bytes.iter().skip(offset)) {
            *slot = *byte;
        }
        key
    };
    Some(PeerCard {
        bytes: bytes.to_vec(),
        sig_key: key(0),
        enc_key: key(CARD_KEY_LEN),
        hint_key: key(2 * CARD_KEY_LEN),
        seq: 0,
        kind: ContactKind::Person,
        claimed_name: String::new(),
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };
    for network in [Network::Floonet, Network::Mainnet] {
        let _ = lepic_store::fuzz::contact_backup_import(json, network, &read_card);
    }
});
