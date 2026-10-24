//! Pairing words as the user types them, and the text posted to a rendezvous mailbox. The first
//! byte picks which; the posted text is opened with the stretched words of a golden vector, since
//! Argon2id is far too slow to run per input.

#![no_main]

use lepic_contact::{Invite, Network, PairingWords, WordsKey};
use libfuzzer_sys::fuzz_target;

/// `k` of the words `01 02 03 04 05` on mainnet, from `testdata/vectors/pairing/words.json`.
const VECTOR_KEY: [u8; 32] = [
    0x27, 0x17, 0x42, 0x41, 0x49, 0x34, 0x01, 0xd0, 0xb1, 0xa3, 0xad, 0x38, 0x58, 0xb6, 0x21, 0xe8,
    0x80, 0x21, 0xdf, 0x0c, 0x2e, 0xed, 0x7c, 0x9f, 0x30, 0xbf, 0x74, 0xa5, 0x42, 0x49, 0xc2, 0x61,
];

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    if mode & 1 == 0 {
        let typed: Vec<&str> = text.split('\n').collect();
        if let Ok(words) = PairingWords::parse(&typed) {
            let symbols = words.symbols().expect("parsed words index the table");
            let names: Vec<&str> = symbols.iter().map(|entry| entry.name).collect();
            let emoji: Vec<&str> = symbols.iter().map(|entry| entry.emoji).collect();
            assert_eq!(PairingWords::parse(&names).as_ref(), Ok(&words));
            assert_eq!(PairingWords::parse(&emoji).as_ref(), Ok(&words));
        }
        return;
    }
    let key = WordsKey::from_bytes(VECTOR_KEY);
    for network in [Network::Mainnet, Network::Floonet] {
        let Ok(bytes) = key.open_invite(network, text) else {
            continue;
        };
        if let Ok(invite) = Invite::decode(&bytes, network) {
            let posted = key.seal_invite(&invite).expect("an opened invite seals again");
            assert_eq!(
                key.open_invite(network, &posted).as_deref(),
                Ok(invite.as_bytes())
            );
        }
    }
});
