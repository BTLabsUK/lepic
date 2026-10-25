//! Pairing words as the user types them, and the text posted to a rendezvous mailbox. The first
//! byte picks which; the posted text is opened with the stretched words of a golden vector, since
//! Argon2id is far too slow to run per input, and sealed again under a nonce from the input.

#![no_main]

use std::convert::Infallible;

use lepic_contact::{Invite, Network, PairingWords, WordsKey};
use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};

/// `k` of the words `01 02 03 04 05` on mainnet in window 3,000,000, from
/// `testdata/vectors/pairing/words.json`.
const VECTOR_KEY: [u8; 32] = [
    0x94, 0x36, 0x8c, 0x9f, 0xd3, 0xac, 0x42, 0xc1, 0x72, 0x24, 0xbc, 0x63, 0x0b, 0xeb, 0x9c, 0x6a,
    0x91, 0xf1, 0x18, 0x4e, 0xa7, 0x5c, 0x6e, 0x3e, 0x19, 0x4f, 0x2a, 0x47, 0xdc, 0xa4, 0x7f, 0x60,
];

/// Plays the input's first bytes as the nonce, so resealing is deterministic per input.
struct InputRng<'a>(std::iter::Cycle<std::slice::Iter<'a, u8>>);

impl TryRng for InputRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for byte in dst {
            *byte = self.0.next().copied().unwrap_or_default();
        }
        Ok(())
    }
}

impl TryCryptoRng for InputRng<'_> {}

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
            let mut rng = InputRng(data.iter().cycle());
            let posted = key
                .seal_invite(&invite, &mut rng)
                .expect("an opened invite seals again");
            assert_eq!(
                key.open_invite(network, &posted).as_deref(),
                Ok(invite.as_bytes())
            );
        }
    }
});
