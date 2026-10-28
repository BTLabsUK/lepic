// SPDX-License-Identifier: Apache-2.0
//! Sealed envelopes: decoding and opening untrusted bytes, and sealing then opening any body.

#![no_main]

use std::convert::Infallible;

use lepic_contact::{
    Content, EncSecretKey, HintRule, MessageType, Network, SealedEnvelope, SigningKey, seal,
};
use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};

/// A counter stream: the fuzzer drives the input, not the ephemeral key.
struct CounterRng(u8);

impl TryRng for CounterRng {
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
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

impl TryCryptoRng for CounterRng {}

fuzz_target!(|data: &[u8]| {
    // The recipient key of the samples snapshot, so its envelopes open and the fuzzer reaches the
    // inner fields.
    let key = EncSecretKey::from_bytes([11; 32]);
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        for network in [Network::Mainnet, Network::Floonet] {
            if let Ok(sealed) = SealedEnvelope::decode(rest, network) {
                let _ = sealed.open(&key);
            }
        }
        return;
    }
    let signer = SigningKey::from_bytes(&[1; 32]);
    let content = Content::new(MessageType::Slate, rest.to_vec());
    let Ok(envelope) = seal(
        Network::Floonet,
        &key.public_key(),
        HintRule::ReplyKey,
        &content,
        (mode & 2 == 2).then_some(&signer),
        &mut CounterRng(*mode),
    ) else {
        assert!(
            rest.len() > usize::from(u16::MAX),
            "sealing a short body failed"
        );
        return;
    };
    let opened = SealedEnvelope::decode(&envelope, Network::Floonet)
        .and_then(|sealed| sealed.open(&key))
        .expect("a sealed envelope opens");
    assert_eq!(opened.content, content);
});
