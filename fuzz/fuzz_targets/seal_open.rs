// SPDX-License-Identifier: Apache-2.0
//! Sealed envelopes: decoding and opening untrusted bytes with every key class, and sealing then
//! opening any body with `seal`, `seal_padded` and, for type 0A under each key class, `seal_tx`.
//!
//! The first byte is the mode. Bit 0 clear: the rest is an envelope to open. Bit 0 set: the rest
//! is a body to seal; bit 1 signs, bit 2 seals type 0A with the class in bits 3 and 4, and
//! otherwise bit 3 pads.

#![no_main]

use std::convert::Infallible;

use lepic_seal::{
    Content, EncSecretKey, HintRule, KeyClass, MessageType, Network, SealedEnvelope, SigningKey,
    TxContent, TxKey, pad_target, seal, seal_padded, seal_tx,
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
                for class in [
                    KeyClass::Seal,
                    KeyClass::Epic1,
                    KeyClass::Listener,
                    KeyClass::Epicbox,
                ] {
                    let _ = sealed.open_tx(&key, class);
                }
            }
        }
        return;
    }
    let signer = SigningKey::from_bytes(&[1; 32]);
    let signer = (mode & 2 == 2).then_some(&signer);
    if mode & 4 == 4 {
        seal_tx_and_open(&key, *mode, rest, signer);
        return;
    }
    let content = Content::new(MessageType::Slate, rest.to_vec());
    let sealed = if mode & 8 == 8 {
        seal_padded(
            Network::Floonet,
            &key.public_key(),
            HintRule::ReplyKey,
            &content,
            signer,
            &mut CounterRng(*mode),
        )
    } else {
        seal(
            Network::Floonet,
            &key.public_key(),
            HintRule::ReplyKey,
            &content,
            signer,
            &mut CounterRng(*mode),
        )
    };
    let Ok(envelope) = sealed else {
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

/// Seals `body` as type 0A under the class bits 3 and 4 of `mode` pick, opens it, and checks
/// the body and that the inner content is exactly the padded length.
fn seal_tx_and_open(key: &EncSecretKey, mode: u8, body: &[u8], signer: Option<&SigningKey>) {
    let (tx_key, class) = match (mode >> 3) & 3 {
        0 => (TxKey::Seal(HintRule::ReplyKey), KeyClass::Seal),
        1 => (TxKey::Epic1, KeyClass::Epic1),
        2 => (TxKey::Listener, KeyClass::Listener),
        _ => (TxKey::Epicbox, KeyClass::Epicbox),
    };
    let content = TxContent::new(body.to_vec());
    let Ok(envelope) = seal_tx(
        Network::Floonet,
        &key.public_key(),
        tx_key,
        &content,
        signer,
        &mut CounterRng(mode),
    ) else {
        assert!(
            body.len() > usize::from(u16::MAX),
            "sealing a short body failed"
        );
        return;
    };
    let opened = SealedEnvelope::decode(&envelope, Network::Floonet)
        .and_then(|sealed| sealed.open_tx(key, class))
        .expect("a sealed type 0A envelope opens");
    assert_eq!(opened.content, content);
    let padding = opened.padding.expect("type 0A is padded");
    let unpadded = opened
        .inner_len
        .checked_sub(padding)
        .expect("the padding is inside the inner content");
    assert_eq!(pad_target(unpadded), opened.inner_len);
}
