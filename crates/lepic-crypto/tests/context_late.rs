// SPDX-License-Identifier: Apache-2.0
// The context is created once per process, so this binary holds the single test that uses it
// before randomizing. Tests may unwrap (docs/rules.md).
#![allow(clippy::unwrap_used)]

use std::convert::Infallible;

use lepic_crypto::{CryptoError, PublicKey, SecretKey, context_is_randomized, randomize_context};
use rand_core::{TryCryptoRng, TryRng};

/// Records whether anything drew from it.
#[derive(Default)]
struct WatchedRng {
    drawn: bool,
}

impl TryRng for WatchedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.drawn = true;
        Ok(1)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.drawn = true;
        Ok(1)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.drawn = true;
        dst.fill(1);
        Ok(())
    }
}

impl TryCryptoRng for WatchedRng {}

#[test]
fn rejects_randomizing_a_context_already_in_use() {
    let key = SecretKey::from_bytes(&[7; 32]).unwrap();
    let before = PublicKey::from_secret_key(&key).unwrap();
    let mut rng = WatchedRng::default();
    assert_eq!(
        randomize_context(&mut rng),
        Err(CryptoError::ContextAlreadyCreated)
    );
    assert!(!rng.drawn);
    assert!(!context_is_randomized());
    assert_eq!(PublicKey::from_secret_key(&key), Ok(before));
}
