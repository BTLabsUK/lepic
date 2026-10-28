// SPDX-License-Identifier: Apache-2.0
//! What a host does once when its process starts, before any wallet exists.

use rand_core::CryptoRng;

/// Blinds the process's secp256k1 context with 32 bytes from `rng`, so signing and key
/// generation resist timing and power side channels. Call it once at process start, before
/// any other engine call. Returns `false` when the context already existed; it then stays as it
/// was, which changes no result.
pub fn randomize_crypto_context<R: CryptoRng + ?Sized>(rng: &mut R) -> bool {
    lepic_crypto::randomize_context(rng).is_ok()
}

/// Whether [`randomize_crypto_context`] created the process's secp256k1 context.
pub fn crypto_context_is_randomized() -> bool {
    lepic_crypto::context_is_randomized()
}
