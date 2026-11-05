// SPDX-License-Identifier: Apache-2.0
//! The feature bits a LEPIC wallet claims in the marker's `f` and in a pairing envelope's
//! features extension. The registry only grows: a bit is never reused or given another meaning.
//! A claimed bit only decides whether a convenience is offered to a peer; no check is ever
//! skipped because of one.

/// The marker and the notices between LEPIC wallets. Implied by any marker without `f`.
pub const MARKER: u32 = 1 << 0;
/// Unasked pair requests over Epicbox.
pub const PAIR_REQUESTS: u32 = 1 << 1;
/// The address proof in pairing envelopes.
pub const ADDRESS_PROOF: u32 = 1 << 2;
/// The pairing-outcome notices.
pub const STATUS_NOTICES: u32 = 1 << 3;
/// Forwarding between linked devices; a host bit.
pub const DEVICE_FORWARDING: u32 = 1 << 4;
/// The directory listing; a host bit.
pub const DIRECTORY: u32 = 1 << 5;
/// Keeping app payloads that arrive over a pairing until the host acknowledges them.
pub const APP_PAYLOADS: u32 = 1 << 6;

/// The bits the host app may claim; it passes them as one constant of its build.
pub const HOST_FEATURES: u32 = DEVICE_FORWARDING | DIRECTORY;

/// The bits this build of LEPIC claims for itself, the same for every wallet it runs, never
/// derived from a setting.
pub const LEPIC_FEATURES: u32 =
    MARKER | PAIR_REQUESTS | ADDRESS_PROOF | STATUS_NOTICES | APP_PAYLOADS;

/// What a wallet whose host claims `host` writes: LEPIC's own bits, and of `host` only the
/// host bits.
pub const fn claimed(host: u32) -> u32 {
    LEPIC_FEATURES | (host & HOST_FEATURES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_bits_outside_the_host_mask_are_dropped() {
        assert_eq!(claimed(0), LEPIC_FEATURES);
        assert_eq!(claimed(u32::MAX), LEPIC_FEATURES | HOST_FEATURES);
        assert_eq!(claimed(ADDRESS_PROOF | PAIR_REQUESTS), LEPIC_FEATURES);
        assert_eq!(claimed(DIRECTORY | 1 << 7), LEPIC_FEATURES | DIRECTORY);
    }

    #[test]
    fn lepic_never_claims_a_host_bit_itself() {
        assert_eq!(LEPIC_FEATURES & HOST_FEATURES, 0);
        assert_ne!(LEPIC_FEATURES & MARKER, 0);
    }

    #[test]
    fn lepic_claims_app_payloads() {
        assert_eq!(LEPIC_FEATURES, 0b100_1111);
        assert_ne!(claimed(0) & APP_PAYLOADS, 0);
    }
}
