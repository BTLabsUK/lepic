// SPDX-License-Identifier: Apache-2.0
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The first four bytes of SHA-256(SHA-256(bytes)), the checksum of every text form.
pub fn checksum(bytes: &[u8]) -> [u8; 4] {
    let [a, b, c, d, ..] = sha256(&[&sha256(&[bytes])]);
    [a, b, c, d]
}

/// HMAC-SHA256 with a 32-byte key.
pub fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    // HMAC pads a key shorter than the block with zeros, so passing the padded block is the same
    // MAC as passing the 32-byte key, and needs no fallible length check.
    let mut block = [0u8; 64];
    for (slot, byte) in block.iter_mut().zip(key) {
        *slot = *byte;
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new(&block.into());
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The first eight bytes of a digest.
pub fn first8(digest: &[u8; 32]) -> [u8; 8] {
    let [a, b, c, d, e, f, g, h, ..] = *digest;
    [a, b, c, d, e, f, g, h]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_2_shape_with_a_short_key() {
        // RFC 4231 test case 2 uses the 4-byte key "Jefe"; zero-padding it to 32 bytes is the
        // same HMAC key, so the published value must come out.
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(b"Jefe");
        let mac = hmac_sha256(&key, b"what do ya want for nothing?");
        assert_eq!(
            mac,
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43
            ]
        );
    }
}
