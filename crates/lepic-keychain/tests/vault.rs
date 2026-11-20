// SPDX-License-Identifier: Apache-2.0
// Tests may unwrap, index and use plain arithmetic (docs/rules.md); helpers outside `#[test]`
// functions are not covered by clippy's in-tests settings.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::Cell;

use lepic_keychain::vault::{
    BackendError, HEADER_LEN, MAX_SECRET_LEN, MAX_SECRETS, MAX_VAULT_LEN, MIN_VAULT_LEN, VaultFile,
};
use lepic_keychain::{
    KdfParams, MemoryVaultStorage, SecretBytes, SecretName, SecretStore, SecretStoreError, Vault,
    VaultError, VaultStorage,
};
use lepic_telemetry::{assert_no_secrets, capture};
use rand::SeedableRng;
use rand::rngs::StdRng;

const PASSWORD: &[u8] = b"correct horse battery staple";

/// A format version 1 vault with the password `lepic vault v1`, m=8 KiB t=1 p=1, and bytes 0 to
/// 31 stored as `wallet/default/seed`. Stored vaults must keep opening, so this never changes; a
/// new format version gets a new constant.
const VERSION_1_VAULT: &str = concat!(
    "4c45504943564c54010100000008000000010000000",
    "1befba86ae9e0c207865f7e24e8349d4ee06bb0bc4f577df3d2f49798ab0deb2c8ade5abea069bb413bb32cbcc8b8",
    "77bbba5dfccf4f840aa41c3741203809b7578a7d20f9de8dfad5f361bf9da51a826d5d7a1e94f41f58d2695774a3",
    "1b4936672bcec3c883a6d3f515896a4e9dc047beddd9",
);

fn fast() -> KdfParams {
    KdfParams::for_tests(8, 1, 1).unwrap()
}

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// The stored bytes, so tests compare plain byte vectors rather than secret values.
fn secret_of(store: &impl SecretStore, name: &SecretName) -> Option<Vec<u8>> {
    store
        .get(name)
        .unwrap()
        .map(|secret| secret.expose_bytes().to_vec())
}

fn name(text: &str) -> SecretName {
    SecretName::new(text).unwrap()
}

fn seed_name() -> SecretName {
    name("wallet/default/seed")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn new_vault() -> Vault<MemoryVaultStorage, StdRng> {
    Vault::create(MemoryVaultStorage::new(), rng(1), PASSWORD, fast()).unwrap()
}

fn reopen<S: VaultStorage + Clone>(
    vault: &Vault<S, StdRng>,
    password: &[u8],
) -> Result<Vault<S, StdRng>, VaultError> {
    Vault::open(vault.storage().clone(), rng(2), password)
}

fn stored(vault: &Vault<MemoryVaultStorage, StdRng>) -> Vec<u8> {
    vault.storage().contents().unwrap().to_vec()
}

fn open_bytes(
    bytes: Vec<u8>,
    password: &[u8],
) -> Result<Vault<MemoryVaultStorage, StdRng>, VaultError> {
    Vault::open(MemoryVaultStorage::with_contents(bytes), rng(2), password)
}

#[test]
fn round_trips_secrets_through_storage() {
    let mut vault = new_vault();
    let seed = SecretBytes::from_slice(&[0x5a; 32]);
    let other = SecretBytes::from_slice(b"another secret");
    vault.put(&seed_name(), &seed).unwrap();
    vault.put(&name("other"), &other).unwrap();

    let mut reopened = reopen(&vault, PASSWORD).unwrap();
    assert_eq!(
        secret_of(&reopened, &seed_name()),
        Some(seed.expose_bytes().to_vec())
    );
    assert_eq!(
        secret_of(&reopened, &name("other")),
        Some(other.expose_bytes().to_vec())
    );
    assert_eq!(secret_of(&reopened, &name("missing")), None);
    assert_eq!(
        reopened.names().map(SecretName::as_str).collect::<Vec<_>>(),
        ["other", "wallet/default/seed"]
    );
    assert_eq!(reopened.params(), fast());

    assert!(reopened.delete(&name("other")).unwrap());
    assert!(!reopened.delete(&name("other")).unwrap());
    let reopened = reopen(&reopened, PASSWORD).unwrap();
    assert_eq!(secret_of(&reopened, &name("other")), None);
    assert_eq!(
        secret_of(&reopened, &seed_name()),
        Some(seed.expose_bytes().to_vec())
    );
}

#[test]
fn put_replaces_a_stored_secret() {
    let mut vault = new_vault();
    vault
        .put(&seed_name(), &SecretBytes::from_slice(b"old"))
        .unwrap();
    vault
        .put(&seed_name(), &SecretBytes::from_slice(b"new"))
        .unwrap();
    let reopened = reopen(&vault, PASSWORD).unwrap();
    assert_eq!(secret_of(&reopened, &seed_name()), Some(b"new".to_vec()));
    assert_eq!(reopened.names().count(), 1);
}

#[test]
fn stores_empty_and_maximum_size_secrets() {
    let mut vault = new_vault();
    let largest = SecretBytes::from(vec![0xa5; MAX_SECRET_LEN]);
    vault
        .put(&name("empty"), &SecretBytes::from_slice(b""))
        .unwrap();
    vault.put(&name("largest"), &largest).unwrap();
    let reopened = reopen(&vault, PASSWORD).unwrap();
    assert_eq!(secret_of(&reopened, &name("empty")).unwrap().len(), 0);
    assert_eq!(
        secret_of(&reopened, &name("largest")),
        Some(largest.expose_bytes().to_vec())
    );
}

#[test]
fn every_write_uses_a_fresh_nonce() {
    let mut vault = new_vault();
    let first = VaultFile::decode(&stored(&vault)).unwrap();
    vault
        .put(&seed_name(), &SecretBytes::from_slice(b"x"))
        .unwrap();
    vault.delete(&seed_name()).unwrap();
    let second = VaultFile::decode(&stored(&vault)).unwrap();
    assert_eq!(first.header().salt, second.header().salt);
    assert_ne!(first.header().nonce, second.header().nonce);
}

#[test]
fn rekey_re_encrypts_under_the_new_password_and_parameters() {
    let mut vault = new_vault();
    let seed = SecretBytes::from_slice(&[7; 32]);
    vault.put(&seed_name(), &seed).unwrap();
    let before = VaultFile::decode(&stored(&vault)).unwrap();

    let params = KdfParams::for_tests(16, 2, 2).unwrap();
    vault.rekey(b"new password", params).unwrap();
    assert_eq!(vault.params(), params);

    let after = VaultFile::decode(&stored(&vault)).unwrap();
    assert_eq!(after.header().params, params);
    assert_ne!(after.header().salt, before.header().salt);

    assert!(matches!(
        reopen(&vault, PASSWORD),
        Err(VaultError::Decryption)
    ));
    let mut reopened = reopen(&vault, b"new password").unwrap();
    assert_eq!(reopened.params(), params);
    assert_eq!(
        secret_of(&reopened, &seed_name()),
        Some(seed.expose_bytes().to_vec())
    );

    // The rekeyed vault keeps writing under the new key.
    reopened
        .put(&name("later"), &SecretBytes::from_slice(b"l"))
        .unwrap();
    assert_eq!(
        reopen(&reopened, b"new password").unwrap().names().count(),
        2
    );
}

#[test]
fn create_refuses_to_overwrite_a_stored_vault() {
    let vault = new_vault();
    assert!(matches!(
        Vault::create(vault.storage().clone(), rng(3), PASSWORD, fast()),
        Err(VaultError::AlreadyExists)
    ));
}

#[test]
fn create_and_rekey_refuse_parameters_below_the_write_floor() {
    let weak = KdfParams::new(8, 1, 1).unwrap();
    assert!(matches!(
        Vault::create(MemoryVaultStorage::new(), rng(1), PASSWORD, weak),
        Err(VaultError::WeakKdf {
            memory_kib: 8,
            iterations: 1
        })
    ));

    let mut vault = new_vault();
    vault
        .put(&seed_name(), &SecretBytes::from_slice(&[7; 32]))
        .unwrap();
    let before = stored(&vault);
    assert!(matches!(
        vault.rekey(b"new password", KdfParams::new(32 * 1024, 1, 1).unwrap()),
        Err(VaultError::WeakKdf { .. })
    ));
    assert_eq!(stored(&vault), before);
    assert_eq!(vault.params(), fast());
}

#[test]
fn the_write_floor_admits_the_default_and_the_owasp_settings_only() {
    let floor = |memory_kib, iterations| {
        KdfParams::new(memory_kib, iterations, 1)
            .unwrap()
            .meets_write_floor()
    };
    assert!(KdfParams::DEFAULT.meets_write_floor());
    assert!(floor(19 * 1024, 2));
    assert!(floor(46 * 1024, 1));
    assert!(!floor(19 * 1024, 1));
    assert!(!floor(19 * 1024 - 1, 4));
    assert!(!floor(37 * 1024, 1));
    assert!(!floor(8, 1));
}

#[test]
fn a_vault_with_parameters_below_the_floor_still_opens() {
    let bytes = unhex(VERSION_1_VAULT);
    let header = VaultFile::decode(&bytes).unwrap().header().params;
    assert!(!header.meets_write_floor());
    let vault = Vault::open(
        MemoryVaultStorage::with_contents(bytes),
        rng(1),
        b"lepic vault v1",
    )
    .unwrap();
    assert_eq!(vault.params(), KdfParams::new(8, 1, 1).unwrap());
}

#[test]
fn open_without_a_stored_vault_is_not_found() {
    assert!(matches!(
        Vault::open(MemoryVaultStorage::new(), rng(3), PASSWORD),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn rejects_a_wrong_password() {
    let vault = new_vault();
    for password in [
        b"".as_slice(),
        b"correct horse battery stapl",
        b"Correct horse battery staple",
    ] {
        assert!(matches!(
            reopen(&vault, password),
            Err(VaultError::Decryption)
        ));
    }
}

#[test]
fn rejects_every_truncation() {
    let mut vault = new_vault();
    vault
        .put(&seed_name(), &SecretBytes::from_slice(&[1; 32]))
        .unwrap();
    let bytes = stored(&vault);
    for len in 0..bytes.len() {
        let result = open_bytes(bytes[..len].to_vec(), PASSWORD);
        if len < MIN_VAULT_LEN {
            assert!(
                matches!(result, Err(VaultError::Truncated { actual, min: MIN_VAULT_LEN }) if actual == len),
                "{len}"
            );
        } else {
            assert!(matches!(result, Err(VaultError::Decryption)), "{len}");
        }
    }
}

#[test]
fn rejects_every_tampered_byte() {
    let mut vault = new_vault();
    vault
        .put(&seed_name(), &SecretBytes::from_slice(&[1; 32]))
        .unwrap();
    let bytes = stored(&vault);
    for index in 0..bytes.len() {
        for bit in [0x01, 0x80] {
            let mut tampered = bytes.clone();
            tampered[index] ^= bit;
            let error = open_bytes(tampered, PASSWORD).err().unwrap();
            let expected = match index {
                0..8 => matches!(error, VaultError::NotAVault),
                8 => matches!(error, VaultError::UnsupportedVersion { .. }),
                9 => matches!(error, VaultError::UnsupportedKdf { .. }),
                // A changed cost is rejected when out of range, else it derives another key.
                10..22 => matches!(error, VaultError::KdfParams(_) | VaultError::Decryption),
                _ => matches!(error, VaultError::Decryption),
            };
            assert!(expected, "byte {index} bit {bit:#x}: {error:?}");
        }
    }
    assert_eq!(HEADER_LEN, 62);
}

#[test]
fn rejects_appended_bytes_and_oversized_files() {
    let vault = new_vault();
    let mut bytes = stored(&vault);
    bytes.push(0);
    assert!(matches!(
        open_bytes(bytes, PASSWORD),
        Err(VaultError::Decryption)
    ));
    assert!(matches!(
        VaultFile::decode(&vec![0; MAX_VAULT_LEN + 1]),
        Err(VaultError::TooLong { actual, max: MAX_VAULT_LEN }) if actual == MAX_VAULT_LEN + 1
    ));
}

#[test]
fn rejects_oversized_secrets_and_a_full_vault() {
    let mut vault = new_vault();
    assert!(matches!(
        vault.put(
            &seed_name(),
            &SecretBytes::from(vec![0; MAX_SECRET_LEN + 1])
        ),
        Err(SecretStoreError::SecretTooLarge {
            max: MAX_SECRET_LEN,
            ..
        })
    ));
    for index in 0..MAX_SECRETS {
        vault
            .put(
                &name(&format!("s{index:03}")),
                &SecretBytes::from_slice(b"v"),
            )
            .unwrap();
    }
    assert!(matches!(
        vault.put(&name("one-more"), &SecretBytes::from_slice(b"v")),
        Err(SecretStoreError::Full { max: MAX_SECRETS })
    ));
    // Replacing a stored secret still works when the vault is full.
    vault
        .put(&name("s000"), &SecretBytes::from_slice(b"w"))
        .unwrap();
    assert_eq!(
        reopen(&vault, PASSWORD).unwrap().names().count(),
        MAX_SECRETS
    );
}

/// Storage whose writes can be made to fail, to check that a failed write changes nothing.
#[derive(Debug, Clone, Default)]
struct FlakyStorage {
    inner: MemoryVaultStorage,
    fail_writes: Cell<bool>,
}

impl VaultStorage for FlakyStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.load()
    }

    fn replace(&mut self, contents: &[u8]) -> Result<(), BackendError> {
        if self.fail_writes.get() {
            return Err("disk full".into());
        }
        self.inner.replace(contents)
    }
}

#[test]
fn a_failed_write_leaves_the_vault_and_storage_unchanged() {
    let mut vault = Vault::create(FlakyStorage::default(), rng(1), PASSWORD, fast()).unwrap();
    let seed = SecretBytes::from_slice(b"seed");
    vault.put(&seed_name(), &seed).unwrap();
    let before = vault.storage().inner.clone();
    vault.storage().fail_writes.set(true);

    assert!(matches!(
        vault.put(&seed_name(), &SecretBytes::from_slice(b"replacement")),
        Err(SecretStoreError::Backend(_))
    ));
    assert!(matches!(
        vault.put(&name("new"), &SecretBytes::from_slice(b"new")),
        Err(SecretStoreError::Backend(_))
    ));
    assert!(matches!(
        vault.delete(&seed_name()),
        Err(SecretStoreError::Backend(_))
    ));
    assert!(matches!(
        vault.rekey(b"new password", KdfParams::for_tests(16, 1, 1).unwrap()),
        Err(VaultError::Storage(_))
    ));

    assert_eq!(
        secret_of(&vault, &seed_name()),
        Some(seed.expose_bytes().to_vec())
    );
    assert_eq!(secret_of(&vault, &name("new")), None);
    assert_eq!(vault.params(), fast());
    assert_eq!(vault.storage().inner, before);

    // Once writes work again, the vault still writes under the original password.
    vault.storage().fail_writes.set(false);
    vault
        .put(&name("new"), &SecretBytes::from_slice(b"new"))
        .unwrap();
    let reopened = reopen(&vault, PASSWORD).unwrap();
    assert_eq!(
        secret_of(&reopened, &seed_name()),
        Some(seed.expose_bytes().to_vec())
    );
    assert_eq!(reopened.names().count(), 2);
}

#[test]
fn opens_a_version_1_vault() {
    let bytes = unhex(VERSION_1_VAULT);
    let header = *VaultFile::decode(&bytes).unwrap().header();
    assert_eq!(header.params, fast());

    let opened = open_bytes(bytes, b"lepic vault v1").unwrap();
    assert_eq!(opened.params(), fast());
    assert_eq!(secret_of(&opened, &seed_name()), Some((0u8..32).collect()));
    assert_eq!(opened.names().count(), 1);
}

#[test]
fn secrets_never_reach_logs_or_debug_output() {
    let mut vault = new_vault();
    let seed = SecretBytes::from_slice(b"seed bytes that must not leak");
    vault.put(&seed_name(), &seed).unwrap();
    let wrong = reopen(&vault, b"wrong password").err().unwrap();
    let store_error = SecretStoreError::from(VaultError::Decryption);

    let ((), captured) = capture(|| {
        tracing::debug!(vault = ?vault, secret = ?seed, "vault opened");
        tracing::warn!(error = %wrong, debug = ?wrong, "vault rejected");
        tracing::warn!(error = %store_error, debug = ?store_error, "store rejected");
    });
    assert_eq!(captured.records.len(), 3);
    let secrets: [&[u8]; 4] = [
        seed.expose_bytes(),
        PASSWORD,
        b"wrong password",
        b"must not leak",
    ];
    assert_eq!(assert_no_secrets(&captured.records, &secrets), Ok(()));
}
