use lepic_crypto::PublicKey;
use lepic_keychain::{
    ChildNumber, ExtKeyVersion, Identifier, IdentifierError, Keychain, KeychainError,
    MnemonicError, Seed, SwitchCommitment,
};
use lepic_primitives::ser::{ProtocolVersion, SerError, deserialize, ser_vec};
use lepic_telemetry::{assert_no_secrets, capture};
use proptest::prelude::*;

const V2: ProtocolVersion = ProtocolVersion::V2;
const PHRASE: &str = "pipe stock song coast pair always emotion member joy sting dash theory";

#[cfg(test)]
fn default_account() -> Identifier {
    Identifier::new(2, [0, 0, 0, 0]).unwrap()
}

#[test]
fn rejects_identifier_deeper_than_four() {
    assert_eq!(
        Identifier::new(5, [0; 4]),
        Err(IdentifierError::DepthTooLarge { depth: 5 })
    );
    let mut bytes = [0u8; 17];
    bytes[0] = 5;
    assert_eq!(
        Identifier::from_bytes(&bytes),
        Err(IdentifierError::DepthTooLarge { depth: 5 })
    );
    assert_eq!(
        Identifier::from_serialized_path(255, [0; 16]),
        Err(IdentifierError::DepthTooLarge { depth: 255 })
    );
}

#[test]
fn rejects_identifier_of_the_wrong_length() {
    for len in [0, 16, 18] {
        assert_eq!(
            Identifier::from_bytes(&vec![0; len]),
            Err(IdentifierError::WrongLength { actual: len })
        );
    }
    assert_eq!(
        Identifier::from_hex("0300"),
        Err(IdentifierError::WrongLength { actual: 2 })
    );
}

#[test]
fn rejects_identifier_hex_with_bad_digits() {
    assert_eq!(
        Identifier::from_hex(&"0g".repeat(17)),
        Err(IdentifierError::InvalidHex)
    );
}

#[test]
fn rejects_serialized_identifier_too_deep_or_truncated() {
    let mut bytes = [0u8; 17];
    bytes[0] = 9;
    assert!(matches!(
        deserialize::<Identifier>(&bytes, V2),
        Err(SerError::Invalid { .. })
    ));
    assert!(matches!(
        deserialize::<Identifier>(&bytes[..16], V2),
        Err(SerError::Truncated { .. })
    ));
}

#[test]
fn root_is_its_own_parent() {
    assert_eq!(Identifier::ROOT.parent(), Identifier::ROOT);
    assert_eq!(Identifier::ROOT.to_bip32_path(), "m");
    assert_eq!(Identifier::ROOT.last_path_index(), 0);
}

#[test]
fn output_path_parent_is_the_account() {
    let output = Identifier::new(3, [0, 0, 42, 0]).unwrap();
    assert_eq!(output.parent(), default_account());
    assert_eq!(output.last_path_index(), 42);
    assert_eq!(
        output.path().collect::<Vec<_>>(),
        [
            ChildNumber::Normal(0),
            ChildNumber::Normal(0),
            ChildNumber::Normal(42)
        ]
    );
}

#[test]
fn serialized_path_drops_only_the_depth() {
    let id = Identifier::new(3, [1, 2, 3, 4]).unwrap();
    let path = id.serialize_path();
    assert_eq!(&path[..], &id.to_bytes()[1..]);
    assert_eq!(Identifier::from_serialized_path(3, path), Ok(id));
}

#[test]
fn rejects_address_key_under_a_depth_four_parent() {
    let keychain = Keychain::from_mnemonic(PHRASE, ExtKeyVersion::MAINNET).unwrap();
    let parent = Identifier::new(4, [0; 4]).unwrap();
    assert_eq!(
        keychain.address_key(&parent, 0).err(),
        Some(KeychainError::AddressParentTooDeep { depth: 4 })
    );
}

#[test]
fn keys_do_not_depend_on_the_network() {
    let mainnet = Keychain::from_mnemonic(PHRASE, ExtKeyVersion::MAINNET).unwrap();
    let floonet = Keychain::from_mnemonic(PHRASE, ExtKeyVersion::FLOONET).unwrap();
    let id = Identifier::new(3, [0, 0, 7, 0]).unwrap();
    assert_eq!(
        mainnet.commit(5, &id, SwitchCommitment::Regular),
        floonet.commit(5, &id, SwitchCommitment::Regular)
    );
    assert_ne!(mainnet.version(), floonet.version());
}

#[test]
fn switch_commitment_changes_the_blind() {
    let keychain = Keychain::from_mnemonic(PHRASE, ExtKeyVersion::MAINNET).unwrap();
    let id = Identifier::new(3, [0, 0, 1, 0]).unwrap();
    let plain = keychain.derive_key(9, &id, SwitchCommitment::None).unwrap();
    let switched = keychain
        .derive_key(9, &id, SwitchCommitment::Regular)
        .unwrap();
    assert_ne!(plain.expose_bytes(), switched.expose_bytes());
}

#[test]
fn secrets_stay_out_of_logs_debug_and_errors() {
    let keychain = Keychain::from_mnemonic(PHRASE, ExtKeyVersion::MAINNET).unwrap();
    let seed = Seed::from_mnemonic(PHRASE).unwrap();
    let id = Identifier::new(3, [0, 0, 3, 0]).unwrap();
    let ext = keychain.derive_ext_key(&id).unwrap();
    let blind = keychain
        .derive_key(1, &id, SwitchCommitment::Regular)
        .unwrap();
    let address = keychain.address_key(&default_account(), 0).unwrap();
    let bad_phrase = PHRASE.replace("joy", "hunter");
    let mnemonic_error = Seed::from_mnemonic(&bad_phrase).err().unwrap();
    let keychain_error = Keychain::from_mnemonic(&bad_phrase, ExtKeyVersion::MAINNET)
        .err()
        .unwrap();
    assert_eq!(mnemonic_error, MnemonicError::UnknownWord { position: 8 });

    let ((), captured) = capture(|| {
        tracing::debug!(
            seed = ?seed,
            keychain = ?keychain,
            master = ?keychain.master(),
            ext = ?ext,
            chain_code = ?ext.chain_code(),
            blind = ?blind,
            address = ?address,
            "keys derived"
        );
        tracing::warn!(error = %mnemonic_error, debug = ?mnemonic_error, "mnemonic rejected");
        tracing::warn!(error = %keychain_error, debug = ?keychain_error, "keychain rejected");
    });
    assert_eq!(captured.records.len(), 3);

    let phrase = seed.to_mnemonic().unwrap();
    let master_public = keychain.master_public_key().unwrap();
    assert_eq!(
        PublicKey::from_secret_key(keychain.master().secret_key()),
        Ok(master_public)
    );
    let secrets: [&[u8]; 9] = [
        seed.expose_bytes(),
        phrase.as_bytes(),
        b"pipe stock song",
        b"hunter",
        keychain.master().secret_key().expose_bytes(),
        keychain.master().chain_code().expose_bytes(),
        ext.chain_code().expose_bytes(),
        blind.expose_bytes(),
        address.expose_bytes(),
    ];
    assert_eq!(assert_no_secrets(&captured.records, &secrets), Ok(()));
}

proptest! {
    #[test]
    fn identifier_round_trips_through_bytes_hex_and_ser(
        depth in 0u8..=4,
        components in any::<[u32; 4]>(),
    ) {
        let id = Identifier::new(depth, components).unwrap();
        prop_assert_eq!(id.depth(), depth);
        prop_assert_eq!(id.components(), components);
        prop_assert_eq!(Identifier::from_bytes(&id.to_bytes()), Ok(id));
        prop_assert_eq!(Identifier::from_hex(&id.to_hex()), Ok(id));
        let bytes = ser_vec(&id, V2);
        prop_assert_eq!(bytes.as_slice(), &id.to_bytes()[..]);
        prop_assert_eq!(deserialize::<Identifier>(&bytes, V2), Ok(id));
        prop_assert_eq!(id.path().count(), usize::from(depth));
    }
}
