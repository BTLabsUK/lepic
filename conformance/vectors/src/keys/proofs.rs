//! Bulletproofs: raw creation with given nonces, and outputs built through the node's
//! `ProofBuilder` and `LegacyProofBuilder` with their rewinds.

use epic_core::libtx::proof::{self, LegacyProofBuilder, ProofBuild, ProofBuilder};
use epic_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
use epic_util::secp::key::SecretKey;
use epic_util::secp::pedersen::ProofMessage;
use epic_util::secp::{ContextFlag, Secp256k1};
use serde::Serialize;

use super::{AREA, KeyPath, KeysPins, Network, SEED_16, SEED_32, ensure, keychain, switch_name};
use crate::{Error, Rendered, hex, render};

const AMOUNTS: [u64; 4] = [0, 1, 100_000_000, u64::MAX];

const LEGACY_PATHS: [KeyPath; 3] = [
    KeyPath::new(3, [0, 0, 0, 0]),
    KeyPath::new(3, [0, 0, 1, 0]),
    KeyPath::new(3, [1, 0, 5, 0]),
];

const CURRENT_PATHS: [KeyPath; 4] = [
    LEGACY_PATHS[0],
    LEGACY_PATHS[1],
    LEGACY_PATHS[2],
    KeyPath::new(4, [0, 0, 0, 3]),
];

const RAW_BLIND: [u8; 32] = [0x21; 32];
const RAW_REWIND_NONCE: [u8; 32] = [0x31; 32];
const RAW_PRIVATE_NONCE: [u8; 32] = [0x41; 32];
const RAW_WRONG_NONCE: [u8; 32] = [0x51; 32];
const RAW_MESSAGE: [u8; 20] = [
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x2a,
];
const RAW_EXTRA_DATA: &[u8] = b"lepic extra data";

#[derive(Serialize)]
struct RawInputs {
    blind: String,
    rewind_nonce: String,
    private_nonce: String,
    wrong_nonce: String,
    message: String,
    cases: Vec<RawCaseInputs>,
}

#[derive(Serialize)]
struct RawCaseInputs {
    amount: String,
    extra_data: Option<String>,
}

#[derive(Serialize)]
struct RawExpected {
    cases: Vec<RawCase>,
}

/// `rewind` is what `rewind_bullet_proof` with the rewind nonce returns. Rewinding with
/// `wrong_nonce` and verifying without the extra data both fail; `wrong_nonce_error` and
/// `missing_extra_data_error` record upstream's message (null when the case has no extra data).
#[derive(Serialize)]
struct RawCase {
    amount: String,
    extra_data: Option<String>,
    commit: String,
    proof: String,
    rewind: RawRewind,
    wrong_nonce_error: String,
    missing_extra_data_error: Option<String>,
}

#[derive(Serialize)]
struct RawRewind {
    value: String,
    blinding: String,
    message: String,
}

#[derive(Serialize)]
struct BuilderInputs {
    builder: &'static str,
    seed: String,
    other_seed: String,
    network: &'static str,
    paths: Vec<KeyPath>,
    amounts: Vec<String>,
    switches: Vec<&'static str>,
}

#[derive(Serialize)]
struct BuilderExpected {
    cases: Vec<BuilderCase>,
}

/// One output built with `proof::create`. `rewind` is `proof::rewind` with the same builder;
/// `rewind_with_other_builder` uses the other builder of the same wallet, and
/// `rewind_by_other_wallet` the same builder over `other_seed`. Upstream returns `None` for both,
/// recorded as null.
#[derive(Serialize)]
struct BuilderCase {
    path: KeyPath,
    identifier: String,
    amount: String,
    switch: &'static str,
    commit: String,
    rewind_nonce: String,
    private_nonce: String,
    message: String,
    proof: String,
    rewind: Option<Rewound>,
    rewind_with_other_builder: Option<Rewound>,
    rewind_by_other_wallet: Option<Rewound>,
}

#[derive(Serialize)]
struct Rewound {
    amount: String,
    identifier: String,
    switch: &'static str,
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let own = keychain(&SEED_32, Network::Mainnet)?;
    let other = keychain(&SEED_16, Network::Mainnet)?;
    let current = ProofBuilder::new(&own);
    let legacy = LegacyProofBuilder::new(&own);
    let other_current = ProofBuilder::new(&other);
    let other_legacy = LegacyProofBuilder::new(&other);

    let current_cases = builder_cases(
        &own,
        &current,
        &legacy,
        &other_current,
        &CURRENT_PATHS,
        &[SwitchCommitmentType::None, SwitchCommitmentType::Regular],
    )?;
    let legacy_cases = builder_cases(
        &own,
        &legacy,
        &current,
        &other_legacy,
        &LEGACY_PATHS,
        &[SwitchCommitmentType::Regular],
    )?;

    Ok(vec![
        raw(pins)?,
        render(
            AREA,
            "proofs_builder_seed32",
            pins.node,
            builder_inputs("ProofBuilder", &CURRENT_PATHS, &["none", "regular"]),
            BuilderExpected {
                cases: current_cases,
            },
        )?,
        render(
            AREA,
            "proofs_legacy_builder_seed32",
            pins.node,
            builder_inputs("LegacyProofBuilder", &LEGACY_PATHS, &["regular"]),
            BuilderExpected {
                cases: legacy_cases,
            },
        )?,
    ])
}

fn builder_inputs(
    builder: &'static str,
    paths: &[KeyPath],
    switches: &[&'static str],
) -> BuilderInputs {
    BuilderInputs {
        builder,
        seed: hex(SEED_32),
        other_seed: hex(SEED_16),
        network: Network::Mainnet.name(),
        paths: paths.to_vec(),
        amounts: AMOUNTS.iter().map(u64::to_string).collect(),
        switches: switches.to_vec(),
    }
}

fn builder_cases<B, O, W>(
    keychain: &ExtKeychain,
    builder: &B,
    other_builder: &O,
    other_wallet: &W,
    paths: &[KeyPath],
    switches: &[SwitchCommitmentType],
) -> Result<Vec<BuilderCase>, Error>
where
    B: ProofBuild,
    O: ProofBuild,
    W: ProofBuild,
{
    let secp = keychain.secp();
    let mut cases = Vec::new();
    for path in paths {
        let id = path.identifier();
        for amount in AMOUNTS {
            for switch in switches {
                let commit = keychain
                    .commit(amount, &id, switch)
                    .map_err(Error::reference("output commit"))?;
                let rewind_nonce = builder
                    .rewind_nonce(secp, &commit)
                    .map_err(Error::reference("rewind nonce"))?;
                let private_nonce = builder
                    .private_nonce(secp, &commit)
                    .map_err(Error::reference("private nonce"))?;
                let message = builder
                    .proof_message(secp, &id, switch)
                    .map_err(Error::reference("proof message"))?;
                let range_proof =
                    proof::create(keychain, builder, amount, &id, switch, commit, None)
                        .map_err(Error::reference("proof creation"))?;
                proof::verify(secp, commit, range_proof, None)
                    .map_err(Error::reference("proof verification"))?;

                let rewind = proof::rewind(secp, builder, commit, None, range_proof)
                    .map_err(Error::reference("rewind"))?;
                ensure(
                    rewind
                        .as_ref()
                        .is_some_and(|(a, i, s)| *a == amount && *i == id && s == switch),
                    "rewind with the creating builder recovers the output",
                )?;
                let rewind_with_other_builder =
                    proof::rewind(secp, other_builder, commit, None, range_proof)
                        .map_err(Error::reference("rewind with other builder"))?;
                let rewind_by_other_wallet =
                    proof::rewind(secp, other_wallet, commit, None, range_proof)
                        .map_err(Error::reference("rewind by other wallet"))?;

                cases.push(BuilderCase {
                    path: *path,
                    identifier: id.to_hex(),
                    amount: amount.to_string(),
                    switch: switch_name(*switch),
                    commit: hex(commit.0),
                    rewind_nonce: hex(rewind_nonce.0),
                    private_nonce: hex(private_nonce.0),
                    message: hex(message.as_bytes()),
                    proof: hex(range_proof.bytes()),
                    rewind: rewind.map(rewound),
                    rewind_with_other_builder: rewind_with_other_builder.map(rewound),
                    rewind_by_other_wallet: rewind_by_other_wallet.map(rewound),
                });
            }
        }
    }
    Ok(cases)
}

fn rewound((amount, id, switch): (u64, Identifier, SwitchCommitmentType)) -> Rewound {
    Rewound {
        amount: amount.to_string(),
        identifier: id.to_hex(),
        switch: switch_name(switch),
    }
}

fn raw(pins: &KeysPins<'_>) -> Result<Rendered, Error> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let key =
        |bytes: &[u8; 32]| SecretKey::from_slice(&secp, bytes).map_err(Error::reference("key"));
    let blind = key(&RAW_BLIND)?;
    let rewind_nonce = key(&RAW_REWIND_NONCE)?;
    let private_nonce = key(&RAW_PRIVATE_NONCE)?;
    let wrong_nonce = key(&RAW_WRONG_NONCE)?;

    let mut case_inputs: Vec<(u64, Option<&[u8]>)> =
        AMOUNTS.iter().map(|amount| (*amount, None)).collect();
    case_inputs.push((100_000_000, Some(RAW_EXTRA_DATA)));

    let mut cases = Vec::new();
    for (amount, extra_data) in &case_inputs {
        let amount = *amount;
        let extra = extra_data.map(<[u8]>::to_vec);
        let commit = secp
            .commit(amount, blind.clone())
            .map_err(Error::reference("commit"))?;
        let range_proof = secp.bullet_proof(
            amount,
            blind.clone(),
            rewind_nonce.clone(),
            private_nonce.clone(),
            extra.clone(),
            Some(ProofMessage::from_bytes(&RAW_MESSAGE)),
        );
        secp.verify_bullet_proof(commit, range_proof, extra.clone())
            .map_err(Error::reference("raw proof verification"))?;
        let info = secp
            .rewind_bullet_proof(commit, rewind_nonce.clone(), extra.clone(), range_proof)
            .map_err(Error::reference("raw rewind"))?;
        ensure(info.value == amount, "raw rewind recovers the amount")?;
        let wrong_nonce_error =
            match secp.rewind_bullet_proof(commit, wrong_nonce.clone(), extra.clone(), range_proof)
            {
                Ok(_) => {
                    return Err(Error::reference("raw rewind")(super::Inconsistent(
                        "rewind with a wrong nonce succeeded",
                    )));
                }
                Err(error) => error.to_string(),
            };
        let missing_extra_data_error = match extra {
            None => None,
            Some(_) => match secp.verify_bullet_proof(commit, range_proof, None) {
                Ok(_) => {
                    return Err(Error::reference("raw verification")(super::Inconsistent(
                        "proof verified without its extra data",
                    )));
                }
                Err(error) => Some(error.to_string()),
            },
        };
        cases.push(RawCase {
            amount: amount.to_string(),
            extra_data: extra_data.map(hex),
            commit: hex(commit.0),
            proof: hex(range_proof.bytes()),
            rewind: RawRewind {
                value: info.value.to_string(),
                blinding: hex(info.blinding.0),
                message: hex(info.message.as_bytes()),
            },
            wrong_nonce_error,
            missing_extra_data_error,
        });
    }

    let inputs = RawInputs {
        blind: hex(RAW_BLIND),
        rewind_nonce: hex(RAW_REWIND_NONCE),
        private_nonce: hex(RAW_PRIVATE_NONCE),
        wrong_nonce: hex(RAW_WRONG_NONCE),
        message: hex(RAW_MESSAGE),
        cases: case_inputs
            .iter()
            .map(|(amount, extra_data)| RawCaseInputs {
                amount: amount.to_string(),
                extra_data: extra_data.map(hex),
            })
            .collect(),
    };
    render(
        AREA,
        "bulletproof_raw",
        pins.node,
        inputs,
        RawExpected { cases },
    )
}
