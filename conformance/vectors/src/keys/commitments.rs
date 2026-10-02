//! Pedersen commitments, switch commitments and blinding-factor sums: raw over given blinding
//! factors, and through the node keychain at several paths and amounts.

use epic_keychain::{Keychain, SwitchCommitmentType};
use epic_util::secp::key::SecretKey;
use epic_util::secp::pedersen::Commitment;
use epic_util::secp::{ContextFlag, Secp256k1};
use serde::Serialize;

use super::{
    AMOUNTS, AREA, HARDENED, KeyPath, KeysPins, Network, SEEDS, ensure, keychain, switch_name,
};
use crate::{Error, Rendered, hex, render};

/// One, a repeated byte, a mixed value and the group order minus one.
const BLINDS: [[u8; 32]; 4] = [
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ],
    [0x11; 32],
    [
        0x3c, 0x9a, 0x01, 0xe7, 0x55, 0x42, 0x8f, 0x10, 0xb6, 0x2d, 0x73, 0xc4, 0x09, 0xee, 0x61,
        0x38, 0x9d, 0x04, 0xfa, 0x27, 0x8b, 0x5e, 0xc0, 0x13, 0x76, 0xa9, 0x2f, 0x48, 0xd1, 0x6b,
        0x85, 0x0c,
    ],
    [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x3f,
    ],
];

const PATHS: [KeyPath; 5] = [
    KeyPath::new(3, [0, 0, 0, 0]),
    KeyPath::new(3, [0, 0, 1, 0]),
    KeyPath::new(3, [0, 0, HARDENED - 1, 0]),
    KeyPath::new(3, [1, 0, 5, 0]),
    KeyPath::new(4, [0, 0, 0, 3]),
];

#[derive(Serialize)]
struct RawInputs {
    amounts: Vec<String>,
    blinds: Vec<String>,
}

/// `switched_blind` is `blind_switch(amount, blind)`; `switched_commit` commits to the amount
/// under it, which is how outputs with the regular switch type are committed.
#[derive(Serialize)]
struct RawCase {
    amount: String,
    blind: String,
    commit: String,
    switched_blind: String,
    switched_commit: String,
}

#[derive(Serialize)]
struct RawExpected {
    cases: Vec<RawCase>,
}

#[derive(Serialize)]
struct SumInputs {
    positive_blinds: Vec<String>,
    negative_blinds: Vec<String>,
    amounts: Vec<String>,
}

/// `commits` are `commit(amounts[i], positive_blinds[i])` for the positive side and
/// `commit(0, negative_blinds[i])` for the negative side. `commit_sum` is the positive commits
/// minus the negative ones, and equals `commit(sum of amounts, blind_sum)`.
#[derive(Serialize)]
struct SumExpected {
    positive_commits: Vec<String>,
    negative_commits: Vec<String>,
    blind_sum: String,
    commit_sum: String,
}

#[derive(Serialize)]
struct KeychainInputs {
    seed: String,
    network: &'static str,
    paths: Vec<KeyPath>,
    amounts: Vec<String>,
}

/// `blind` is `Keychain::derive_key(amount, id, switch)` and `commit` is
/// `Keychain::commit(amount, id, switch)`. The floonet keychain gives the same values.
#[derive(Serialize)]
struct KeychainCase {
    path: KeyPath,
    identifier: String,
    amount: String,
    switch: &'static str,
    blind: String,
    commit: String,
}

#[derive(Serialize)]
struct KeychainExpected {
    cases: Vec<KeychainCase>,
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let mut vectors = vec![raw(&secp, pins)?, sums(&secp, pins)?];
    for seed in &SEEDS {
        let name = format!("commitments_{}", seed.name);
        let inputs = KeychainInputs {
            seed: hex(seed.entropy),
            network: Network::Mainnet.name(),
            paths: PATHS.to_vec(),
            amounts: AMOUNTS.iter().map(u64::to_string).collect(),
        };
        let expected = keychain_cases(seed.entropy)?;
        vectors.push(render(AREA, &name, pins.node, inputs, expected)?);
    }
    Ok(vectors)
}

fn secret(secp: &Secp256k1, bytes: &[u8; 32]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(secp, bytes).map_err(Error::reference("secret key"))
}

fn raw(secp: &Secp256k1, pins: &KeysPins<'_>) -> Result<Rendered, Error> {
    let mut cases = Vec::new();
    for blind_bytes in &BLINDS {
        for amount in AMOUNTS {
            let blind = secret(secp, blind_bytes)?;
            let commit = secp
                .commit(amount, blind.clone())
                .map_err(Error::reference("commit"))?;
            let switched = secp
                .blind_switch(amount, blind)
                .map_err(Error::reference("blind switch"))?;
            let switched_commit = secp
                .commit(amount, switched.clone())
                .map_err(Error::reference("switched commit"))?;
            cases.push(RawCase {
                amount: amount.to_string(),
                blind: hex(blind_bytes),
                commit: hex(commit.0),
                switched_blind: hex(switched.0),
                switched_commit: hex(switched_commit.0),
            });
        }
    }
    let inputs = RawInputs {
        amounts: AMOUNTS.iter().map(u64::to_string).collect(),
        blinds: BLINDS.iter().map(hex).collect(),
    };
    render(AREA, "commit_raw", pins.node, inputs, RawExpected { cases })
}

fn sums(secp: &Secp256k1, pins: &KeysPins<'_>) -> Result<Rendered, Error> {
    let [one, repeated, mixed, max] = &BLINDS;
    let positive_bytes = [mixed, repeated, one];
    let negative_bytes = [max, repeated];
    let amounts: [u64; 3] = [100_000_000, 2_500_000, 7];
    let total: u64 = 102_500_007;

    let positive: Vec<SecretKey> = positive_bytes
        .iter()
        .map(|b| secret(secp, b))
        .collect::<Result<_, _>>()?;
    let negative: Vec<SecretKey> = negative_bytes
        .iter()
        .map(|b| secret(secp, b))
        .collect::<Result<_, _>>()?;
    let positive_commits: Vec<Commitment> = positive
        .iter()
        .zip(amounts)
        .map(|(blind, amount)| secp.commit(amount, blind.clone()))
        .collect::<Result<_, _>>()
        .map_err(Error::reference("positive commit"))?;
    let negative_commits: Vec<Commitment> = negative
        .iter()
        .map(|blind| secp.commit(0, blind.clone()))
        .collect::<Result<_, _>>()
        .map_err(Error::reference("negative commit"))?;
    let blind_sum = secp
        .blind_sum(positive, negative)
        .map_err(Error::reference("blind sum"))?;
    let commit_sum = secp
        .commit_sum(positive_commits.clone(), negative_commits.clone())
        .map_err(Error::reference("commit sum"))?;
    let direct = secp
        .commit(total, blind_sum.clone())
        .map_err(Error::reference("commit to sums"))?;
    ensure(direct == commit_sum, "commit sum homomorphism")?;

    let inputs = SumInputs {
        positive_blinds: positive_bytes.iter().map(hex).collect(),
        negative_blinds: negative_bytes.iter().map(hex).collect(),
        amounts: amounts.iter().map(u64::to_string).collect(),
    };
    let expected = SumExpected {
        positive_commits: positive_commits.iter().map(|c| hex(c.0)).collect(),
        negative_commits: negative_commits.iter().map(|c| hex(c.0)).collect(),
        blind_sum: hex(blind_sum.0),
        commit_sum: hex(commit_sum.0),
    };
    render(AREA, "commit_sums", pins.node, inputs, expected)
}

fn keychain_cases(seed: &[u8]) -> Result<KeychainExpected, Error> {
    let mainnet = keychain(seed, Network::Mainnet)?;
    let floonet = keychain(seed, Network::Floonet)?;
    let mut cases = Vec::new();
    for path in PATHS {
        let id = path.identifier();
        for amount in AMOUNTS {
            for switch in [SwitchCommitmentType::None, SwitchCommitmentType::Regular] {
                let blind = mainnet
                    .derive_key(amount, &id, &switch)
                    .map_err(Error::reference("derive key"))?;
                let commit = mainnet
                    .commit(amount, &id, &switch)
                    .map_err(Error::reference("keychain commit"))?;
                let floonet_commit = floonet
                    .commit(amount, &id, &switch)
                    .map_err(Error::reference("floonet keychain commit"))?;
                ensure(
                    commit == floonet_commit,
                    "commitments equal on both networks",
                )?;
                cases.push(KeychainCase {
                    path,
                    identifier: id.to_hex(),
                    amount: amount.to_string(),
                    switch: switch_name(switch),
                    blind: hex(blind.0),
                    commit: hex(commit.0),
                });
            }
        }
    }
    Ok(KeychainExpected { cases })
}
