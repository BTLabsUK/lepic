// SPDX-License-Identifier: Apache-2.0
//! LEPIC's own keys and tags of a pairing and of a wallet's seed, which no upstream wallet has:
//! the seed check, the keys of a private pairing, the `epic-private/1` reply key, channel key
//! and words check, and the hash a pairing verdict carries. Each is written here from its
//! description, with code independent of LEPIC's: BLAKE2b from `blake2-rfc`, SHA-256, HKDF,
//! HMAC and Ed25519 from `ring`, secp256k1 from the node's secp256k1-zkp.
//!
//! - seed check: BLAKE2b-256(key = seed, "lepic-wallet seed check v1");
//! - private pairing keys: root = HKDF-SHA256(salt "epic-contact/1", ikm = BLAKE2b-256(raw),
//!   info "root" || net); then HKDF-SHA256(salt "epic-private/1 keys" || secret, ikm = root)
//!   expanded under "private enc" | "private sig" | "private hint" || slot (u32 BE), and
//!   "private box" || slot || counter (u8), the counter from 0 up to the first valid secp256k1
//!   key;
//! - private pairing tags: reply key SHA-256("epic-private/1 reply" || sA); channel key
//!   HMAC-SHA256(key = SHA-256("epic-private/1 channel" || sA || sB), H(invite) || H(card B));
//!   words check SHA-256("epic-private/1 sas" || net || H(card A) || H(card B) || nA || nB ||
//!   H(sA || sB))[0..4]; HPKE PSK id "epic-private/1";
//! - pairing verdict: BLAKE2b-256("lepic-wallet pairing verdict v1" || sas).
//!
//! The cards, invite and nonces of the private pairing tags are those of the first floonet
//! pairing of `testdata/vectors/pairing/cards_invites.json`.

use blake2_rfc::blake2b::blake2b;
use epic_util::secp::key::{PublicKey, SecretKey};
use ring::{hkdf, hmac, signature};
use serde::Serialize;

use super::namespace::{OkmLen, keyed, secp, sha256, unhex};
use super::{AREA, Inconsistent, KeysPins, SEEDS};
use crate::{Error, Rendered, hex, render};

const SEED_CHECK_DOMAIN: &str = "lepic-wallet seed check v1";
const ROOT_SALT: &str = "epic-contact/1";
const PRIVATE_SALT: &str = "epic-private/1 keys";
const REPLY_DOMAIN: &str = "epic-private/1 reply";
const CHANNEL_DOMAIN: &str = "epic-private/1 channel";
const SAS_DOMAIN: &str = "epic-private/1 sas";
const PSK_ID: &str = "epic-private/1";
const VERDICT_DOMAIN: &str = "lepic-wallet pairing verdict v1";

const PAIRINGS: &str = include_str!("../../../../testdata/vectors/pairing/cards_invites.json");

/// The raw account key, network and record secret of the private pairing keys.
const RAW: [u8; 32] = [0x07; 32];
const FLOONET: u8 = 1;
const SECRET: [u8; 32] = [0x01; 32];
/// The first private slot, the next one, and the last.
const SLOTS: [u32; 3] = [65_536, 65_537, u32::MAX];

const LINK: [u8; 32] = [0x51; 32];
const JOINER: [u8; 32] = [0x52; 32];

const VERDICT_SAS: [[u8; 4]; 3] = [[0x7b, 0x49, 0xeb, 0x6f], [0; 4], [0xff; 4]];

fn inconsistent(what: &'static str) -> Error {
    Error::reference("pairing keys")(Inconsistent(what))
}

fn hkdf_expand(prk: &hkdf::Prk, info: &[u8]) -> Result<[u8; 32], Error> {
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, OkmLen)
        .map_err(|_| inconsistent("hkdf expand"))?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| inconsistent("hkdf fill"))?;
    Ok(out)
}

#[derive(Serialize)]
struct SeedCheckInputs {
    seed: String,
    domain: &'static str,
}

#[derive(Serialize)]
struct SeedCheck {
    check: String,
}

fn seed_checks(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for seed in &SEEDS {
        let check = keyed(seed.entropy, &[SEED_CHECK_DOMAIN.as_bytes()]);
        let name = format!("seed_check_{}", seed.name);
        vectors.push(render(
            AREA,
            &name,
            &pins.wallet,
            SeedCheckInputs {
                seed: hex(seed.entropy),
                domain: SEED_CHECK_DOMAIN,
            },
            SeedCheck { check: hex(check) },
        )?);
    }
    Ok(vectors)
}

#[derive(Serialize)]
struct PrivateKeyInputs {
    raw: String,
    network: u8,
    root_salt: &'static str,
    private_salt: &'static str,
    secret: String,
    slots: Vec<u32>,
}

#[derive(Serialize)]
struct PrivateKeyCase {
    slot: u32,
    enc_secret: String,
    sig_seed: String,
    sig_public: String,
    hint_key: String,
    box_counter: u8,
    box_secret: String,
    box_public: String,
}

#[derive(Serialize)]
struct PrivateKeys {
    root: String,
    cases: Vec<PrivateKeyCase>,
}

fn private_pairing_keys(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let secp = secp();
    let hashed = blake2b(32, &[], &RAW);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, ROOT_SALT.as_bytes()).extract(hashed.as_bytes());
    let root = hkdf_expand(&prk, &[b"root".as_slice(), &[FLOONET]].concat())?;
    let salt = [PRIVATE_SALT.as_bytes(), &SECRET].concat();
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&root);
    let mut cases = Vec::new();
    for slot in SLOTS {
        let slot_bytes = slot.to_be_bytes();
        let label = |name: &str| [name.as_bytes(), &slot_bytes].concat();
        let sig_seed = hkdf_expand(&prk, &label("private sig"))?;
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&sig_seed)
            .map_err(|_| inconsistent("ed25519 seed"))?;
        let mut found = None;
        for counter in 0..=u8::MAX {
            let bytes = hkdf_expand(
                &prk,
                &[label("private box").as_slice(), &[counter]].concat(),
            )?;
            if let Ok(key) = SecretKey::from_slice(&secp, &bytes) {
                found = Some((counter, key));
                break;
            }
        }
        let (box_counter, box_secret) = found.ok_or_else(|| inconsistent("no box key"))?;
        let box_public = PublicKey::from_secret_key(&secp, &box_secret)
            .map_err(Error::reference("box public key"))?;
        cases.push(PrivateKeyCase {
            slot,
            enc_secret: hex(hkdf_expand(&prk, &label("private enc"))?),
            sig_seed: hex(sig_seed),
            sig_public: hex(signature::KeyPair::public_key(&pair).as_ref()),
            hint_key: hex(hkdf_expand(&prk, &label("private hint"))?),
            box_counter,
            box_secret: hex(box_secret.0),
            box_public: hex(box_public.serialize_vec(&secp, true)),
        });
    }
    Ok(vec![render(
        AREA,
        "private_pairing_keys",
        &pins.wallet,
        PrivateKeyInputs {
            raw: hex(RAW),
            network: FLOONET,
            root_salt: ROOT_SALT,
            private_salt: PRIVATE_SALT,
            secret: hex(SECRET),
            slots: SLOTS.to_vec(),
        },
        PrivateKeys {
            root: hex(root),
            cases,
        },
    )?])
}

#[derive(Serialize)]
struct TagInputs {
    network: u8,
    link: String,
    joiner: String,
    invite: String,
    card_a: String,
    card_b: String,
    nonce_a: String,
    nonce_b: String,
    reply_domain: &'static str,
    channel_domain: &'static str,
    sas_domain: &'static str,
}

#[derive(Serialize)]
struct Tags {
    reply_key: String,
    channel_key: String,
    sas: String,
    psk_id: &'static str,
}

/// The hex field at `path` of `value`, as bytes.
fn field(value: &serde_json::Value, path: &str) -> Result<Vec<u8>, Error> {
    value
        .pointer(path)
        .and_then(serde_json::Value::as_str)
        .map(unhex)
        .ok_or_else(|| inconsistent("pairing vector field"))
}

fn private_pairing_tags(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let pairings: serde_json::Value = serde_json::from_str(PAIRINGS)?;
    let floonet = serde_json::Value::from(FLOONET);
    let pairing = pairings
        .get("vectors")
        .and_then(serde_json::Value::as_array)
        .and_then(|vectors| {
            vectors.iter().find(|vector| {
                vector.get("kind").and_then(serde_json::Value::as_str) == Some("pairing")
                    && vector.get("net") == Some(&floonet)
            })
        })
        .ok_or_else(|| inconsistent("no floonet pairing"))?;
    let invite = field(pairing, "/invite")?;
    let card_a = field(pairing, "/card_a")?;
    let card_b = field(pairing, "/card_b")?;
    let nonce_a = field(pairing, "/inputs/nA")?;
    let nonce_b = field(pairing, "/inputs/nB")?;
    let reply_key = sha256(&[REPLY_DOMAIN.as_bytes(), &LINK]);
    let channel_secret = sha256(&[CHANNEL_DOMAIN.as_bytes(), &LINK, &JOINER]);
    let transcript = [sha256(&[&invite]), sha256(&[&card_b])].concat();
    let channel_key = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &channel_secret),
        &transcript,
    );
    let secrets = sha256(&[&LINK, &JOINER]);
    let words = sha256(&[
        SAS_DOMAIN.as_bytes(),
        &[FLOONET],
        &sha256(&[&card_a]),
        &sha256(&[&card_b]),
        &nonce_a,
        &nonce_b,
        &secrets,
    ]);
    let sas = words
        .get(..4)
        .ok_or_else(|| inconsistent("short words hash"))?;
    Ok(vec![render(
        AREA,
        "private_pairing_tags",
        &pins.wallet,
        TagInputs {
            network: FLOONET,
            link: hex(LINK),
            joiner: hex(JOINER),
            invite: hex(&invite),
            card_a: hex(&card_a),
            card_b: hex(&card_b),
            nonce_a: hex(&nonce_a),
            nonce_b: hex(&nonce_b),
            reply_domain: REPLY_DOMAIN,
            channel_domain: CHANNEL_DOMAIN,
            sas_domain: SAS_DOMAIN,
        },
        Tags {
            reply_key: hex(reply_key),
            channel_key: hex(channel_key.as_ref()),
            sas: hex(sas),
            psk_id: PSK_ID,
        },
    )?])
}

#[derive(Serialize)]
struct VerdictInputs {
    domain: &'static str,
    sas: Vec<String>,
}

#[derive(Serialize)]
struct Verdicts {
    hashes: Vec<String>,
}

fn pairing_verdicts(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let hashes = VERDICT_SAS
        .iter()
        .map(|sas| hex(blake2b(32, &[], &[VERDICT_DOMAIN.as_bytes(), sas].concat()).as_bytes()))
        .collect();
    Ok(vec![render(
        AREA,
        "pairing_verdicts",
        &pins.wallet,
        VerdictInputs {
            domain: VERDICT_DOMAIN,
            sas: VERDICT_SAS.iter().map(hex).collect(),
        },
        Verdicts { hashes },
    )?])
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = seed_checks(pins)?;
    vectors.extend(private_pairing_keys(pins)?);
    vectors.extend(private_pairing_tags(pins)?);
    vectors.extend(pairing_verdicts(pins)?);
    Ok(vectors)
}
