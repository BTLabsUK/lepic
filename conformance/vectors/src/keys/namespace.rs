// SPDX-License-Identifier: Apache-2.0
//! Keys of the LEPIC namespace and what they sign, which no upstream wallet has: listing keys,
//! the device-link key, the onion key, signatures by a listing key per service domain, and the pairing address
//! proof. Each is written here from its description, with code independent of LEPIC's: keyed
//! BLAKE2b-256 from `blake2-rfc`, secp256k1 keys, ECDH and ECDSA from the node's secp256k1-zkp,
//! SHA-256, HKDF, HMAC and Ed25519 from `ring`. Listing addresses use the wallet's own Epicbox
//! address code.
//!
//! - listing key: BLAKE2b(key = seed, "lepic-wallet listing key v1" || service_key (33) ||
//!   generation (u32 BE) || counter (u8)), the counter from 0 up to the first valid secp256k1 key;
//! - device-link key: Ed25519 from BLAKE2b(key = seed, "lepic-wallet device link key v1"), signing
//!   "lepic/device-link/v1" || transcript;
//! - onion key: Ed25519 from BLAKE2b(key = seed, "lepic-wallet onion key v1"), its onion v3
//!   address written by the wallet's own onion address code;
//! - owner TLS key: Ed25519 from BLAKE2b(key = seed, "lepic-wallet api tls v1"), and the SHA-256
//!   of its RFC 8410 SubjectPublicKeyInfo, the fingerprint clients pin;
//! - listing signature: ECDSA by the listing key over SHA-256(SHA-256(tag) || SHA-256(tag) ||
//!   len(domain) (u8) || domain || message), tag "lepic/listing-signature/v1";
//! - address proof: K = HKDF-SHA256(salt "lepic/addr-proof/1", ikm = x(ECDH), info = "mac" ||
//!   net || step), tag = HMAC-SHA256(K, H(prover card) || H(verifier card) || H(invite)), 32 zero
//!   bytes for a hash a step does not have.

use blake2_rfc::blake2b::blake2b;
use epic_util::secp::key::{PublicKey, SecretKey};
use epic_util::secp::{ContextFlag, Message, Secp256k1};
use epic_wallet_libwallet::address;
use ring::{digest, hkdf, hmac, signature};
use serde::Serialize;

use super::address::epicbox_form;
use super::{AREA, Inconsistent, KeysPins, Network, SEEDS, keychain};
use crate::{Error, Rendered, hex, render};

const LISTING_KEY_LABEL: &[u8] = b"lepic-wallet listing key v1";
const DEVICE_LINK_KEY_LABEL: &[u8] = b"lepic-wallet device link key v1";
const DEVICE_LINK_TAG: &[u8] = b"lepic/device-link/v1";
const ONION_KEY_LABEL: &[u8] = b"lepic-wallet onion key v1";
const API_TLS_KEY_LABEL: &[u8] = b"lepic-wallet api tls v1";
/// SubjectPublicKeyInfo of an Ed25519 key (RFC 8410), before the 32-byte public key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const LISTING_TAG: &[u8] = b"lepic/listing-signature/v1";
const ADDRESS_PROOF_SALT: &[u8] = b"lepic/addr-proof/1";

/// Service keys: the secret keys whose public keys the listings are for.
const SERVICES: [[u8; 32]; 2] = [[0x31; 32], [0x32; 32]];
const GENERATIONS: [u32; 3] = [0, 1, u32::MAX];

/// The app domains of the registry, and the message signed under each.
const DOMAINS: [&str; 5] = [
    "epic-listing/1",
    "epic-listing-moved/1",
    "epic-payreq/1",
    "epic-unlist/1",
    "epic-dir-hello/1",
];
const MESSAGE: &[u8] = b"lepic listing signature vector";
const TRANSCRIPTS: [&[u8]; 2] = [b"", b"hello transcript"];

pub(super) fn secp() -> Secp256k1 {
    Secp256k1::with_caps(ContextFlag::Full)
}

pub(super) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    for part in parts {
        context.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    out
}

pub(super) fn keyed(seed: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let message = parts.concat();
    let mut out = [0u8; 32];
    out.copy_from_slice(blake2b(32, seed, &message).as_bytes());
    out
}

#[derive(Serialize)]
struct ListingInputs {
    seed: String,
    label: &'static str,
    service_keys: Vec<String>,
    generations: Vec<u32>,
}

#[derive(Serialize)]
struct ListingCase {
    service_key: String,
    generation: u32,
    counter: u8,
    secret_key: String,
    public_key: String,
    epicbox: Vec<super::address::EpicboxForm>,
}

#[derive(Serialize)]
struct Cases<T> {
    cases: Vec<T>,
}

/// The listing key of `seed` for `service_key` and `generation`, and the counter that made it.
fn listing_key(
    secp: &Secp256k1,
    seed: &[u8],
    service_key: &[u8],
    generation: u32,
) -> Result<(u8, SecretKey), Error> {
    for counter in 0..=u8::MAX {
        let bytes = keyed(
            seed,
            &[
                LISTING_KEY_LABEL,
                service_key,
                &generation.to_be_bytes(),
                &[counter],
            ],
        );
        if let Ok(key) = SecretKey::from_slice(secp, &bytes) {
            return Ok((counter, key));
        }
    }
    Err(Error::reference("listing key")(Inconsistent(
        "no valid key",
    )))
}

fn service_key(secp: &Secp256k1, secret: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let secret = SecretKey::from_slice(secp, secret).map_err(Error::reference("service key"))?;
    let public =
        PublicKey::from_secret_key(secp, &secret).map_err(Error::reference("service key"))?;
    Ok(public.serialize_vec(secp, true).to_vec())
}

fn listing_keys(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let secp = secp();
    let mut vectors = Vec::new();
    for seed in &SEEDS {
        let service_keys = SERVICES
            .iter()
            .map(|secret| service_key(&secp, secret))
            .collect::<Result<Vec<_>, _>>()?;
        let mut cases = Vec::new();
        for service_key in &service_keys {
            for generation in GENERATIONS {
                let (counter, key) = listing_key(&secp, seed.entropy, service_key, generation)?;
                let public = PublicKey::from_secret_key(&secp, &key)
                    .map_err(Error::reference("listing public key"))?;
                cases.push(ListingCase {
                    service_key: hex(service_key),
                    generation,
                    counter,
                    secret_key: hex(key.0),
                    public_key: hex(public.serialize_vec(&secp, true)),
                    epicbox: Network::ALL
                        .iter()
                        .map(|network| epicbox_form(*network, public))
                        .collect::<Result<_, _>>()?,
                });
            }
        }
        let inputs = ListingInputs {
            seed: hex(seed.entropy),
            label: "lepic-wallet listing key v1",
            service_keys: service_keys.iter().map(hex).collect(),
            generations: GENERATIONS.to_vec(),
        };
        let name = format!("listing_keys_{}", seed.name);
        vectors.push(render(AREA, &name, &pins.wallet, inputs, Cases { cases })?);
    }
    Ok(vectors)
}

#[derive(Serialize)]
struct SignatureInputs {
    seed: String,
    service_key: String,
    generation: u32,
    tag: &'static str,
    message: String,
    domains: Vec<&'static str>,
}

#[derive(Serialize)]
struct SignatureCase {
    domain: &'static str,
    digest: String,
    signature_der: String,
}

#[derive(Serialize)]
struct SignatureExpected {
    public_key: String,
    cases: Vec<SignatureCase>,
}

fn listing_signatures(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let secp = secp();
    let seed = SEEDS
        .first()
        .ok_or(Error::reference("seeds")(Inconsistent("no seed")))?;
    let service_key = service_key(&secp, &SERVICES[0])?;
    let (_, key) = listing_key(&secp, seed.entropy, &service_key, 0)?;
    let public =
        PublicKey::from_secret_key(&secp, &key).map_err(Error::reference("listing public key"))?;
    let tag = sha256(&[LISTING_TAG]);
    let mut cases = Vec::new();
    for domain in DOMAINS {
        let length = u8::try_from(domain.len())
            .map_err(|_| Error::reference("domain")(Inconsistent("domain too long")))?;
        let digest = sha256(&[&tag, &tag, &[length], domain.as_bytes(), MESSAGE]);
        let message = Message::from_slice(&digest).map_err(Error::reference("message"))?;
        let signature = secp
            .sign(&message, &key)
            .map_err(Error::reference("listing signature"))?;
        secp.verify(&message, &signature, &public)
            .map_err(Error::reference("listing signature verify"))?;
        cases.push(SignatureCase {
            domain,
            digest: hex(digest),
            signature_der: hex(signature.serialize_der(&secp)),
        });
    }
    let inputs = SignatureInputs {
        seed: hex(seed.entropy),
        service_key: hex(&service_key),
        generation: 0,
        tag: "lepic/listing-signature/v1",
        message: hex(MESSAGE),
        domains: DOMAINS.to_vec(),
    };
    let expected = SignatureExpected {
        public_key: hex(public.serialize_vec(&secp, true)),
        cases,
    };
    Ok(vec![render(
        AREA,
        "listing_signatures",
        &pins.wallet,
        inputs,
        expected,
    )?])
}

#[derive(Serialize)]
struct DeviceLinkInputs {
    seed: String,
    label: &'static str,
    tag: &'static str,
    transcripts: Vec<String>,
}

#[derive(Serialize)]
struct DeviceLinkCase {
    transcript: String,
    signature: String,
}

#[derive(Serialize)]
struct DeviceLinkExpected {
    ed25519_seed: String,
    public_key: String,
    cases: Vec<DeviceLinkCase>,
}

fn device_link_keys(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for seed in &SEEDS {
        let ed_seed = keyed(seed.entropy, &[DEVICE_LINK_KEY_LABEL]);
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&ed_seed)
            .map_err(|_| Error::reference("device link key")(Inconsistent("key rejected")))?;
        let public = signature::KeyPair::public_key(&pair).as_ref().to_vec();
        let cases = TRANSCRIPTS
            .iter()
            .map(|transcript| DeviceLinkCase {
                transcript: hex(transcript),
                signature: hex(pair.sign(&[DEVICE_LINK_TAG, transcript].concat())),
            })
            .collect();
        let inputs = DeviceLinkInputs {
            seed: hex(seed.entropy),
            label: "lepic-wallet device link key v1",
            tag: "lepic/device-link/v1",
            transcripts: TRANSCRIPTS.iter().map(hex).collect(),
        };
        let expected = DeviceLinkExpected {
            ed25519_seed: hex(ed_seed),
            public_key: hex(public),
            cases,
        };
        let name = format!("device_link_key_{}", seed.name);
        vectors.push(render(AREA, &name, &pins.wallet, inputs, expected)?);
    }
    Ok(vectors)
}

#[derive(Serialize)]
struct OnionInputs {
    seed: String,
    label: &'static str,
}

#[derive(Serialize)]
struct OnionExpected {
    ed25519_seed: String,
    public_key: String,
    onion_v3: String,
}

fn onion_keys(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for seed in &SEEDS {
        let ed_seed = keyed(seed.entropy, &[ONION_KEY_LABEL]);
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&ed_seed)
            .map_err(|_| Error::reference("onion key")(Inconsistent("key rejected")))?;
        let public = signature::KeyPair::public_key(&pair).as_ref().to_vec();
        let dalek = address::ed25519_parse_pubkey(&hex(&public))
            .map_err(Error::reference("onion public key"))?;
        let onion =
            address::onion_v3_from_pubkey(&dalek).map_err(Error::reference("onion v3 address"))?;
        let inputs = OnionInputs {
            seed: hex(seed.entropy),
            label: "lepic-wallet onion key v1",
        };
        let expected = OnionExpected {
            ed25519_seed: hex(ed_seed),
            public_key: hex(public),
            onion_v3: onion,
        };
        let name = format!("onion_key_{}", seed.name);
        vectors.push(render(AREA, &name, &pins.wallet, inputs, expected)?);
    }
    Ok(vectors)
}

#[derive(Serialize)]
struct ApiTlsExpected {
    ed25519_seed: String,
    public_key: String,
    spki_sha256: String,
}

fn api_tls_keys(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for seed in &SEEDS {
        let ed_seed = keyed(seed.entropy, &[API_TLS_KEY_LABEL]);
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&ed_seed)
            .map_err(|_| Error::reference("api tls key")(Inconsistent("key rejected")))?;
        let public = signature::KeyPair::public_key(&pair).as_ref().to_vec();
        let inputs = OnionInputs {
            seed: hex(seed.entropy),
            label: "lepic-wallet api tls v1",
        };
        let expected = ApiTlsExpected {
            ed25519_seed: hex(ed_seed),
            spki_sha256: hex(sha256(&[&ED25519_SPKI_PREFIX, &public])),
            public_key: hex(public),
        };
        let name = format!("api_tls_key_{}", seed.name);
        vectors.push(render(AREA, &name, &pins.wallet, inputs, expected)?);
    }
    Ok(vectors)
}

#[derive(Serialize)]
struct ProofInputs {
    salt: &'static str,
    prover_address_secret: String,
    verifier_mailbox_secret: String,
    cases: Vec<ProofCaseInputs>,
}

#[derive(Serialize, Clone)]
struct ProofCaseInputs {
    /// 0 mainnet, 1 floonet, as the contact formats write it.
    network: u8,
    /// 1 reply, 2 confirm, 3 contact update.
    step: u8,
    prover_card_digest: String,
    /// Empty for a reply, which has no verifier card.
    verifier_card_digest: String,
    /// Empty for a contact update, which has no invite.
    invite: String,
}

#[derive(Serialize)]
struct ProofCase {
    prover_address_public: String,
    verifier_mailbox_public: String,
    shared_x: String,
    key: String,
    tag: String,
}

pub(super) struct OkmLen;

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        32
    }
}

fn shared_x(secp: &Secp256k1, secret: &SecretKey, public: &PublicKey) -> Result<[u8; 32], Error> {
    let mut point = *public;
    point
        .mul_assign(secp, secret)
        .map_err(Error::reference("ecdh"))?;
    let bytes = point.serialize_vec(secp, true);
    let mut x = [0u8; 32];
    x.copy_from_slice(
        bytes
            .get(1..33)
            .ok_or(Error::reference("ecdh")(Inconsistent("short point")))?,
    );
    Ok(x)
}

pub(super) fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|at| text.get(at..at.checked_add(2)?))
        .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
        .collect()
}

fn address_proofs(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    let secp = secp();
    let prover = SecretKey::from_slice(&secp, &[0x41; 32]).map_err(Error::reference("prover"))?;
    let verifier =
        SecretKey::from_slice(&secp, &[0x42; 32]).map_err(Error::reference("verifier"))?;
    let prover_public =
        PublicKey::from_secret_key(&secp, &prover).map_err(Error::reference("prover public"))?;
    let verifier_public = PublicKey::from_secret_key(&secp, &verifier)
        .map_err(Error::reference("verifier public"))?;
    let card_a = hex(sha256(&[b"card of the prover"]));
    let card_b = hex(sha256(&[b"card of the verifier"]));
    let invite = hex(b"invite bytes");
    let inputs_cases = vec![
        ProofCaseInputs {
            network: 1,
            step: 1,
            prover_card_digest: card_a.clone(),
            verifier_card_digest: String::new(),
            invite: invite.clone(),
        },
        ProofCaseInputs {
            network: 1,
            step: 2,
            prover_card_digest: card_a.clone(),
            verifier_card_digest: card_b.clone(),
            invite,
        },
        ProofCaseInputs {
            network: 0,
            step: 3,
            prover_card_digest: card_a,
            verifier_card_digest: card_b,
            invite: String::new(),
        },
    ];
    let mut cases = Vec::new();
    for case in &inputs_cases {
        let x = shared_x(&secp, &prover, &verifier_public)?;
        let other_side = shared_x(&secp, &verifier, &prover_public)?;
        super::ensure(x == other_side, "both sides share the point")?;
        let info = [b'm', b'a', b'c', case.network, case.step];
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, ADDRESS_PROOF_SALT).extract(&x);
        let info_parts = [&info[..]];
        let okm = prk
            .expand(&info_parts, OkmLen)
            .map_err(|_| Error::reference("hkdf")(Inconsistent("expand")))?;
        let mut key = [0u8; 32];
        okm.fill(&mut key)
            .map_err(|_| Error::reference("hkdf")(Inconsistent("fill")))?;
        let mut message = [0u8; 96];
        let digests = [
            unhex(&case.prover_card_digest),
            unhex(&case.verifier_card_digest),
            if case.invite.is_empty() {
                Vec::new()
            } else {
                sha256(&[&unhex(&case.invite)]).to_vec()
            },
        ];
        for (slot, digest) in message.chunks_mut(32).zip(digests.iter()) {
            if digest.len() == 32 {
                slot.copy_from_slice(digest);
            }
        }
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &message);
        cases.push(ProofCase {
            prover_address_public: hex(prover_public.serialize_vec(&secp, true)),
            verifier_mailbox_public: hex(verifier_public.serialize_vec(&secp, true)),
            shared_x: hex(x),
            key: hex(key),
            tag: hex(tag.as_ref()),
        });
    }
    let inputs = ProofInputs {
        salt: "lepic/addr-proof/1",
        prover_address_secret: hex(prover.0),
        verifier_mailbox_secret: hex(verifier.0),
        cases: inputs_cases,
    };
    Ok(vec![render(
        AREA,
        "address_proofs",
        &pins.wallet,
        inputs,
        Cases { cases },
    )?])
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    // Each seed is a valid wallet seed upstream.
    for seed in &SEEDS {
        keychain(seed.entropy, Network::Mainnet)?;
    }
    let mut vectors = Vec::new();
    vectors.extend(listing_keys(pins)?);
    vectors.extend(listing_signatures(pins)?);
    vectors.extend(device_link_keys(pins)?);
    vectors.extend(onion_keys(pins)?);
    vectors.extend(api_tls_keys(pins)?);
    vectors.extend(address_proofs(pins)?);
    Ok(vectors)
}
