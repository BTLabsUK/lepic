// SPDX-License-Identifier: Apache-2.0
//! The address proof of a pairing: a MAC that shows the verifier of one pairing that the prover
//! holds the key of the payments address its card names (tag 09). It is keyed by ECDH between
//! the prover's payments key and the verifier's own mailbox key for the pairing (card tag 08), so
//! the verifier could have made it too: it convinces nobody else, and it is never a signature.
//!
//! `K = HKDF-SHA256(salt = "lepic/addr-proof/1", ikm = x(ECDH), info = "mac" || net || role)`,
//! `tag = HMAC-SHA256(K, H(prover card) || H(verifier card) || H(invite))`, with 32 zero bytes
//! for a hash the step does not have: the verifier's card in a reply (the invite commits to it),
//! the invite in a contact update. The raw ECDH value is never used as a key.
//!
//! Only this crate computes or checks it. No call of the wallet's API makes one for a caller.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use lepic_contact::{ContactCard, MailboxAddress, Network as ContactNetwork};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::EpicboxAddress;
use lepic_keychain::Keychain;
use lepic_methods::epicbox::relay_network;
use lepic_primitives::params::Network;
use lepic_wallet::account::parent_key_id;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use jiff::Timestamp;
use lepic_contact::{DomainName, PairingExtras, seal_contact_update_with};
use lepic_store::{ContactRecord, ContactState, Repositories};

use crate::collect::update_entry;
use crate::domain::DomainSigner;
use crate::keys::{contact_keys, contact_network, signing_key};
use crate::private::is_private;
use crate::{ContactError, ContactRelays, LockedRng};

/// The HKDF salt of the proof key; a LEPIC-reserved domain no other key or signature uses.
pub(crate) const ADDRESS_PROOF_SALT: &[u8] = b"lepic/addr-proof/1";

pub(crate) const ADDRESS_PROOF_LEN: usize = 32;

/// Which message of a pairing carries the proof, and so who proves to whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofStep {
    /// The invitee's reply, verified by the inviter's mailbox key from the invite.
    Reply,
    /// The inviter's confirm, verified by the invitee's mailbox key from its card.
    Confirm,
    /// A contact update, from either side.
    Update,
}

impl ProofStep {
    fn byte(self) -> u8 {
        match self {
            Self::Reply => 0x01,
            Self::Confirm => 0x02,
            Self::Update => 0x03,
        }
    }
}

/// What a proof is bound to.
pub(crate) struct ProofBinding<'a> {
    pub network: ContactNetwork,
    pub step: ProofStep,
    pub prover_card: &'a ContactCard,
    /// `None` only in a reply.
    pub verifier_card: Option<&'a ContactCard>,
    /// The invite's exact bytes; `None` only in a contact update.
    pub invite: Option<&'a [u8]>,
}

impl ProofBinding<'_> {
    fn message(&self) -> [u8; 96] {
        let mut message = [0; 96];
        let (prover, rest) = message.split_at_mut(32);
        let (verifier, invite) = rest.split_at_mut(32);
        prover.copy_from_slice(&self.prover_card.digest());
        if let Some(card) = self.verifier_card {
            verifier.copy_from_slice(&card.digest());
        }
        if let Some(bytes) = self.invite {
            invite.copy_from_slice(&Sha256::digest(bytes));
        }
        message
    }

    fn info(&self) -> [u8; 5] {
        [b'm', b'a', b'c', self.network.byte(), self.step.byte()]
    }
}

/// Why no proof could be made; the message then goes without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProofError {
    #[error("the address proof key could not be derived")]
    Derivation,
}

/// The MAC over `binding` keyed for the shared point of `secret` and `public`.
fn mac(
    secret: &SecretKey,
    public: &PublicKey,
    binding: &ProofBinding<'_>,
) -> Result<Hmac<Sha256>, ProofError> {
    mac_over(secret, public, &binding.info(), &binding.message())
}

fn mac_over(
    secret: &SecretKey,
    public: &PublicKey,
    info: &[u8],
    message: &[u8],
) -> Result<Hmac<Sha256>, ProofError> {
    let shared = public
        .shared_secret(secret)
        .map_err(|_| ProofError::Derivation)?;
    let hkdf = Hkdf::<Sha256>::new(Some(ADDRESS_PROOF_SALT), shared.expose_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, key.as_mut())
        .map_err(|_| ProofError::Derivation)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref())
        .map_err(|_| ProofError::Derivation)?;
    mac.update(message);
    Ok(mac)
}

/// The prover's proof: its payments `address_secret` with the verifier's mailbox key of the
/// pairing.
pub(crate) fn prove(
    address_secret: &SecretKey,
    verifier_mailbox: &PublicKey,
    binding: &ProofBinding<'_>,
) -> Result<[u8; ADDRESS_PROOF_LEN], ProofError> {
    Ok(mac(address_secret, verifier_mailbox, binding)?
        .finalize()
        .into_bytes()
        .into())
}

/// Whether `proof` shows that the holder of `prover_address` made it for this verifier, whose
/// mailbox secret of the pairing is `mailbox_secret`. Compared in constant time.
pub(crate) fn verify(
    mailbox_secret: &SecretKey,
    prover_address: &PublicKey,
    binding: &ProofBinding<'_>,
    proof: &[u8; ADDRESS_PROOF_LEN],
) -> bool {
    mac(mailbox_secret, prover_address, binding).is_ok_and(|mac| mac.verify_slice(proof).is_ok())
}

/// The wallet's payments identity as a card names it in tag 09: its Epicbox address on the
/// wallet's relay, and the key of that address.
pub(crate) struct Payments {
    secret: SecretKey,
    address: EpicboxAddress,
}

impl Payments {
    /// The payments address of the wallet behind `keychain`: the Epicbox address the wallet
    /// listens on, at the relay of `relays`.
    pub(crate) fn of(
        keychain: &Keychain,
        network: Network,
        relays: &ContactRelays,
    ) -> Result<Self, ContactError> {
        let parent = parent_key_id(PAYMENTS_ACCOUNT)?;
        let secret = keychain
            .address_key(&parent, PAYMENTS_INDEX)
            .map_err(|error| ContactError::Wallet(error.into()))?;
        let public = PublicKey::from_secret_key(&secret).map_err(|_| ContactError::RelayAddress)?;
        let endpoint = &relays.epicbox.settings().endpoint;
        let address = EpicboxAddress::new(
            public,
            relay_network(network),
            endpoint.domain().clone(),
            Some(endpoint.port()),
        );
        Ok(Self { secret, address })
    }

    /// The payments key.
    pub(crate) fn key(&self) -> [u8; 33] {
        self.address.public_key().to_bytes()
    }

    /// The card's tag 09 value.
    pub(crate) fn card_address(&self) -> Result<MailboxAddress, ContactError> {
        MailboxAddress::new(&self.address.to_string()).map_err(ContactError::Name)
    }

    /// The proof for `binding`, to the verifier whose mailbox key of the pairing is
    /// `verifier_mailbox`; `None` when it cannot be made, and the message goes without one.
    pub(crate) fn prove(
        &self,
        verifier_mailbox: &PublicKey,
        binding: &ProofBinding<'_>,
    ) -> Option<[u8; ADDRESS_PROOF_LEN]> {
        prove(&self.secret, verifier_mailbox, binding).ok()
    }
}

/// The address index and account of the payments identity, which `epic-wallet` derives too.
/// The signer of the domain claims of the wallet behind `keychain`, when `domain` names one:
/// the domain key is the payments account's, so the wallet claims one domain whatever account
/// a pairing is made in. `None` for a wallet that claims no domain.
pub(crate) fn domain_signer(
    keychain: &Keychain,
    network: Network,
    domain: Option<&str>,
) -> Result<Option<DomainSigner>, ContactError> {
    let Some(domain) = domain else {
        return Ok(None);
    };
    let domain = DomainName::new(domain).map_err(ContactError::Domain)?;
    let root =
        crate::key_schedule::contact_root(keychain, &parent_key_id(PAYMENTS_ACCOUNT)?, network)
            .map_err(ContactError::Keys)?;
    let key = root.domain_key(network).map_err(ContactError::Keys)?;
    Ok(Some(DomainSigner { key, domain }))
}

const PAYMENTS_ACCOUNT: lepic_store::AccountIndex = lepic_store::AccountIndex(0);
const PAYMENTS_INDEX: u32 = 0;

/// A payments address a pairing proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvenAddress {
    /// `key@relay`, as the card names it.
    pub address: String,
    pub key: [u8; 33],
}

/// The key of the mailbox `card` names (tag 08), the verifier key of proofs made for its owner.
pub(crate) fn mailbox_key(card: &ContactCard, network: Network) -> Option<PublicKey> {
    EpicboxAddress::parse(card.fields().mailbox.as_str(), relay_network(network))
        .ok()
        .map(|address| *address.public_key())
}

/// The key in an invite's mailbox-key extension, if it is a curve point.
pub(crate) fn invite_mailbox_key(invite: &lepic_contact::Invite) -> Option<PublicKey> {
    invite
        .fields()
        .mailbox_key
        .and_then(|bytes| PublicKey::from_bytes(&bytes).ok())
}

/// The address `binding.prover_card` names in tag 09 when `proof` shows its holder made it for
/// this verifier, whose mailbox secret of the pairing is `mailbox_secret`; `None` otherwise: no
/// address, no proof, or one that does not verify.
pub(crate) fn proven(
    mailbox_secret: &SecretKey,
    network: Network,
    binding: &ProofBinding<'_>,
    proof: Option<&[u8; ADDRESS_PROOF_LEN]>,
) -> Option<ProvenAddress> {
    let text = binding.prover_card.fields().payments_address.as_ref()?;
    let address = EpicboxAddress::parse(text.as_str(), relay_network(network)).ok()?;
    let key = *address.public_key();
    verify(mailbox_secret, &key, binding, proof?).then(|| ProvenAddress {
        address: address.to_string(),
        key: key.to_bytes(),
    })
}

/// The payments address in a contact update's card, when the update's `proof` shows the
/// contact made it for `record`'s mailbox key over that card and our card of the pairing.
pub(crate) fn proven_in_update(
    keychain: &Keychain,
    network: Network,
    record: &ContactRecord,
    card: &ContactCard,
    proof: Option<&[u8; ADDRESS_PROOF_LEN]>,
) -> Result<Option<ProvenAddress>, ContactError> {
    if proof.is_none() {
        return Ok(None);
    }
    let net = contact_network(network);
    let keys = contact_keys(
        keychain,
        network,
        record.account,
        record.slot,
        record.box_salt,
    )?;
    let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
    Ok(proven(
        keys.expose_box_secret(),
        network,
        &ProofBinding {
            network: net,
            step: ProofStep::Update,
            prover_card: card,
            verifier_card: Some(&own),
            invite: None,
        },
        proof,
    ))
}

/// What a card update is made with.
pub(crate) struct CardUpdate<'a> {
    pub(crate) keychain: &'a Keychain,
    pub(crate) network: Network,
    pub(crate) payments: &'a Payments,
    pub(crate) features: u32,
    /// What signs the domain claim the update carries; none when the wallet claims no domain.
    pub(crate) domain: Option<&'a DomainSigner>,
    pub(crate) now: Timestamp,
}

/// Gives the contact of `record` our card changed by `change`, with the next sequence number,
/// the payments address and its proof, in a contact update queued for its mailbox. Returns
/// whether one was queued: only a contact pairing that is paired and has not ended gets one.
pub(crate) fn queue_card_update(
    repos: &mut dyn Repositories,
    rng: &lepic_wallet::SharedRng,
    at: &CardUpdate<'_>,
    mut record: ContactRecord,
    change: impl FnOnce(&mut lepic_contact::CardFields),
) -> Result<bool, ContactError> {
    let paired = matches!(record.state, ContactState::Paired | ContactState::Verified);
    if !paired || is_private(&record) || record.facts.ended_reason.is_some() {
        return Ok(false);
    }
    let (Some(peer), Some(mailbox)) = (&record.peer, repos.contact_mailbox(record.contact_id)?)
    else {
        return Ok(false);
    };
    let net = contact_network(at.network);
    let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
    let peer_card = ContactCard::decode(&peer.bytes, net).map_err(ContactError::StoredData)?;
    let keys = contact_keys(
        at.keychain,
        at.network,
        record.account,
        record.slot,
        record.box_salt,
    )?;
    let mut fields = own.fields().clone();
    change(&mut fields);
    fields.payments_address = Some(at.payments.card_address()?);
    fields.seq = fields.seq.saturating_add(1);
    let signer = signing_key(&keys);
    let card = ContactCard::sign(net, fields, &signer).map_err(ContactError::Encode)?;
    let address_proof = mailbox_key(&peer_card, at.network).and_then(|verifier| {
        at.payments.prove(
            &verifier,
            &ProofBinding {
                network: net,
                step: ProofStep::Update,
                prover_card: &card,
                verifier_card: Some(&peer_card),
                invite: None,
            },
        )
    });
    let extras = PairingExtras {
        address_proof,
        features: Some(at.features),
        domain: at.domain.map(|domain| {
            domain.claim(
                net,
                &signer.verifying_key(),
                u64::try_from(at.now.as_second()).unwrap_or(0),
            )
        }),
    };
    let envelope = seal_contact_update_with(
        &peer_card,
        &card,
        &signer,
        &extras,
        &mut LockedRng(&mut **rng.lock()),
    )
    .map_err(ContactError::Encode)?;
    record.own_card = card.as_bytes().to_vec();
    record.updated_at = at.now;
    repos.put_contact(&record)?;
    repos.enqueue_contact_outbox(&update_entry(
        record.contact_id,
        &envelope,
        mailbox.peer_mailbox.clone(),
        at.now,
    ))?;
    Ok(true)
}

/// The settings key holding the payments address our contact cards were last given.
const ADDRESS_CARDS_KEY: &str = "contact.address-cards";

/// Queues one contact update to every paired contact whose card from us names another payments
/// address than `payments`' (the wallet's relay changed), with the card naming the new one and
/// its proof, and returns how many. A card that names no payments address is left as it is: such
/// a pairing was made before address proofs and stays unproven. Done once per payments address:
/// nothing is queued while the stored address is the same.
pub(crate) fn queue_address_cards(
    repos: &mut dyn Repositories,
    rng: &lepic_wallet::SharedRng,
    at: &CardUpdate<'_>,
) -> Result<usize, ContactError> {
    let CardUpdate {
        network, payments, ..
    } = *at;
    let address = payments.address.to_string();
    if repos.setting(ADDRESS_CARDS_KEY)?.as_deref() == Some(address.as_str()) {
        return Ok(0);
    }
    let net = contact_network(network);
    let card_address = payments.card_address()?;
    let mut queued = 0usize;
    for record in repos.contacts()? {
        let Ok(own) = ContactCard::decode(&record.own_card, net) else {
            continue;
        };
        match own.fields().payments_address.as_ref() {
            Some(named) if *named != card_address => {}
            _ => continue,
        }
        if queue_card_update(repos, rng, at, record, |fields| {
            fields.payments_address = Some(card_address.clone());
        })? {
            queued = queued.saturating_add(1);
        }
    }
    repos.put_setting(ADDRESS_CARDS_KEY, &address)?;
    Ok(queued)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use lepic_contact::{
        Capabilities, CardFields, ContactKind, ContactName, EncSecretKey, HintKey, SigningKey,
    };

    use super::*;

    const NET: ContactNetwork = ContactNetwork::Floonet;

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn public(secret: &SecretKey) -> PublicKey {
        PublicKey::from_secret_key(secret).unwrap()
    }

    fn address_text(key: &PublicKey, relay: &str) -> String {
        format!(
            "{}@{relay}",
            EpicboxAddress::key_text_of(key, relay_network(Network::Floonet))
        )
    }

    /// A card of `sig` whose mailbox key is `mailbox` and whose payments address is `payments`
    /// on `relay`.
    fn card(sig: u8, mailbox: &PublicKey, payments: Option<(&PublicKey, &str)>) -> ContactCard {
        let signing = SigningKey::from_bytes(&[sig; 32]);
        let fields = CardFields {
            kind: ContactKind::Person,
            name: ContactName::new("Anna").unwrap(),
            enc_key: EncSecretKey::from_bytes([sig; 32]).public_key(),
            sig_key: signing.verifying_key(),
            hint_key: HintKey::from_bytes([sig; 32]),
            mailbox: MailboxAddress::new(&address_text(mailbox, "relay.test:80")).unwrap(),
            payments_address: payments
                .map(|(key, relay)| MailboxAddress::new(&address_text(key, relay)).unwrap()),
            home_onion: None,
            caps: Capabilities::default(),
            max_envelope_version: 1,
            seq: 1,
        };
        ContactCard::sign(NET, fields, &signing).unwrap()
    }

    /// The prover's payments key, the verifier's mailbox key, and the cards of both.
    struct Pairing {
        prover_address: SecretKey,
        verifier_box: SecretKey,
        prover_card: ContactCard,
        verifier_card: ContactCard,
        invite: Vec<u8>,
    }

    fn pairing() -> Pairing {
        let prover_address = secret(1);
        let verifier_box = secret(2);
        let prover_card = card(
            3,
            &public(&secret(4)),
            Some((&public(&prover_address), "relay.test:80")),
        );
        let verifier_card = card(5, &public(&verifier_box), None);
        Pairing {
            prover_address,
            verifier_box,
            prover_card,
            verifier_card,
            invite: b"invite bytes".to_vec(),
        }
    }

    impl Pairing {
        fn binding(&self, step: ProofStep) -> ProofBinding<'_> {
            ProofBinding {
                network: NET,
                step,
                prover_card: &self.prover_card,
                verifier_card: Some(&self.verifier_card),
                invite: Some(&self.invite),
            }
        }

        fn proof(&self, step: ProofStep) -> [u8; 32] {
            prove(
                &self.prover_address,
                &public(&self.verifier_box),
                &self.binding(step),
            )
            .unwrap()
        }

        fn checks(&self, binding: &ProofBinding<'_>, proof: &[u8; 32]) -> bool {
            proven(&self.verifier_box, Network::Floonet, binding, Some(proof)).is_some()
        }
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    /// `testdata/vectors/keys/address_proofs.json`, written by the conformance generator from
    /// the construction with `ring` and the node's secp256k1: the tag of each step, made from
    /// either side of the pairing.
    #[test]
    fn address_proofs_match_the_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/keys/address_proofs.json"
        ))
        .unwrap();
        let text = |value: &serde_json::Value| value.as_str().unwrap().to_owned();
        let key =
            |name: &str| SecretKey::from_bytes(&unhex(&text(&vector["inputs"][name]))).unwrap();
        let (prover, verifier) = (key("prover_address_secret"), key("verifier_mailbox_secret"));
        let inputs = vector["inputs"]["cases"].as_array().unwrap();
        let expected = vector["expected"]["cases"].as_array().unwrap();
        assert_eq!(inputs.len(), 3);
        for (input, expected) in inputs.iter().zip(expected) {
            let network = u8::try_from(input["network"].as_u64().unwrap()).unwrap();
            let step = u8::try_from(input["step"].as_u64().unwrap()).unwrap();
            let info = [b'm', b'a', b'c', network, step];
            let invite = text(&input["invite"]);
            let parts = [
                unhex(&text(&input["prover_card_digest"])),
                unhex(&text(&input["verifier_card_digest"])),
                if invite.is_empty() {
                    Vec::new()
                } else {
                    Sha256::digest(unhex(&invite)).to_vec()
                },
            ];
            let mut message = [0u8; 96];
            for (slot, part) in message.chunks_mut(32).zip(&parts) {
                if part.len() == 32 {
                    slot.copy_from_slice(part);
                }
            }
            let tag = unhex(&text(&expected["tag"]));
            for (secret, other) in [(&prover, &verifier), (&verifier, &prover)] {
                let mac = mac_over(secret, &public(other), &info, &message).unwrap();
                assert_eq!(mac.finalize().into_bytes().as_slice(), tag.as_slice());
            }
        }
        // The step and network bytes are the ones this module writes.
        assert_eq!(
            [ProofStep::Reply, ProofStep::Confirm, ProofStep::Update].map(ProofStep::byte),
            [1, 2, 3]
        );
        assert_eq!(
            [ContactNetwork::Mainnet, ContactNetwork::Floonet].map(ContactNetwork::byte),
            [0, 1]
        );
    }

    #[test]
    fn a_proof_names_the_address_of_the_prover_card() {
        let pairing = pairing();
        let proof = pairing.proof(ProofStep::Confirm);
        let found = proven(
            &pairing.verifier_box,
            Network::Floonet,
            &pairing.binding(ProofStep::Confirm),
            Some(&proof),
        )
        .unwrap();
        assert_eq!(found.key, public(&pairing.prover_address).to_bytes());
        assert_eq!(
            found.address,
            address_text(&public(&pairing.prover_address), "relay.test:80")
        );
    }

    #[test]
    fn the_verifier_can_make_the_same_proof_so_it_convinces_nobody_else() {
        let pairing = pairing();
        let by_verifier = prove(
            &pairing.verifier_box,
            &public(&pairing.prover_address),
            &pairing.binding(ProofStep::Confirm),
        )
        .unwrap();
        assert_eq!(by_verifier, pairing.proof(ProofStep::Confirm));
    }

    #[test]
    fn a_proof_holds_only_for_its_cards_invite_and_step() {
        let pairing = pairing();
        let proof = pairing.proof(ProofStep::Confirm);
        let other_card = card(9, &public(&secret(4)), None);
        let other_invite = b"another invite".to_vec();
        let bindings = [
            ProofBinding {
                verifier_card: Some(&other_card),
                ..pairing.binding(ProofStep::Confirm)
            },
            ProofBinding {
                invite: Some(&other_invite),
                ..pairing.binding(ProofStep::Confirm)
            },
            ProofBinding {
                invite: None,
                ..pairing.binding(ProofStep::Confirm)
            },
            pairing.binding(ProofStep::Reply),
            pairing.binding(ProofStep::Update),
            ProofBinding {
                network: ContactNetwork::Mainnet,
                ..pairing.binding(ProofStep::Confirm)
            },
        ];
        assert!(pairing.checks(&pairing.binding(ProofStep::Confirm), &proof));
        for binding in &bindings {
            assert!(!pairing.checks(binding, &proof));
        }
    }

    #[test]
    fn a_proof_with_the_roles_swapped_does_not_verify() {
        let pairing = pairing();
        let proof = pairing.proof(ProofStep::Confirm);
        let swapped = ProofBinding {
            prover_card: &pairing.verifier_card,
            verifier_card: Some(&pairing.prover_card),
            ..pairing.binding(ProofStep::Confirm)
        };
        assert!(!verify(
            &pairing.prover_address,
            &public(&pairing.verifier_box),
            &swapped,
            &proof
        ));
    }

    #[test]
    fn a_card_naming_the_address_on_another_relay_does_not_take_the_proof() {
        let pairing = pairing();
        let proof = pairing.proof(ProofStep::Confirm);
        let moved = card(
            3,
            &public(&secret(4)),
            Some((&public(&pairing.prover_address), "other.test:80")),
        );
        let binding = ProofBinding {
            prover_card: &moved,
            ..pairing.binding(ProofStep::Confirm)
        };
        assert!(!pairing.checks(&binding, &proof));
    }

    #[test]
    fn a_proof_made_for_any_key_but_the_verifiers_own_mailbox_does_not_verify() {
        let pairing = pairing();
        let binding = pairing.binding(ProofStep::Reply);
        // The pairing mailbox keys, which anyone holding the invite's code derives, and the
        // invite's X25519 key read as a curve point.
        let (pbox, pfrom) =
            crate::key_schedule::pairing_mailbox_keys(&[7; 16], Network::Floonet).unwrap();
        let enc = EncSecretKey::from_bytes([5; 32]).public_key();
        let mut enc_point = [2u8; 33];
        enc_point[1..].copy_from_slice(enc.as_bytes());
        let mut keys = vec![public(&pbox), public(&pfrom), public(&secret(4))];
        keys.extend(PublicKey::from_bytes(&enc_point).ok());
        for key in keys {
            let proof = prove(&pairing.prover_address, &key, &binding).unwrap();
            assert!(!pairing.checks(&binding, &proof));
        }
        // And the holder of such a key, with the prover's public key only, makes no proof.
        let forged = prove(&pbox, &public(&pairing.prover_address), &binding).unwrap();
        assert!(!pairing.checks(&binding, &forged));
    }

    #[test]
    fn no_signature_by_the_address_key_passes_as_a_proof() {
        let pairing = pairing();
        let binding = pairing.binding(ProofStep::Confirm);
        let message = binding.message();
        let digest = lepic_crypto::Message::from(<[u8; 32]>::from(Sha256::digest(message)));
        let der = lepic_crypto::EcdsaSignature::sign(&digest, &pairing.prover_address)
            .unwrap()
            .to_der();
        for window in der.windows(32) {
            let candidate: [u8; 32] = window.try_into().unwrap();
            assert!(!pairing.checks(&binding, &candidate));
        }
    }

    #[test]
    fn a_card_without_an_address_or_a_missing_proof_proves_nothing() {
        let pairing = pairing();
        let proof = pairing.proof(ProofStep::Confirm);
        let bare = card(3, &public(&secret(4)), None);
        let binding = ProofBinding {
            prover_card: &bare,
            ..pairing.binding(ProofStep::Confirm)
        };
        assert!(!pairing.checks(&binding, &proof));
        assert!(
            proven(
                &pairing.verifier_box,
                Network::Floonet,
                &pairing.binding(ProofStep::Confirm),
                None
            )
            .is_none()
        );
    }
}
