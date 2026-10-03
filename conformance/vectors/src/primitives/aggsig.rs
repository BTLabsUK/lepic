//! Aggregate signatures through `core/src/libtx/aggsig.rs`, called in the order `epic-wallet`'s
//! slate code calls them for a two-party transaction: the sender subtracts the offset from its
//! excess, each party signs a partial signature over the nonce and key sums, each partial is
//! verified, and the sum is checked against the kernel excess.

use epic_core::core::hash::Hashed;
use epic_core::core::transaction::{KernelFeatures, TxKernel};
use epic_core::libtx::aggsig;
use epic_util::secp::key::{PublicKey, SecretKey};
use epic_util::secp::pedersen::Commitment;
use epic_util::secp::{Message, Secp256k1, Signature};
use serde::Serialize;

use super::AGGSIG_AREA;
use super::fixtures::{Features, ensure, public, public_hex, secp, secret, sig_hex};
use crate::{Error, Pins, Rendered, hex, render_from};

const MODULE: &str = "primitives/aggsig";

#[derive(Serialize)]
struct FlowInputs {
    features: Features,
    sender_excess: String,
    offset: String,
    sender_nonce: String,
    receiver_excess: String,
    receiver_nonce: String,
}

/// `kind` selects the call: `partial` is `verify_partial_sig`, `completed` is
/// `verify_completed_sig`, both through `aggsig::verify_single`.
#[derive(Serialize)]
struct Check {
    name: &'static str,
    kind: &'static str,
    sig: String,
    msg: String,
    pub_nonce_sum: Option<String>,
    pubkey: String,
    pubkey_sum: Option<String>,
    valid: bool,
}

#[derive(Serialize)]
struct CommitCheck {
    name: &'static str,
    sig: String,
    msg: String,
    commit: String,
    valid: bool,
}

/// `sender_excess_split` is the sender's excess less the offset, the key it signs with.
#[derive(Serialize)]
struct FlowExpected {
    sig_msg: String,
    sender_excess_split: String,
    sender_public_excess: String,
    sender_public_nonce: String,
    receiver_public_excess: String,
    receiver_public_nonce: String,
    public_nonce_sum: String,
    public_excess_sum: String,
    receiver_partial_sig: String,
    sender_partial_sig: String,
    final_sig: String,
    kernel_excess: String,
    kernel_serialized_v2: String,
    checks: Vec<Check>,
    commit_checks: Vec<CommitCheck>,
}

struct Party {
    excess: SecretKey,
    nonce: SecretKey,
    public_excess: PublicKey,
    public_nonce: PublicKey,
}

impl Party {
    fn new(secp: &Secp256k1, excess: SecretKey, nonce: &[u8; 32]) -> Result<Party, Error> {
        let nonce = secret(secp, nonce)?;
        Ok(Party {
            public_excess: public(secp, &excess)?,
            public_nonce: public(secp, &nonce)?,
            excess,
            nonce,
        })
    }
}

fn sum(secp: &Secp256k1, keys: Vec<&PublicKey>) -> Result<PublicKey, Error> {
    PublicKey::from_combination(secp, keys).map_err(Error::reference("public key sum"))
}

struct Verifier<'a> {
    secp: &'a Secp256k1,
    checks: Vec<Check>,
}

impl Verifier<'_> {
    #[allow(clippy::too_many_arguments)] // mirrors the upstream verify_single parameters
    fn check(
        &mut self,
        name: &'static str,
        sig: &Signature,
        msg: &Message,
        pub_nonce_sum: Option<&PublicKey>,
        pubkey: &PublicKey,
        pubkey_sum: Option<&PublicKey>,
        partial: bool,
        expect_valid: bool,
    ) -> Result<(), Error> {
        let valid = aggsig::verify_single(
            self.secp,
            sig,
            msg,
            pub_nonce_sum,
            pubkey,
            pubkey_sum,
            partial,
        );
        ensure(valid == expect_valid, name)?;
        self.checks.push(Check {
            name,
            kind: if partial { "partial" } else { "completed" },
            sig: sig_hex(self.secp, sig),
            msg: hex(msg),
            pub_nonce_sum: pub_nonce_sum.map(|key| public_hex(self.secp, key)),
            pubkey: public_hex(self.secp, pubkey),
            pubkey_sum: pubkey_sum.map(|key| public_hex(self.secp, key)),
            valid,
        });
        Ok(())
    }
}

fn commit_check(
    secp: &Secp256k1,
    name: &'static str,
    sig: &Signature,
    msg: &Message,
    commit: &Commitment,
    expect_valid: bool,
) -> Result<CommitCheck, Error> {
    let valid = aggsig::verify_single_from_commit(secp, sig, msg, commit).is_ok();
    ensure(valid == expect_valid, name)?;
    Ok(CommitCheck {
        name,
        sig: sig_hex(secp, sig),
        msg: hex(msg),
        commit: hex(commit),
        valid,
    })
}

fn other_message(features: KernelFeatures) -> Result<Message, Error> {
    let other = match features {
        KernelFeatures::Plain { fee } => KernelFeatures::Plain {
            fee: fee.wrapping_add(1),
        },
        KernelFeatures::HeightLocked { fee, lock_height } => KernelFeatures::HeightLocked {
            fee,
            lock_height: lock_height.wrapping_add(1),
        },
        KernelFeatures::Coinbase => KernelFeatures::Plain { fee: 0 },
    };
    other
        .kernel_sig_msg()
        .map_err(Error::reference("other message"))
}

struct Flow {
    name: &'static str,
    features: KernelFeatures,
    sender_excess: [u8; 32],
    offset: [u8; 32],
    sender_nonce: [u8; 32],
    receiver_excess: [u8; 32],
    receiver_nonce: [u8; 32],
}

fn two_party(pins: &Pins, flow: &Flow) -> Result<Rendered, Error> {
    let secp = secp();
    let msg = flow
        .features
        .kernel_sig_msg()
        .map_err(Error::reference("kernel signature message"))?;
    let wrong_msg = other_message(flow.features)?;

    let split = secp
        .blind_sum(
            vec![secret(&secp, &flow.sender_excess)?],
            vec![secret(&secp, &flow.offset)?],
        )
        .map_err(Error::reference("offset split"))?;
    let sender = Party::new(&secp, split, &flow.sender_nonce)?;
    let receiver = Party::new(
        &secp,
        secret(&secp, &flow.receiver_excess)?,
        &flow.receiver_nonce,
    )?;
    let nonce_sum = sum(&secp, vec![&sender.public_nonce, &receiver.public_nonce])?;
    let excess_sum = sum(&secp, vec![&sender.public_excess, &receiver.public_excess])?;

    let partial = |party: &Party| {
        aggsig::calculate_partial_sig(
            &secp,
            &party.excess,
            &party.nonce,
            &nonce_sum,
            Some(&excess_sum),
            &msg,
        )
        .map_err(Error::reference("partial signature"))
    };
    let receiver_sig = partial(&receiver)?;
    aggsig::verify_partial_sig(
        &secp,
        &receiver_sig,
        &nonce_sum,
        &receiver.public_excess,
        Some(&excess_sum),
        &msg,
    )
    .map_err(Error::reference("receiver partial verification"))?;
    let sender_sig = partial(&sender)?;
    aggsig::verify_partial_sig(
        &secp,
        &sender_sig,
        &nonce_sum,
        &sender.public_excess,
        Some(&excess_sum),
        &msg,
    )
    .map_err(Error::reference("sender partial verification"))?;
    let final_sig = aggsig::add_signatures(&secp, vec![&sender_sig, &receiver_sig], &nonce_sum)
        .map_err(Error::reference("signature aggregation"))?;
    aggsig::verify_completed_sig(&secp, &final_sig, &excess_sum, Some(&excess_sum), &msg)
        .map_err(Error::reference("final signature verification"))?;

    let excess_key = secp
        .blind_sum(vec![sender.excess.clone(), receiver.excess.clone()], vec![])
        .map_err(Error::reference("excess sum"))?;
    let kernel_excess = secp
        .commit(0, excess_key)
        .map_err(Error::reference("kernel excess"))?;
    let excess_pubkey = kernel_excess
        .to_pubkey(&secp)
        .map_err(Error::reference("excess as public key"))?;
    ensure(
        excess_pubkey == excess_sum,
        "kernel excess is the public excess sum",
    )?;
    let kernel = TxKernel {
        features: flow.features,
        excess: kernel_excess,
        excess_sig: final_sig,
    };
    kernel
        .verify()
        .map_err(Error::reference("kernel verification"))?;
    let kernel_serialized_v2 = epic_core::ser::ser_vec(&kernel, epic_core::ser::ProtocolVersion(2))
        .map_err(Error::reference("kernel layout"))?;

    // Summing the partials over the receiver's nonce alone instead of the nonce sum.
    let misaggregated = aggsig::add_signatures(
        &secp,
        vec![&sender_sig, &receiver_sig],
        &receiver.public_nonce,
    )
    .map_err(Error::reference(
        "signature aggregation over the wrong nonce",
    ))?;

    let mut v = Verifier {
        secp: &secp,
        checks: Vec::new(),
    };
    let (rx, sx) = (&receiver.public_excess, &sender.public_excess);
    let (n, x) = (Some(&nonce_sum), Some(&excess_sum));
    v.check(
        "receiver_partial",
        &receiver_sig,
        &msg,
        n,
        rx,
        x,
        true,
        true,
    )?;
    v.check("sender_partial", &sender_sig, &msg, n, sx, x, true, true)?;
    v.check(
        "receiver_partial_with_sender_key",
        &receiver_sig,
        &msg,
        n,
        sx,
        x,
        true,
        false,
    )?;
    v.check(
        "receiver_partial_with_own_nonce_only",
        &receiver_sig,
        &msg,
        Some(&receiver.public_nonce),
        rx,
        x,
        true,
        false,
    )?;
    v.check(
        "receiver_partial_other_message",
        &receiver_sig,
        &wrong_msg,
        n,
        rx,
        x,
        true,
        false,
    )?;
    v.check(
        "receiver_partial_with_own_key_as_sum",
        &receiver_sig,
        &msg,
        n,
        rx,
        Some(rx),
        true,
        false,
    )?;
    v.check("final", &final_sig, &msg, None, &excess_sum, x, false, true)?;
    v.check(
        "final_other_message",
        &final_sig,
        &wrong_msg,
        None,
        &excess_sum,
        x,
        false,
        false,
    )?;
    v.check(
        "final_with_receiver_key",
        &final_sig,
        &msg,
        None,
        rx,
        Some(rx),
        false,
        false,
    )?;
    v.check(
        "partial_as_final",
        &receiver_sig,
        &msg,
        None,
        &excess_sum,
        x,
        false,
        false,
    )?;
    v.check(
        "final_aggregated_over_wrong_nonce",
        &misaggregated,
        &msg,
        None,
        &excess_sum,
        x,
        false,
        false,
    )?;

    let other_commit = secp
        .commit(0, sender.excess.clone())
        .map_err(Error::reference("other commitment"))?;
    let commit_checks = vec![
        commit_check(
            &secp,
            "final_against_excess",
            &final_sig,
            &msg,
            &kernel_excess,
            true,
        )?,
        commit_check(
            &secp,
            "final_other_message",
            &final_sig,
            &wrong_msg,
            &kernel_excess,
            false,
        )?,
        commit_check(
            &secp,
            "final_against_sender_commit",
            &final_sig,
            &msg,
            &other_commit,
            false,
        )?,
    ];

    let inputs = FlowInputs {
        features: Features::from(&flow.features),
        sender_excess: hex(flow.sender_excess),
        offset: hex(flow.offset),
        sender_nonce: hex(flow.sender_nonce),
        receiver_excess: hex(flow.receiver_excess),
        receiver_nonce: hex(flow.receiver_nonce),
    };
    let expected = FlowExpected {
        sig_msg: hex(msg),
        sender_excess_split: hex(sender.excess.0),
        sender_public_excess: public_hex(&secp, &sender.public_excess),
        sender_public_nonce: public_hex(&secp, &sender.public_nonce),
        receiver_public_excess: public_hex(&secp, &receiver.public_excess),
        receiver_public_nonce: public_hex(&secp, &receiver.public_nonce),
        public_nonce_sum: public_hex(&secp, &nonce_sum),
        public_excess_sum: public_hex(&secp, &excess_sum),
        receiver_partial_sig: sig_hex(&secp, &receiver_sig),
        sender_partial_sig: sig_hex(&secp, &sender_sig),
        final_sig: sig_hex(&secp, &final_sig),
        kernel_excess: hex(kernel_excess),
        kernel_serialized_v2: hex(kernel_serialized_v2),
        checks: v.checks,
        commit_checks,
    };
    render_from(MODULE, AGGSIG_AREA, flow.name, &pins.node, inputs, expected)
}

#[derive(Serialize)]
struct SingleInputs {
    key: String,
    nonce: String,
    /// The signed message is BLAKE2b-256 of this text, as participant messages are signed.
    text: String,
    /// Whether the signer commits to its own public key in the challenge.
    pubkey_for_e: bool,
}

#[derive(Serialize)]
struct SingleExpected {
    msg: String,
    pubkey: String,
    sig: String,
    checks: Vec<Check>,
}

struct Single {
    name: &'static str,
    key: [u8; 32],
    nonce: [u8; 32],
    text: &'static str,
    pubkey_for_e: bool,
}

fn single_signer(pins: &Pins, case: &Single) -> Result<Rendered, Error> {
    let secp = secp();
    let key = secret(&secp, &case.key)?;
    let pubkey = public(&secp, &key)?;
    let nonce = secret(&secp, &case.nonce)?;
    let digest = case.text.as_bytes().to_vec().hash();
    let msg = Message::from_slice(digest.as_bytes()).map_err(Error::reference("message"))?;
    let other_digest = format!("{}.", case.text).into_bytes().hash();
    let other_msg =
        Message::from_slice(other_digest.as_bytes()).map_err(Error::reference("other message"))?;
    let other_key = public(&secp, &secret(&secp, &[0x7e; 32])?)?;
    let e_key = case.pubkey_for_e.then_some(&pubkey);
    let sig = aggsig::sign_single(&secp, &msg, &key, Some(&nonce), e_key)
        .map_err(Error::reference("single-signer signature"))?;

    let mut v = Verifier {
        secp: &secp,
        checks: Vec::new(),
    };
    let other_e_key = if case.pubkey_for_e {
        None
    } else {
        Some(&pubkey)
    };
    v.check("as_signed", &sig, &msg, None, &pubkey, e_key, false, true)?;
    v.check(
        "other_message",
        &sig,
        &other_msg,
        None,
        &pubkey,
        e_key,
        false,
        false,
    )?;
    v.check(
        "other_key",
        &sig,
        &msg,
        None,
        &other_key,
        e_key,
        false,
        false,
    )?;
    v.check(
        "other_challenge_key",
        &sig,
        &msg,
        None,
        &pubkey,
        other_e_key,
        false,
        false,
    )?;

    let inputs = SingleInputs {
        key: hex(case.key),
        nonce: hex(case.nonce),
        text: case.text.to_owned(),
        pubkey_for_e: case.pubkey_for_e,
    };
    let expected = SingleExpected {
        msg: hex(msg),
        pubkey: public_hex(&secp, &pubkey),
        sig: sig_hex(&secp, &sig),
        checks: v.checks,
    };
    render_from(MODULE, AGGSIG_AREA, case.name, &pins.node, inputs, expected)
}

#[derive(Serialize)]
struct RuleInputs {
    key: String,
    nonce: String,
    msg: String,
}

/// One signature and the verdicts of the three upstream checks that differ in what they require
/// of the nonce: `partial` is `verify_partial_sig` against `nonce_sum`, `completed` is
/// `verify_completed_sig` (X coordinate only), `kernel` is `verify_single_from_commit` against
/// the key's commitment (X coordinate and a square Y), as the node verifies kernels.
#[derive(Serialize)]
struct RuleCase {
    name: &'static str,
    sig: String,
    msg: String,
    nonce_sum: String,
    partial: bool,
    completed: bool,
    kernel: bool,
}

#[derive(Serialize)]
struct RuleExpected {
    pubkey: String,
    public_nonce: String,
    commit: String,
    cases: Vec<RuleCase>,
}

struct RuleCheck<'a> {
    secp: &'a Secp256k1,
    pubkey: &'a PublicKey,
    commit: &'a Commitment,
    cases: Vec<RuleCase>,
}

impl RuleCheck<'_> {
    fn case(
        &mut self,
        name: &'static str,
        sig: &Signature,
        msg: &Message,
        nonce_sum: &PublicKey,
        expect: [bool; 3],
    ) -> Result<(), Error> {
        let (secp, pubkey) = (self.secp, self.pubkey);
        let partial =
            aggsig::verify_partial_sig(secp, sig, nonce_sum, pubkey, Some(pubkey), msg).is_ok();
        let completed = aggsig::verify_completed_sig(secp, sig, pubkey, Some(pubkey), msg).is_ok();
        let kernel = aggsig::verify_single_from_commit(secp, sig, msg, self.commit).is_ok();
        ensure([partial, completed, kernel] == expect, name)?;
        self.cases.push(RuleCase {
            name,
            sig: sig_hex(secp, sig),
            msg: hex(msg),
            nonce_sum: public_hex(secp, nonce_sum),
            partial,
            completed,
            kernel,
        });
        Ok(())
    }
}

/// A one-party share whose nonce sum is the negation of its own public nonce verifies as a
/// partial, and its nonce point has the signature's X coordinate but not a square Y. Upstream's
/// `verify_completed_sig` checks X only and accepts it; kernel verification rejects it.
fn completed_and_kernel_rules(pins: &Pins) -> Result<Rendered, Error> {
    const KEY: [u8; 32] = [0x66; 32];
    const NONCE: [u8; 32] = [0x68; 32];
    const MSG: [u8; 32] = [0x67; 32];
    let secp = secp();
    let key = secret(&secp, &KEY)?;
    let pubkey = public(&secp, &key)?;
    let nonce = secret(&secp, &NONCE)?;
    let negated = secp
        .blind_sum(vec![], vec![nonce.clone()])
        .map_err(Error::reference("nonce negation"))?;
    let (public_nonce, public_negated) = (public(&secp, &nonce)?, public(&secp, &negated)?);
    let msg = Message::from_slice(&MSG).map_err(Error::reference("message"))?;
    let other_msg = other_fixed_message(&MSG)?;
    let commit = secp
        .commit(0, key.clone())
        .map_err(Error::reference("key commitment"))?;
    let share = |nonce: &SecretKey, nonce_sum: &PublicKey| {
        aggsig::calculate_partial_sig(&secp, &key, nonce, nonce_sum, Some(&pubkey), &msg)
            .map_err(Error::reference("one-party share"))
    };
    let complete = aggsig::sign_single(&secp, &msg, &key, Some(&nonce), Some(&pubkey))
        .map_err(Error::reference("complete signature"))?;

    let mut rules = RuleCheck {
        secp: &secp,
        pubkey: &pubkey,
        commit: &commit,
        cases: Vec::new(),
    };
    let accepted = [true, true, true];
    let x_only = [true, true, false];
    let rejected = [false, false, false];
    rules.case(
        "share_over_negated_nonce",
        &share(&nonce, &public_negated)?,
        &msg,
        &public_negated,
        x_only,
    )?;
    rules.case(
        "negated_share_over_nonce",
        &share(&negated, &public_nonce)?,
        &msg,
        &public_nonce,
        x_only,
    )?;
    rules.case(
        "complete_signature",
        &complete,
        &msg,
        &public_nonce,
        accepted,
    )?;
    rules.case(
        "complete_signature_other_message",
        &complete,
        &other_msg,
        &public_nonce,
        rejected,
    )?;

    let inputs = RuleInputs {
        key: hex(KEY),
        nonce: hex(NONCE),
        msg: hex(MSG),
    };
    let expected = RuleExpected {
        pubkey: public_hex(&secp, &pubkey),
        public_nonce: public_hex(&secp, &public_nonce),
        commit: hex(commit),
        cases: rules.cases,
    };
    render_from(
        MODULE,
        AGGSIG_AREA,
        "completed_and_kernel_rules",
        &pins.node,
        inputs,
        expected,
    )
}

fn other_fixed_message(msg: &[u8; 32]) -> Result<Message, Error> {
    let mut other = *msg;
    if let Some(last) = other.last_mut() {
        *last ^= 1;
    }
    Message::from_slice(&other).map_err(Error::reference("other message"))
}

pub(crate) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    let flows = [
        Flow {
            name: "two_party_plain",
            features: KernelFeatures::Plain { fee: 800_000 },
            sender_excess: [0x51; 32],
            offset: [0x52; 32],
            sender_nonce: [0x53; 32],
            receiver_excess: [0x61; 32],
            receiver_nonce: [0x62; 32],
        },
        Flow {
            name: "two_party_height_locked",
            features: KernelFeatures::HeightLocked {
                fee: 1_100_000,
                lock_height: 1_000_000,
            },
            sender_excess: [0x54; 32],
            offset: [0x55; 32],
            sender_nonce: [0x56; 32],
            receiver_excess: [0x63; 32],
            receiver_nonce: [0x64; 32],
        },
    ];
    // epic-wallet signs participant messages with the nonce [1; 32] in test-RNG mode.
    let singles = [
        Single {
            name: "single_signer_message",
            key: [0x71; 32],
            nonce: [0x01; 32],
            text: "lepic participant message",
            pubkey_for_e: true,
        },
        Single {
            name: "single_signer_without_pubkey_in_challenge",
            key: [0x72; 32],
            nonce: [0x73; 32],
            text: "lepic plain schnorr",
            pubkey_for_e: false,
        },
    ];
    let mut rendered = Vec::new();
    for flow in &flows {
        rendered.push(two_party(pins, flow)?);
    }
    for single in &singles {
        rendered.push(single_signer(pins, single)?);
    }
    rendered.push(completed_and_kernel_rules(pins)?);
    Ok(rendered)
}
