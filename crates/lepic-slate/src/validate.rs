//! Checks and field parsers shared by the codecs, so every legacy format applies the same rules
//! (`docs/compat/legacy-slates.md`, "Checks LEPIC performs on decode").

use lepic_crypto::hex;
use lepic_crypto::{Commitment, PublicKey, RangeProof, Signature};
use lepic_primitives::amount::Fee;
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::kernel::KernelFeatures;

use crate::codec::{MAX_WIRE_SLATE_LEN, WireSlate};
use crate::error::{DecodeError, FieldProblem, HexError, ValidationError};
use crate::model::{FinalKernel, KernelLock, ProofAddress, ProofSignature, SlateId};
use crate::role::Role;
use crate::stage::{Flow, Stage, Step};

/// Refuses input above [`MAX_WIRE_SLATE_LEN`] before any parsing.
pub fn check_size(wire: &WireSlate) -> Result<(), DecodeError> {
    let len = wire.len();
    if len > MAX_WIRE_SLATE_LEN {
        return Err(DecodeError::TooLarge {
            len,
            max: MAX_WIRE_SLATE_LEN,
        });
    }
    Ok(())
}

/// Lowercase hex, as upstream writes it.
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Exactly `2 * N` hex digits in either case.
pub fn decode_hex_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    hex::decode_array(text).map_err(HexError::from)
}

/// Between `min_bytes` and `max_bytes` bytes of hex in either case. The length is checked
/// before anything is allocated.
pub fn decode_hex_bounded(
    text: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, HexError> {
    hex::decode_bounded(text, min_bytes, max_bytes).map_err(HexError::from)
}

pub fn parse_slate_id(text: &str) -> Result<SlateId, FieldProblem> {
    SlateId::parse(text).map_err(FieldProblem::SlateId)
}

pub fn parse_offset(hex: &str) -> Result<BlindingFactor, FieldProblem> {
    decode_hex_array::<{ BlindingFactor::LEN }>(hex)
        .map(BlindingFactor::from_array)
        .map_err(FieldProblem::Hex)
}

pub fn parse_commitment(hex: &str) -> Result<Commitment, FieldProblem> {
    let bytes = decode_hex_array::<{ Commitment::LEN }>(hex).map_err(FieldProblem::Hex)?;
    Commitment::from_bytes(&bytes).map_err(FieldProblem::Crypto)
}

pub fn parse_public_key(hex: &str) -> Result<PublicKey, FieldProblem> {
    let bytes = decode_hex_array::<{ PublicKey::LEN }>(hex).map_err(FieldProblem::Hex)?;
    PublicKey::from_bytes(&bytes).map_err(FieldProblem::Crypto)
}

/// A signature in the 64-byte compact form JSON slates use.
pub fn parse_signature(hex: &str) -> Result<Signature, FieldProblem> {
    let bytes = decode_hex_array::<{ Signature::LEN }>(hex).map_err(FieldProblem::Hex)?;
    Signature::from_compact(&bytes).map_err(FieldProblem::Crypto)
}

pub fn parse_range_proof(hex: &str) -> Result<RangeProof, FieldProblem> {
    let bytes = decode_hex_bounded(hex, 1, RangeProof::MAX_LEN).map_err(FieldProblem::Hex)?;
    RangeProof::from_bytes(&bytes).map_err(FieldProblem::Crypto)
}

pub fn parse_proof_address(hex: &str) -> Result<ProofAddress, FieldProblem> {
    let bytes = decode_hex_array::<{ ProofAddress::LEN }>(hex).map_err(FieldProblem::Hex)?;
    ProofAddress::from_bytes(bytes).map_err(FieldProblem::ProofAddress)
}

pub fn parse_proof_signature(hex: &str) -> Result<ProofSignature, FieldProblem> {
    decode_hex_array::<{ ProofSignature::LEN }>(hex)
        .map(ProofSignature::from_bytes)
        .map_err(FieldProblem::Hex)
}

/// Participant count every legacy slate LEPIC accepts declares.
pub const LEGACY_PARTICIPANTS: u64 = 2;

/// Legacy slates number parties by role in both flows: the sender is 0 and the receiver 1.
/// In the invoice flow the receiver starts, so participant 1 comes first on the wire.
pub const fn legacy_participant_id(role: Role) -> u64 {
    match role {
        Role::Sender => 0,
        Role::Receiver => 1,
    }
}

pub fn role_from_legacy_id(id: u64) -> Result<Role, ValidationError> {
    match id {
        0 => Ok(Role::Sender),
        1 => Ok(Role::Receiver),
        _ => Err(ValidationError::ParticipantIdOutOfRange {
            id,
            declared: LEGACY_PARTICIPANTS,
        }),
    }
}

/// The declared count is two, there are no more entries than that, and every id is below the
/// count and unique.
pub fn check_participant_ids(declared: u64, ids: &[u64]) -> Result<(), ValidationError> {
    if declared != LEGACY_PARTICIPANTS {
        return Err(ValidationError::UnsupportedParticipantCount { declared });
    }
    if !u64::try_from(ids.len()).is_ok_and(|count| count <= declared) {
        return Err(ValidationError::TooManyParticipants {
            count: ids.len(),
            declared,
        });
    }
    for (position, &id) in ids.iter().enumerate() {
        if id >= declared {
            return Err(ValidationError::ParticipantIdOutOfRange { id, declared });
        }
        if ids.iter().take(position).any(|&earlier| earlier == id) {
            return Err(ValidationError::DuplicateParticipantId { id });
        }
    }
    Ok(())
}

/// The stage of a legacy slate from its participant entries in wire order, each as its role and
/// whether it carries a partial signature. Parties appear in the order they joined, so the
/// first entry is the initiator and names the flow.
pub fn legacy_stage(entries: &[(Role, bool)]) -> Result<Stage, ValidationError> {
    let (flow, step) = match entries {
        [(initiator, false)] => (flow_started_by(*initiator), Step::Proposed),
        [(initiator, false), (responder, true)] if initiator != responder => {
            (flow_started_by(*initiator), Step::Responded)
        }
        [(initiator, true), (responder, true)] if initiator != responder => {
            (flow_started_by(*initiator), Step::Finalized)
        }
        _ => return Err(ValidationError::UnrecognisedStage),
    };
    Ok(Stage::new(flow, step))
}

const fn flow_started_by(initiator: Role) -> Flow {
    match initiator {
        Role::Sender => Flow::Standard,
        Role::Receiver => Flow::Invoice,
    }
}

/// Exactly one kernel.
pub fn single_kernel<T>(kernels: &[T]) -> Result<&T, ValidationError> {
    match kernels {
        [kernel] => Ok(kernel),
        _ => Err(ValidationError::KernelCount {
            count: kernels.len(),
        }),
    }
}

/// The kernel's features agree with the slate's fee and lock height.
pub fn check_kernel_features(
    features: KernelFeatures,
    fee: Fee,
    lock: KernelLock,
) -> Result<(), ValidationError> {
    if features == KernelFeatures::Coinbase {
        return Err(ValidationError::CoinbaseKernel);
    }
    if features.fee() != fee {
        return Err(ValidationError::KernelFeeMismatch {
            slate: fee,
            kernel: features.fee(),
        });
    }
    if features != lock.kernel_features(fee) {
        return Err(ValidationError::KernelLockMismatch {
            slate: lock.lock_height(),
            kernel: features.lock_height().unwrap_or_default(),
        });
    }
    Ok(())
}

/// The kernel excess and signature as a legacy slate carries them: both all-zero before the
/// final stage, both valid at it. Whether the stage matches is the model's check.
pub fn kernel_from_wire(
    excess: &[u8; Commitment::LEN],
    excess_sig: &[u8; Signature::LEN],
) -> Result<Option<FinalKernel>, ValidationError> {
    let zero_excess = excess.iter().all(|&byte| byte == 0);
    let zero_sig = excess_sig.iter().all(|&byte| byte == 0);
    match (zero_excess, zero_sig) {
        (true, true) => Ok(None),
        (false, false) => Ok(Some(FinalKernel {
            excess: Commitment::from_bytes(excess).map_err(ValidationError::InvalidKernelExcess)?,
            excess_sig: Signature::from_compact(excess_sig)
                .map_err(ValidationError::InvalidKernelSignature)?,
        })),
        _ => Err(ValidationError::PartialKernelPlaceholder),
    }
}

/// The all-zero excess and signature legacy slates carry before the final stage.
pub const KERNEL_PLACEHOLDER: ([u8; Commitment::LEN], [u8; Signature::LEN]) =
    ([0; Commitment::LEN], [0; Signature::LEN]);

/// The fee covers the weight of the final transaction at `base_fee` per unit. The caller
/// supplies the counts of the final body, including parts the slate does not carry yet, and
/// the base fee of its network policy.
pub fn check_minimum_fee(
    fee: Fee,
    final_counts: BodyCounts,
    base_fee: Fee,
) -> Result<(), ValidationError> {
    let minimum = final_counts
        .tx_fee(base_fee)
        .map_err(|_| ValidationError::MinimumFeeOverflow)?;
    if fee < minimum {
        return Err(ValidationError::FeeBelowMinimum { fee, minimum });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lepic_primitives::amount::Height;

    use super::*;

    #[test]
    fn hex_round_trips_in_either_case() {
        let bytes = [0x00, 0x7f, 0xab, 0xff];
        assert_eq!(encode_hex(&bytes), "007fabff");
        assert_eq!(decode_hex_array::<4>("007FABff"), Ok(bytes));
        assert_eq!(decode_hex_bounded("007fabff", 1, 4), Ok(bytes.to_vec()));
    }

    #[test]
    fn rejects_hex_of_the_wrong_length() {
        assert_eq!(
            decode_hex_array::<2>("abc"),
            Err(HexError::WrongLength {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            decode_hex_bounded("abcdef", 1, 2),
            Err(HexError::LengthOutOfRange {
                min: 2,
                max: 4,
                actual: 6
            })
        );
        assert_eq!(
            decode_hex_bounded("", 1, 2),
            Err(HexError::LengthOutOfRange {
                min: 2,
                max: 4,
                actual: 0
            })
        );
        assert_eq!(decode_hex_bounded("abc", 1, 2), Err(HexError::OddLength));
    }

    #[test]
    fn rejects_characters_that_are_not_hex_digits() {
        for text in ["0g", "+f", " 1", "é"] {
            assert!(decode_hex_bounded(text, 1, 2).is_err(), "{text}");
        }
        assert_eq!(decode_hex_array::<1>("0g"), Err(HexError::InvalidDigit));
        assert_eq!(decode_hex_array::<1>("+f"), Err(HexError::InvalidDigit));
    }

    #[test]
    fn rejects_participant_count_other_than_two() {
        for declared in [0, 1, 3] {
            assert_eq!(
                check_participant_ids(declared, &[0]),
                Err(ValidationError::UnsupportedParticipantCount { declared })
            );
        }
    }

    #[test]
    fn rejects_more_participants_than_declared() {
        assert_eq!(
            check_participant_ids(2, &[0, 1, 1]),
            Err(ValidationError::TooManyParticipants {
                count: 3,
                declared: 2
            })
        );
    }

    #[test]
    fn rejects_participant_id_not_below_the_count() {
        assert_eq!(
            check_participant_ids(2, &[0, 2]),
            Err(ValidationError::ParticipantIdOutOfRange { id: 2, declared: 2 })
        );
        assert_eq!(
            role_from_legacy_id(2),
            Err(ValidationError::ParticipantIdOutOfRange { id: 2, declared: 2 })
        );
    }

    #[test]
    fn rejects_duplicate_participant_id() {
        assert_eq!(
            check_participant_ids(2, &[1, 1]),
            Err(ValidationError::DuplicateParticipantId { id: 1 })
        );
    }

    #[test]
    fn accepts_both_participant_orders() {
        assert_eq!(check_participant_ids(2, &[0, 1]), Ok(()));
        assert_eq!(check_participant_ids(2, &[1, 0]), Ok(()));
        assert_eq!(check_participant_ids(2, &[1]), Ok(()));
    }

    #[test]
    fn legacy_ids_map_to_roles_in_both_directions() {
        for role in Role::ALL {
            assert_eq!(role_from_legacy_id(legacy_participant_id(role)), Ok(role));
        }
    }

    #[test]
    fn legacy_stage_follows_join_order_and_signatures() {
        use Role::{Receiver, Sender};
        let cases = [
            (&[(Sender, false)][..], Stage::S1),
            (&[(Sender, false), (Receiver, true)][..], Stage::S2),
            (&[(Sender, true), (Receiver, true)][..], Stage::S3),
            (&[(Receiver, false)][..], Stage::I1),
            (&[(Receiver, false), (Sender, true)][..], Stage::I2),
            (&[(Receiver, true), (Sender, true)][..], Stage::I3),
        ];
        for (entries, stage) in cases {
            assert_eq!(legacy_stage(entries), Ok(stage));
        }
    }

    #[test]
    fn rejects_participant_arrangements_of_no_stage() {
        use Role::{Receiver, Sender};
        let cases: [&[(Role, bool)]; 6] = [
            &[],
            &[(Sender, true)],
            &[(Sender, false), (Receiver, false)],
            &[(Sender, true), (Receiver, false)],
            &[(Sender, false), (Sender, true)],
            &[(Sender, true), (Receiver, true), (Sender, true)],
        ];
        for entries in cases {
            assert_eq!(
                legacy_stage(entries),
                Err(ValidationError::UnrecognisedStage),
                "{entries:?}"
            );
        }
    }

    #[test]
    fn requires_exactly_one_kernel() {
        assert_eq!(single_kernel(&[7]), Ok(&7));
        assert_eq!(
            single_kernel::<u8>(&[]),
            Err(ValidationError::KernelCount { count: 0 })
        );
        assert_eq!(
            single_kernel(&[1, 2]),
            Err(ValidationError::KernelCount { count: 2 })
        );
    }

    #[test]
    fn kernel_features_must_match_fee_and_lock() {
        let fee = Fee::new(800_000);
        let lock = KernelLock::at_height(Height::new(10));
        assert_eq!(
            check_kernel_features(lock.kernel_features(fee), fee, lock),
            Ok(())
        );
        assert_eq!(
            check_kernel_features(KernelFeatures::Coinbase, fee, lock),
            Err(ValidationError::CoinbaseKernel)
        );
        assert_eq!(
            check_kernel_features(
                KernelFeatures::Plain { fee: Fee::new(1) },
                fee,
                KernelLock::NONE
            ),
            Err(ValidationError::KernelFeeMismatch {
                slate: fee,
                kernel: Fee::new(1)
            })
        );
        assert_eq!(
            check_kernel_features(KernelFeatures::Plain { fee }, fee, lock),
            Err(ValidationError::KernelLockMismatch {
                slate: Height::new(10),
                kernel: Height::ZERO
            })
        );
        assert_eq!(
            check_kernel_features(
                KernelFeatures::HeightLocked {
                    fee,
                    lock_height: Height::ZERO
                },
                fee,
                KernelLock::NONE
            ),
            Err(ValidationError::KernelLockMismatch {
                slate: Height::ZERO,
                kernel: Height::ZERO
            })
        );
    }

    #[test]
    fn kernel_placeholder_is_all_zero_or_fully_set() {
        let (zero_excess, zero_sig) = KERNEL_PLACEHOLDER;
        assert_eq!(kernel_from_wire(&zero_excess, &zero_sig), Ok(None));
        assert_eq!(
            kernel_from_wire(&zero_excess, &[1; 64]),
            Err(ValidationError::PartialKernelPlaceholder)
        );
        let mut excess = [0u8; 33];
        excess[0] = 8;
        excess[32] = 5;
        assert_eq!(
            kernel_from_wire(&excess, &zero_sig),
            Err(ValidationError::PartialKernelPlaceholder)
        );
        assert!(matches!(
            kernel_from_wire(&excess, &[1; 64]),
            Err(ValidationError::InvalidKernelExcess(_))
        ));
    }

    #[test]
    fn fee_must_cover_the_final_weight() {
        let counts = BodyCounts::new(1, 2, 1);
        let base = Fee::new(100_000);
        assert_eq!(check_minimum_fee(Fee::new(800_000), counts, base), Ok(()));
        assert_eq!(
            check_minimum_fee(Fee::new(799_999), counts, base),
            Err(ValidationError::FeeBelowMinimum {
                fee: Fee::new(799_999),
                minimum: Fee::new(800_000)
            })
        );
        assert_eq!(
            check_minimum_fee(Fee::new(1), counts, Fee::new(u64::MAX)),
            Err(ValidationError::MinimumFeeOverflow)
        );
    }

    #[test]
    fn rejects_size_above_the_limit() {
        let wire = WireSlate::binary(
            crate::codec::MediaType::JSON,
            vec![b' '; MAX_WIRE_SLATE_LEN + 1],
        );
        assert_eq!(
            check_size(&wire),
            Err(DecodeError::TooLarge {
                len: MAX_WIRE_SLATE_LEN + 1,
                max: MAX_WIRE_SLATE_LEN
            })
        );
    }
}
