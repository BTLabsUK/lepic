use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::ser::{ProtocolVersion, deserialize, ser_vec};
use proptest::prelude::*;

#[test]
fn amount_arithmetic_is_checked() {
    assert_eq!(
        Amount::new(2).checked_add(Amount::new(3)),
        Ok(Amount::new(5))
    );
    assert_eq!(
        Amount::new(u64::MAX).checked_add(Amount::new(1)),
        Err(ArithmeticError::Overflow)
    );
    assert_eq!(Amount::new(3).checked_sub(Amount::new(3)), Ok(Amount::ZERO));
    assert_eq!(
        Amount::new(2).checked_sub(Amount::new(3)),
        Err(ArithmeticError::Underflow)
    );
}

#[test]
fn fee_arithmetic_is_checked() {
    assert_eq!(Fee::new(2).checked_add(Fee::new(3)), Ok(Fee::new(5)));
    assert_eq!(
        Fee::new(u64::MAX).checked_add(Fee::new(1)),
        Err(ArithmeticError::Overflow)
    );
    assert_eq!(
        Fee::ZERO.checked_sub(Fee::new(1)),
        Err(ArithmeticError::Underflow)
    );
    assert_eq!(Fee::new(9).to_amount(), Amount::new(9));
}

#[test]
fn height_arithmetic_is_checked() {
    assert_eq!(Height::new(10).checked_add_blocks(5), Ok(Height::new(15)));
    assert_eq!(
        Height::new(u64::MAX).checked_add_blocks(1),
        Err(ArithmeticError::Overflow)
    );
    assert_eq!(Height::new(10).checked_sub_blocks(10), Ok(Height::ZERO));
    assert_eq!(
        Height::new(10).checked_sub_blocks(11),
        Err(ArithmeticError::Underflow)
    );
}

#[test]
fn tx_weight_never_drops_below_one() {
    assert_eq!(BodyCounts::new(0, 0, 0).tx_weight(), 1);
    assert_eq!(BodyCounts::new(100, 1, 1).tx_weight(), 1);
    assert_eq!(BodyCounts::new(1, 2, 1).tx_weight(), 8);
}

#[test]
fn weights_saturate_instead_of_overflowing() {
    let huge = BodyCounts::new(0, u64::MAX, u64::MAX);
    assert_eq!(huge.tx_weight(), u64::MAX);
    assert_eq!(huge.weight_as_block(), u64::MAX);
}

#[test]
fn rejects_fee_that_overflows() {
    assert_eq!(
        BodyCounts::new(0, u64::MAX / 4, 0).tx_fee(Fee::new(5)),
        Err(ArithmeticError::Overflow)
    );
}

#[test]
fn fee_is_weight_times_base_fee() {
    assert_eq!(
        BodyCounts::new(1, 2, 1).tx_fee(Fee::new(100_000)),
        Ok(Fee::new(800_000))
    );
}

proptest! {
    #[test]
    fn base_unit_types_round_trip(value in any::<u64>()) {
        for version in [ProtocolVersion::V1, ProtocolVersion::V2] {
            let fee = Fee::new(value);
            prop_assert_eq!(deserialize::<Fee>(&ser_vec(&fee, version), version), Ok(fee));
            let amount = Amount::new(value);
            prop_assert_eq!(
                deserialize::<Amount>(&ser_vec(&amount, version), version),
                Ok(amount)
            );
            let height = Height::new(value);
            prop_assert_eq!(
                deserialize::<Height>(&ser_vec(&height, version), version),
                Ok(height)
            );
            prop_assert_eq!(ser_vec(&fee, version), value.to_be_bytes());
        }
    }
}
