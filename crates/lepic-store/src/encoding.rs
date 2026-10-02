//! Conversions between record fields and the column types both implementations agree on.

use jiff::Timestamp;

use crate::error::{Record, StoreError};

/// SQLite integers are signed. Unsigned values are stored with their bits unchanged so that the
/// whole `u64` range round-trips; values below `2^63` read the same in an SQL shell.
pub(crate) const fn u64_to_column(value: u64) -> i64 {
    i64::from_be_bytes(value.to_be_bytes())
}

pub(crate) const fn u64_from_column(value: i64) -> u64 {
    u64::from_be_bytes(value.to_be_bytes())
}

pub(crate) fn timestamp_to_column(time: Timestamp) -> Result<i64, StoreError> {
    i64::try_from(time.as_nanosecond()).map_err(|_| StoreError::OutOfRange { field: "timestamp" })
}

pub(crate) fn timestamp_from_column(
    value: i64,
    record: Record,
    field: &'static str,
) -> Result<Timestamp, StoreError> {
    Timestamp::from_nanosecond(i128::from(value)).map_err(|_| StoreError::Corrupt { record, field })
}

/// Declares a fieldless enum together with the stable text code it is stored as. Codes are part
/// of the schema: renaming a variant is fine, changing its code needs a migration.
macro_rules! stored_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $code:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            pub(crate) const fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),+
                }
            }

            pub(crate) fn from_code(code: &str) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

pub(crate) use stored_enum;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_values_round_trip_through_signed_columns() {
        for value in [0, 1, i64::MAX.unsigned_abs(), u64::MAX] {
            assert_eq!(u64_from_column(u64_to_column(value)), value);
        }
        assert_eq!(u64_to_column(42), 42);
    }

    #[test]
    fn timestamps_round_trip_with_nanosecond_precision() {
        let time = Timestamp::from_nanosecond(1_727_000_000_123_456_789).unwrap();
        let column = timestamp_to_column(time).unwrap();
        assert_eq!(
            timestamp_from_column(column, Record::Transaction, "created_at").unwrap(),
            time
        );
    }

    #[test]
    fn rejects_timestamp_beyond_column_range() {
        assert!(matches!(
            timestamp_to_column(Timestamp::MAX),
            Err(StoreError::OutOfRange { field: "timestamp" })
        ));
    }
}
