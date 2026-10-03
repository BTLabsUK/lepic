//! JSON arrays read with a cap on the elements kept, so the memory a decode spends is bounded by
//! the counts a legacy slate may have, not by the length of the input. Elements past the cap are
//! skipped unparsed but counted, so the count checks refuse the slate exactly as they would have
//! with every element kept.

use std::fmt;
use std::marker::PhantomData;

use lepic_primitives::params::{BLOCK_INPUT_WEIGHT, BLOCK_OUTPUT_WEIGHT, MAX_TX_WEIGHT};
use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};

use crate::error::ValidationError;
use crate::validate::{LEGACY_PARTICIPANTS, check_participant_ids, single_kernel};

/// The elements of a JSON array up to a cap, and how many the array had.
pub(crate) struct Bounded<T> {
    kept: Vec<T>,
    len: usize,
}

impl<T> Bounded<T> {
    /// The leading elements, all of them unless [`Self::len`] is larger.
    pub(crate) fn kept(&self) -> &[T] {
        &self.kept
    }

    /// The number of elements in the array, kept or skipped.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    const fn is_truncated(&self) -> bool {
        self.len > self.kept.len()
    }
}

/// `participant_data`: more than two entries is refused.
pub(crate) fn participants<'de, D, T>(deserializer: D) -> Result<Option<Bounded<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    optional_bounded(
        deserializer,
        usize::try_from(LEGACY_PARTICIPANTS).unwrap_or(usize::MAX),
    )
}

/// `tx.body.kernels`: anything but one kernel is refused.
pub(crate) fn kernels<'de, D, T>(deserializer: D) -> Result<Option<Bounded<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    optional_bounded(deserializer, 1)
}

/// `tx.body.inputs`: more than the weight limit spent on inputs alone is refused.
pub(crate) fn inputs<'de, D, T>(deserializer: D) -> Result<Option<Bounded<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    optional_bounded(deserializer, weight_cap(BLOCK_INPUT_WEIGHT))
}

/// `tx.body.outputs`: more than the weight limit spent on outputs alone is refused.
pub(crate) fn outputs<'de, D, T>(deserializer: D) -> Result<Option<Bounded<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    optional_bounded(deserializer, weight_cap(BLOCK_OUTPUT_WEIGHT))
}

/// The most elements of one weight that fit the transaction weight limit. Any count above it
/// exceeds the limit on its own, so the body weight check refuses a truncated array.
fn weight_cap(element_weight: u64) -> usize {
    MAX_TX_WEIGHT
        .checked_div(element_weight)
        .and_then(|count| usize::try_from(count).ok())
        .unwrap_or(usize::MAX)
}

/// [`check_participant_ids`] over the kept ids, refusing a truncated array with the count it had.
pub(crate) fn check_participants<T>(
    declared: u64,
    participants: &Bounded<T>,
    kept_ids: &[u64],
) -> Result<(), ValidationError> {
    if participants.is_truncated() {
        // An unsupported declared count is reported first, as for a complete array.
        check_participant_ids(declared, &[])?;
        return Err(ValidationError::TooManyParticipants {
            count: participants.len(),
            declared,
        });
    }
    check_participant_ids(declared, kept_ids)
}

/// [`single_kernel`], refusing a truncated array with the count it had.
pub(crate) fn only_kernel<T>(kernels: &Bounded<T>) -> Result<&T, ValidationError> {
    if kernels.is_truncated() {
        return Err(ValidationError::KernelCount {
            count: kernels.len(),
        });
    }
    single_kernel(kernels.kept())
}

/// `null` reads as `None`, as it does for `Option<Vec<T>>`.
fn optional_bounded<'de, D, T>(deserializer: D, cap: usize) -> Result<Option<Bounded<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_option(OptionVisitor {
        cap,
        element: PhantomData,
    })
}

struct OptionVisitor<T> {
    cap: usize,
    element: PhantomData<T>,
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for OptionVisitor<T> {
    type Value = Option<Bounded<T>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array or null")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer
            .deserialize_seq(SeqVisitor {
                cap: self.cap,
                element: PhantomData,
            })
            .map(Some)
    }
}

struct SeqVisitor<T> {
    cap: usize,
    element: PhantomData<T>,
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for SeqVisitor<T> {
    type Value = Bounded<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bounded<T>, A::Error> {
        let mut kept = Vec::new();
        while kept.len() < self.cap {
            match seq.next_element::<T>()? {
                Some(element) => kept.push(element),
                None => {
                    let len = kept.len();
                    return Ok(Bounded { kept, len });
                }
            }
        }
        let mut len = kept.len();
        while seq.next_element::<IgnoredAny>()?.is_some() {
            len = len.saturating_add(1);
        }
        Ok(Bounded { kept, len })
    }
}

#[cfg(test)]
mod tests {
    use lepic_primitives::fee::BodyCounts;

    use super::*;

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Wire {
        #[serde(deserialize_with = "kernels")]
        kernels: Option<Bounded<u8>>,
    }

    fn read(json: &str) -> Option<Bounded<u8>> {
        serde_json::from_str::<Wire>(json).unwrap().kernels
    }

    #[test]
    fn keeps_elements_up_to_the_cap_and_counts_the_rest() {
        let kernels = read(r#"{"kernels":[7,"skipped",{"also":["skipped"]}]}"#).unwrap();
        assert_eq!(kernels.kept(), [7]);
        assert_eq!(kernels.len(), 3);
        assert!(kernels.is_truncated());
    }

    #[test]
    fn keeps_every_element_of_an_array_within_the_cap() {
        let kernels = read(r#"{"kernels":[7]}"#).unwrap();
        assert_eq!((kernels.kept(), kernels.len()), (&[7][..], 1));
        let empty = read(r#"{"kernels":[]}"#).unwrap();
        assert_eq!((empty.kept(), empty.len()), (&[][..], 0));
    }

    #[test]
    fn reads_null_and_an_absent_key_as_none() {
        assert!(read(r#"{"kernels":null}"#).is_none());
        assert!(read("{}").is_none());
    }

    #[test]
    fn refuses_a_value_that_is_not_an_array() {
        for json in [
            r#"{"kernels":5}"#,
            r#"{"kernels":{}}"#,
            r#"{"kernels":[300]}"#,
        ] {
            assert!(serde_json::from_str::<Wire>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn any_count_above_a_weight_cap_exceeds_the_weight_limit() {
        let input_cap = u64::try_from(weight_cap(BLOCK_INPUT_WEIGHT)).unwrap();
        let output_cap = u64::try_from(weight_cap(BLOCK_OUTPUT_WEIGHT)).unwrap();
        assert!(BodyCounts::new(input_cap, 0, 0).weight_as_block() <= MAX_TX_WEIGHT);
        assert!(BodyCounts::new(input_cap + 1, 0, 0).weight_as_block() > MAX_TX_WEIGHT);
        assert!(BodyCounts::new(0, output_cap, 0).weight_as_block() <= MAX_TX_WEIGHT);
        assert!(BodyCounts::new(0, output_cap + 1, 0).weight_as_block() > MAX_TX_WEIGHT);
    }
}
