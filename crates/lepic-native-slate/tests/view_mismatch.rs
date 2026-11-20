// SPDX-License-Identifier: Apache-2.0
//! A view is accepted only when it is exactly what the slate it describes would render: a field
//! the view carries beyond what the slate fixes (`flags`, `kernel_features`, `header_version`) is
//! checked, and a spelling the slate would not produce is refused with `ViewMismatch`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use lepic_native_slate::{NativeError, NativeSlate, SlateView};
use proptest::prelude::*;
use serde_json::{Value, json};

fn view_of(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/slates_native")
        .join(format!("{name}.json"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vector["expected"]["view"].clone()
}

/// A slate that carries a time-to-live, so `flags` is not empty.
const NAME: &str = "send_file_ttl_s1_mainnet";

fn into_native(view: Value) -> Result<(), NativeError> {
    let view: SlateView = serde_json::from_value(view).unwrap();
    view.into_native().map(|_| ())
}

#[test]
fn the_recorded_view_is_accepted() {
    into_native(view_of(NAME)).unwrap();
}

#[test]
fn a_view_with_one_derived_field_changed_is_a_mismatch() {
    for (field, value) in [
        ("flags", json!([])),
        ("flags", json!(["ttl", "proof"])),
        ("kernel_features", json!("height_locked")),
        ("header_version", json!(7)),
        ("id", json!("0436430C-2B02-624C-2032-570501212B03")),
        ("height", json!("04")),
        ("amount", json!("0130000000")),
    ] {
        let mut view = view_of(NAME);
        view[field] = value.clone();
        let outcome = into_native(view);
        assert!(
            matches!(outcome, Err(NativeError::ViewMismatch)),
            "{field} = {value}: {outcome:?}"
        );
    }
}

proptest! {
    /// Any header version but the one the slate has is refused, whatever the number.
    #[test]
    fn another_header_version_is_never_accepted(version in any::<u16>()) {
        prop_assume!(version != 6);
        let mut view = view_of(NAME);
        view["header_version"] = json!(version);
        prop_assert!(into_native(view).is_err());
    }

    /// Whatever a view is accepted as, rendering that slate gives the same view back.
    #[test]
    fn an_accepted_view_renders_back_to_itself(fee in 1u64..1_000_000_000) {
        let mut view = view_of(NAME);
        view["fee"] = json!(fee.to_string());
        let view: SlateView = serde_json::from_value(view).unwrap();
        if let Ok((network, native)) = view.clone().into_native() {
            prop_assert_eq!(SlateView::new(network, &native), view);
            let _ = NativeSlate::decode(network, &native.encode(network)).unwrap();
        }
    }
}
