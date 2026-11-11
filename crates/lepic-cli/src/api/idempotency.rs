// SPDX-License-Identifier: Apache-2.0
//! Idempotent creates. A create names its object with a caller-chosen `id` (a payment's is its
//! slate id). The first call records the digest of its body in the store; a repeat with the same
//! body answers 200 with the object as it is now, one with another body 409
//! `idempotency_mismatch`. While a call with an id is answered, another with the same id gets 409
//! `in_progress`.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::problem::Problem;

/// The record a call wrote for its create: `(scope, id)`.
pub(crate) type Fresh = Rc<RefCell<Option<(&'static str, String)>>>;

tokio::task_local! {
    /// Set around each operation by [`track`]; [`begin`](crate::commands::serve) notes in it
    /// the record it wrote.
    static FRESH: Fresh;
}

/// Runs `call` with a slot for the record it writes, and returns its output with the slot.
pub(crate) async fn track<T>(
    call: impl std::future::Future<Output = T>,
) -> (T, Option<(&'static str, String)>) {
    let slot = Fresh::default();
    let out = FRESH.scope(slot.clone(), call).await;
    let record = slot.borrow_mut().take();
    (out, record)
}

/// Notes that this call wrote the record `(scope, id)`.
pub(crate) fn note_fresh(scope: &'static str, id: &str) {
    let _ = FRESH.try_with(|slot| *slot.borrow_mut() = Some((scope, id.to_owned())));
}

/// Whether an error answer means the create made nothing, so its record can go. A 500 or 503
/// may come after the object was made, so those keep the record.
pub(crate) fn made_nothing(problem: &Problem) -> bool {
    let status = problem.status();
    status.is_client_error() || status == hyper::StatusCode::BAD_GATEWAY
}

/// The scopes of the creates: what each creates.
pub(crate) const PAYMENT: &str = "payment";
pub(crate) const ADDRESS: &str = "address";
pub(crate) const LINK: &str = "link";
pub(crate) const CONTACT: &str = "contact";

/// The digest of a create's body: SHA-256 of its JSON with object keys sorted, so the same
/// request in another key order or spacing has the same digest.
pub(crate) fn digest(body: &Value) -> [u8; 32] {
    // `serde_json::Map` keeps keys sorted (no `preserve_order`), and serializing a `Value`
    // cannot fail.
    let canonical = serde_json::to_vec(body).unwrap_or_default();
    Sha256::digest(canonical).into()
}

/// The creates being answered, by scope and id.
#[derive(Debug, Default)]
pub(crate) struct InProgress(RefCell<HashSet<(&'static str, String)>>);

impl InProgress {
    /// Marks `(scope, id)` as being answered until the guard drops; 409 `in_progress` if it
    /// already is.
    pub(crate) fn start(&self, scope: &'static str, id: &str) -> Result<Started<'_>, Problem> {
        let key = (scope, id.to_owned());
        if !self.0.borrow_mut().insert(key.clone()) {
            return Err(Problem::in_progress());
        }
        Ok(Started { set: self, key })
    }
}

/// Holds a create as in progress.
#[derive(Debug)]
pub(crate) struct Started<'a> {
    set: &'a InProgress,
    key: (&'static str, String),
}

impl Drop for Started<'_> {
    fn drop(&mut self) {
        self.set.0.borrow_mut().remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_digest_ignores_key_order_and_spacing() {
        let one: Value = serde_json::from_str(r#"{"amount":"1","id":"a","to":"x"}"#).unwrap();
        let two: Value =
            serde_json::from_str(r#"{ "to": "x", "id": "a",  "amount": "1" }"#).unwrap();
        let other: Value = serde_json::from_str(r#"{"amount":"2","id":"a","to":"x"}"#).unwrap();
        assert_eq!(digest(&one), digest(&two));
        assert_ne!(digest(&one), digest(&other));
    }

    #[test]
    fn a_second_start_of_the_same_id_waits_for_the_first_to_end() {
        let set = InProgress::default();
        let first = set.start(PAYMENT, "a").unwrap();
        assert_eq!(set.start(PAYMENT, "a").unwrap_err().code(), "in_progress");
        assert!(set.start(LINK, "a").is_ok());
        drop(first);
        assert!(set.start(PAYMENT, "a").is_ok());
    }
}
