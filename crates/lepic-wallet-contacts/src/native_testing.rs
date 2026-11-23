// SPDX-License-Identifier: Apache-2.0
//! Native slates as a contact's wallet writes them, for tests of the wallet that reads them and
//! writes none. Built only with the `test-support` feature.

use lepic_contact::{Content, TxContent};
use lepic_primitives::params::Network;

use super::ContactError;

/// The content of a native slate that carries `content`, a slate as V3 JSON in a type 01
/// envelope: the same fields, the slate as `lepic.v1`.
///
/// # Errors
///
/// [`ContactError::NotASlate`] when the body is not a slate `lepic.v1` can carry.
pub fn native_content(network: Network, content: Content) -> Result<TxContent, ContactError> {
    Ok(TxContent {
        body: super::native::native_body(network, &content.body)?,
        reply_key: content.reply_key,
        reply_route: None,
        purpose: content.purpose,
        reference: content.reference,
        expires: content.expires,
        card: content.card,
        sent_at: content.sent_at,
        address_proof: content.address_proof,
        features: content.features,
        domain: content.domain,
        receipt_ask: None,
        receipt: None,
    })
}
