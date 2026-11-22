// SPDX-License-Identifier: Apache-2.0
//! The invoice link: a lepic.v1 I1 (a checkout request, signed or not) as a URI a payee shows
//! as a link or QR code, `epiccash://invoice/1/<base64url, no padding>`.
//!
//! The payload is the code's bytes as they are, so a signed code keeps its signature. Reading a
//! link decodes the code and refuses anything other than an I1; it does not check a request
//! claim, which is [`crate::verify_request`]'s job.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lepic_native_slate::NativeSlate;
use lepic_slate::stage::Stage;
use thiserror::Error;

/// What every invoice link starts with.
pub const INVOICE_LINK_PREFIX: &str = "epiccash://invoice/1/";
/// The longest invoice link read, in bytes.
pub const MAX_INVOICE_LINK_LEN: usize = 8 * 1024;

const SCHEME: &str = "epiccash://";

/// Why an invoice link was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvoiceLinkError {
    #[error("the invoice link is longer than {MAX_INVOICE_LINK_LEN} bytes")]
    TooLong,
    #[error("not an epiccash://invoice/1/ link")]
    Prefix,
    #[error("the invoice link payload is not unpadded base64url")]
    Encoding,
    #[error("the invoice link does not hold a lepic.v1 slate")]
    Malformed,
    #[error("the invoice link holds a slate that is not an I1 invoice request")]
    NotAnInvoice,
}

/// The link for `code`, a lepic.v1 I1. Nothing is checked: a code too long for
/// [`parse_invoice_link`] gives a link it refuses.
pub fn invoice_link(code: &[u8]) -> String {
    format!("{INVOICE_LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(code))
}

/// The lepic.v1 code an invoice link holds. Surrounding whitespace is ignored and the scheme
/// matches in any case, as URI schemes do; the rest must be exact. Refused: a link over
/// [`MAX_INVOICE_LINK_LEN`] bytes, another prefix, padded or non-base64url text, and a payload
/// that is not a lepic.v1 I1 of either network.
pub fn parse_invoice_link(text: &str) -> Result<Vec<u8>, InvoiceLinkError> {
    let text = text.trim();
    if text.len() > MAX_INVOICE_LINK_LEN {
        return Err(InvoiceLinkError::TooLong);
    }
    let scheme = text
        .get(..SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
        .ok_or(InvoiceLinkError::Prefix)?;
    let payload = text
        .get(scheme.len()..)
        .and_then(|rest| rest.strip_prefix(&INVOICE_LINK_PREFIX[SCHEME.len()..]))
        .ok_or(InvoiceLinkError::Prefix)?;
    let code = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| InvoiceLinkError::Encoding)?;
    let (_, slate) = NativeSlate::decode_any(&code).map_err(|_| InvoiceLinkError::Malformed)?;
    if slate.slate().stage() != Stage::I1 {
        return Err(InvoiceLinkError::NotAnInvoice);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::domain::tests::code;

    #[test]
    fn a_link_round_trips_its_code() {
        for name in [
            "invoice_file_plain_i1_mainnet",
            "invoice_file_ttl_i1_floonet",
        ] {
            let code = code(name);
            let link = invoice_link(&code);
            assert!(link.starts_with(INVOICE_LINK_PREFIX));
            assert!(!link.contains('='));
            assert_eq!(parse_invoice_link(&link), Ok(code.clone()));
            assert_eq!(parse_invoice_link(&format!("  {link}\n")), Ok(code.clone()));
            let upper = link.replacen("epiccash://", "EpicCash://", 1);
            assert_eq!(parse_invoice_link(&upper), Ok(code));
        }
    }

    #[test]
    fn a_link_of_another_shape_is_refused() {
        let payload =
            &invoice_link(&code("invoice_file_plain_i1_mainnet"))[INVOICE_LINK_PREFIX.len()..];
        for prefix in [
            "",
            "epiccash://invoice/2/",
            "epiccash://Invoice/1/",
            "epiccash://pair/1/",
            "epic://invoice/1/",
            "epiccash://invoice/1",
        ] {
            assert_eq!(
                parse_invoice_link(&format!("{prefix}{payload}")),
                Err(InvoiceLinkError::Prefix),
                "{prefix}"
            );
        }
        for bad in [
            format!("{payload}="),
            format!("{payload}+"),
            format!("{payload} x"),
        ] {
            assert_eq!(
                parse_invoice_link(&format!("{INVOICE_LINK_PREFIX}{bad}")),
                Err(InvoiceLinkError::Encoding),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_link_must_hold_an_i1() {
        assert_eq!(
            parse_invoice_link(&invoice_link(b"not a slate")),
            Err(InvoiceLinkError::Malformed)
        );
        assert_eq!(
            parse_invoice_link(&invoice_link(&code("send_file_plain_s1_mainnet"))),
            Err(InvoiceLinkError::NotAnInvoice)
        );
    }

    #[test]
    fn a_link_over_eight_kib_is_refused() {
        let long = format!("{INVOICE_LINK_PREFIX}{}", "A".repeat(MAX_INVOICE_LINK_LEN));
        assert_eq!(parse_invoice_link(&long), Err(InvoiceLinkError::TooLong));
        let at_limit = format!(
            "{INVOICE_LINK_PREFIX}{}",
            "A".repeat(MAX_INVOICE_LINK_LEN - INVOICE_LINK_PREFIX.len())
        );
        assert_eq!(
            parse_invoice_link(&at_limit),
            Err(InvoiceLinkError::Malformed)
        );
    }
}
