// SPDX-License-Identifier: Apache-2.0
//! The signed text of a push registration (the push service's PROTOCOL.md, "The signed text").
//!
//! The wallet proves to a push service that it owns an Epicbox address by signing a text of one
//! fixed shape with the address key. The first line separates the domain: no relay challenge, slate
//! or message id has this shape, and [`crate::Identity::sign_push`] signs nothing else with it.

use std::fmt;

use lepic_crypto::EcdsaSignature;
use thiserror::Error;

use crate::address::EpicboxAddress;

/// First line of every push text.
const DOMAIN: &str = "epic-push-v1";

/// Longest token, in characters.
pub const MAX_PUSH_TOKEN_LEN: usize = 4096;

/// What the wallet asks the push service to do with a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushAction {
    Register,
    Unregister,
}

impl PushAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Unregister => "unregister",
        }
    }

    pub fn parse(text: &str) -> Result<Self, PushError> {
        match text {
            "register" => Ok(Self::Register),
            "unregister" => Ok(Self::Unregister),
            _ => Err(PushError::Action),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PushError {
    #[error("push action must be \"register\" or \"unregister\"")]
    Action,
    #[error("push token must be 1 to {MAX_PUSH_TOKEN_LEN} characters of [A-Za-z0-9_:.-]")]
    Token,
}

/// A checked push registration request. Its token stays out of `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct PushRequest {
    action: PushAction,
    token: String,
    timestamp: u64,
}

impl PushRequest {
    /// Fails with [`PushError::Token`] unless `token` is 1 to [`MAX_PUSH_TOKEN_LEN`] characters of
    /// `[A-Za-z0-9_:.-]`, so it can never hold a line break.
    pub fn new(action: PushAction, token: &str, timestamp: u64) -> Result<Self, PushError> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '-');
        if token.is_empty() || token.len() > MAX_PUSH_TOKEN_LEN || !token.chars().all(allowed) {
            return Err(PushError::Token);
        }
        Ok(Self {
            action,
            token: token.to_owned(),
            timestamp,
        })
    }

    /// The five lines joined by `\n`, without a trailing newline. `key_text` is the base58 key
    /// of the Epicbox address, the part before `@`. Public so a verifier builds the same text.
    pub fn signed_text(&self, key_text: &str) -> String {
        format!(
            "{DOMAIN}\n{}\n{key_text}\n{}\n{}",
            self.action.as_str(),
            self.token,
            self.timestamp
        )
    }
}

impl PushRequest {
    /// True when `signature_hex` (DER hex) is a signature of this request made with the key of
    /// `address`: what a push service checks.
    pub fn verify(&self, address: &EpicboxAddress, signature_hex: &str) -> bool {
        EcdsaSignature::from_der_hex(signature_hex).is_ok_and(|signature| {
            crate::verify_text(
                &self.signed_text(&address.key_text()),
                &signature,
                address.public_key(),
            )
            .is_ok()
        })
    }
}

impl fmt::Debug for PushRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushRequest")
            .field("action", &self.action)
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use lepic_crypto::{PublicKey, SecretKey};

    use super::*;
    use crate::address::{Domain, Network};
    use crate::{Identity, verify_text};

    fn identity() -> Identity {
        let secret = SecretKey::from_array([1; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secret).unwrap();
        let address = EpicboxAddress::new(public, Network::Mainnet, Domain::default(), None);
        Identity::new(secret, address).unwrap()
    }

    fn request() -> PushRequest {
        PushRequest::new(PushAction::Register, "fcm:AP-a_b.c1", 1_761_000_000).unwrap()
    }

    #[test]
    fn text_is_the_five_lines_without_a_trailing_newline() {
        let key = identity().address().key_text();
        assert_eq!(
            request().signed_text(&key),
            format!("epic-push-v1\nregister\n{key}\nfcm:AP-a_b.c1\n1761000000")
        );
    }

    #[test]
    fn signature_verifies_over_the_text_with_the_address_key() {
        let identity = identity();
        let signature = identity.sign_push(&request()).unwrap();
        let text = request().signed_text(&identity.address().key_text());
        verify_text(&text, &signature, identity.address().public_key()).unwrap();
        let other = PushRequest::new(PushAction::Unregister, "fcm:AP-a_b.c1", 1_761_000_000);
        let other = other.unwrap().signed_text(&identity.address().key_text());
        assert!(verify_text(&other, &signature, identity.address().public_key()).is_err());
    }

    /// Secret key `[1; 32]`; deterministic ECDSA (RFC 6979) keeps the DER stable.
    #[test]
    fn known_key_vector() {
        let identity = identity();
        let signature = identity.sign_push(&request()).unwrap().to_der_hex();
        assert_eq!(
            identity.address().key_text(),
            "esYTimgooNuxKXdEEXJk3fbXoy2HWyyY2CaRXYU8Z8B7fSPyz6YL"
        );
        assert!(EcdsaSignature::from_der_hex(&signature).is_ok());
        assert_eq!(
            signature,
            "3045022100a49bb2a334804838c1096b79367cdbc6edfa537734d78f9e8c2e6148ff224d03\
             022017a7121fe7f71a1790350cf89614d37b53e874fbe7187dda80e74cf1661e53b8"
        );
    }

    #[test]
    fn action_and_token_are_checked() {
        assert_eq!(PushAction::parse("Register"), Err(PushError::Action));
        assert_eq!(PushAction::parse(""), Err(PushError::Action));
        assert_eq!(PushAction::parse("unregister"), Ok(PushAction::Unregister));
        let ok = "a".repeat(MAX_PUSH_TOKEN_LEN);
        assert!(PushRequest::new(PushAction::Register, &ok, 1).is_ok());
        for bad in [
            "",
            &"a".repeat(MAX_PUSH_TOKEN_LEN + 1),
            "a\nb",
            "a b",
            "a/b",
            "tökén",
        ] {
            assert_eq!(
                PushRequest::new(PushAction::Register, bad, 1).unwrap_err(),
                PushError::Token
            );
        }
    }

    #[test]
    fn debug_leaves_out_the_token() {
        assert!(!format!("{:?}", request()).contains("fcm:AP"));
    }
}
