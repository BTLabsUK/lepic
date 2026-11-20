// SPDX-License-Identifier: Apache-2.0
//! The endpoint's errors as RFC 9457 problem details, in the shape of the wallet API's: `type`
//! is `about:blank` and `code` names the problem from a closed list.

use serde::{Deserialize, Serialize};

/// The media type of a problem answer.
pub const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
/// The longest problem answer read.
pub(crate) const MAX_PROBLEM_LEN: usize = 4096;

/// The problems the endpoint answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemCode {
    /// The wallet cannot take a payment now; `Retry-After` says when to try again.
    NotReady,
    /// The wallet refused the slate, such as an invoice, which this endpoint never takes.
    Refused,
    /// The body is longer than [`crate::MAX_ENVELOPE_LEN`].
    TooLarge,
    /// Over the listener's budget of requests or payments.
    RateLimited,
    /// Not an envelope of a format the wallet reads, or not posted as
    /// [`crate::ENVELOPE_MEDIA_TYPE`].
    UnsupportedFormat,
}

impl ProblemCode {
    pub const ALL: [Self; 5] = [
        Self::NotReady,
        Self::Refused,
        Self::TooLarge,
        Self::RateLimited,
        Self::UnsupportedFormat,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::Refused => "refused",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::UnsupportedFormat => "unsupported_format",
        }
    }

    pub const fn status(self) -> u16 {
        match self {
            Self::NotReady => 503,
            Self::Refused => 422,
            Self::TooLarge => 413,
            Self::RateLimited => 429,
            Self::UnsupportedFormat => 415,
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::NotReady => "Not ready",
            Self::Refused => "Refused",
            Self::TooLarge => "Too large",
            Self::RateLimited => "Too many requests",
            Self::UnsupportedFormat => "Unsupported format",
        }
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::NotReady => "The wallet cannot take a payment now. Try again later.",
            Self::Refused => "The wallet did not take the slate.",
            Self::TooLarge => "The envelope is longer than the endpoint takes.",
            Self::RateLimited => "The wallet is taking no more requests for now.",
            Self::UnsupportedFormat => "The body is not an envelope the wallet reads.",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|known| known.as_str() == code)
    }
}

/// A problem details body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Problem {
    pub fn new(code: ProblemCode) -> Self {
        Self {
            kind: "about:blank".to_owned(),
            title: code.title().to_owned(),
            status: code.status(),
            code: code.as_str().to_owned(),
            detail: Some(code.detail().to_owned()),
        }
    }

    /// The code, when it is one of the closed list.
    pub fn known_code(&self) -> Option<ProblemCode> {
        ProblemCode::from_code(&self.code)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_its_status_and_round_trips() {
        let statuses: Vec<_> = ProblemCode::ALL.iter().map(|code| code.status()).collect();
        assert_eq!(statuses, [503, 422, 413, 429, 415]);
        for code in ProblemCode::ALL {
            let problem = Problem::new(code);
            let read: Problem = serde_json::from_slice(&problem.to_bytes()).unwrap();
            assert_eq!(read, problem);
            assert_eq!(read.known_code(), Some(code));
            assert_eq!(read.kind, "about:blank");
        }
        assert_eq!(ProblemCode::from_code("other"), None);
    }
}
