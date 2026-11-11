// SPDX-License-Identifier: Apache-2.0
//! The serve API's event log and the records that make its creates idempotent.
//!
//! Events carry JSON bytes the API builds; the store keeps them as given. Ids rise and are never
//! given twice, also after pruning. A request record keeps the digest of what a create was first
//! called with, under a scope (what is created) and the caller's id, so a retry with the same
//! digest can be told from a reused id with other content.

use jiff::Timestamp;

use crate::error::StoreError;

/// The longest event kind, in bytes.
pub const MAX_API_KIND_LEN: usize = 64;
/// The largest event data, in bytes (1 MiB).
pub const MAX_API_EVENT_DATA_LEN: usize = 1 << 20;
/// The longest request scope, in bytes.
pub const MAX_API_SCOPE_LEN: usize = 32;
/// The longest request id, in bytes.
pub const MAX_API_REQUEST_ID_LEN: usize = 128;
/// The most kind patterns one read takes.
pub const MAX_API_KIND_PATTERNS: usize = 32;
/// The most events one read returns.
pub const MAX_API_EVENTS_PER_READ: usize = 1000;
/// The digest length of a request record.
pub const API_DIGEST_LEN: usize = 32;

/// One event of the serve API's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiEvent {
    pub id: u64,
    pub kind: String,
    pub created_at: Timestamp,
    /// JSON bytes.
    pub data: Vec<u8>,
}

/// What an idempotent create was first called with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    /// What is created: `payment`, `link`, `contact`, `address`.
    pub scope: String,
    pub id: String,
    pub digest: [u8; API_DIGEST_LEN],
    pub created_at: Timestamp,
}

pub trait ApiLogRepository {
    /// Appends an event and returns its id. Ids rise and are never reused, even after pruning.
    /// Fails with [`StoreError::OutOfRange`] for an empty or too long kind, a kind outside
    /// `[A-Za-z0-9._:-]`, or data above [`MAX_API_EVENT_DATA_LEN`].
    fn append_api_event(
        &mut self,
        kind: &str,
        created_at: Timestamp,
        data: &[u8],
    ) -> Result<u64, StoreError>;

    /// Up to `limit` events with id above `after`, oldest first. `kinds` empty means all;
    /// otherwise an event matches when its kind equals an entry, or the entry ends in `.*` and
    /// the kind starts with the entry's text before the `*` (`payment.*` matches
    /// `payment.created`). Fails with [`StoreError::OutOfRange`] for a malformed pattern, more
    /// than [`MAX_API_KIND_PATTERNS`] of them, or a `limit` above [`MAX_API_EVENTS_PER_READ`].
    fn api_events_after(
        &self,
        after: u64,
        limit: usize,
        kinds: &[String],
    ) -> Result<Vec<ApiEvent>, StoreError>;

    /// The lowest and highest id the log holds; `None` when empty.
    fn api_event_bounds(&self) -> Result<Option<(u64, u64)>, StoreError>;

    /// The highest id ever given, also after every event was pruned; 0 when none ever was.
    fn api_event_last_id(&self) -> Result<u64, StoreError>;

    /// Deletes the events created before `before` and returns how many.
    fn prune_api_events(&mut self, before: Timestamp) -> Result<u64, StoreError>;

    /// Stores a request record. Fails with [`StoreError::Duplicate`] if `(scope, id)` exists, and
    /// with [`StoreError::OutOfRange`] for an empty or too long scope or id.
    fn put_api_request(&mut self, request: &ApiRequest) -> Result<(), StoreError>;

    fn api_request(&self, scope: &str, id: &str) -> Result<Option<ApiRequest>, StoreError>;

    /// Deletes the request record `(scope, id)`; true if there was one.
    fn delete_api_request(&mut self, scope: &str, id: &str) -> Result<bool, StoreError>;

    /// Deletes the request records created before `before` and returns how many.
    fn prune_api_requests(&mut self, before: Timestamp) -> Result<u64, StoreError>;
}

/// One kind filter entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KindPattern<'a> {
    Exact(&'a str),
    /// Every kind starting with this text, which ends in a dot.
    Prefix(&'a str),
}

impl KindPattern<'_> {
    pub(crate) fn matches(&self, kind: &str) -> bool {
        match self {
            Self::Exact(exact) => kind == *exact,
            Self::Prefix(prefix) => kind.starts_with(prefix),
        }
    }
}

const fn kind_byte_ok(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
}

pub(crate) fn check_kind(kind: &str) -> Result<(), StoreError> {
    if kind.is_empty() || kind.len() > MAX_API_KIND_LEN || !kind.bytes().all(kind_byte_ok) {
        return Err(StoreError::OutOfRange {
            field: "api event kind",
        });
    }
    Ok(())
}

pub(crate) fn check_event_data(data: &[u8]) -> Result<(), StoreError> {
    if data.len() > MAX_API_EVENT_DATA_LEN {
        return Err(StoreError::OutOfRange {
            field: "api event data",
        });
    }
    Ok(())
}

pub(crate) fn check_limit(limit: usize) -> Result<(), StoreError> {
    if limit > MAX_API_EVENTS_PER_READ {
        return Err(StoreError::OutOfRange {
            field: "api event limit",
        });
    }
    Ok(())
}

pub(crate) fn parse_patterns(kinds: &[String]) -> Result<Vec<KindPattern<'_>>, StoreError> {
    let bad = StoreError::OutOfRange {
        field: "api event kind filter",
    };
    if kinds.len() > MAX_API_KIND_PATTERNS {
        return Err(bad);
    }
    kinds
        .iter()
        .map(|entry| {
            if let Some(prefix) = entry.strip_suffix('*') {
                // Only `<text>.*` is a pattern: the text before the star ends in a dot.
                if prefix.len() < 2 || !prefix.ends_with('.') {
                    return Err(StoreError::OutOfRange {
                        field: "api event kind filter",
                    });
                }
                check_kind(prefix).map_err(|_| StoreError::OutOfRange {
                    field: "api event kind filter",
                })?;
                Ok(KindPattern::Prefix(prefix))
            } else {
                check_kind(entry).map_err(|_| StoreError::OutOfRange {
                    field: "api event kind filter",
                })?;
                Ok(KindPattern::Exact(entry))
            }
        })
        .collect()
}

pub(crate) fn check_request_key(scope: &str, id: &str) -> Result<(), StoreError> {
    if scope.is_empty() || scope.len() > MAX_API_SCOPE_LEN {
        return Err(StoreError::OutOfRange {
            field: "api request scope",
        });
    }
    if id.is_empty() || id.len() > MAX_API_REQUEST_ID_LEN {
        return Err(StoreError::OutOfRange {
            field: "api request id",
        });
    }
    Ok(())
}
