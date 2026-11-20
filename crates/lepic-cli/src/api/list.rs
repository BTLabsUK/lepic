// SPDX-License-Identifier: Apache-2.0
//! Lists: `{items, next_cursor}`, `limit` (default 50, at most 500) and an opaque `cursor`.
//!
//! A cursor holds the key of the last item a page returned and a digest of the list's other
//! query parameters, so a page asked with other filters than the cursor's is refused. Keys are
//! strings that sort in the list's order; the next page starts after the key, so an item added
//! or removed between pages moves no other item to another page.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::problem::Problem;

pub(crate) const DEFAULT_LIMIT: usize = 50;
pub(crate) const MAX_LIMIT: usize = 500;

/// How long the filter digest in a cursor is, in bytes.
const FILTER_DIGEST_LEN: usize = 8;

/// A request's query parameters, decoded. A name given twice is refused.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Query(BTreeMap<String, String>);

impl Query {
    pub(crate) fn parse(query: Option<&str>) -> Result<Self, Problem> {
        let mut fields = BTreeMap::new();
        for pair in query.iter().flat_map(|query| query.split('&')) {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let (key, value) = (super::decode(key, true)?, super::decode(value, true)?);
            if fields.contains_key(&key) {
                return Err(Problem::usage(format!("query parameter {key} given twice")));
            }
            fields.insert(key, value);
        }
        Ok(Self(fields))
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// The parameter `name` as `T`, parsed with `FromStr`; 400 `invalid_field` when it does not
    /// parse.
    pub(crate) fn parsed<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, Problem> {
        self.get(name)
            .map(|text| {
                text.parse().map_err(|_| {
                    Problem::invalid(&format!("/{name}"), format!("{name}: not valid"))
                })
            })
            .transpose()
    }

    /// `true` or `false`; 400 for anything else.
    pub(crate) fn flag(&self, name: &str) -> Result<Option<bool>, Problem> {
        self.parsed(name)
    }

    /// The parameters other than `limit` and `cursor`, for a cursor's filter digest.
    fn filters(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "limit" | "cursor"))
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

/// A list call's page size and cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListQuery {
    pub(crate) limit: usize,
    /// The key of the last item of the page before, from `cursor`.
    pub(crate) after: Option<String>,
    filter: [u8; FILTER_DIGEST_LEN],
}

impl ListQuery {
    /// `limit` and `cursor` from `query`. 400 for a limit outside 1..=500, a cursor that is not
    /// one serve gave, or one given with other filters than its first page had.
    pub(crate) fn parse(query: &Query) -> Result<Self, Problem> {
        let limit = query.parsed::<usize>("limit")?.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(Problem::invalid(
                "/limit",
                format!("limit must be 1 to {MAX_LIMIT}"),
            ));
        }
        let filter = filter_digest(query.filters());
        let after = query
            .get("cursor")
            .map(|cursor| {
                let invalid = || Problem::bad_request("invalid_cursor", "the cursor is not valid");
                let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
                let (digest, key) = bytes
                    .split_at_checked(FILTER_DIGEST_LEN)
                    .ok_or_else(invalid)?;
                if digest != filter {
                    return Err(Problem::bad_request(
                        "cursor_filters_changed",
                        "the other query parameters must stay those of the first page",
                    )
                    .with_param("/cursor"));
                }
                String::from_utf8(key.to_vec()).map_err(|_| invalid())
            })
            .transpose()?;
        Ok(Self {
            limit,
            after,
            filter,
        })
    }

    fn cursor(&self, key: &str) -> String {
        let mut bytes = self.filter.to_vec();
        bytes.extend_from_slice(key.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }
}

fn filter_digest<'a>(filters: impl Iterator<Item = (&'a str, &'a str)>) -> [u8; FILTER_DIGEST_LEN] {
    let mut hasher = Sha256::new();
    for (key, value) in filters {
        hasher.update(key.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut short = [0; FILTER_DIGEST_LEN];
    for (to, from) in short.iter_mut().zip(digest) {
        *to = from;
    }
    short
}

/// Which way a list's keys run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Order {
    /// Oldest first: keys rise.
    Ascending,
    /// Newest first: keys fall.
    Descending,
}

/// One page of a list.
#[derive(Debug, Serialize)]
pub(crate) struct Page<T> {
    pub(crate) items: Vec<T>,
    /// Absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// The page `query` asks for of `items`, which hold the whole filtered list in `order` of
    /// `key`. Keys must be unique.
    pub(crate) fn of(
        items: impl IntoIterator<Item = T>,
        query: &ListQuery,
        order: Order,
        key: impl Fn(&T) -> String,
    ) -> Self {
        let mut rest = items.into_iter().filter(|item| match &query.after {
            None => true,
            Some(after) => match order {
                Order::Ascending => key(item).as_str() > after.as_str(),
                Order::Descending => key(item).as_str() < after.as_str(),
            },
        });
        let items: Vec<T> = rest.by_ref().take(query.limit).collect();
        let next_cursor = match (rest.next(), items.last()) {
            (Some(_), Some(last)) => Some(query.cursor(&key(last))),
            _ => None,
        };
        Self { items, next_cursor }
    }
}

/// A key that sorts as the number `value` does: zero-padded to 20 digits.
pub(crate) fn number_key(value: u64) -> String {
    format!("{value:020}")
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn list(query: &str) -> Result<ListQuery, Problem> {
        ListQuery::parse(&Query::parse(Some(query)).unwrap())
    }

    #[test]
    fn pages_follow_each_other_without_gaps_in_both_orders() {
        for order in [Order::Ascending, Order::Descending] {
            let mut numbers: Vec<u64> = (1..=7).collect();
            if order == Order::Descending {
                numbers.reverse();
            }
            let mut seen = Vec::new();
            let mut query = "limit=3&state=posted".to_owned();
            loop {
                let page = Page::of(numbers.clone(), &list(&query).unwrap(), order, |n| {
                    number_key(*n)
                });
                seen.extend(page.items);
                match page.next_cursor {
                    Some(cursor) => query = format!("limit=3&state=posted&cursor={cursor}"),
                    None => break,
                }
            }
            assert_eq!(seen, numbers);
        }
    }

    #[test]
    fn a_cursor_with_other_filters_or_a_bad_limit_is_refused() {
        let numbers: Vec<u64> = (1..=4).collect();
        let page = Page::of(
            numbers,
            &list("limit=2&state=a").unwrap(),
            Order::Ascending,
            |n| number_key(*n),
        );
        let cursor = page.next_cursor.unwrap();
        assert!(list(&format!("limit=2&state=a&cursor={cursor}")).is_ok());
        let refused = list(&format!("state=b&cursor={cursor}")).unwrap_err();
        assert_eq!(refused.code(), "cursor_filters_changed");
        assert_eq!(list("cursor=%21%21").unwrap_err().code(), "invalid_cursor");
        for limit in ["0", "501", "x", "-1"] {
            assert_eq!(
                list(&format!("limit={limit}")).unwrap_err().code(),
                "invalid_field"
            );
        }
        assert_eq!(list("").unwrap().limit, DEFAULT_LIMIT);
        assert_eq!(list("limit=500").unwrap().limit, MAX_LIMIT);
    }

    #[test]
    fn a_query_is_percent_decoded_and_a_name_given_twice_is_refused() {
        let query = Query::parse(Some("account=my+savings%21&x=")).unwrap();
        assert_eq!(query.get("account"), Some("my savings!"));
        assert_eq!(query.get("x"), Some(""));
        assert!(Query::parse(Some("a=1&a=2")).is_err());
        assert!(Query::parse(Some("a=%zz")).is_err());
    }
}
