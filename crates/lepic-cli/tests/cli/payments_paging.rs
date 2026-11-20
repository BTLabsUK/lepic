// SPDX-License-Identifier: Apache-2.0
//! `GET /api/v1/payments` reads the store a step at a time and pages by the list key (the
//! creation millisecond, then the payment id). A wallet whose transactions share
//! milliseconds in groups, across more entries than one step reads, lists each payment once, in
//! the order of the key, however it is paged or filtered; a cursor of the documented form
//! (the filter digest, then the key of the last item) still continues the list.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lepic_primitives::amount::Height;
use lepic_store::AccountIndex;
use serde_json::Value;
use support::{FUNDING, Instance, SENDER_MNEMONIC, TestHost, serving, text, with_settings};

const TRANSACTIONS: u32 = 600;
/// Entries per shared millisecond.
const TIE: i64 = 7;

/// The ids of the wallet's payments in the list's order, from the store alone: newest
/// millisecond first, then the larger id first.
fn expected(wallet: &Instance) -> Vec<(i128, String)> {
    with_settings(wallet, SENDER_MNEMONIC, |repos| {
        let mut keys: Vec<(i128, String)> = repos
            .transactions(AccountIndex(0))?
            .into_iter()
            .map(|stored| {
                (
                    stored.entry.created_at.as_millisecond().into(),
                    stored.entry.slate_id.map_or_else(
                        || format!("00000000-0000-0000-0000-{:012x}", stored.id.0),
                        |slate| slate.to_string(),
                    ),
                )
            })
            .collect();
        keys.sort();
        keys.reverse();
        // A payment id is listed once, at its newest row.
        let mut seen = std::collections::BTreeSet::new();
        keys.retain(|(_, id)| seen.insert(id.clone()));
        Ok(keys)
    })
}

/// Puts the transactions' creation times into groups of [`TIE`] that share a millisecond but
/// not a nanosecond.
fn tie_times(wallet: &Instance) {
    with_settings(wallet, SENDER_MNEMONIC, |repos| {
        for (number, mut stored) in repos.transactions(AccountIndex(0))?.into_iter().enumerate() {
            let number = i64::try_from(number).unwrap();
            let nanos = 1_735_689_600_000_000_000_i128
                + i128::from(number / TIE) * 1_000_000
                + i128::from(number % TIE) * 1_000;
            stored.entry.created_at = jiff::Timestamp::from_nanosecond(nanos).unwrap();
            repos.update_transaction(stored.id, &stored.entry)?;
        }
        Ok(())
    });
}

/// Gives an early outgoing entry and a late incoming one the same slate id: one payment with two
/// rows, a step or more apart.
fn share_a_slate(wallet: &Instance) {
    use lepic_store::TxDirection;
    with_settings(wallet, SENDER_MNEMONIC, |repos| {
        let all = repos.transactions(AccountIndex(0))?;
        let outgoing = all[..100]
            .iter()
            .find(|stored| {
                stored.entry.direction == TxDirection::Outgoing && stored.entry.slate_id.is_some()
            })
            .unwrap();
        let mut incoming = all
            .iter()
            .rfind(|stored| {
                stored.entry.direction == TxDirection::Incoming
                    && stored.entry.slate_id.is_some()
                    && stored.entry.transport.as_deref() != Some("self")
            })
            .unwrap()
            .clone();
        incoming.entry.slate_id = outgoing.entry.slate_id;
        repos.update_transaction(incoming.id, &incoming.entry)?;
        Ok(())
    });
}

/// Every item `query` lists, `limit` at a time, from `cursor` on, with the number of pages.
fn walk(socket: &Path, query: &str, limit: usize, mut cursor: Option<String>) -> Vec<Value> {
    let mut items = Vec::new();
    loop {
        let mut path = format!("/api/v1/payments?limit={limit}{query}");
        if let Some(cursor) = &cursor {
            path.push_str(&format!("&cursor={cursor}"));
        }
        let page = support::http(socket, "GET", &path, None).ok();
        let got = page["items"].as_array().unwrap();
        assert!(got.len() <= limit, "{page}");
        items.extend(got.iter().cloned());
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return items,
        }
        assert!(items.len() <= 1000, "the cursor never ends");
    }
}

fn ids(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .map(|item| text(item, "id").to_owned())
        .collect()
}

#[test]
fn tied_creation_times_list_every_payment_once_in_key_order_across_pages_and_steps() {
    let host = TestHost::new();
    host.node.update_chain(|chain| {
        chain.tip.height = Height::new(u64::from(TRANSACTIONS) + 10);
    });
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    {
        use lepic_wallet::StoreOpener as _;
        let seed = lepic_keychain::Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = lepic_wallet::EncryptedSqliteStores
            .open(
                &wallet.data_dir(),
                lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
                &lepic_wallet::store_key(&seed).unwrap(),
            )
            .unwrap();
        lepic_store::seed::seed(&store, TRANSACTIONS, 1).unwrap();
    }
    tie_times(&wallet);
    share_a_slate(&wallet);
    let order = expected(&wallet);
    let want: Vec<String> = order.iter().map(|(_, id)| id.clone()).collect();
    assert!(want.len() >= usize::try_from(TRANSACTIONS).unwrap() - 1);
    // The key of the item at `at`, as an old cursor writes it.
    let key_of = |at: usize| -> String { format!("{:020}{}", order[at].0, order[at].1) };
    let keys: Vec<String> = [0, 250, 255, 256, 300]
        .iter()
        .map(|at| key_of(*at))
        .collect();

    serving(host, &wallet, |socket, _| {
        // The first refresh may record entries of its own, newer than the seeded ones.
        while
            support::http(socket, "GET", "/api/v1/status", None).ok()["refresh"]["last_success_at"]
                .is_null()
        {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let all = walk(socket, "", 500, None);
        let listed = ids(&all);
        let extra = listed.len() - want.len();
        assert_eq!(listed[extra..], want, "the whole list, two pages of 500");
        assert_eq!(
            listed
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            listed.len(),
            "no payment id twice"
        );
        let want: Vec<String> = listed;
        // Pages whose size cuts a tie, and one that never does.
        for limit in [1, 3, 7, 100] {
            assert_eq!(ids(&walk(socket, "", limit, None)), want, "limit {limit}");
        }
        // A filter keeps the order and loses nothing, across steps.
        for direction in ["in", "out"] {
            let filtered = walk(socket, &format!("&direction={direction}"), 5, None);
            let kept: Vec<String> = all
                .iter()
                .filter(|item| text(item, "direction") == direction)
                .map(|item| text(item, "id").to_owned())
                .collect();
            assert!(!kept.is_empty() && kept.len() < want.len(), "{direction}");
            assert_eq!(ids(&filtered), kept, "direction {direction}");
        }
        // An old-form cursor (the filter digest of the first page, then the key of the last item
        // shown) continues after that item, whatever step it falls in.
        let first = support::http(socket, "GET", "/api/v1/payments?limit=1", None).ok();
        let cursor = first["next_cursor"].as_str().unwrap();
        let digest = &URL_SAFE_NO_PAD.decode(cursor).unwrap()[..8];
        let made = |key: &str| {
            let mut bytes = digest.to_vec();
            bytes.extend_from_slice(key.as_bytes());
            URL_SAFE_NO_PAD.encode(bytes)
        };
        let key = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor).unwrap()[8..].to_vec()).unwrap();
        assert_eq!(
            &key[20..],
            want[0],
            "the first page's cursor has the documented form"
        );
        for (key, at) in keys.iter().zip([0, 250, 255, 256, 300]) {
            let rest = walk(socket, "", 50, Some(made(key)));
            assert_eq!(ids(&rest), want[extra + at + 1..], "after item {at}");
        }
    });
}
