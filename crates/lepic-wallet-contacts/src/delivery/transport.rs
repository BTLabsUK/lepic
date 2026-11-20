// SPDX-License-Identifier: Apache-2.0
//! The transport the features use: post, cancel, watch a set, how much waits, status.
//!
//! The carrier is its one implementation. Outside the adapter (`carrier`, `epicbox`, `peer`,
//! `router`, `watch`, this module and `crate::relay`) no code names a mux/1 session.

use std::collections::BTreeMap;

use futures_util::future::join_all;
use jiff::Timestamp;
use lepic_epic1::{MethodId, RouteEntry};
use lepic_epicbox::sessions::MailboxHealth;
use lepic_epicbox::{EpicboxTxId, Identity, MuxCode, MuxError, MuxWaiting, RelayEndpoint};
use lepic_slate::model::SlateId;
use lepic_store::{WalletStore, WatchRow};
use thiserror::Error;

use super::carrier::{Carrier, CarrierError, Part};
use super::epicbox::{Envelope, PostError, Posted, Unsent};
use super::watch::{MailboxKeys, WatchReport};
use crate::MailboxStatus;
use crate::relay::host_text;

/// What a socket says still waits for the mailboxes it carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Waiting {
    /// Messages not yet offered, per mailbox index of the socket. Every mailbox the socket
    /// carries is listed, with 0 when nothing of it waits.
    pub(crate) waiting: BTreeMap<usize, u64>,
    /// Messages pushed and not yet acknowledged or held.
    pub(crate) inflight: u64,
    /// Messages held back by a hold that has not ended.
    pub(crate) held: u64,
}

impl From<MuxWaiting> for Waiting {
    fn from(answer: MuxWaiting) -> Self {
        Self {
            waiting: answer.waiting,
            inflight: answer.inflight,
            held: answer.held,
        }
    }
}

/// Why a socket did not say what waits.
#[derive(Debug, Error)]
#[error("the mailbox did not say what waits")]
pub(crate) struct NotAnswered(#[source] MuxError);

impl NotAnswered {
    /// The socket is up and keeps the mailbox's pace: the session spent its `Waiting` requests
    /// for now, or the mailbox answered `rate_limited`. Ask again on a later cycle.
    pub(crate) fn paced(&self) -> bool {
        matches!(
            self.0,
            MuxError::Paced { .. }
                | MuxError::Refused {
                    code: Some(MuxCode::RateLimited)
                }
        )
    }
}

/// What a watch does once the set is claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    /// Nothing more: a timed pass.
    Claim,
    /// Every mailbox waiting to reconnect tries now: a pull. A mailbox another socket of the
    /// wallet took over stays with it until its hold-off ends, so two installs that both pull
    /// do not trade it on every pull.
    Retry,
    /// As [`Reach::Retry`], and every mailbox another socket of the wallet took over is taken
    /// back at once: an open, as on a start or an unlock.
    TakeBack,
}

/// Posting, cancelling and reading the mailboxes.
pub(crate) trait Transport {
    /// Posts `envelope` on `route`. With `only`, `domain:port`, a route of a key alone goes to
    /// that one mailbox of the list: a copy owed to a mailbox that missed it; a route that names
    /// a mailbox or is not a mailbox route is then [`Unsent::NoRelay`].
    async fn post(
        &self,
        envelope: &Envelope,
        route: &RouteEntry,
        only: Option<&str>,
    ) -> Result<Posted, PostError>;

    /// Cancels transaction `txid` of `payment` as `from` on each mailbox of `endpoints`, all at
    /// once. Returns, for each in order, whether it cancelled.
    async fn cancel(
        &self,
        payment: &SlateId,
        from: &Identity,
        txid: &EpicboxTxId,
        endpoints: Vec<RelayEndpoint>,
    ) -> Vec<bool>;

    /// Makes the transport carry exactly the live rows of `set`; see [`Carrier::claim`]. Then
    /// does what `reach` asks, once the set is claimed.
    async fn watch(
        &self,
        set: Vec<WatchRow>,
        keys: &impl MailboxKeys,
        store: &impl WalletStore,
        now: Timestamp,
        reach: Reach,
    ) -> Result<WatchReport, CarrierError>;

    /// Asks the socket of `part` what still waits, after it sent the acknowledgements of what
    /// was read.
    async fn waiting(&self, part: &Part) -> Result<Waiting, NotAnswered>;

    /// Each mailbox of the list, in its order, with its origin and health. Opens no connection.
    fn status(&self) -> Vec<MailboxStatus>;
}

impl Transport for Carrier {
    async fn post(
        &self,
        envelope: &Envelope,
        route: &RouteEntry,
        only: Option<&str>,
    ) -> Result<Posted, PostError> {
        if only.is_some() && (route.method != MethodId::Epicbox || route.value.contains('@')) {
            return Err(PostError::NotSent(Unsent::NoRelay));
        }
        self.post_routed(envelope, route, only).await
    }

    async fn cancel(
        &self,
        payment: &SlateId,
        from: &Identity,
        txid: &EpicboxTxId,
        endpoints: Vec<RelayEndpoint>,
    ) -> Vec<bool> {
        self.cancel_post(payment, from, txid, endpoints).await
    }

    async fn watch(
        &self,
        set: Vec<WatchRow>,
        keys: &impl MailboxKeys,
        store: &impl WalletStore,
        now: Timestamp,
        reach: Reach,
    ) -> Result<WatchReport, CarrierError> {
        let report = self.claim(set, keys, store, now).await?;
        let parts = self.parts();
        if reach == Reach::TakeBack {
            for part in &parts {
                part.session.take_back_now();
            }
        }
        if reach != Reach::Claim {
            join_all(parts.iter().map(|part| part.session.retry_now())).await;
        }
        Ok(report)
    }

    async fn waiting(&self, part: &Part) -> Result<Waiting, NotAnswered> {
        part.session
            .waiting()
            .await
            .map(Waiting::from)
            .map_err(NotAnswered)
    }

    fn status(&self) -> Vec<MailboxStatus> {
        let relays = self.relays();
        let health = relays.epicbox.pushed().health();
        relays
            .mailboxes
            .listed()
            .into_iter()
            .map(|listed| {
                let host = host_text(&listed.endpoint);
                let record = health.get(&host);
                MailboxStatus {
                    origin: listed.origin,
                    push: record.and_then(|record| record.push),
                    no_mux: record.is_some_and(MailboxHealth::no_mux),
                    last_success: record.and_then(|record| record.last_success),
                    failures: record.map_or(0, |record| record.failures),
                    last_error: record.and_then(|record| record.last_error.clone()),
                    host,
                }
            })
            .collect()
    }
}
