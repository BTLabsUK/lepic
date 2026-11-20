// SPDX-License-Identifier: Apache-2.0
//! Posting an envelope on a route. An `http` or `tor` route goes through the host's poster
//! (see `peer`).
//!
//! A post to a relay where the carrier holds a session goes on that session's socket, which
//! costs no connection. Any other post, and a post the session wrote nothing of, goes on a short
//! connection of its own. A post that was written and not answered is never sent again: the
//! relay may hold it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures_util::future::join_all;
use lepic_crypto::PublicKey;
use lepic_epic1::{MethodId, RouteEntry};
use lepic_epicbox::sessions::MailboxHealth;
use lepic_epicbox::{
    AddressError, CancelOutcome, ClientError, EpicboxAddress, EpicboxClient, EpicboxTxId, Identity,
    MailboxClient, MailboxError, MuxCancelOutcome, MuxCode, MuxError, MuxPostError, MuxState,
    RELAY_MAX_STR_BYTES, RelayEndpoint, RelayErrorKind, UntrustedHosts, sealed_str_len,
};
use lepic_peer::PeerClientError;
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::model::SlateId;
use thiserror::Error;
use tracing::{debug, warn};

use super::carrier::Carrier;
use super::peer::{AddressRefusal, PeerRefusal};
use super::refusal;
use crate::in_person::mailbox_endpoint;
use crate::outbox::MailboxRefusal;
use crate::relay::{check_online, host_text, mailbox_client};
use crate::{ContactError, ContactRelays};

/// The most mailboxes one post to a key goes to (ADR 0065 §3): never the whole list.
pub(crate) const POST_MAILBOXES: usize = 3;

/// The relays of [`ContactRelays::list`] a key's mailbox is read on, in the list's order: every
/// one. Posts go to [`POST_MAILBOXES`] of them, picked by [`post_mailboxes`]. A relay that fails
/// or answers without push stays: its health is shown and its posts are retried, while the
/// others carry the mail.
pub(crate) fn usable_relays(relays: &ContactRelays) -> Vec<RelayEndpoint> {
    relays.list()
}

/// The relays mail to a key goes to and is read on: each of [`usable_relays`], and `hint`, the
/// relay an invite or a card names, when none of those is it. A payment names no hint.
pub(crate) fn mail_relays(
    relays: &ContactRelays,
    hint: Option<&RelayEndpoint>,
) -> Vec<RelayEndpoint> {
    let mut endpoints = usable_relays(relays);
    if let Some(hint) = hint {
        let host = host_text(hint);
        if !endpoints.iter().any(|endpoint| host_text(endpoint) == host) {
            endpoints.push(hint.clone());
        }
    }
    endpoints
}

/// The mailboxes a post to a key goes to, at most [`POST_MAILBOXES`]: `first` when there is
/// one (the mailbox an answer's payment was read on, or the one a contact's card or an invite
/// names), then the healthiest of `candidates`. Health only orders the pick
/// ([`post_rank`]); mailboxes of equal health keep the order of `candidates`, which in the
/// wallet's list puts the shipped mailboxes first. A mailbox known to lack mux/1
/// ([`MailboxHealth::no_mux`]) is never picked, `first` included: the wallet reads a slot only
/// by push, so a post there would wait for nobody. One whose mux support is not known yet stays
/// eligible. A mailbox left out stays in the list and is read as before; a retry of the post
/// picks again.
pub(crate) fn post_mailboxes(
    candidates: Vec<RelayEndpoint>,
    first: Option<&RelayEndpoint>,
    health: &BTreeMap<String, MailboxHealth>,
    now: SystemTime,
) -> Vec<RelayEndpoint> {
    let has_mux = |host: &str| !health.get(host).is_some_and(MailboxHealth::no_mux);
    let mut picked: Vec<RelayEndpoint> = first
        .filter(|endpoint| has_mux(&host_text(endpoint)))
        .cloned()
        .into_iter()
        .collect();
    let mut ranked: Vec<(RelayEndpoint, String)> = candidates
        .into_iter()
        .map(|endpoint| {
            let host = host_text(&endpoint);
            (endpoint, host)
        })
        .filter(|(_, host)| has_mux(host))
        .collect();
    // A stable sort: equal ranks keep the candidates' order.
    ranked.sort_by_key(|(_, host)| post_rank(health.get(host), now));
    for (endpoint, host) in ranked {
        if picked.len() >= POST_MAILBOXES {
            break;
        }
        if !picked.iter().any(|kept| host_text(kept) == host) {
            picked.push(endpoint);
        }
    }
    picked
}

/// How a mailbox ranks for a post, lowest first: one that holds posts back now, after a post
/// could not reach it, comes last; then the one with fewer failures, of posts and of sockets,
/// since its last success. A mailbox without a record ranks as one without failures.
fn post_rank(health: Option<&MailboxHealth>, now: SystemTime) -> (bool, u32) {
    health.map_or((false, 0), |health| {
        let held = health.post_retry_at.is_some_and(|at| at > now);
        (held, health.post_failures.saturating_add(health.failures))
    })
}

/// What a post carries.
#[allow(clippy::large_enum_variant)] // one per post, moved into the post and dropped after it
pub(crate) enum Envelope {
    /// For an Epicbox route: who sends it, the armored text, the relay as the caller checked it,
    /// and the transaction id the post carries where the relay takes one. `relay: None` takes
    /// the relay the address names, reached as the wallet reaches it when it is in the relay
    /// list and on a client that checks the host before it connects when it is not; a route of
    /// a key alone goes to the relays [`post_mailboxes`] picks, `relay` first.
    Mailbox {
        from: Identity,
        payload: String,
        relay: Option<MailboxRelay>,
        txid: Option<EpicboxTxId>,
        /// The mailboxes a route of a key alone picks from in place of the list: those a
        /// payment was given for itself.
        list: Option<Vec<RelayEndpoint>>,
    },
    /// For an `http` or `tor` route: the sealed envelope, the body of one request.
    Sealed(Vec<u8>),
}

/// The relay of an Epicbox route, as the caller's host rule took it: a relay the caller
/// vouches for, reached as the wallet reaches its own relays.
#[derive(Debug, Clone)]
pub(crate) struct MailboxRelay {
    pub(crate) endpoint: RelayEndpoint,
    /// The relay's onion, dialled when relay traffic goes through Tor.
    pub(crate) onion: Option<String>,
}

/// Which way a post went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Posted {
    /// On the socket of a session the carrier holds.
    Session,
    /// On a short connection.
    Connection,
    /// On a short connection, after the session wrote nothing of it.
    ConnectionAfterSession,
    /// To the native endpoint of the route's host, which answered with this reply envelope,
    /// unopened.
    Reply(Vec<u8>),
    /// To a key's mailbox on the relays of the list: `took` names those that took it and
    /// `missed` those that did not and are owed it again, each in the list's order.
    Relays {
        took: Vec<String>,
        missed: Vec<Missed>,
    },
}

/// A relay that did not take a post to a key's mailbox and is owed it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Missed {
    /// The relay, `domain:port`.
    pub(crate) relay: String,
    /// The wait the relay asked for before the next post, when it named one.
    pub(crate) wait: Option<Duration>,
}

/// Why a post did not reach the relay, or may not have.
#[derive(Debug, Error)]
pub(crate) enum PostError {
    /// The route's method has no carrier.
    #[error("no carrier posts by {0}")]
    NoCarrier(MethodId),
    /// The envelope is not the kind the route's method carries.
    #[error("the envelope is not one {0} carries")]
    Envelope(MethodId),
    /// The route's value is not an address its carrier takes. Nothing was sent.
    #[error("the route is not an address its carrier takes")]
    Address(#[source] RouteAddressError),
    /// Nothing reached the relay or endpoint. Posting again is safe.
    #[error("the post was not sent")]
    NotSent(#[source] Unsent),
    /// The post was written and not answered: the relay may hold it.
    #[error("the post was sent and not answered")]
    Uncertain(#[source] Unanswered),
    /// The sealed message would be longer than a relay takes. Nothing was sent; posting it
    /// again would not help.
    #[error("the message is {bytes} bytes sealed, over the relay's limit of {limit}")]
    TooLong { bytes: usize, limit: usize },
    /// The relay answered the post with an error. Built by [`PostError::refused`].
    #[error("{}", refused_text(.mailbox.as_deref(), .reason.as_deref(), *.retry_after))]
    Refused {
        code: Option<RefusalCode>,
        /// The wait the mailbox asked for before the next post, from its frame or its words.
        retry_after: Option<Duration>,
        /// The mailbox's own words, cut to size by the client.
        reason: Option<String>,
        /// The mailbox that refused, `domain:port`; `None` for a native endpoint.
        mailbox: Option<String>,
        /// The refusal is passing, for a rate limit or for want of room: the post may go again
        /// after `retry_after` and the outbox's back-off. Any other refusal is final.
        retryable: bool,
    },
}

impl PostError {
    /// A refusal of `code`, with the wait it named and the mailbox's words, read by
    /// [`refusal::classify`].
    pub(crate) fn refused(
        code: Option<RefusalCode>,
        retry_after: Option<Duration>,
        reason: Option<String>,
    ) -> Self {
        let read = refusal::classify(code.as_ref(), reason.as_deref(), retry_after);
        Self::Refused {
            code,
            retry_after: read.retry_after,
            reason,
            mailbox: None,
            retryable: read.retryable,
        }
    }

    /// The refusal this error is, as the host is told of it; `None` for any other error.
    pub(crate) fn refusal(&self) -> Option<MailboxRefusal> {
        match self {
            Self::Refused {
                retry_after,
                reason,
                mailbox,
                retryable,
                ..
            } => Some(MailboxRefusal {
                mailbox: mailbox.clone(),
                reason: reason.clone(),
                retry_after: *retry_after,
                retryable: *retryable,
            }),
            _ => None,
        }
    }

    /// This error, a refusal naming the mailbox `host` that made it.
    fn at_mailbox(mut self, host: &str) -> Self {
        if let Self::Refused { mailbox, .. } = &mut self {
            *mailbox = Some(host.to_owned());
        }
        self
    }
}

/// How a refusal ranks among a post's refusals: passing first, then one that names a wait.
fn refusal_rank(error: &PostError) -> (bool, bool) {
    match error {
        PostError::Refused {
            retryable,
            retry_after,
            ..
        } => (*retryable, retry_after.is_some()),
        _ => (false, false),
    }
}

/// What a refusal says: the mailbox, its words and its wait, as far as each is known.
pub(crate) fn refused_text(
    mailbox: Option<&str>,
    reason: Option<&str>,
    wait: Option<Duration>,
) -> String {
    let mut text = match mailbox {
        Some(mailbox) => format!("mailbox {mailbox} refused the post"),
        None => "the relay refused the post".to_owned(),
    };
    if let Some(reason) = reason {
        text.push_str(": ");
        text.push_str(reason.trim_end_matches('.'));
    }
    if let Some(wait) = wait
        && !reason.is_some_and(|reason| reason.contains(refusal::RETRY_IN))
    {
        text.push_str(&format!("; retry in {} s", wait.as_secs()));
    }
    text
}

/// Why a route's value was not taken.
#[derive(Debug, Error)]
pub(crate) enum RouteAddressError {
    #[error("not a mailbox address")]
    Mailbox(#[source] AddressError),
    #[error("not a host and port")]
    HostPort,
    /// The address names a relay the host rule refuses, such as this device.
    #[error("the relay's host is refused")]
    Host(#[source] ContactError),
    /// The host's poster refused the address, such as an onion whose checksum does not match.
    #[error("the poster does not take the address")]
    Peer(#[source] AddressRefusal),
}

/// Why nothing was sent.
#[derive(Debug, Error)]
pub(crate) enum Unsent {
    #[error(transparent)]
    Relay(ContactError),
    #[error(transparent)]
    Peer(PeerClientError),
    /// The list holds no relay that can take the post.
    #[error("no relay of the list is usable")]
    NoRelay,
}

/// Where an unanswered post was written.
#[derive(Debug, Error)]
pub(crate) enum Unanswered {
    #[error("on a mux/1 session")]
    Session,
    #[error("on a short connection")]
    Connection(#[source] MailboxError),
    #[error("to a native endpoint")]
    Peer(#[source] PeerClientError),
}

/// The code of a refusal, as the way the post went names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefusalCode {
    Mux(MuxCode),
    Relay(RelayErrorKind),
    Peer(PeerRefusal),
    /// A relay with the cancel protocol cancelled the transaction the post names.
    Cancelled,
}

impl Carrier {
    /// Posts `envelope` on `route`, to `only` of the relays when a route of a key alone names
    /// one. An `http` or `tor` route goes in one request through the host's poster for it, and
    /// has no carrier without one.
    ///
    /// An Epicbox route `<key>@<relay>` goes on a session the carrier holds on that relay, else
    /// on a short connection; once more on a short connection when the session wrote nothing.
    ///
    /// An Epicbox route of a key alone goes to the key's mailbox on the relays
    /// [`post_mailboxes`] picks: the envelope's relay when it names one, then the healthiest of
    /// the envelope's list or of [`ContactRelays::list`], [`POST_MAILBOXES`] in all; on each as
    /// above, all at once. A copy owed to `only` goes to that relay alone. Its outcome:
    ///
    /// - one relay or more took it: [`Posted::Relays`] names them, and the others, but for one
    ///   that cancelled the post's transaction, as owed it again;
    /// - none took it and one or more wrote it and gave no answer: [`PostError::Uncertain`], as
    ///   such a relay may hold it;
    /// - every relay refused it: [`PostError::Refused`], a passing refusal if one is, one that
    ///   names a wait before one that does not, else the first;
    /// - else, nothing reached a relay or no relay is usable: [`PostError::NotSent`].
    pub(super) async fn post_routed(
        &self,
        envelope: &Envelope,
        route: &RouteEntry,
        only: Option<&str>,
    ) -> Result<Posted, PostError> {
        match route.method {
            MethodId::Epicbox => {}
            MethodId::Http | MethodId::Tor => return self.post_to_peer(envelope, route).await,
        }
        let Envelope::Mailbox {
            from,
            payload,
            relay,
            txid,
            list,
        } = envelope
        else {
            return Err(PostError::Envelope(MethodId::Epicbox));
        };
        let relays = self.relays();
        check_online(relays).map_err(|error| PostError::NotSent(Unsent::Relay(error)))?;
        let network = relays.epicbox.network();
        let mailbox = |error| PostError::Address(RouteAddressError::Mailbox(error));
        if !route.value.contains('@') {
            let key = EpicboxAddress::parse_key(&route.value, network).map_err(mailbox)?;
            let post = Post {
                from,
                payload,
                txid: txid.as_ref(),
            };
            return self
                .post_to_list(&post, &key, (relay.as_ref(), list.as_deref()), only)
                .await;
        }
        let to = EpicboxAddress::parse(&route.value, network).map_err(mailbox)?;
        too_long(payload, &to)?;
        let (endpoint, onion, known) = match relay {
            Some(relay) => (relay.endpoint.clone(), relay.onion.as_deref(), true),
            None => {
                let host = match to.port() {
                    Some(port) => format!("{}:{port}", to.domain()),
                    None => to.domain().to_string(),
                };
                let (endpoint, report) = mailbox_endpoint(&host, relays)
                    .map_err(|error| PostError::Address(RouteAddressError::Host(error)))?;
                (endpoint, None, report.in_relay_list)
            }
        };
        let post = Post {
            from,
            payload,
            txid: txid.as_ref(),
        };
        self.post_on(&post, &to, endpoint, onion, known).await
    }

    /// Posts to `key`'s mailbox on the relays [`post_mailboxes`] picks, or on `only` of the
    /// list's; see [`Carrier::post_routed`]. The hint's own onion is dialled for it; a relay of the list is reached
    /// as the wallet reaches it.
    async fn post_to_list(
        &self,
        post: &Post<'_>,
        key: &PublicKey,
        (hint, list): (Option<&MailboxRelay>, Option<&[RelayEndpoint]>),
        only: Option<&str>,
    ) -> Result<Posted, PostError> {
        let relays = self.relays();
        let network = relays.epicbox.network();
        let hint_host = hint.map(|hint| host_text(&hint.endpoint));
        let mut targets = Vec::new();
        let hint_endpoint = hint.map(|hint| &hint.endpoint);
        let endpoints = match (list, only) {
            // A copy owed to one relay goes there, wherever it ranks.
            (Some(list), Some(_)) => list.to_vec(),
            (None, Some(_)) => mail_relays(relays, hint_endpoint),
            (list, None) => {
                let candidates = list.map_or_else(|| usable_relays(relays), <[_]>::to_vec);
                let health = relays.epicbox.pushed().health();
                post_mailboxes(candidates, hint_endpoint, &health, SystemTime::now())
            }
        };
        for endpoint in endpoints {
            let host = host_text(&endpoint);
            if only.is_some_and(|only| only != host) {
                continue;
            }
            let to = EpicboxAddress::new(
                *key,
                network,
                endpoint.domain().clone(),
                Some(endpoint.port()),
            );
            too_long(post.payload, &to)?;
            targets.push((host, to, endpoint));
        }
        if targets.is_empty() {
            return Err(PostError::NotSent(Unsent::NoRelay));
        }
        let mut missed = Vec::new();
        if only.is_none() {
            missed = self.leave_held(&mut targets, SystemTime::now());
        }
        let results = join_all(targets.iter().map(|(host, to, endpoint)| {
            let onion = hint
                .filter(|_| hint_host.as_ref() == Some(host))
                .and_then(|hint| hint.onion.as_deref());
            self.post_on(post, to, endpoint.clone(), onion, true)
        }))
        .await;
        let mut took = Vec::new();
        let mut uncertain = None;
        let mut refused: Option<PostError> = None;
        let mut not_sent = None;
        for ((host, _, _), result) in targets.into_iter().zip(results) {
            let Err(error) = result else {
                took.push(host);
                continue;
            };
            let wait = match &error {
                PostError::Refused { retry_after, .. } => *retry_after,
                _ => None,
            };
            // A relay that cancelled the transaction takes no copy of it again.
            let cancelled = matches!(
                error,
                PostError::Refused {
                    code: Some(RefusalCode::Cancelled),
                    ..
                }
            );
            if !cancelled {
                missed.push(Missed {
                    relay: host.clone(),
                    wait,
                });
            }
            match error {
                error @ PostError::Uncertain(_) => {
                    warn!(peer_relay = %host, error = %ErrorChain(&error), "post not answered");
                    uncertain.get_or_insert(error);
                }
                error @ PostError::Refused { .. } => {
                    warn!(peer_relay = %host, error = %ErrorChain(&error), "post refused");
                    // A passing refusal is kept over a final one, and one that names a wait
                    // over one that does not: the post goes again if any mailbox may take it.
                    let better = refused
                        .as_ref()
                        .is_none_or(|kept| refusal_rank(&error) > refusal_rank(kept));
                    if better {
                        refused = Some(error);
                    }
                }
                error => {
                    debug!(peer_relay = %host, error = %ErrorChain(&error), "post not sent");
                    not_sent.get_or_insert(error);
                }
            }
        }
        if !took.is_empty() {
            return Ok(Posted::Relays { took, missed });
        }
        match (uncertain, not_sent, refused) {
            (Some(error), _, _) | (None, Some(error), _) | (None, None, Some(error)) => Err(error),
            (None, None, None) => Err(PostError::NotSent(Unsent::NoRelay)),
        }
    }

    /// Posts to `to` on the relay at `endpoint`: on a session the carrier holds there, else on a
    /// short connection; once more on a short connection when the session wrote nothing. A
    /// relay not `known` is reached on a client that checks the host before it connects.
    async fn post_on(
        &self,
        post: &Post<'_>,
        to: &EpicboxAddress,
        endpoint: RelayEndpoint,
        onion: Option<&str>,
        known: bool,
    ) -> Result<Posted, PostError> {
        let relays = self.relays();
        let host = host_text(&endpoint);
        let parts = self.parts();
        let on_host = || parts.iter().filter(|part| part.host == host);
        let session = on_host()
            .find(|part| *part.session.state().borrow() == MuxState::Attached)
            .or_else(|| on_host().next())
            .map(|part| &part.session);
        let posted = match session {
            Some(session) => {
                let sent = match post.txid {
                    Some(txid) => session.post_tx(post.from, to, post.payload, txid).await,
                    None => session.post(post.from, to, post.payload).await,
                };
                match sent {
                    Ok(()) => return Ok(Posted::Session),
                    Err(MuxPostError::NotSent(error)) => {
                        debug!(peer_relay = %host, error = %ErrorChain(&error), "post not sent on mux/1, sent again");
                        Posted::ConnectionAfterSession
                    }
                    Err(MuxPostError::Unanswered) => {
                        return Err(PostError::Uncertain(Unanswered::Session));
                    }
                    Err(MuxPostError::Refused {
                        code,
                        retry_after,
                        description,
                    }) => {
                        let refused = PostError::refused(
                            code.map(RefusalCode::Mux),
                            retry_after,
                            description,
                        );
                        return Err(refused.at_mailbox(&host));
                    }
                    // A failure this layer does not know may have reached the relay.
                    Err(_) => return Err(PostError::Uncertain(Unanswered::Session)),
                }
            }
            None => Posted::Connection,
        };
        let client = if known {
            mailbox_client(relays, endpoint, onion)
        } else {
            client_for(relays, endpoint, false)
        };
        let sent = match post.txid {
            Some(txid) => client.post_tx(post.from, to, post.payload, txid).await,
            None => client.post(post.from, to, post.payload).await,
        };
        // The health record learns whether the mailbox could be reached, to hold posts back
        // from one that could not (see [`Carrier::leave_held`]).
        let failure = match &sent {
            Ok(()) | Err(MailboxError::Protocol(_)) => Some(None),
            Err(error @ MailboxError::Unreachable(_)) => Some(Some(ErrorChain(error).to_string())),
            Err(_) => None,
        };
        if let Some(failure) = failure {
            relays.epicbox.pushed().note_post(&host, failure.as_deref());
        }
        match sent {
            Ok(()) => Ok(posted),
            Err(error) => Err(connection_failure(error).at_mailbox(&host)),
        }
    }

    /// Takes out of `targets` the mailboxes that hold posts back at `now`, after a post could
    /// not reach them ([`MailboxHealth::post_retry_at`]), when one of the others may take the
    /// post: a dead mailbox then adds no connect timeout to the post. One with an attached
    /// session stays, as its post needs no connect. Returns them as missed, each with the time
    /// left on its hold, so that a copy is owed to it; when every target is held, none is taken
    /// out.
    fn leave_held(
        &self,
        targets: &mut Vec<(String, EpicboxAddress, RelayEndpoint)>,
        now: SystemTime,
    ) -> Vec<Missed> {
        let health = self.relays().epicbox.pushed().health();
        let parts = self.parts();
        let held = |host: &str| {
            let attached = parts.iter().any(|part| {
                part.host == host && *part.session.state().borrow() == MuxState::Attached
            });
            health
                .get(host)
                .and_then(|health| health.post_retry_at)
                .and_then(|until| until.duration_since(now).ok())
                .filter(|left| !left.is_zero() && !attached)
        };
        let holds: Vec<Option<Duration>> = targets.iter().map(|(host, _, _)| held(host)).collect();
        if holds.iter().all(Option::is_some) {
            return Vec::new();
        }
        let mut missed = Vec::new();
        let mut holds = holds.into_iter();
        targets.retain(|(host, _, _)| match holds.next().flatten() {
            Some(left) => {
                debug!(peer_relay = %host, wait_secs = left.as_secs(), "post not sent: the mailbox could not be reached before");
                missed.push(Missed {
                    relay: host.clone(),
                    wait: Some(left),
                });
                false
            }
            None => true,
        });
        missed
    }

    /// Cancels transaction `txid` of the payment `payment` as `from` on each relay of
    /// `endpoints`, all at once, with txcancel/1: on a session the carrier holds on the relay
    /// where its socket offers it, else on a short connection. Each cancel gets the client's
    /// connect and response timeouts. Returns, for each relay in order, whether it cancelled;
    /// a cancel that fails or runs out is logged with the payment. A relay that holds no copy
    /// answers as one that removed it.
    pub(super) async fn cancel_post(
        &self,
        payment: &SlateId,
        from: &Identity,
        txid: &EpicboxTxId,
        endpoints: Vec<RelayEndpoint>,
    ) -> Vec<bool> {
        let settings = self.relays().epicbox.settings();
        let limit = settings
            .connect_timeout
            .saturating_add(settings.response_timeout);
        let cancels = endpoints.into_iter().map(|endpoint| async move {
            let host = host_text(&endpoint);
            match tokio::time::timeout(limit, self.cancel_on(from, txid, endpoint)).await {
                Ok(Ok(())) => {
                    debug!(payment = %payment, peer_relay = %host, "copy of a post cancelled");
                    true
                }
                Ok(Err(error)) => {
                    warn!(payment = %payment, peer_relay = %host, error = %ErrorChain(&error), "copy of a post not cancelled");
                    false
                }
                Err(_) => {
                    warn!(payment = %payment, peer_relay = %host, "copy of a post not cancelled: the relay did not answer in time");
                    false
                }
            }
        });
        join_all(cancels).await
    }

    /// Cancels `txid` as `from` on the relay at `endpoint`; see [`Carrier::cancel_post`].
    async fn cancel_on(
        &self,
        from: &Identity,
        txid: &EpicboxTxId,
        endpoint: RelayEndpoint,
    ) -> Result<(), CancelFailed> {
        let relays = self.relays();
        let host = host_text(&endpoint);
        let parts = self.parts();
        let session = parts
            .iter()
            .filter(|part| part.host == host)
            .find(|part| *part.session.state().borrow() == MuxState::Attached)
            .map(|part| &part.session);
        if let Some(session) = session {
            match session.cancel(from, txid).await {
                Ok(MuxCancelOutcome::Cancelled | MuxCancelOutcome::NotFoundOrNotParticipant) => {
                    return Ok(());
                }
                // Nothing was sent, or the outcome is one this build does not know: the short
                // connection decides.
                Ok(_) => {}
                // The socket was lost, maybe before the cancel was sent; a second one is safe.
                Err(MuxError::NotConnected) => {}
                Err(error) => return Err(CancelFailed::Session(error)),
            }
        }
        let mut settings = relays.epicbox.settings().clone();
        settings.endpoint = endpoint;
        let client = EpicboxClient::new(settings, from.clone(), relays.epicbox.connector());
        let report = client
            .cancel(txid)
            .await
            .map_err(CancelFailed::Connection)?;
        match report.outcome {
            CancelOutcome::Unsupported { .. } => Err(CancelFailed::Unsupported),
            _ => Ok(()),
        }
    }
}

/// Why a copy of a post was not cancelled.
#[derive(Debug, Error)]
enum CancelFailed {
    #[error("on mux/1")]
    Session(#[source] MuxError),
    #[error("on a short connection")]
    Connection(#[source] ClientError),
    #[error("the relay has no cancel")]
    Unsupported,
}

/// What one post sends, to whichever relay.
struct Post<'a> {
    from: &'a Identity,
    payload: &'a str,
    txid: Option<&'a EpicboxTxId>,
}

/// Refuses a payload whose sealed text to `to` would be longer than a relay takes, before any
/// relay is chosen: every relay has the same limit.
fn too_long(payload: &str, to: &EpicboxAddress) -> Result<(), PostError> {
    // Past the longest message sealing takes at all, the payload's own length is the lower bound.
    let bytes = sealed_str_len(payload.len(), to).unwrap_or(payload.len());
    if bytes <= RELAY_MAX_STR_BYTES {
        return Ok(());
    }
    warn!(
        bytes,
        limit = RELAY_MAX_STR_BYTES,
        "message not posted: longer than a relay takes"
    );
    Err(PostError::TooLong {
        bytes,
        limit: RELAY_MAX_STR_BYTES,
    })
}

/// How a failed post on a short connection counts.
fn connection_failure(error: MailboxError) -> PostError {
    match error {
        MailboxError::Unreachable(_)
        | MailboxError::Local(_)
        // The greeting names the version before the post is written.
        | MailboxError::Protocol(ClientError::UnsupportedRelayVersion { .. }) => {
            PostError::NotSent(Unsent::Relay(ContactError::Relay(error)))
        }
        MailboxError::Protocol(ClientError::Relay { kind }) => {
            PostError::refused(Some(RefusalCode::Relay(kind)), None, None)
        }
        MailboxError::Protocol(ClientError::PostRefused {
            kind,
            description,
            retry_after,
            ..
        }) => PostError::refused(Some(RefusalCode::Relay(kind)), retry_after, description),
        MailboxError::Protocol(ClientError::TransactionCancelled { .. }) => {
            PostError::refused(Some(RefusalCode::Cancelled), None, None)
        }
        // A failure this layer does not know may have reached the relay.
        error => PostError::Uncertain(Unanswered::Connection(error)),
    }
}

/// A client on `endpoint`: the wallet's own client for a relay it knows, one that checks the
/// host before connecting for any other.
fn client_for(relays: &ContactRelays, endpoint: RelayEndpoint, known: bool) -> MailboxClient {
    if known {
        return mailbox_client(relays, endpoint, None);
    }
    let mut settings = relays.epicbox.settings().clone();
    settings.endpoint = endpoint;
    MailboxClient::new(
        settings,
        Arc::new(UntrustedHosts(relays.epicbox.connector())),
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::sync::Arc;

    use lepic_crypto::{PublicKey, SecretKey};
    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_epicbox::sessions::{Owner, PushedSessions};
    use lepic_epicbox::testing::client_timings;
    use lepic_epicbox::{
        ClientSettings, ClientTimings, Domain, FrameError, MuxOptions, Network, ProtocolVersion,
        Security,
    };
    use lepic_methods::epicbox::Epicbox;
    use lepic_store::{MailClass, MemoryStore, StoreKeys};

    use super::*;

    use crate::delivery::testing::{HOST, RELAY, Routed, Table, now, relays, row, until};
    use crate::delivery::testing::{address, attached, endpoint, identity};
    use crate::delivery::transport::Transport;
    use crate::{ContactRelays, RelayMode};

    /// A carrier holding an attached session on the test relay, and a 3.0.0 relay for
    /// `other.test`.
    async fn watching() -> (Carrier, MuxMockRelay, MockRelay, Arc<Routed>) {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, routed) = relays(&relay, &classic, &["other.test"]);
        let carrier = Carrier::new(relays);
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let table = Table::default().with("k1", identity(1));
        let set = vec![row("k1", MailClass::Contact, None)];
        carrier.claim(set, &table, &store, now()).await.unwrap();
        attached(carrier.relays()).await;
        (carrier, relay, classic, routed)
    }

    fn envelope() -> Envelope {
        Envelope::Mailbox {
            from: identity(1),
            payload: "armored".to_owned(),
            relay: None,
            txid: None,
            list: None,
        }
    }

    fn route(to: &EpicboxAddress) -> RouteEntry {
        RouteEntry {
            method: MethodId::Epicbox,
            value: to.to_string(),
        }
    }

    fn elsewhere(byte: u8) -> EpicboxAddress {
        EpicboxAddress::new(
            PublicKey::from_secret_key(&SecretKey::from_array([byte; 32]).unwrap()).unwrap(),
            Network::Mainnet,
            Domain::parse("other.test").unwrap(),
            None,
        )
    }

    #[tokio::test]
    async fn a_post_to_the_held_relay_goes_on_the_session() {
        let (carrier, relay, classic, _) = watching().await;
        let made = relay.sockets_made();

        let posted = carrier.post(&envelope(), &route(&address(2)), None).await;

        assert_eq!(posted.unwrap(), Posted::Session);
        assert_eq!(relay.received("PostSlate"), 1);
        assert_eq!(relay.sockets_made(), made);
        assert_eq!(classic.received("PostSlate"), 0);
    }

    #[tokio::test]
    async fn a_post_to_another_relay_goes_on_a_short_connection() {
        let (carrier, relay, classic, _) = watching().await;
        let to = elsewhere(2);

        let posted = carrier.post(&envelope(), &route(&to), None).await;

        assert_eq!(posted.unwrap(), Posted::Connection);
        assert_eq!(classic.pending(&to), 1);
        assert_eq!(relay.received("PostSlate"), 0);
    }

    #[tokio::test]
    async fn a_post_the_session_did_not_send_goes_once_on_a_short_connection() {
        let (carrier, relay, classic, routed) = watching().await;
        relay.offer_mux(false);
        relay.drop_sockets();
        let session = carrier.parts()[0].session.clone();
        session
            .state()
            .wait_for(|state| *state == MuxState::NotOffered)
            .await
            .unwrap();
        routed
            .classic_domains
            .lock()
            .unwrap()
            .insert("relay.test".to_owned());

        let posted = carrier.post(&envelope(), &route(&address(2)), None).await;

        assert_eq!(posted.unwrap(), Posted::ConnectionAfterSession);
        assert_eq!(classic.received("PostSlate"), 1);
        assert_eq!(classic.pending(&address(2)), 1);
        assert_eq!(relay.received("PostSlate"), 0);
    }

    #[tokio::test]
    async fn an_unanswered_post_is_not_sent_again() {
        let (carrier, relay, classic, routed) = watching().await;
        relay.ignore_posts(true);
        let (envelope, route) = (envelope(), route(&address(2)));

        let (posted, ()) = tokio::join!(carrier.post(&envelope, &route, None), async {
            relay
                .wait_until(|relay| relay.received("PostSlate") == 1)
                .await;
            // Any later connection to the relay would reach the 3.0.0 mock.
            routed
                .classic_domains
                .lock()
                .unwrap()
                .insert("relay.test".to_owned());
            relay.drop_sockets();
        });

        assert!(matches!(
            posted,
            Err(PostError::Uncertain(Unanswered::Session))
        ));
        assert_eq!(relay.received("PostSlate"), 1);
        assert_eq!(classic.received("PostSlate"), 0);
    }

    #[tokio::test]
    async fn a_refusal_on_the_session_carries_its_code() {
        let (carrier, relay, classic, _) = watching().await;
        relay.set_post_error(Some("rate_limited"), Some(7));

        let posted = carrier.post(&envelope(), &route(&address(2)), None).await;

        let Err(PostError::Refused {
            code: Some(RefusalCode::Mux(code)),
            retry_after,
            mailbox,
            retryable,
            ..
        }) = posted
        else {
            panic!("{posted:?}");
        };
        assert_eq!(code, MuxCode::RateLimited);
        assert_eq!(retry_after, Some(Duration::from_secs(7)));
        assert_eq!(mailbox.as_deref(), Some("relay.test:80"));
        assert!(retryable);
        assert_eq!(classic.received("PostSlate"), 0);
    }

    #[tokio::test]
    async fn a_refusal_on_a_short_connection_carries_its_kind() {
        let (carrier, _relay, classic, _) = watching().await;
        let to = elsewhere(2);
        classic.set_post_refused(&to);

        let posted = carrier.post(&envelope(), &route(&to), None).await;

        let Err(PostError::Refused {
            code: Some(RefusalCode::Relay(kind)),
            retry_after,
            retryable,
            ..
        }) = posted
        else {
            panic!("{posted:?}");
        };
        assert_eq!(kind, RelayErrorKind::InvalidRequest);
        assert_eq!(retry_after, None);
        assert!(!retryable);
        assert_eq!(classic.pending(&to), 0);
    }

    /// The longest payload whose sealed text to `to` a relay takes.
    fn longest_payload(to: &EpicboxAddress) -> usize {
        // Two hex digits a byte: the sealed text grows by two for each byte of payload.
        let empty = sealed_str_len(0, to).unwrap();
        let longest = (RELAY_MAX_STR_BYTES - empty) / 2;
        assert!(sealed_str_len(longest, to).unwrap() <= RELAY_MAX_STR_BYTES);
        assert!(sealed_str_len(longest + 1, to).unwrap() > RELAY_MAX_STR_BYTES);
        longest
    }

    fn sized(len: usize) -> Envelope {
        Envelope::Mailbox {
            from: identity(1),
            payload: "a".repeat(len),
            relay: None,
            txid: None,
            list: None,
        }
    }

    #[tokio::test]
    async fn a_message_at_the_relay_limit_is_posted_and_a_longer_one_is_refused_unsent() {
        let (carrier, relay, classic, _) = watching().await;
        let to = address(2);
        let longest = longest_payload(&to);

        let fits = carrier.post(&sized(longest), &route(&to), None).await;
        assert_eq!(fits.unwrap(), Posted::Session);
        assert_eq!(relay.received("PostSlate"), 1);

        let over = carrier.post(&sized(longest + 1), &route(&to), None).await;
        let Err(PostError::TooLong { bytes, limit }) = &over else {
            panic!("{over:?}");
        };
        assert_eq!(*limit, RELAY_MAX_STR_BYTES);
        assert_eq!(*bytes, sealed_str_len(longest + 1, &to).unwrap());
        assert_eq!(
            super::super::outbox::outcome(&over),
            super::super::outbox::Outcome::Refused
        );
        assert_eq!(relay.received("PostSlate"), 1);
        assert_eq!(classic.received("PostSlate"), 0);

        // Nor on a short connection to another relay.
        let other = elsewhere(2);
        let over = carrier
            .post(&sized(longest_payload(&other) + 1), &route(&other), None)
            .await;
        assert!(matches!(over, Err(PostError::TooLong { .. })), "{over:?}");
        assert_eq!(classic.pending(&other), 0);
    }

    #[tokio::test]
    async fn a_post_answered_with_a_broken_frame_is_uncertain() {
        let classic = MockRelay::new(Network::Mainnet);
        let timings = ClientTimings {
            response_timeout: Duration::from_millis(200),
            ..client_timings()
        };
        let carrier = Carrier::new(ContactRelays::new(
            Epicbox::new(
                ClientSettings::new(endpoint(), timings),
                Network::Mainnet,
                classic.connector(),
            ),
            RelayMode::Online,
        ));
        let to = elsewhere(2);
        classic.set_post_garbled(&to);

        let posted = carrier.post(&envelope(), &route(&to), None).await;

        assert!(
            matches!(posted, Err(PostError::Uncertain(Unanswered::Connection(_)))),
            "{posted:?}"
        );
        assert_eq!(classic.received("PostSlate"), 1);
        assert_eq!(classic.pending(&to), 1);
    }

    #[test]
    fn a_short_connection_failure_is_not_sent_only_before_the_post_is_written() {
        let not_sent = [
            MailboxError::Unreachable(ClientError::Closed),
            MailboxError::Local(ClientError::Closed),
            MailboxError::Protocol(ClientError::UnsupportedRelayVersion {
                version: ProtocolVersion {
                    major: 9,
                    minor: 0,
                    patch: 0,
                },
            }),
        ];
        for error in not_sent {
            let failure = connection_failure(error);
            assert!(matches!(failure, PostError::NotSent(_)), "{failure:?}");
        }
        let uncertain = [
            MailboxError::Unanswered(ClientError::Closed),
            MailboxError::Lost(ClientError::Closed),
            MailboxError::Protocol(ClientError::Frame(FrameError::MissingType)),
            MailboxError::MissingMessageId,
        ];
        for error in uncertain {
            let failure = connection_failure(error);
            assert!(
                matches!(failure, PostError::Uncertain(Unanswered::Connection(_))),
                "{failure:?}"
            );
        }
        let refused = connection_failure(MailboxError::Protocol(ClientError::Relay {
            kind: RelayErrorKind::InvalidRequest,
        }));
        assert!(matches!(
            refused,
            PostError::Refused {
                code: Some(RefusalCode::Relay(RelayErrorKind::InvalidRequest)),
                retry_after: None,
                retryable: false,
                ..
            }
        ));
        let full = connection_failure(MailboxError::Protocol(ClientError::PostRefused {
            kind: RelayErrorKind::InvalidRequest,
            description: Some("Rate limit exceeded; retry in 20 s.".to_owned()),
            retry_after: None,
            mailbox: None,
        }));
        let PostError::Refused {
            retry_after,
            retryable,
            ref reason,
            ..
        } = full
        else {
            panic!("{full:?}");
        };
        assert_eq!(retry_after, Some(Duration::from_secs(20)));
        assert!(retryable);
        assert_eq!(
            reason.as_deref(),
            Some("Rate limit exceeded; retry in 20 s.")
        );
        assert_eq!(
            full.at_mailbox("relay.test:80").to_string(),
            "mailbox relay.test:80 refused the post: Rate limit exceeded; retry in 20 s"
        );
    }

    #[tokio::test]
    async fn http_and_tor_routes_have_no_carrier() {
        let (carrier, relay, classic, _) = watching().await;
        let made = relay.sockets_made();
        for method in [MethodId::Http, MethodId::Tor] {
            let route = RouteEntry {
                method,
                value: "relay.test".to_owned(),
            };
            let posted = carrier.post(&envelope(), &route, None).await;
            assert!(matches!(posted, Err(PostError::NoCarrier(m)) if m == method));
        }
        assert_eq!(relay.sockets_made(), made);
        assert_eq!(relay.received("PostSlate"), 0);
        assert_eq!(classic.received("PostSlate"), 0);
    }

    fn key_route(byte: u8) -> RouteEntry {
        RouteEntry {
            method: MethodId::Epicbox,
            value: address(byte).key_text(),
        }
    }

    fn far(byte: u8, port: u16) -> EpicboxAddress {
        let key = *address(byte).public_key();
        EpicboxAddress::new(
            key,
            Network::Mainnet,
            Domain::parse("far.test").unwrap(),
            Some(port),
        )
    }

    #[tokio::test]
    async fn a_key_post_one_relay_takes_and_one_refuses_is_posted_and_owed_to_the_other() {
        let classic = MockRelay::new(Network::Mainnet);
        classic.set_relays_apart(true);
        classic.set_domain_refused("far.test");
        let carrier = Carrier::new(
            ContactRelays::new(
                Epicbox::new(
                    ClientSettings::new(endpoint(), client_timings()),
                    Network::Mainnet,
                    classic.connector(),
                ),
                RelayMode::Online,
            )
            .with_added(vec![RelayEndpoint::new(
                Domain::parse("far.test").unwrap(),
                Some(80),
                Security::Plain,
            )]),
        );

        let posted = carrier.post(&envelope(), &key_route(2), None).await;

        assert_eq!(
            posted.unwrap(),
            Posted::Relays {
                took: vec![HOST.to_owned()],
                missed: vec![Missed {
                    relay: "far.test:80".to_owned(),
                    wait: None,
                }],
            }
        );
        assert_eq!(classic.received("PostSlate"), 2);
        assert_eq!(classic.pending(&address(2)), 1);
        assert_eq!(classic.pending(&far(2, 80)), 0);
    }

    #[tokio::test]
    async fn a_relay_without_mux_is_never_posted_to() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.offer_mux(false);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, _) = relays(&relay, &classic, &["far.test"]);
        let relays = relays.with_added(vec![RelayEndpoint::new(
            Domain::parse("far.test").unwrap(),
            None,
            Security::Tls,
        )]);
        let endpoint = relays.epicbox.settings().endpoint.clone();
        relays
            .epicbox
            .pushed()
            .get_or_start(HOST, "wallet", Owner::Payments, || {
                mailbox_client(&relays, endpoint, None)
                    .start_mux_queued(Vec::new(), MuxOptions::default())
            })
            .unwrap();
        until(|| relays.epicbox.pushed().supports_push(HOST).is_some()).await;
        let carrier = Carrier::new(relays);

        let posted = carrier.post(&envelope(), &key_route(2), None).await;

        assert_eq!(
            posted.unwrap(),
            Posted::Relays {
                took: vec!["far.test:443".to_owned()],
                missed: Vec::new(),
            }
        );
        assert_eq!(relay.received("PostSlate"), 0);
        assert_eq!(classic.pending(&far(2, 443)), 1);
    }

    #[tokio::test]
    async fn a_key_post_no_relay_answers_is_uncertain() {
        let classic = MockRelay::new(Network::Mainnet);
        let timings = ClientTimings {
            response_timeout: Duration::from_millis(200),
            ..client_timings()
        };
        classic.set_domain_unanswered(RELAY);
        let carrier = Carrier::new(ContactRelays::new(
            Epicbox::new(
                ClientSettings::new(endpoint(), timings),
                Network::Mainnet,
                classic.connector(),
            ),
            RelayMode::Online,
        ));

        let posted = carrier.post(&envelope(), &key_route(2), None).await;

        assert!(matches!(posted, Err(PostError::Uncertain(_))), "{posted:?}");
    }

    fn plain(domain: &str) -> RelayEndpoint {
        RelayEndpoint::new(Domain::parse(domain).unwrap(), Some(80), Security::Plain)
    }

    fn hosts(endpoints: &[RelayEndpoint]) -> Vec<String> {
        endpoints.iter().map(host_text).collect()
    }

    /// Two shipped mailboxes, then two added, as the wallet's list orders them.
    fn four() -> Vec<RelayEndpoint> {
        ["s1.test", "s2.test", "a1.test", "a2.test"]
            .into_iter()
            .map(plain)
            .collect()
    }

    #[test]
    fn a_post_goes_to_three_mailboxes_the_shipped_first_when_health_is_equal() {
        let picked = post_mailboxes(four(), None, &BTreeMap::new(), SystemTime::now());

        assert_eq!(hosts(&picked), ["s1.test:80", "s2.test:80", "a1.test:80"]);
    }

    #[test]
    fn a_mailbox_with_failures_gives_its_place_to_a_healthier_one() {
        let sessions = PushedSessions::default();
        sessions.note_post("s1.test:80", Some("connection refused"));
        sessions.note_post("a1.test:80", None);

        let picked = post_mailboxes(four(), None, &sessions.health(), SystemTime::now());

        assert_eq!(hosts(&picked), ["s2.test:80", "a1.test:80", "a2.test:80"]);
        // Once the hold is over the failure still ranks it after the others.
        let later = SystemTime::now() + Duration::from_secs(3600);
        let picked = post_mailboxes(four(), None, &sessions.health(), later);
        assert_eq!(hosts(&picked), ["s2.test:80", "a1.test:80", "a2.test:80"]);
    }

    #[test]
    fn an_answer_goes_to_the_mailbox_its_payment_was_read_on_and_two_others() {
        let sessions = PushedSessions::default();
        // The mailbox the payment was read on goes first, whatever its health.
        sessions.note_post("a2.test:80", Some("connection refused"));
        sessions.note_post("s2.test:80", Some("connection refused"));
        let read_on = plain("a2.test");

        let picked = post_mailboxes(
            four(),
            Some(&read_on),
            &sessions.health(),
            SystemTime::now(),
        );

        assert_eq!(hosts(&picked), ["a2.test:80", "s1.test:80", "a1.test:80"]);
        // A mailbox outside the list, as a contact's card may name, is first too.
        let card = plain("card.test");
        let picked = post_mailboxes(four(), Some(&card), &BTreeMap::new(), SystemTime::now());
        assert_eq!(hosts(&picked), ["card.test:80", "s1.test:80", "s2.test:80"]);
    }

    /// The health of `hosts`, each marked as the sessions mark a mailbox that answered the
    /// greeting without mux/1.
    fn without_mux(hosts: &[&str]) -> BTreeMap<String, MailboxHealth> {
        let sessions = PushedSessions::default();
        for host in hosts {
            sessions.note_post(host, None);
        }
        let mut health = sessions.health();
        for host in hosts {
            health.get_mut(*host).unwrap().push = Some(false);
        }
        health
    }

    #[test]
    fn a_mailbox_without_mux_is_never_picked() {
        let health = without_mux(&["s1.test:80", "a1.test:80"]);

        let picked = post_mailboxes(four(), None, &health, SystemTime::now());

        // The next of the list takes the place, and the order of the others is kept.
        assert_eq!(hosts(&picked), ["s2.test:80", "a2.test:80"]);
    }

    #[test]
    fn a_mailbox_whose_mux_is_not_known_stays_eligible_in_its_place() {
        let sessions = PushedSessions::default();
        // A record without an answer about mux/1, and one that offered it.
        sessions.note_post("s1.test:80", None);
        let mut health = sessions.health();
        assert_eq!(health["s1.test:80"].push, None);
        health.get_mut("s1.test:80").unwrap().push = Some(true);
        health.insert("s2.test:80".to_owned(), health["s1.test:80"].clone());
        health.get_mut("s2.test:80").unwrap().push = None;

        let picked = post_mailboxes(four(), None, &health, SystemTime::now());

        assert_eq!(hosts(&picked), ["s1.test:80", "s2.test:80", "a1.test:80"]);
    }

    #[test]
    fn an_answer_skips_a_read_on_mailbox_without_mux_and_its_extras_too() {
        let health = without_mux(&["a2.test:80", "s1.test:80"]);
        let read_on = plain("a2.test");

        let picked = post_mailboxes(four(), Some(&read_on), &health, SystemTime::now());

        assert_eq!(hosts(&picked), ["s2.test:80", "a1.test:80"]);
        // Every mailbox lacking it leaves nothing to post to.
        let all = without_mux(&["s1.test:80", "s2.test:80", "a1.test:80", "a2.test:80"]);
        assert!(post_mailboxes(four(), Some(&read_on), &all, SystemTime::now()).is_empty());
    }

    #[test]
    fn a_short_list_is_posted_to_whole() {
        let picked = post_mailboxes(
            vec![plain("s1.test")],
            Some(&plain("s1.test")),
            &BTreeMap::new(),
            SystemTime::now(),
        );

        assert_eq!(hosts(&picked), ["s1.test:80"]);
    }

    #[tokio::test]
    async fn an_answer_is_posted_to_its_read_on_mailbox_and_two_others_of_four() {
        let classic = MockRelay::new(Network::Mainnet);
        classic.set_relays_apart(true);
        let carrier = Carrier::new(
            ContactRelays::new(
                Epicbox::new(
                    ClientSettings::new(endpoint(), client_timings()),
                    Network::Mainnet,
                    classic.connector(),
                ),
                RelayMode::Online,
            )
            .with_added(
                ["a.test", "b.test", "c.test"]
                    .into_iter()
                    .map(plain)
                    .collect(),
            ),
        );
        carrier
            .relays()
            .epicbox
            .pushed()
            .note_post("a.test:80", Some("connection refused"));
        let envelope = Envelope::Mailbox {
            from: identity(1),
            payload: "armored".to_owned(),
            relay: Some(MailboxRelay {
                endpoint: plain("c.test"),
                onion: None,
            }),
            txid: None,
            list: None,
        };

        let posted = carrier.post(&envelope, &key_route(2), None).await;

        assert_eq!(
            posted.unwrap(),
            Posted::Relays {
                took: vec![
                    "c.test:80".to_owned(),
                    HOST.to_owned(),
                    "b.test:80".to_owned()
                ],
                missed: Vec::new(),
            }
        );
        assert_eq!(classic.received("PostSlate"), 3);
    }

    /// A mailbox that could not be reached is recorded, and the next post leaves it out while
    /// it holds posts back: no connect is tried, and a copy is owed to it for after its hold.
    /// Once the others are held too, every mailbox is tried.
    #[tokio::test]
    async fn a_dead_mailbox_is_held_back_and_owed_a_copy() {
        let classic = MockRelay::new(Network::Mainnet);
        classic.set_relays_apart(true);
        classic.set_domain_down("dead.test", true);
        let carrier = Carrier::new(
            ContactRelays::new(
                Epicbox::new(
                    ClientSettings::new(endpoint(), client_timings()),
                    Network::Mainnet,
                    classic.connector(),
                ),
                RelayMode::Online,
            )
            .with_added(vec![plain("dead.test"), plain("b.test")]),
        );
        let envelope = Envelope::Mailbox {
            from: identity(1),
            payload: "armored".to_owned(),
            relay: None,
            txid: None,
            list: None,
        };
        let health = || {
            carrier
                .relays()
                .epicbox
                .pushed()
                .health()
                .get("dead.test:80")
                .cloned()
                .unwrap()
        };

        let first = carrier.post(&envelope, &key_route(2), None).await.unwrap();

        let Posted::Relays { took, missed } = first else {
            panic!("{first:?}");
        };
        assert_eq!(took, [HOST.to_owned(), "b.test:80".to_owned()]);
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0].relay, "dead.test:80");
        assert_eq!(missed[0].wait, None);
        assert_eq!(health().post_failures, 1);
        assert!(health().last_error.is_some());
        let held_until = health().post_retry_at.unwrap();
        assert!(held_until > SystemTime::now());

        let second = carrier.post(&envelope, &key_route(2), None).await.unwrap();

        let Posted::Relays { took, missed } = second else {
            panic!("{second:?}");
        };
        assert_eq!(took, [HOST.to_owned(), "b.test:80".to_owned()]);
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0].relay, "dead.test:80");
        let wait = missed[0].wait.unwrap();
        assert!(
            !wait.is_zero() && wait <= Duration::from_secs(30),
            "{wait:?}"
        );
        // No connect was tried: the failure count and the hold are those of the first post.
        assert_eq!(health().post_failures, 1);
        assert_eq!(health().post_retry_at, Some(held_until));
        assert_eq!(classic.received("PostSlate"), 4);

        // A copy owed to the dead mailbox alone is tried, whatever its hold.
        let copy = carrier
            .post(&envelope, &key_route(2), Some("dead.test:80"))
            .await;
        assert!(matches!(copy, Err(PostError::NotSent(_))), "{copy:?}");
        assert_eq!(health().post_failures, 2);

        // A mailbox that answers clears its record.
        classic.set_domain_down("dead.test", false);
        carrier
            .post(&envelope, &key_route(2), Some("dead.test:80"))
            .await
            .unwrap();
        assert_eq!((health().post_failures, health().post_retry_at), (0, None));
    }

    #[tokio::test]
    async fn a_key_post_names_its_txid_to_every_relay() {
        let classic = MockRelay::new(Network::Mainnet);
        classic.set_version(Some("3.1.0"));
        classic.set_relays_apart(true);
        let carrier = Carrier::new(
            ContactRelays::new(
                Epicbox::new(
                    ClientSettings::new(endpoint(), client_timings()),
                    Network::Mainnet,
                    classic.connector(),
                ),
                RelayMode::Online,
            )
            .with_added(vec![RelayEndpoint::new(
                Domain::parse("far.test").unwrap(),
                Some(80),
                Security::Plain,
            )]),
        );
        let txid = EpicboxTxId::generate().unwrap();
        let envelope = Envelope::Mailbox {
            from: identity(1),
            payload: "armored".to_owned(),
            relay: None,
            txid: Some(txid.clone()),
            list: None,
        };

        let posted = carrier.post(&envelope, &key_route(2), None).await;

        assert_eq!(
            posted.unwrap(),
            Posted::Relays {
                took: vec![HOST.to_owned(), "far.test:80".to_owned()],
                missed: Vec::new(),
            }
        );
        // One mock plays both relays: the txid is recorded once, the copies are two.
        assert_eq!(classic.posted_txids(), vec![txid.as_str().to_owned()]);
        assert_eq!(classic.pending(&address(2)), 1);
        assert_eq!(classic.pending(&far(2, 80)), 1);
    }
}
