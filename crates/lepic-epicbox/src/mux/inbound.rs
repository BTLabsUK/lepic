// SPDX-License-Identifier: Apache-2.0
//! What the relay sends on a served socket: answers to requests, pushed mail and detaches.

use std::sync::PoisonError;
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::client::ClientError;
use crate::frame::bounded_description;
use crate::mailbox::{Handled, MailboxMessage, RelayedMail, open_message};
use crate::mux_frame::{
    AttachedFrame, CancelledFrame, DetachReason, DetachedFrame, ErrorFrame, ForeignCancelledFrame,
    MAX_ATTACH_PER_FRAME, MailFrame, MuxCode, MuxRelayFrame, OkFrame, TransactionCancelledFrame,
};
use crate::session::deadline_after;

use super::counters::bump;
use super::link::{Link, Lost, PendingKind};
use super::manager::Manager;
use super::{Delivery, MuxCancelOutcome, MuxError, MuxEvent, MuxPostError, MuxWaiting};

/// The longest `retry_after` honoured, whatever the relay says.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// How long an acknowledgement or an attach answered `internal` waits before it is sent
/// again. An attach waits twice as long each further time, up to [`INTERNAL_RETRY_MAX`].
const INTERNAL_RETRY: Duration = Duration::from_secs(1);

/// The longest wait before a mailbox answered `internal` is attached again.
const INTERNAL_RETRY_MAX: Duration = Duration::from_secs(60);

impl Manager {
    pub(super) async fn handle_text(&mut self, link: &mut Link, text: &str) -> Result<(), Lost> {
        let frame = match MuxRelayFrame::from_json(text) {
            Ok(frame) => frame,
            Err(error) => {
                debug!(error = %ErrorChain(&error), "epicbox mux frame ignored");
                return Ok(());
            }
        };
        match frame {
            MuxRelayFrame::Ok(ok) => self.on_ok(link, &ok),
            MuxRelayFrame::Attached(attached) => self.on_attached(link, attached).await,
            MuxRelayFrame::Mail(mail) => self.on_mail(link, mail).await,
            MuxRelayFrame::Detached(detached) => self.on_detached(link, &detached),
            MuxRelayFrame::Error(error) => self.on_error(link, error),
            MuxRelayFrame::Cancelled(cancelled) => {
                self.on_cancelled(link, &cancelled);
                Ok(())
            }
            MuxRelayFrame::ForeignCancelled(cancelled) => {
                self.on_foreign_cancelled(link, cancelled).await
            }
            MuxRelayFrame::TransactionCancelled(done) => {
                Self::on_transaction_cancelled(link, &done);
                Ok(())
            }
            // A pushed cancellation whose txid is not an id: nothing to apply or acknowledge.
            MuxRelayFrame::Unknown { type_name } if type_name == "Cancelled" => {
                warn!("epicbox mux cancellation without a valid transaction id dropped");
                Ok(())
            }
            MuxRelayFrame::Challenge | MuxRelayFrame::Unknown { .. } | MuxRelayFrame::Keepalive => {
                Ok(())
            }
        }
    }

    fn on_ok(&self, link: &mut Link, ok: &OkFrame) -> Result<(), Lost> {
        let Some(pending) = link.take_pending(ok.reference.as_deref()) else {
            debug!("epicbox mux ok without a matching request ignored");
            return Ok(());
        };
        match pending.kind {
            PendingKind::Waiting => {
                link.probe_outstanding = false;
                if Self::stalled(link, ok) {
                    bump(&self.shared.counters.stall_reconnects);
                    warn!("epicbox relay holds waiting mail it does not push, reconnecting");
                    return Err(Lost::Stalled);
                }
            }
            PendingKind::Cancel { reply, .. } => {
                // An `Ok` to a `CancelTx`: no action was taken (unknown id or not a participant).
                let _ = reply.send(Ok(MuxCancelOutcome::NotFoundOrNotParticipant));
            }
            PendingKind::Post { reply } => reply.answer(Ok(())),
            PendingKind::Asked { reply } => {
                let waiting = ok
                    .waiting
                    .iter()
                    .flatten()
                    .filter_map(|(key, count)| self.keys.get(key).map(|index| (*index, *count)))
                    .collect();
                let _ = reply.send(Ok(MuxWaiting {
                    waiting,
                    inflight: ok.inflight,
                    held: ok.held,
                }));
            }
            _ => {}
        }
        Ok(())
    }

    /// The relay confirmed a `CancelTx`.
    fn on_transaction_cancelled(link: &mut Link, done: &TransactionCancelledFrame) {
        let Some(pending) = link.take_pending(done.reference.as_deref()) else {
            debug!("epicbox mux transaction cancelled without a matching request ignored");
            return;
        };
        if let PendingKind::Cancel { reply, .. } = pending.kind {
            let _ = reply.send(Ok(MuxCancelOutcome::Cancelled));
        }
    }

    /// The other party cancelled a transaction: surfaced as an event, acknowledged only when the
    /// consumer says it applied it. Ignored on a socket that did not negotiate `txcancel/1`.
    fn on_cancelled(&self, link: &Link, frame: &CancelledFrame) {
        let Some(&index) = self.keys.get(&frame.mailbox) else {
            debug!("epicbox mux cancellation for an unknown mailbox ignored");
            return;
        };
        if !link.cancel || !link.attached.contains(&index) {
            debug!(
                mailbox = index,
                "epicbox mux cancellation for a mailbox not attached ignored"
            );
            return;
        }
        bump(&self.shared.counters.cancelled);
        info!(
            mailbox = index,
            "epicbox transaction cancelled by the other party"
        );
        self.emit(MuxEvent::Cancelled {
            mailbox: index,
            txid: frame.epicboxtxid.clone(),
        });
    }

    /// The other party cancelled a transaction whose id Epicmail takes but no wallet of LEPIC
    /// makes: nothing of ours to apply, so it is acknowledged at once with the id as the relay
    /// sent it, or the relay would push it again on every attach. The consumer never sees it.
    async fn on_foreign_cancelled(
        &self,
        link: &mut Link,
        frame: ForeignCancelledFrame,
    ) -> Result<(), Lost> {
        let Some(&index) = self.keys.get(&frame.mailbox) else {
            debug!("epicbox mux cancellation for an unknown mailbox ignored");
            return Ok(());
        };
        debug!(
            mailbox = index,
            "epicbox mux cancellation of a transaction id not of ours acknowledged"
        );
        self.send_cancel_ack(link, index, frame.epicboxtxid).await
    }

    /// Whether this probe is the second in a row that finds waiting mail with nothing in flight
    /// or held, and no mail arrived since the first.
    fn stalled(link: &mut Link, ok: &OkFrame) -> bool {
        let waiting = ok
            .waiting
            .as_ref()
            .is_some_and(|waiting| waiting.values().any(|count| *count > 0));
        if !(waiting && ok.inflight == 0 && ok.held == 0 && link.inflight.is_empty()) {
            link.stuck_at = None;
            return false;
        }
        match link.stuck_at {
            Some(mails) if mails == link.mails_seen => true,
            _ => {
                link.stuck_at = Some(link.mails_seen);
                false
            }
        }
    }

    async fn on_attached(&mut self, link: &mut Link, frame: AttachedFrame) -> Result<(), Lost> {
        let Some(pending) = link.take_pending(frame.reference.as_deref()) else {
            debug!("epicbox mux attached without a matching request ignored");
            return Ok(());
        };
        let resumed = matches!(pending.kind, PendingKind::Resume);
        // Every frame of an attach is sent before the first answer, so a later frame may still
        // be host-bound after an earlier answer cleared the host: ask the frame, not the link.
        let bound = matches!(pending.kind, PendingKind::Attach { bound: true, .. });
        if let Some(token) = frame.token {
            self.token = Some(token);
        }
        let mut unwanted = Vec::new();
        let mut unbound = Vec::new();
        for entry in &frame.mailboxes {
            let Some(&index) = self.keys.get(&entry.mailbox) else {
                if entry.ok {
                    unwanted.push(entry.mailbox.clone());
                }
                continue;
            };
            link.asked.insert(index);
            if entry.ok {
                link.attached.insert(index);
                link.attach_backoff.remove(&index);
                self.emit(MuxEvent::Attached {
                    mailbox: index,
                    waiting: entry.waiting.unwrap_or_default(),
                });
            } else if entry.code == Some(MuxCode::WrongHost) && bound {
                // The mailbox does not answer to the name it was dialled by (an onion or an
                // alias it does not list): sign the bare challenge for the rest of the socket.
                unbound.push(index);
            } else if entry.code == Some(MuxCode::Internal) {
                // A store error: the relay may even have attached it. Not a refusal; the same
                // socket asks again after a back-off.
                let wait = link.retry_attach_later(index, INTERNAL_RETRY, INTERNAL_RETRY_MAX);
                info!(
                    mailbox = index,
                    retry_in_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    "epicbox relay could not attach a mailbox, retrying"
                );
            } else if !resumed {
                let code = or_unspecified(entry.code.clone());
                warn!(mailbox = index, code = %code, "epicbox relay refused a mailbox");
                self.emit(MuxEvent::Refused {
                    mailbox: index,
                    code,
                });
            }
        }
        if !unbound.is_empty() {
            info!(
                mailboxes = unbound.len(),
                "epicbox relay does not answer to the host it was dialled by, attaching unbound"
            );
            link.attach_host = None;
            self.attach(link, unbound).await?;
        }
        if resumed {
            link.resume_pending = false;
            self.emit(MuxEvent::Resumed);
            // The session the relay held may differ from ours: sign for what it dropped.
            let missing = self.unattached(link);
            self.attach(link, missing).await?;
        }
        for chunk in unwanted.chunks(MAX_ATTACH_PER_FRAME) {
            link.detach(chunk.to_vec()).await?;
        }
        self.mark_ready(link);
        Ok(())
    }

    async fn on_mail(&mut self, link: &mut Link, mail: MailFrame) -> Result<(), Lost> {
        let Some(&index) = self.keys.get(&mail.mailbox) else {
            debug!("epicbox mux mail for an unknown mailbox ignored");
            return Ok(());
        };
        if !link.attached.contains(&index) {
            if link.asked.contains(&index) {
                // Asked for and answered `internal`: the relay attached it after all. A hold
                // frees its in-flight place; the mail comes again once the mailbox attaches.
                debug!(
                    mailbox = index,
                    "epicbox mux mail for a mailbox not attached yet held"
                );
                return self.hold(link, mail.id).await;
            }
            debug!(
                mailbox = index,
                "epicbox mux mail for a mailbox not attached ignored"
            );
            return Ok(());
        }
        bump(&self.shared.counters.mails);
        link.mails_seen = link.mails_seen.saturating_add(1);
        if link.inflight.contains_key(&mail.id) {
            return Ok(());
        }
        if link.inflight.len() >= link.limits.inflight_per_socket {
            // Not handed out, and not forgotten: a hold frees the relay's slot for it.
            warn!("epicbox relay pushed more mail than its in-flight limit, message held");
            return self.hold(link, mail.id).await;
        }
        let size = mail_size(&mail);
        if link.inflight.would_overflow(size) {
            // The same as one past the count: held, and offered again when the hold ends.
            warn!(
                inflight_bytes = link.inflight.bytes(),
                size, "epicbox mail in flight past the byte cap, message held"
            );
            return self.hold(link, mail.id).await;
        }
        let id = mail.id.clone();
        if self.stored.contains(&id) {
            // Stored before, and the acknowledgement was lost: acknowledge again.
            bump(&self.shared.counters.duplicates);
            link.inflight.insert(id.clone(), index, size);
            return self.queue_ack(link, id).await;
        }
        let Some(entry) = self.entries.get(&index) else {
            return Ok(());
        };
        let content = open_message(&entry.identity, &mail.from, &mail.str, &mail.signature);
        let mut message = MailboxMessage::new(index, id.clone(), content)
            .with_epicbox_txid(mail.epicboxtxid.clone());
        if matches!(self.delivery, Delivery::Queued) {
            message = message.with_relayed(RelayedMail {
                from: mail.from.clone(),
                str: mail.str.clone(),
                signature: mail.signature.clone(),
            });
        }
        link.inflight.insert(id.clone(), index, size);
        let handler = match &mut self.delivery {
            Delivery::Inline(handler) => handler.get_mut().unwrap_or_else(PoisonError::into_inner),
            Delivery::Queued => {
                self.shared.push(message);
                return Ok(());
            }
        };
        match handler.handle(message).await {
            Handled::Stored => {
                self.stored.insert(id.clone());
                self.queue_ack(link, id).await
            }
            Handled::Later => self.hold(link, id).await,
        }
    }

    fn on_detached(&mut self, link: &mut Link, detached: &DetachedFrame) -> Result<(), Lost> {
        let index = self.keys.get(&detached.mailbox).copied();
        match &detached.reason {
            DetachReason::Replaced => {
                if let Some(index) = index {
                    // Another socket holds the mailbox. Taking it back at once would make two
                    // installs trade it in a loop, so it is left to the other one for a while.
                    let until = deadline_after(self.options.replaced_hold_off);
                    self.replaced.insert(detached.mailbox.clone(), until);
                    self.shared
                        .layout()
                        .replaced
                        .insert(detached.mailbox.clone());
                    link.forget_mailbox(index);
                    self.shared.purge(Some(index));
                    info!(
                        mailbox = index,
                        "epicbox mailbox replaced by another socket"
                    );
                    self.emit(MuxEvent::Replaced { mailbox: index });
                }
                Ok(())
            }
            DetachReason::Shutdown => Err(Lost::Shutdown),
            DetachReason::Limit => {
                if let Some(index) = index {
                    link.forget_mailbox(index);
                    self.shared.purge(Some(index));
                    warn!(
                        mailbox = index,
                        "epicbox relay stopped delivering a mailbox: limit"
                    );
                    self.emit(MuxEvent::Limit { mailbox: index });
                }
                Ok(())
            }
            DetachReason::Other(_) => {
                debug!("epicbox mux detached for an unknown reason ignored");
                Ok(())
            }
        }
    }

    fn on_error(&mut self, link: &mut Link, error: ErrorFrame) -> Result<(), Lost> {
        let retry_after =
            Duration::from_secs(error.retry_after.unwrap_or_default()).min(MAX_RETRY_AFTER);
        let code = error.code.clone();
        let Some(pending) = link.take_pending(error.reference.as_deref()) else {
            return match code {
                Some(MuxCode::ClassicOnly | MuxCode::NotMux) => {
                    Err(Lost::Client(ClientError::Relay { kind: error.kind }))
                }
                Some(MuxCode::RateLimited) => Err(Lost::RateLimited { retry_after }),
                _ => {
                    debug!(code = ?code, "epicbox mux error without a matching request ignored");
                    Ok(())
                }
            };
        };
        match pending.kind {
            PendingKind::Resume => {
                link.resume_pending = false;
                if code == Some(MuxCode::RateLimited) {
                    return Err(Lost::RateLimited { retry_after });
                }
                bump(&self.shared.counters.token_unknown);
                info!(code = ?code, "epicbox resume refused, attaching with signatures");
                self.token = None;
                // Sending needs `await`: the serve loop picks the fallback up after this frame.
                link.fallback_attach = true;
                Ok(())
            }
            PendingKind::Attach { indexes, .. } => {
                if code == Some(MuxCode::RateLimited) {
                    return Err(Lost::RateLimited { retry_after });
                }
                if code == Some(MuxCode::Internal) {
                    for index in indexes {
                        let wait =
                            link.retry_attach_later(index, INTERNAL_RETRY, INTERNAL_RETRY_MAX);
                        info!(
                            mailbox = index,
                            retry_in_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                            "epicbox relay could not attach a mailbox, retrying"
                        );
                    }
                    self.mark_ready(link);
                    return Ok(());
                }
                let code = or_unspecified(code);
                for index in indexes {
                    self.emit(MuxEvent::Refused {
                        mailbox: index,
                        code: code.clone(),
                    });
                }
                self.mark_ready(link);
                Ok(())
            }
            PendingKind::Ack { ids } => {
                let wait = match code {
                    Some(MuxCode::RateLimited) => retry_after.max(self.options.ack_window),
                    Some(MuxCode::Internal) => INTERNAL_RETRY,
                    _ => return Ok(()),
                };
                link.acks.extend(ids);
                let due = deadline_after(wait);
                link.ack_due = Some(link.ack_due.map_or(due, |current| current.max(due)));
                Ok(())
            }
            PendingKind::Waiting => {
                link.probe_outstanding = false;
                if code == Some(MuxCode::RateLimited) {
                    self.waiting.pause(Instant::now(), retry_after);
                }
                Ok(())
            }
            PendingKind::Cancel { reply, .. } => {
                let _ = reply.send(Err(MuxError::Refused { code }));
                Ok(())
            }
            PendingKind::Asked { reply } => {
                if code == Some(MuxCode::RateLimited) {
                    self.waiting.pause(Instant::now(), retry_after);
                }
                let _ = reply.send(Err(MuxError::Refused { code }));
                Ok(())
            }
            // A refused post leaves the socket as it is, `rate_limited` included.
            PendingKind::Post { reply } => {
                let retry_after = error
                    .retry_after
                    .map(|seconds| Duration::from_secs(seconds).min(MAX_RETRY_AFTER));
                let description = bounded_description(&error.description);
                reply.answer(Err(MuxPostError::Refused {
                    code,
                    retry_after,
                    description,
                }));
                Ok(())
            }
            PendingKind::Hold | PendingKind::Detach | PendingKind::CancelAck => {
                debug!(code = ?code, "epicbox mux request refused");
                Ok(())
            }
        }
    }
}

/// The code of a refusal, or `unspecified` when the relay gave none.
fn or_unspecified(code: Option<MuxCode>) -> MuxCode {
    code.unwrap_or_else(|| MuxCode::Other("unspecified".to_owned()))
}

/// The bytes a pushed mail keeps in memory while in flight: its sealed payload, sender and
/// signature. A queued session keeps the opened content as well, of about the same size.
fn mail_size(mail: &MailFrame) -> usize {
    mail.str
        .len()
        .saturating_add(mail.from.len())
        .saturating_add(mail.signature.len())
}
