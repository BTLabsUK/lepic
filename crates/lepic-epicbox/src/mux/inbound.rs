// SPDX-License-Identifier: Apache-2.0
//! What the relay sends on a served socket: answers to requests, pushed mail and detaches.

use std::sync::PoisonError;
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tracing::{debug, info, warn};

use crate::client::ClientError;
use crate::mailbox::{Handled, MailboxMessage, RelayedMail, open_message};
use crate::mux_frame::{
    AttachedFrame, DetachReason, DetachedFrame, ErrorFrame, MAX_ATTACH_PER_FRAME, MailFrame,
    MuxClientFrame, MuxCode, MuxRelayFrame, OkFrame,
};
use crate::session::deadline_after;

use super::counters::bump;
use super::link::{Link, Lost, PendingKind};
use super::manager::Manager;
use super::{Delivery, MuxEvent};

/// The longest `retry_after` honoured, whatever the relay says.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// How long an acknowledgement of an `internal` error waits before it is sent again.
const INTERNAL_RETRY: Duration = Duration::from_secs(1);

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
        if let PendingKind::Waiting = pending.kind {
            link.probe_outstanding = false;
            if Self::stalled(link, ok) {
                bump(&self.shared.counters.stall_reconnects);
                warn!("epicbox relay holds waiting mail it does not push, reconnecting");
                return Err(Lost::Stalled);
            }
        }
        Ok(())
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
        if let Some(token) = frame.token {
            self.token = Some(token);
        }
        let mut unwanted = Vec::new();
        for entry in &frame.mailboxes {
            let Some(&index) = self.keys.get(&entry.mailbox) else {
                if entry.ok {
                    unwanted.push(entry.mailbox.clone());
                }
                continue;
            };
            if entry.ok {
                link.attached.insert(index);
                self.emit(MuxEvent::Attached {
                    mailbox: index,
                    waiting: entry.waiting.unwrap_or_default(),
                });
            } else if !resumed {
                let code = entry
                    .code
                    .clone()
                    .unwrap_or_else(|| MuxCode::Other("unspecified".to_owned()));
                warn!(mailbox = index, code = %code, "epicbox relay refused a mailbox");
                self.emit(MuxEvent::Refused {
                    mailbox: index,
                    code,
                });
            }
        }
        if resumed {
            link.resume_pending = false;
            self.emit(MuxEvent::Resumed);
            // The session the relay held may differ from ours: sign for what it dropped.
            let missing = self.unattached(link);
            self.attach(link, missing).await?;
        }
        for chunk in unwanted.chunks(MAX_ATTACH_PER_FRAME) {
            let mailboxes = chunk.to_vec();
            link.send(
                |reference| MuxClientFrame::Detach {
                    reference,
                    mailboxes,
                },
                PendingKind::Detach,
            )
            .await?;
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
        let id = mail.id.clone();
        if self.stored.contains(&id) {
            // Stored before, and the acknowledgement was lost: acknowledge again.
            bump(&self.shared.counters.duplicates);
            link.inflight.insert(id.clone(), index);
            return self.queue_ack(link, id).await;
        }
        let Some(entry) = self.entries.get(&index) else {
            return Ok(());
        };
        let content = open_message(&entry.identity, &mail.from, &mail.str, &mail.signature);
        let mut message = MailboxMessage::new(index, id.clone(), content);
        if matches!(self.delivery, Delivery::Queued) {
            message = message.with_relayed(RelayedMail {
                from: mail.from.clone(),
                str: mail.str.clone(),
                signature: mail.signature.clone(),
            });
        }
        link.inflight.insert(id.clone(), index);
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
                    // Another socket holds the mailbox. Never attached again from here, or two
                    // instances would take it from each other in a loop.
                    self.replaced.insert(detached.mailbox.clone());
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
            PendingKind::Attach { indexes } => {
                if code == Some(MuxCode::RateLimited) {
                    return Err(Lost::RateLimited { retry_after });
                }
                let code = code.unwrap_or_else(|| MuxCode::Other("unspecified".to_owned()));
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
                Ok(())
            }
            PendingKind::Hold | PendingKind::Detach => {
                debug!(code = ?code, "epicbox mux request refused");
                Ok(())
            }
        }
    }
}
