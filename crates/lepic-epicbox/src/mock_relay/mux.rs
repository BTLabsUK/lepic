//! mux/1 on [`MockRelay`](super::MockRelay), switched on with
//! [`MockRelay::offer_mux`](super::MockRelay::offer_mux). It serves the same store as the 3.0.0
//! frames: mail posted either way is pushed to the socket that attached its mailbox, a mux/1
//! `Ack` removes it for every reader, and a 3.0.0 `Subscribe` collects what no mux/1 socket
//! holds. Attach tokens are never issued, so a session always attaches with fresh signatures;
//! every `Resume` is refused.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::Instant;

use super::{MailboxCount, RelayState, signed_by};
use crate::address::Network;
use crate::mock_mux::{INFLIGHT_LIMIT, bare_key, error, with_ref};
use crate::mux_frame::{AttachEntry, MAX_HOLD_SECS, MuxClientFrame};

impl RelayState {
    /// Answers a `ClientDetails` that asks for mux/1: the socket takes mux/1 frames from now on.
    pub(super) fn negotiate_mux(&mut self, id: u64) {
        self.next_challenge = self.next_challenge.wrapping_add(1);
        // 22 characters, the length mux/1 requires.
        let challenge = format!("mockmuxchallenge{:06}", self.next_challenge % 1_000_000);
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        socket.mux = true;
        socket.challenge.clone_from(&challenge);
        self.send(
            id,
            json!({
                "type": "Ok",
                "ext": ["mux/1"],
                "challenge": challenge,
                "limits": {
                    "attach_per_frame": 64,
                    "mailboxes_per_socket": 256,
                    "inflight_per_socket": INFLIGHT_LIMIT,
                    "hold_max_s": MAX_HOLD_SECS,
                },
            })
            .to_string(),
        );
    }

    pub(super) fn is_mux(&self, id: u64) -> bool {
        self.sockets.get(&id).is_some_and(|socket| socket.mux)
    }

    /// Serves frame `type_name` on a mux/1 socket. False leaves it to the 3.0.0 handling, which
    /// a mux/1 socket shares for `Ping`, `GetVersion` and `ClientDetails`.
    pub(super) fn handle_mux(
        &mut self,
        id: u64,
        network: Network,
        type_name: &str,
        message: &Value,
        text: &str,
    ) -> bool {
        let reference = message.get("ref").and_then(Value::as_str);
        match type_name {
            "ping" | "getversion" | "clientdetails" => false,
            "subscribe" | "made" | "unsubscribe" | "challenge" | "canceltx" => {
                // CancelTx on a mux/1 socket is a txcancel/1 frame, which this relay does not
                // offer.
                let code = if type_name == "canceltx" {
                    "unknown_type"
                } else {
                    "classic_only"
                };
                self.send(id, error("InvalidRequest", code, reference, None));
                true
            }
            "postslate" => {
                self.post_slate(id, network, message, reference);
                true
            }
            _ => {
                match MuxClientFrame::from_json(text) {
                    Ok(Some(frame)) => self.mux_frame(id, network, frame),
                    Ok(None) => {
                        self.send(id, error("InvalidRequest", "unknown_type", reference, None));
                    }
                    Err(_) => self.send(id, error("InvalidRequest", "bad_frame", reference, None)),
                }
                true
            }
        }
    }

    fn mux_frame(&mut self, id: u64, network: Network, frame: MuxClientFrame) {
        match frame {
            MuxClientFrame::Attach {
                reference,
                mailboxes,
            } => self.attach(id, network, reference.as_deref(), &mailboxes),
            MuxClientFrame::Resume { reference, .. } => self.send(
                id,
                error(
                    "InvalidChallenge",
                    "token_unknown",
                    reference.as_deref(),
                    None,
                ),
            ),
            MuxClientFrame::Detach {
                reference,
                mailboxes,
            } => {
                for address in &mailboxes {
                    if let Some(queue) = self.attached_queue(id, &bare_key(address)) {
                        self.release(id, &queue);
                        if let Some(socket) = self.sockets.get_mut(&id) {
                            socket.attached.remove(&queue);
                        }
                    }
                }
                self.count_mailboxes(id);
                self.send(id, with_ref(json!({"type": "Ok"}), reference.as_deref()));
            }
            MuxClientFrame::Ack { reference, ids } => {
                let attached = self.attached_of(id);
                for acked in &ids {
                    for stored in &mut self.messages {
                        if stored.id == acked.as_str() && attached.contains_key(&stored.queue) {
                            stored.made = true;
                            stored.pushed_to = None;
                        }
                    }
                }
                self.send(id, with_ref(json!({"type": "Ok"}), reference.as_deref()));
                self.push(id);
            }
            MuxClientFrame::Hold {
                reference,
                id: message_id,
                seconds,
            } => {
                let seconds = seconds.clamp(1, MAX_HOLD_SECS);
                let now = Instant::now();
                let until = now
                    .checked_add(Duration::from_secs(u64::from(seconds)))
                    .unwrap_or(now);
                for stored in &mut self.messages {
                    if stored.id == message_id.as_str() && stored.pushed_to == Some(id) {
                        stored.pushed_to = None;
                        stored.held_until = Some(until);
                        self.hold_wakes.push(until);
                    }
                }
                self.send(id, with_ref(json!({"type": "Ok"}), reference.as_deref()));
                self.push(id);
            }
            MuxClientFrame::Waiting { reference } => self.waiting(id, reference.as_deref()),
            MuxClientFrame::CancelTx { reference, .. }
            | MuxClientFrame::CancelAck { reference, .. } => self.send(
                id,
                error("InvalidRequest", "unknown_type", reference.as_deref(), None),
            ),
            MuxClientFrame::PostSlate { .. } => {}
        }
    }

    fn attach(
        &mut self,
        id: u64,
        network: Network,
        reference: Option<&str>,
        mailboxes: &[AttachEntry],
    ) {
        let Some((challenge, domain)) = self
            .sockets
            .get(&id)
            .map(|socket| (socket.challenge.clone(), socket.domain.clone()))
        else {
            return;
        };
        let mut entries = Vec::new();
        for entry in mailboxes {
            let key = bare_key(&entry.address);
            if signed_by(&key, network, &challenge, &entry.signature) {
                let queue = self.queue_name(&key, domain.as_deref());
                self.take_over(id, &queue, &key);
                let waiting = self.offerable(&queue);
                entries.push(json!({"mailbox": key, "ok": true, "waiting": waiting}));
            } else {
                entries.push(json!({"mailbox": key, "ok": false, "code": "bad_signature"}));
            }
        }
        self.count_mailboxes(id);
        let frame = json!({"type": "Attached", "mailboxes": entries});
        self.send(id, with_ref(frame, reference));
        self.push(id);
    }

    /// Records how many mailboxes socket `id` holds now.
    fn count_mailboxes(&mut self, id: u64) {
        if let Some(socket) = self.sockets.get(&id) {
            let mailboxes = socket.attached.len();
            self.mailbox_counts.push(MailboxCount {
                socket: id,
                mailboxes,
            });
        }
    }

    /// Attaches `queue` to socket `id`, detaching it from any other socket with `replaced`.
    fn take_over(&mut self, id: u64, queue: &str, key: &str) {
        let others: Vec<u64> = self
            .sockets
            .iter()
            .filter(|(other, socket)| **other != id && socket.attached.contains_key(queue))
            .map(|(other, _)| *other)
            .collect();
        for other in others {
            self.release(other, queue);
            if let Some(socket) = self.sockets.get_mut(&other) {
                socket.attached.remove(queue);
            }
            self.send(
                other,
                json!({"type": "Detached", "mailbox": key, "reason": "replaced"}).to_string(),
            );
        }
        if let Some(socket) = self.sockets.get_mut(&id) {
            socket.attached.insert(queue.to_owned(), key.to_owned());
        }
    }

    /// Makes the messages of `queue` pushed to socket `id` and not acknowledged offerable again.
    fn release(&mut self, id: u64, queue: &str) {
        for stored in &mut self.messages {
            if stored.queue == queue && stored.pushed_to == Some(id) {
                stored.pushed_to = None;
            }
        }
    }

    /// Makes every message pushed to socket `id` offerable again, as the socket is gone.
    pub(super) fn release_socket(&mut self, id: u64) {
        for stored in &mut self.messages {
            if stored.pushed_to == Some(id) {
                stored.pushed_to = None;
            }
        }
    }

    fn attached_of(&self, id: u64) -> HashMap<String, String> {
        self.sockets
            .get(&id)
            .map(|socket| socket.attached.clone())
            .unwrap_or_default()
    }

    fn attached_queue(&self, id: u64, key: &str) -> Option<String> {
        self.sockets.get(&id).and_then(|socket| {
            socket
                .attached
                .iter()
                .find(|(_, attached)| attached.as_str() == key)
                .map(|(queue, _)| queue.clone())
        })
    }

    /// Messages of `queue` a socket may be offered now: not acknowledged, not held and not in
    /// flight on any mux/1 socket.
    fn offerable(&self, queue: &str) -> usize {
        let now = Instant::now();
        self.messages
            .iter()
            .filter(|stored| stored.queue == queue && stored.offerable(now))
            .count()
    }

    /// Counts a `Waiting` as Epicmail does and answers it `rate_limited` past the limit. True
    /// when it was refused.
    fn refuse_waiting(&mut self, id: u64, reference: Option<&str>) -> bool {
        let now = Instant::now();
        self.waiting_asked.push((id, now));
        let Some((limit, window)) = self.waiting_limit else {
            return false;
        };
        let Some(socket) = self.sockets.get_mut(&id) else {
            return false;
        };
        if now.duration_since(socket.waiting_window.0) >= window {
            socket.waiting_window = (now, 0);
        }
        socket.waiting_window.1 = socket.waiting_window.1.saturating_add(1);
        if socket.waiting_window.1 <= limit {
            return false;
        }
        let left = window
            .saturating_sub(now.duration_since(socket.waiting_window.0))
            .as_secs()
            .max(1);
        self.waiting_refused = self.waiting_refused.saturating_add(1);
        self.send(
            id,
            error("InvalidRequest", "rate_limited", reference, Some(left)),
        );
        true
    }

    fn waiting(&mut self, id: u64, reference: Option<&str>) {
        if self.refuse_waiting(id, reference) {
            return;
        }
        let attached = self.attached_of(id);
        let now = Instant::now();
        let mut waiting = serde_json::Map::new();
        for (queue, key) in &attached {
            waiting.insert(key.clone(), json!(self.offerable(queue)));
        }
        let inflight = self
            .messages
            .iter()
            .filter(|stored| stored.pushed_to == Some(id))
            .count();
        let held = self
            .messages
            .iter()
            .filter(|stored| {
                !stored.made
                    && attached.contains_key(&stored.queue)
                    && stored.held_until.is_some_and(|until| until > now)
            })
            .count();
        let frame = json!({
            "type": "Ok", "waiting": waiting, "inflight": inflight, "held": held,
        });
        self.send(id, with_ref(frame, reference));
    }

    /// Pushes what is offerable in `queue` to the mux/1 socket that holds it. False when no
    /// mux/1 socket holds it, so a 3.0.0 listener may have it.
    pub(super) fn push_queue(&mut self, queue: &str) -> bool {
        let holder = self
            .sockets
            .iter()
            .find(|(_, socket)| socket.attached.contains_key(queue))
            .map(|(id, _)| *id);
        match holder {
            Some(id) => {
                self.push(id);
                true
            }
            None => false,
        }
    }

    /// Pushes offerable mail to every mux/1 socket, as a hold that ended frees it.
    pub(super) fn push_all(&mut self) {
        let ids: Vec<u64> = self
            .sockets
            .iter()
            .filter(|(_, socket)| socket.mux)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.push(id);
        }
    }

    /// Sends offerable mail of the mailboxes socket `id` attached, oldest first, up to the
    /// in-flight limit.
    fn push(&mut self, id: u64) {
        let attached = self.attached_of(id);
        if attached.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut inflight = self
            .messages
            .iter()
            .filter(|stored| stored.pushed_to == Some(id))
            .count();
        let mut frames = Vec::new();
        for stored in &mut self.messages {
            if inflight >= INFLIGHT_LIMIT {
                break;
            }
            let Some(key) = attached.get(&stored.queue) else {
                continue;
            };
            if !stored.offerable(now) {
                continue;
            }
            stored.pushed_to = Some(id);
            inflight = inflight.saturating_add(1);
            let count = self.deliveries.entry(stored.id.clone()).or_default();
            *count = count.saturating_add(1);
            frames.push(
                json!({
                    "type": "Mail", "mailbox": key, "id": stored.id, "from": stored.from,
                    "str": stored.str, "signature": stored.signature, "created": 0,
                })
                .to_string(),
            );
        }
        for frame in frames {
            self.send(id, frame);
        }
    }

    /// Sends `text` in answer to a request with `reference`, which a mux/1 client matches the
    /// answer by. Text that is not a JSON object goes as is.
    pub(super) fn reply(&self, id: u64, reference: Option<&str>, text: String) {
        match serde_json::from_str::<Value>(&text) {
            Ok(frame) if reference.is_some() && frame.is_object() => {
                self.send(id, with_ref(frame, reference));
            }
            _ => self.send(id, text),
        }
    }
}
