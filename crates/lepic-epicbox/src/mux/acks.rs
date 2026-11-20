// SPDX-License-Identifier: Apache-2.0
//! Settling mail with the relay: acknowledgements gathered into `Ack` frames, and holds.

use crate::frame::RelayMessageId;
use crate::mux_frame::{MAX_ACK_IDS, MuxClientFrame};
use crate::session::deadline_after;

use super::counters::{add, bump};
use super::link::{Link, Lost, PendingKind};
use super::manager::Manager;

impl Manager {
    pub(super) async fn queue_ack(&self, link: &mut Link, id: RelayMessageId) -> Result<(), Lost> {
        link.acks.push(id);
        let flush_at = MAX_ACK_IDS.min(link.limits.inflight_per_socket);
        if link.acks.len() >= flush_at || self.options.ack_window.is_zero() {
            self.flush_acks(link).await
        } else {
            if link.ack_due.is_none() {
                link.ack_due = Some(deadline_after(self.options.ack_window));
            }
            Ok(())
        }
    }

    pub(super) async fn flush_acks(&self, link: &mut Link) -> Result<(), Lost> {
        link.ack_due = None;
        while !link.acks.is_empty() {
            let take = link.acks.len().min(MAX_ACK_IDS);
            let ids: Vec<RelayMessageId> = link.acks.drain(..take).collect();
            for id in &ids {
                link.inflight.remove(id);
            }
            add(&self.shared.counters.acks, ids.len());
            let frame_ids = ids.clone();
            link.send(
                |reference| MuxClientFrame::Ack {
                    reference,
                    ids: frame_ids,
                },
                PendingKind::Ack { ids },
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn hold(&self, link: &mut Link, id: RelayMessageId) -> Result<(), Lost> {
        let hold = self.options.hold;
        let whole = hold
            .as_secs()
            .saturating_add(u64::from(hold.subsec_nanos() > 0));
        let seconds = u32::try_from(whole)
            .unwrap_or(u32::MAX)
            .clamp(1, link.limits.hold_max_s);
        link.inflight.remove(&id);
        bump(&self.shared.counters.holds);
        link.send(
            |reference| MuxClientFrame::Hold {
                reference,
                id,
                seconds,
            },
            PendingKind::Hold,
        )
        .await
    }
}
