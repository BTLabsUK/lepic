// SPDX-License-Identifier: Apache-2.0
//! What the history reads from the stored stages of a slate, decoded once per session.
//!
//! A stage is stored once per slate id and is never changed or removed, so what the stages of
//! a slate decode to changes only when a stage is added. An entry keeps the stages and lengths
//! it was decoded from, and is decoded again when the stored ones differ.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lepic_crypto::Commitment;
use lepic_primitives::amount::Height;
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{Repositories, SlateStage, StoreError, StoredSlate, TxId};
use uuid::Uuid;

use crate::details::{SlateMessage, verified_messages};
use crate::finalize::kernel_excess;
use crate::refresh::decode_stored;

/// The decoded stages of each slate a history read looked at, by slate id. It holds no more
/// than the slates of the open wallet carry, and goes with its session.
#[derive(Default)]
pub(crate) struct SlateCache {
    entries: Mutex<HashMap<Uuid, Arc<Stages>>>,
}

impl SlateCache {
    /// The stages stored for `slate_id`, decoded. Reads the stored stages and their lengths
    /// each time; reads and decodes the rows only when they are not the ones the kept entry
    /// was decoded from.
    pub(crate) fn stages(
        &self,
        repos: &dyn Repositories,
        codecs: &CodecRegistry,
        tx_id: TxId,
        slate_id: Uuid,
    ) -> Result<Arc<Stages>, StoreError> {
        let stored = repos.slate_stages(slate_id)?;
        if let Some(stages) = self
            .lock()
            .get(&slate_id)
            .filter(|stages| stages.stored == stored)
        {
            return Ok(Arc::clone(stages));
        }
        let rows = repos.slates(slate_id)?;
        let stages = Arc::new(Stages::decode(codecs, tx_id, rows, stored));
        self.lock().insert(slate_id, Arc::clone(&stages));
        Ok(stages)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Uuid, Arc<Stages>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The stored stages of one slate, in the order [`Repositories::slates`] reads them.
pub(crate) struct Stages {
    stored: Vec<(SlateStage, usize)>,
    /// Each stored stage with what it decoded to, `None` for one that no longer decodes.
    decoded: Vec<(SlateStage, Option<Decoded>)>,
}

/// What a history read takes from one decoded stage.
pub(crate) struct Decoded {
    /// The excess of the final kernel, present when the stage is final.
    pub(crate) kernel: Option<Commitment>,
    /// For an I2, the excess its payer computes from it. `None` for any other stage.
    pub(crate) payer_excess: Option<Commitment>,
    pub(crate) height: Height,
    pub(crate) ttl_cutoff_height: Option<Height>,
    pub(crate) messages: Vec<SlateMessage>,
    pub(crate) inputs: Vec<Commitment>,
    pub(crate) outputs: Vec<Commitment>,
}

impl Stages {
    fn decode(
        codecs: &CodecRegistry,
        tx_id: TxId,
        rows: Vec<StoredSlate>,
        stored: Vec<(SlateStage, usize)>,
    ) -> Self {
        let decoded = rows
            .into_iter()
            .map(|row| {
                let slate = decode_stored(codecs, tx_id, &row.bytes);
                (row.stage, slate.map(|slate| Decoded::of(row.stage, &slate)))
            })
            .collect();
        Self { stored, decoded }
    }

    /// Whether `stage` is stored, whether it decodes or not.
    pub(crate) fn has(&self, stage: SlateStage) -> bool {
        self.stored.iter().any(|&(stored, _)| stored == stage)
    }

    /// The stored `stage`, when it decodes.
    pub(crate) fn decoded(&self, stage: SlateStage) -> Option<&Decoded> {
        self.decoded
            .iter()
            .find(|(stored, _)| *stored == stage)
            .and_then(|(_, decoded)| decoded.as_ref())
    }

    /// The first stored stage that decodes, in stage code order.
    pub(crate) fn first(&self) -> Option<&Decoded> {
        self.decoded.iter().find_map(|(_, decoded)| decoded.as_ref())
    }

    /// The final kernel and the slate height, as [`crate::refresh::final_kernel`] reads them.
    pub(crate) fn final_kernel(&self) -> Option<(Commitment, Height)> {
        let final_slate = [SlateStage::Standard3, SlateStage::Invoice3]
            .into_iter()
            .find_map(|stage| self.decoded(stage));
        if let Some(slate) = final_slate {
            return slate.kernel.map(|excess| (excess, slate.height));
        }
        self.decoded(SlateStage::Invoice2)
            .and_then(|slate| slate.payer_excess.map(|excess| (excess, slate.height)))
    }
}

impl Decoded {
    fn of(stage: SlateStage, slate: &Slate) -> Self {
        Self {
            kernel: slate.kernel().map(|kernel| kernel.excess),
            payer_excess: (stage == SlateStage::Invoice2)
                .then(|| kernel_excess(slate).ok())
                .flatten(),
            height: slate.height(),
            ttl_cutoff_height: slate.ttl_cutoff_height(),
            messages: verified_messages(slate),
            inputs: slate.inputs().iter().map(|input| input.commitment).collect(),
            outputs: slate
                .outputs()
                .iter()
                .map(|output| output.commitment)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use lepic_primitives::amount::Fee;
    use lepic_store::{CONTEXT_KEY_LEN, ContextKey, MemoryStore, WalletStore};

    use super::*;

    fn row(slate_id: Uuid, stage: SlateStage, bytes: &[u8]) -> StoredSlate {
        StoredSlate {
            slate_id,
            stage,
            codec: "test".to_owned(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn unchanged_stages_are_decoded_once_and_an_added_one_is_seen() {
        let store = MemoryStore::new(ContextKey::from_bytes([2; CONTEXT_KEY_LEN]));
        let codecs = crate::codecs::legacy(Fee::new(1_000_000));
        let cache = SlateCache::default();
        let slate_id = Uuid::from_bytes([7; 16]);
        let stages = |cache: &SlateCache| {
            store
                .read(|repos| cache.stages(repos, &codecs, TxId(1), slate_id))
                .unwrap()
        };
        store
            .write(|repos| repos.insert_slate(&row(slate_id, SlateStage::Standard1, b"{}")))
            .unwrap();

        let first = stages(&cache);
        assert!(first.has(SlateStage::Standard1));
        assert!(first.decoded(SlateStage::Standard1).is_none());
        assert!(Arc::ptr_eq(&first, &stages(&cache)));

        store
            .write(|repos| repos.insert_slate(&row(slate_id, SlateStage::Standard2, b"{}")))
            .unwrap();
        let second = stages(&cache);
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(second.has(SlateStage::Standard2));
        assert!(!second.has(SlateStage::Invoice1));
        assert_eq!(second.first().map(|slate| slate.height), None);
        assert_eq!(second.final_kernel(), None);
    }
}
