// SPDX-License-Identifier: Apache-2.0
use uuid::Uuid;

use crate::encoding::stored_enum;
use crate::error::StoreError;

stored_enum! {
    /// The point in a transaction flow a slate was captured at.
    pub enum SlateStage {
        Standard1 => "S1",
        Standard2 => "S2",
        Standard3 => "S3",
        Invoice1 => "I1",
        Invoice2 => "I2",
        Invoice3 => "I3",
    }
}

/// A slate in wire form, kept with the codec that produced or decoded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSlate {
    pub slate_id: Uuid,
    pub stage: SlateStage,
    pub codec: String,
    pub bytes: Vec<u8>,
}

pub trait SlateRepository {
    /// Stores a slate once per slate id and stage; a second one fails with
    /// [`StoreError::Duplicate`].
    fn insert_slate(&mut self, slate: &StoredSlate) -> Result<(), StoreError>;

    fn slate(&self, slate_id: Uuid, stage: SlateStage) -> Result<Option<StoredSlate>, StoreError>;

    /// Every stored stage of a slate, ordered by stage code.
    fn slates(&self, slate_id: Uuid) -> Result<Vec<StoredSlate>, StoreError>;

    /// The stage and byte length of every stored stage of a slate, in the order of
    /// [`SlateRepository::slates`]. A store overrides it to answer without reading the bytes.
    fn slate_stages(&self, slate_id: Uuid) -> Result<Vec<(SlateStage, usize)>, StoreError> {
        Ok(self
            .slates(slate_id)?
            .into_iter()
            .map(|slate| (slate.stage, slate.bytes.len()))
            .collect())
    }
}
