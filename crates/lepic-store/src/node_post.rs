// SPDX-License-Identifier: Apache-2.0
//! What the wallet keeps about posting a transaction to the node, so a retry knows what came
//! before. The record belongs to one transaction and is deleted with it.

use jiff::Timestamp;
use lepic_primitives::amount::Height;

use crate::encoding::{stored_enum, timestamp_to_column};
use crate::error::StoreError;
use crate::transaction::TxId;

/// The longest error text kept of a post, in bytes.
pub const MAX_NODE_ERROR_LEN: usize = 1024;

stored_enum! {
    /// How the node answered the latest post.
    pub enum NodeOutcome {
        Accepted => "accepted",
        Refused => "refused",
        Unreachable => "unreachable",
    }
}

/// The posts of one transaction to the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePost {
    pub tx_id: TxId,
    pub attempts: u32,
    pub last_at: Timestamp,
    /// The tip when the latest post was made.
    pub last_height: Height,
    pub last_outcome: NodeOutcome,
    pub last_error: Option<String>,
    /// The node accepted one of the posts.
    pub accepted_once: bool,
    /// One of the posts found the node unreachable.
    pub unreachable_once: bool,
}

pub trait NodePostRepository {
    /// Stores `post`, replacing the one of the same transaction. Fails with
    /// [`StoreError::UnknownTransaction`] when the transaction does not exist, and with
    /// [`StoreError::OutOfRange`] for an error text longer than [`MAX_NODE_ERROR_LEN`].
    fn put_node_post(&mut self, post: &NodePost) -> Result<(), StoreError>;

    fn node_post(&self, tx_id: TxId) -> Result<Option<NodePost>, StoreError>;
}

pub(crate) fn check_node_post(post: &NodePost) -> Result<(), StoreError> {
    if post
        .last_error
        .as_ref()
        .is_some_and(|error| error.len() > MAX_NODE_ERROR_LEN)
    {
        return Err(StoreError::OutOfRange {
            field: "node post error",
        });
    }
    timestamp_to_column(post.last_at)?;
    Ok(())
}
