// SPDX-License-Identifier: Apache-2.0
//! The transaction that made a coin a send of this wallet spends (ADR 0071). Locking a coin
//! links it to the send, so the store keeps no link to its maker. The maker is found again
//! from what is stored: a coin is one of the outputs listed by the stage its maker built, a
//! transaction confirmed at the coin's height or one a refresh reopened since a
//! reorganisation took its block.
//!
//! A block reward has no maker: its coin comes back if the chain returns to the block that paid
//! it, as [`crate::coinbase::confirm_again`] takes it back. A send of one waits as a send of any
//! other coin does, and its kernel, which commits to the coin less its value, tells the same.
//!
//! A send whose node refuses it because such coins are gone tells a reorganisation from a
//! spend by the maker's kernel: kernels stay on chain once their block is in it, so a maker
//! whose kernel the chain no longer holds lost its block, and the coin can come back when the
//! maker is mined again. A send that waits [`crate::reorg_marks::REORG_WAIT_BLOCKS`] in vain
//! ends, and [`release_to_maker`] gives each such coin back to the transaction that made it.

use std::collections::BTreeMap;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_primitives::output::OutputFeatures;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    OutputRecord, OutputStatus, Repositories, SlateStage, StoreError, TransactionEntry,
    TxDirection, TxId, TxState, WalletStore,
};
use tracing::{debug, info};

use crate::chain;
use crate::codecs;
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{RefreshError, confirmed_kernel, open_transactions, stored_slate};
use crate::state::{StateChange, is_final};
use crate::wallet::Wallet;

/// What the store tells of the transaction that made a coin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Made by this transaction, which a refresh reopened after a reorganisation took the
    /// block that confirmed it: off chain.
    Reopened(TxId),
    /// Made by `maker`, a transaction held as confirmed, whose kernel `excess`, mined no lower
    /// than `min_height`, tells whether the chain still holds it.
    Kernel {
        maker: TxId,
        excess: Commitment,
        min_height: Height,
    },
    /// The coin of the block reward `reward`, held as confirmed, whose kernel `excess`, in the
    /// block at the coin's height, tells whether the chain still holds it.
    Reward { reward: TxId, excess: Commitment },
    /// No maker found, or one whose kernel is not known.
    Unknown,
}

/// The origin of `coin`, which the transaction `spender` spends.
pub(crate) fn origin(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    coin: &OutputRecord,
    spender: TxId,
) -> Result<Origin, RefreshError> {
    if coin.id.features == OutputFeatures::Coinbase {
        return reward(repos, coin);
    }
    let Some(tx_id) = maker(repos, codecs, coin, spender)? else {
        return Ok(Origin::Unknown);
    };
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(Origin::Unknown);
    };
    if !is_final(entry.state) {
        return Ok(Origin::Reopened(tx_id));
    }
    let (TxState::Confirmed, Some(slate_id)) = (entry.state, entry.slate_id) else {
        return Ok(Origin::Unknown);
    };
    Ok(
        match confirmed_kernel(repos, codecs, tx_id, &entry, slate_id)? {
            Some((excess, min_height)) => Origin::Kernel {
                maker: tx_id,
                excess,
                min_height,
            },
            None => Origin::Unknown,
        },
    )
}

/// The block reward that paid `coin`, a coinbase output: the confirmed reward entry at the
/// coin's height for the coin's amount, with no slate. Its kernel commits to the coin less its
/// value ([`crate::coinbase::reward_kernel`]).
fn reward(repos: &dyn Repositories, coin: &OutputRecord) -> Result<Origin, RefreshError> {
    for (tx_id, height) in repos.confirmed_from(coin.height)? {
        if height != coin.height {
            continue;
        }
        let Some(entry) = repos.transaction(tx_id)? else {
            continue;
        };
        if entry.direction != TxDirection::Incoming
            || entry.slate_id.is_some()
            || entry.state != TxState::Confirmed
            || entry.amount_credited != coin.amount
        {
            continue;
        }
        let excess = crate::coinbase::reward_kernel(&entry, std::slice::from_ref(coin), height);
        return Ok(excess.map_or(Origin::Unknown, |excess| Origin::Reward {
            reward: tx_id,
            excess,
        }));
    }
    Ok(Origin::Unknown)
}

/// Gives `coin`, which the send `spender` held and that a reorganisation took, back to the
/// transaction that made it, once the send ended: it is `unconfirmed`, off chain, linked to its
/// maker, and a refresh confirms it when the maker is mined again. The coin of a block reward
/// goes back to the reward, which ends orphaned ([`crate::coinbase::orphan`]) and is confirmed
/// again if the chain returns to its block. `None`, and nothing changed, for a coin not stored
/// or of unknown origin.
pub(crate) fn release_to_maker(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    coin: &Commitment,
    spender: TxId,
    now: Timestamp,
) -> Result<Option<Vec<StateChange>>, RefreshError> {
    let Some(mut stored) = repos.output(coin.as_bytes())? else {
        return Ok(None);
    };
    let maker = match origin(repos, codecs, &stored, spender)? {
        Origin::Reopened(maker) | Origin::Kernel { maker, .. } => maker,
        Origin::Reward { reward, .. } => {
            stored.status = OutputStatus::Unconfirmed;
            stored.mmr_index = None;
            stored.tx = Some(reward);
            repos.put_output(&stored)?;
            info!(tx_id = %reward, "reorged block reward given back");
            return Ok(Some(
                crate::coinbase::orphan(repos, reward, now)?
                    .into_iter()
                    .collect(),
            ));
        }
        Origin::Unknown => return Ok(None),
    };
    stored.status = OutputStatus::Unconfirmed;
    stored.mmr_index = None;
    stored.tx = Some(maker);
    repos.put_output(&stored)?;
    debug!(tx_id = %maker, "reorged coin given back to its maker");
    Ok(Some(Vec::new()))
}

/// The send that ended, cancelled or expired, while it waited for `coin`, an input a
/// reorganisation took that it held: the coin is linked to it still, unspent or spent, and the
/// send carries its mark ([`crate::reorg_marks`]).
pub(crate) fn reorged_spender(
    repos: &dyn Repositories,
    coin: &OutputRecord,
) -> Result<Option<TxId>, StoreError> {
    let (OutputStatus::Unspent | OutputStatus::Spent, Some(tx_id)) = (coin.status, coin.tx) else {
        return Ok(None);
    };
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    if !matches!(entry.state, TxState::Cancelled | TxState::Expired)
        || crate::reorg_marks::inputs_reorged_at(repos, &entry)?.is_none()
    {
        return Ok(None);
    }
    Ok(Some(tx_id))
}

/// The transaction other than `spender` whose built stage adds `coin`: one confirmed at the
/// coin's height, or an open one, which a reorganisation may have reopened. The height only
/// narrows the search; the stage decides.
pub(crate) fn maker(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    coin: &OutputRecord,
    spender: TxId,
) -> Result<Option<TxId>, RefreshError> {
    let mut candidates: Vec<TxId> = repos
        .confirmed_from(coin.height)?
        .into_iter()
        .filter(|&(tx_id, height)| height == coin.height && tx_id != spender)
        .map(|(tx_id, _)| tx_id)
        .collect();
    for stored in open_transactions(repos)? {
        if stored.id != spender && !candidates.contains(&stored.id) {
            candidates.push(stored.id);
        }
    }
    for tx_id in candidates {
        let Some(entry) = repos.transaction(tx_id)? else {
            continue;
        };
        if made_outputs(repos, codecs, tx_id, &entry)?.contains(&coin.id.commitment) {
            return Ok(Some(tx_id));
        }
    }
    Ok(None)
}

/// The outputs of the open transactions with a slate, by commitment, each with the
/// transaction whose built stage adds it.
pub(crate) fn open_makers(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
) -> Result<BTreeMap<Commitment, TxId>, RefreshError> {
    let mut makers = BTreeMap::new();
    for stored in open_transactions(repos)? {
        for commitment in made_outputs(repos, codecs, stored.id, &stored.entry)? {
            makers.insert(commitment, stored.id);
        }
    }
    Ok(makers)
}

/// The outputs the stage `tx_id` built adds, as the transaction's details list them: the
/// sender's S1 and the payer's I2 add change, the receiver's S2 and the issuer's I1 add the
/// amount. An answer also carries the outputs of the stage it answers, which are left out. A
/// transaction stores stages of one flow only, and a self-send both parties' stages under one
/// slate id.
fn made_outputs(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    entry: &TransactionEntry,
) -> Result<Vec<Commitment>, StoreError> {
    let Some(slate_id) = entry.slate_id else {
        return Ok(Vec::new());
    };
    let stages = match entry.direction {
        TxDirection::Outgoing => [
            (SlateStage::Standard1, None),
            (SlateStage::Invoice2, Some(SlateStage::Invoice1)),
        ],
        TxDirection::Incoming => [
            (SlateStage::Standard2, Some(SlateStage::Standard1)),
            (SlateStage::Invoice1, None),
        ],
    };
    for (built, answered) in stages {
        let Some(slate) = stored_slate(repos, codecs, tx_id, slate_id, built)? else {
            continue;
        };
        let theirs: Vec<Commitment> = match answered {
            Some(stage) => stored_slate(repos, codecs, tx_id, slate_id, stage)?
                .map(|slate| {
                    slate
                        .outputs()
                        .iter()
                        .map(|output| output.commitment)
                        .collect()
                })
                .unwrap_or_default(),
            None => Vec::new(),
        };
        return Ok(slate
            .outputs()
            .iter()
            .map(|output| output.commitment)
            .filter(|commitment| !theirs.contains(commitment))
            .collect());
    }
    Ok(Vec::new())
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Whether every one of `gone`, coins of this wallet the transaction `spender` spends and
    /// the node's UTXO set misses, was made by a transaction the chain no longer holds: one a
    /// refresh reopened, or one whose kernel, or the kernel of the block reward that paid it,
    /// the node does not find up to `tip`. `false` when
    /// `gone` is empty or the maker of one is not known. Fails when the store or the node
    /// cannot tell.
    pub(crate) async fn inputs_reorged(
        &self,
        session: &Arc<Session<S::Store>>,
        spender: TxId,
        gone: Vec<Commitment>,
        tip: Height,
    ) -> Result<bool, RefreshError> {
        if gone.is_empty() {
            return Ok(false);
        }
        let origins = {
            let session = Arc::clone(session);
            self.blocking(move |_, config| {
                let codecs = codecs::legacy(config.network.params().default_base_fee());
                Ok(session.store.read(|repos| {
                    let mut origins = Vec::with_capacity(gone.len());
                    for commitment in &gone {
                        let Some(coin) = repos.output(commitment.as_bytes())? else {
                            return Ok::<_, RefreshError>(None);
                        };
                        origins.push((origin(repos, &codecs, &coin, spender)?, coin.height));
                    }
                    Ok(Some(origins))
                }))
            })
            .await??
        };
        let Some(origins) = origins else {
            return Ok(false);
        };
        for (origin, height) in origins {
            let (excess, floor) = match origin {
                Origin::Reopened(_) => continue,
                Origin::Unknown => return Ok(false),
                Origin::Kernel {
                    excess, min_height, ..
                } => (excess, chain::kernel_floor(min_height, tip)),
                Origin::Reward { excess, .. } => (excess, height.min(tip).max(Height::new(1))),
            };
            let kernel = self
                .ports()
                .node
                .get_kernel(&excess, Some(floor), None)
                .await?;
            if let Some(kernel) = kernel {
                debug!(height = %kernel.height, "maker of a gone input still on chain");
                return Ok(false);
            }
        }
        Ok(true)
    }
}
