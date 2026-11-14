// SPDX-License-Identifier: Apache-2.0
//! The session's mailboxes: what each owner claims, and the entries that are the union of the
//! claims.

use crate::client::Identity;

use super::link::Link;
use super::manager::Manager;
use super::{Claimed, MuxError};

pub(super) struct Reconciled {
    pub(super) indexes: Vec<usize>,
    pub(super) added: Vec<usize>,
    pub(super) removed: Vec<(usize, String)>,
}

impl Reconciled {
    pub(super) fn claimed(&self) -> Claimed {
        Claimed {
            indexes: self.indexes.clone(),
            fresh: self
                .indexes
                .iter()
                .copied()
                .filter(|index| self.added.contains(index))
                .collect(),
        }
    }
}

pub(super) struct Entry {
    pub(super) identity: Identity,
    /// The bare key, as the relay names the mailbox.
    pub(super) key: String,
}

impl Manager {
    fn add_entry(&mut self, identity: Identity) -> Result<usize, MuxError> {
        if self.entries.len() >= self.mailbox_cap {
            return Err(MuxError::TooManyMailboxes {
                count: self.entries.len().saturating_add(1),
                max: self.mailbox_cap,
            });
        }
        let key = identity.address().key_text();
        if self.keys.contains_key(&key) {
            return Err(MuxError::DuplicateMailbox);
        }
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        self.keys.insert(key.clone(), index);
        self.entries.insert(index, Entry { identity, key });
        Ok(index)
    }

    /// Adds an identity to the session and to the claim of owner `""`.
    pub(super) fn add_claimed(&mut self, identity: Identity) -> Result<usize, MuxError> {
        let claimed = identity.clone();
        let index = self.add_entry(identity)?;
        self.claims.entry(String::new()).or_default().push(claimed);
        Ok(index)
    }

    /// Removes a mailbox from the session and from every claim.
    pub(super) fn remove_claimed(&mut self, key: &str) -> Option<usize> {
        for claim in self.claims.values_mut() {
            claim.retain(|identity| identity.address().key_text() != key);
        }
        self.claims.retain(|_, claim| !claim.is_empty());
        self.remove_entry(key)
    }

    fn remove_entry(&mut self, key: &str) -> Option<usize> {
        let index = self.keys.remove(key)?;
        self.entries.remove(&index);
        self.replaced.remove(key);
        self.shared.purge(Some(index));
        Some(index)
    }

    /// Sets the claim of `owner` and makes the entries match the union of the claims. Returns
    /// the index of each identity of the claim, what was added and what was removed.
    pub(super) fn reconcile(
        &mut self,
        owner: String,
        merge: bool,
        identities: Vec<Identity>,
    ) -> Result<Reconciled, MuxError> {
        let mut own: Vec<(String, Identity)> = Vec::with_capacity(identities.len());
        for identity in identities {
            let key = identity.address().key_text();
            if !own.iter().any(|(known, _)| *known == key) {
                own.push((key, identity));
            }
        }
        let mut kept: Vec<Identity> = Vec::new();
        if merge && let Some(claim) = self.claims.get(&owner) {
            for identity in claim {
                let key = identity.address().key_text();
                if !own.iter().any(|(known, _)| *known == key) {
                    kept.push(identity.clone());
                }
            }
        }
        let mut wanted: Vec<String> = own.iter().map(|(key, _)| key.clone()).collect();
        wanted.extend(kept.iter().map(|identity| identity.address().key_text()));
        for (other, claim) in &self.claims {
            if *other == owner {
                continue;
            }
            for identity in claim {
                let key = identity.address().key_text();
                if !wanted.contains(&key) {
                    wanted.push(key);
                }
            }
        }
        if wanted.len() > self.mailbox_cap {
            return Err(MuxError::TooManyMailboxes {
                count: wanted.len(),
                max: self.mailbox_cap,
            });
        }
        let claim: Vec<Identity> = own
            .iter()
            .map(|(_, identity)| identity.clone())
            .chain(kept)
            .collect();
        if claim.is_empty() {
            self.claims.remove(&owner);
        } else {
            self.claims.insert(owner, claim);
        }
        let gone: Vec<String> = self
            .keys
            .keys()
            .filter(|key| !wanted.contains(*key))
            .cloned()
            .collect();
        let mut removed = Vec::with_capacity(gone.len());
        for key in gone {
            if let Some(index) = self.remove_entry(&key) {
                removed.push((index, key));
            }
        }
        let mut indexes = Vec::with_capacity(own.len());
        let mut added = Vec::new();
        for (key, identity) in own {
            if let Some(&index) = self.keys.get(&key) {
                indexes.push(index);
            } else {
                let index = self.add_entry(identity)?;
                added.push(index);
                indexes.push(index);
            }
        }
        Ok(Reconciled {
            indexes,
            added,
            removed,
        })
    }

    /// The mailboxes this socket should carry and does not: every one but those another socket
    /// took over.
    pub(super) fn unattached(&self, link: &Link) -> Vec<usize> {
        self.entries
            .iter()
            .filter(|(index, entry)| {
                !link.attached.contains(index) && !self.replaced.contains(&entry.key)
            })
            .map(|(index, _)| *index)
            .collect()
    }
}
