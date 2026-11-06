// SPDX-License-Identifier: Apache-2.0
//! The contact check (RFC 0002 8.5): a signed envelope of type 09 with an empty body that asks
//! a paired contact for its current card. The contact answers through its outbox with a contact
//! update, so the asking wallet hears it, refreshes the card or sees the relay move it names.
//! Answers are paced per contact by the host's policy; checks beyond it are taken and dropped.

use std::collections::BTreeMap;

use lepic_contact::{Content, MessageType};
use lepic_epicbox::Handled;
use lepic_node::NodeApi;
use lepic_store::{ContactId, ContactRecord, Repositories, SlateStage, StoreError, WalletStore};
use lepic_wallet::WalletPolicy;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};
use uuid::Uuid;

use super::address_proof::{CardUpdate, Payments, domain_signer, queue_card_update};
use super::{ContactError, ContactRelays};
use crate::ContactBook;
use crate::hex;
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// The answers given to checks, per contact, over the last day; older ones are forgotten.
const ANSWERS_KEY: &str = "contact.check.answers";

#[derive(Default, Serialize, Deserialize)]
struct Answers {
    per_contact: BTreeMap<String, Vec<i64>>,
}

/// Whether the check of `contact_id` at `now` (seconds) may be answered under `policy`; one that
/// may is counted.
fn may_answer(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    now: i64,
    policy: &WalletPolicy,
) -> Result<bool, StoreError> {
    let day_ago = now.saturating_sub(24 * 60 * 60);
    let hour_ago = now.saturating_sub(60 * 60);
    let mut answers: Answers = read_answers(repos)?;
    for times in answers.per_contact.values_mut() {
        times.retain(|at| *at > day_ago);
    }
    answers.per_contact.retain(|_, times| !times.is_empty());
    let key = hex::encode(&contact_id.0);
    let times = answers.per_contact.get(&key).map_or(&[][..], Vec::as_slice);
    let in_hour = times.iter().filter(|at| **at > hour_ago).count();
    let allowed = in_hour < policy.contact_check_answers_per_hour as usize
        && times.len() < policy.contact_check_answers_per_day as usize;
    if allowed {
        answers.per_contact.entry(key).or_default().push(now);
    }
    write_answers(repos, &answers)?;
    Ok(allowed)
}

/// The answers given so far. They only pace answers, so a damaged value starts afresh, which
/// the next write repairs.
fn read_answers(repos: &dyn Repositories) -> Result<Answers, StoreError> {
    Ok(repos
        .setting(ANSWERS_KEY)?
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default())
}

fn write_answers(repos: &mut dyn Repositories, answers: &Answers) -> Result<(), StoreError> {
    let text = serde_json::to_string(answers).map_err(|_| StoreError::Corrupt {
        record: lepic_store::Record::Contact,
        field: "contact check answers",
    })?;
    repos.put_setting(ANSWERS_KEY, &text)
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Asks the contact `contact_id` for its current card (RFC 0002 8.5): a check queued in the
    /// outbox for its mailbox and posted when relays may be reached. A contact that takes it
    /// answers with a contact update, which a later collect takes as any other: it sets
    /// `last_sealed_in`, refreshes the card on the same relay and raises
    /// [`Event::ContactRelayMoveRequested`](lepic_wallet::event::Event::ContactRelayMoveRequested)
    /// for another. Which contacts to check, when, and how long to wait for the answer are the
    /// host's.
    ///
    /// Fails with [`ContactError::Ended`] for an ended pairing, [`ContactError::WrongClass`]
    /// for a private pairing, which carries no checks, [`ContactError::UnknownContact`] for no
    /// such contact or one not paired, and as the store does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_check(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
    ) -> Result<(), ContactError> {
        self.check_contact_network(relays)?;
        let session = self.wallet.session()?;
        let record = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    let record = repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    if record.facts.ended_reason.is_some() {
                        return Err(ContactError::Ended);
                    }
                    if super::private::is_private(&record) {
                        return Err(ContactError::WrongClass);
                    }
                    let paired = matches!(
                        record.state,
                        lepic_store::ContactState::Paired | lepic_store::ContactState::Verified
                    );
                    if !paired || record.peer.is_none() {
                        return Err(ContactError::UnknownContact);
                    }
                    Ok(record)
                })
            })
            .await?;
        let envelope = self
            .seal_for_contact(&record, Content::new(MessageType::ContactCheck, Vec::new()))
            .await?;
        self.enqueue_for_contact(
            contact_id,
            Uuid::from_bytes(contact_id.0),
            SlateStage::Standard1,
            &envelope,
        )
        .await?;
        self.deliver_soon(relays).await;
        info!("contact check queued");
        Ok(())
    }

    /// Takes a contact check from the paired, not ended contact of `record`: within the host's
    /// pace it queues a contact update with our current card, the next sequence number, the
    /// payments address and its proof; beyond it the check is dropped. Either way it is taken.
    pub(crate) async fn take_contact_check(
        &self,
        relays: &ContactRelays,
        record: &ContactRecord,
    ) -> Result<Handled, ContactError> {
        let network = self.wallet.config().network;
        let features = self.wallet.config().pairing_features();
        let policy = self.wallet.config().policy;
        let session = self.wallet.session()?;
        let payments = Payments::of(&session.keychain, network, relays)?;
        let domain = domain_signer(
            &session.keychain,
            network,
            self.wallet.config().domain.as_deref(),
        )?;
        let record = record.clone();
        let answered = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    if !may_answer(repos, record.contact_id, now.as_second(), &policy)? {
                        return Ok(false);
                    }
                    let at = CardUpdate {
                        keychain: &session.keychain,
                        network,
                        payments: &payments,
                        features,
                        domain: domain.as_ref(),
                        now,
                    };
                    queue_card_update(repos, &ports.rng, &at, record, |_| {})
                })
            })
            .await?;
        // The cycle that took the check runs the outbox after its drains, under its turn.
        if answered {
            info!("contact check answered");
        } else {
            debug!("contact check beyond the answer pace dropped");
        }
        Ok(Handled::Stored)
    }
}
