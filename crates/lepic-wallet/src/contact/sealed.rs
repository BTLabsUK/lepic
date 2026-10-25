//! Sealed slates in files and pastes (RFC 0002 sections 5 and 9): sending to a paired contact
//! sealed and signed, opening what arrives by hint, answering on the same channel, the plain
//! fallback, and anonymous answers to the reply key in the LEPIC marker.

use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::{
    Capabilities, ContactCard, Content, EncPublicKey, EncSecretKey, Hint, HintKey, HintRule,
    MessageType, Purpose, SealedEnvelope, armor, dearmor, seal,
};
use lepic_node::{NodeApi, Propagation};
use lepic_slate::codec::marked_v3::lepic_marker_reply_key;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::stage::Stage;
use lepic_store::{
    ContactId, ContactRecord, ContactState, Repositories, SealMode, SlateStage, StoreError,
    TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::file::FILE;
use tracing::{info, instrument};
use uuid::Uuid;

use super::keys::{contact_keys, contact_network, enc_secret, signing_key};
use super::{ContactError, LockedRng};
use crate::finalize::Finalized;
use crate::invoice::{PaidInvoice, PayRequest};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::{ReceiveRequest, Received, legacy_codecs};
use crate::wallet::Wallet;

/// A contact with no envelope opened for this long is shown as lapsed (RFC 0002 9.4).
pub const SEAL_LAPSE: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Prefix of the setting that names the contact a transaction was sealed to or from.
const TX_CONTACT_PREFIX: &str = "contact.tx.";

/// Sealed text that opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSlate {
    /// The contact whose signature the envelope carries. `None` for an anonymous envelope,
    /// which authenticates nothing: its slate is trusted only as the slate itself proves.
    pub contact_id: Option<ContactId>,
    pub stage: Stage,
    /// The slate as V3 JSON, as it would have arrived plain.
    pub wire: WireSlate,
    pub purpose: Option<Purpose>,
    /// The sender's own reference, shown and never trusted for crediting.
    pub reference: Option<String>,
    /// When the sender stops honouring the slate, in unix seconds; advisory.
    pub expires: Option<u64>,
}

/// How an answer goes back on the channel its slate came by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedAnswer {
    /// Armored text, sealed to the contact and signed, or sealed anonymously to the reply key
    /// of the slate's marker. Save it as `.epicsealed` or paste it back.
    Sealed(String),
    /// The plain slate, for a sender that cannot open sealed text.
    Plain(WireSlate),
}

/// A sealed or marked slate received and answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedReceived {
    pub received: Received,
    pub answer: SealedAnswer,
}

/// A sealed invoice paid and answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPayment {
    pub paid: PaidInvoice,
    pub answer: SealedAnswer,
}

/// The key a sealed text may open with.
enum Opening {
    /// Our key for the contacts in one slot of one account; twins may share it.
    Contact {
        key: EncSecretKey,
        records: Vec<ContactRecord>,
    },
    /// The one-time reply key of a slate this wallet started.
    Reply { key: EncSecretKey },
}

fn tx_key(tx_id: TxId) -> String {
    format!("{TX_CONTACT_PREFIX}{tx_id}")
}

/// Records that the transaction `tx_id` is an exchange with `contact`.
pub(crate) fn link_tx(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    contact: ContactId,
) -> Result<(), StoreError> {
    repos.put_setting(&tx_key(tx_id), &hex(&contact.0))
}

/// The contact the transaction `tx_id` was exchanged with, if any: what a contact's notices
/// are matched by.
pub(crate) fn tx_contact(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<ContactId>, StoreError> {
    Ok(repos
        .setting(&tx_key(tx_id))?
        .and_then(|text| contact_id_from_hex(&text)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn contact_id_from_hex(text: &str) -> Option<ContactId> {
    let mut id = [0u8; 16];
    if text.len() != 32 {
        return None;
    }
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(ContactId(id))
}

/// The stage of the slate this wallet last wrote for a transaction: what it sends onwards.
fn outgoing_stage(
    repos: &dyn Repositories,
    slate_id: Uuid,
    direction: TxDirection,
) -> Result<Option<SlateStage>, StoreError> {
    let order: &[SlateStage] = match direction {
        TxDirection::Outgoing => &[SlateStage::Invoice2, SlateStage::Standard1],
        TxDirection::Incoming => &[SlateStage::Standard2, SlateStage::Invoice1],
    };
    for stage in order {
        if repos.slate(slate_id, *stage)?.is_some() {
            return Ok(Some(*stage));
        }
    }
    Ok(None)
}

fn wire_text(bytes: Vec<u8>) -> Result<WireSlate, ContactError> {
    let text = String::from_utf8(bytes).map_err(|_| ContactError::NotASlate)?;
    Ok(WireSlate::text(MediaType::JSON, text))
}

/// Whether the contact can take a sealed send now.
fn check_sealable(record: &ContactRecord, card: &ContactCard) -> Result<(), ContactError> {
    if !matches!(record.state, ContactState::Paired | ContactState::Verified) {
        return Err(ContactError::UnknownContact);
    }
    if record.seal == SealMode::Off
        || !card
            .fields()
            .caps
            .contains(Capabilities::OPENS_SEALED_FILES)
    {
        return Err(ContactError::SealOff);
    }
    Ok(())
}

/// Whether a contact has gone quiet for longer than [`SEAL_LAPSE`].
pub(crate) fn lapsed(record: &ContactRecord, now: Timestamp) -> bool {
    let last = record.last_sealed_in.unwrap_or(record.created_at);
    last.checked_add(SEAL_LAPSE).is_ok_and(|end| end <= now)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Seals the slate this wallet last wrote for `tx_id` (its S1, I1, S2 or I2) to the paired
    /// contact `contact_id`, signed, with our current card (RFC 0002 9.1). Returns armored text
    /// for a `.epicsealed` file or a paste. `purpose` defaults to a payment for an S1 and a
    /// request for an I1. The transaction is remembered as the contact's, for
    /// [`Wallet::contact_plain_fallback`].
    ///
    /// Fails with [`ContactError::UnknownContact`] for a contact that is not paired or whose keys
    /// changed, [`ContactError::SealOff`] when sealing is off for it or its card says it cannot
    /// open sealed files, and [`ContactError::UnknownTransaction`] when the transaction has no
    /// slate to send.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn contact_seal_slate(
        &self,
        contact_id: ContactId,
        tx_id: TxId,
        purpose: Option<Purpose>,
    ) -> Result<String, ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let session = self.session()?;
        let armored = self
            .contact_work(move |ports, _| {
                session.store.write(|repos| {
                    let record = repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
                    let card =
                        ContactCard::decode(&peer.bytes, net).map_err(ContactError::StoredData)?;
                    check_sealable(&record, &card)?;
                    let entry = repos
                        .transaction(tx_id)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    let slate_id = entry.slate_id.ok_or(ContactError::UnknownTransaction)?;
                    let stage = outgoing_stage(repos, slate_id, entry.direction)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    let stored = repos
                        .slate(slate_id, stage)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    let own = ContactCard::decode(&record.own_card, net)
                        .map_err(ContactError::StoredData)?;
                    let keys = contact_keys(
                        &session.keychain,
                        network,
                        record.account,
                        record.slot,
                        record.box_salt,
                    )?;
                    let purpose = purpose.or(match stage {
                        SlateStage::Standard1 => Some(Purpose::Payment),
                        SlateStage::Invoice1 => Some(Purpose::Request),
                        _ => None,
                    });
                    let content = Content {
                        purpose,
                        card: Some(own),
                        ..Content::new(MessageType::Slate, stored.bytes)
                    };
                    let envelope = seal(
                        net,
                        card.enc_key(),
                        card.hint_rule(),
                        &content,
                        Some(&signing_key(&keys)),
                        &mut LockedRng(&mut **ports.rng.lock()),
                    )
                    .map_err(ContactError::Encode)?;
                    repos.put_setting(&tx_key(tx_id), &hex(&contact_id.0))?;
                    Ok(armor(&envelope))
                })
            })
            .await?;
        info!("slate sealed for a contact");
        Ok(armored)
    }

    /// Sends the slate this wallet last wrote for `tx_id` through the contact's mailbox (RFC 0002
    /// 9.1, "Send through Anna's mailbox"; 12.5 for a withdrawal): sealed as
    /// [`Wallet::contact_seal_slate`] seals it, queued in the outbox, and posted once when relays
    /// may be reached. The answer comes back to our mailbox and is taken by collecting.
    ///
    /// Fails as [`Wallet::contact_seal_slate`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn contact_post_slate(
        &self,
        relays: &super::ContactRelays,
        contact_id: ContactId,
        tx_id: TxId,
        purpose: Option<Purpose>,
    ) -> Result<(), ContactError> {
        let armored = self.contact_seal_slate(contact_id, tx_id, purpose).await?;
        let envelope = dearmor(&armored).map_err(ContactError::StoredData)?;
        let session = self.session()?;
        let (slate_id, stage) = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    let entry = repos
                        .transaction(tx_id)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    let slate_id = entry.slate_id.ok_or(ContactError::UnknownTransaction)?;
                    let stage = outgoing_stage(repos, slate_id, entry.direction)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    // A slate another contact holds is never moved to this one.
                    if !super::invoices::link_slate(repos, slate_id, contact_id)? {
                        return Err(ContactError::UnknownTransaction);
                    }
                    Ok((slate_id, stage))
                })
            })
            .await?;
        self.enqueue_for_contact(contact_id, slate_id, stage, &envelope)
            .await?;
        self.deliver_soon(relays).await;
        Ok(())
    }

    /// Opens sealed text from a file or a paste (RFC 0002 3.4 and 9.2). The hint finds the key:
    /// ours for a paired contact, or the reply key of a slate this wallet started. A signed
    /// envelope is attributed to the contact whose recorded key signed it; a newer card in it
    /// refreshes the contact. Nothing else is stored.
    ///
    /// Fails with [`ContactError::Decode`] for text that is not sealed, damaged or for the other
    /// network, [`ContactError::NotForThisInstall`] when no key of this wallet matches, or the
    /// signer is not the contact of the key that opened it (sealed for another wallet or
    /// install), [`ContactError::CannotOpen`], and [`ContactError::NotASlate`] for an envelope
    /// that holds no slate.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn sealed_open(&self, text: &str) -> Result<SealedSlate, ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let envelope = dearmor(text).map_err(ContactError::Decode)?;
        let sealed = SealedEnvelope::decode(&envelope, net).map_err(ContactError::Decode)?;
        let hint = sealed.hint();
        let enc = *sealed.enc();
        let session = self.session()?;
        let opening = self
            .contact_work(move |_, _| {
                session
                    .store
                    .read(|repos| find_opening(repos, &session.keychain, network, &hint, &enc))
            })
            .await?
            .ok_or(ContactError::NotForThisInstall)?;
        let (opened, contact) = match opening {
            Opening::Contact { key, records } => {
                let opened = sealed.open(&key).map_err(|_| ContactError::CannotOpen)?;
                let contact = match &opened.sender {
                    Some(sender) => Some(
                        records
                            .iter()
                            .find(|record| {
                                record
                                    .peer
                                    .as_ref()
                                    .is_some_and(|peer| peer.sig_key == sender.to_bytes())
                            })
                            .map(|record| record.contact_id)
                            .ok_or(ContactError::NotForThisInstall)?,
                    ),
                    None => None,
                };
                (opened, contact)
            }
            Opening::Reply { key } => {
                let opened = sealed.open(&key).map_err(|_| ContactError::CannotOpen)?;
                (opened, None)
            }
        };
        let content = opened.content;
        if content.kind != MessageType::Slate {
            return Err(ContactError::NotASlate);
        }
        let wire = wire_text(content.body)?;
        let slate = legacy_codecs(network)
            .map_err(|_| ContactError::NotASlate)?
            .decode(&wire)
            .map_err(|_| ContactError::NotASlate)?;
        if let Some(contact_id) = contact {
            if let Some(card) = content.card {
                self.refresh_card(contact_id, card, None).await?;
            }
            self.mark_sealed_in(contact_id).await?;
        }
        info!("sealed slate opened");
        Ok(SealedSlate {
            contact_id: contact,
            stage: slate.stage(),
            wire,
            purpose: content.purpose,
            reference: content
                .reference
                .map(|reference| reference.as_str().to_owned()),
            expires: content.expires,
        })
    }

    /// Receives the S1 in sealed text as [`Wallet::receive`] receives one by file, and answers
    /// on the same channel (RFC 0002 9.2): sealed and signed to the contact that signed it, or
    /// sealed anonymously to its marker's reply key, or else plain.
    ///
    /// Fails as [`Wallet::sealed_open`] does, with [`ContactError::Stage`] for another stage, and
    /// with [`ContactError::Receive`] as [`Wallet::receive`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn sealed_receive(
        &self,
        text: &str,
        request: ReceiveRequest,
    ) -> Result<SealedReceived, ContactError> {
        let opened = self.sealed_open(text).await?;
        if opened.stage != Stage::S1 {
            return Err(ContactError::Stage(opened.stage));
        }
        let received = self
            .receive(FILE, &opened.wire, request)
            .await
            .map_err(ContactError::Receive)?;
        let answer = self
            .sealed_answer(
                opened.contact_id,
                received.tx_id,
                &opened.wire,
                &received.reply,
            )
            .await?;
        Ok(SealedReceived { received, answer })
    }

    /// Pays the I1 in sealed text as [`Wallet::pay_invoice`] pays one by file, and answers on the
    /// same channel as [`Wallet::sealed_receive`] does. Paying is the user's decision: call it
    /// only after they approved the amount.
    ///
    /// Fails as [`Wallet::sealed_open`] does, with [`ContactError::Stage`] for another stage, and
    /// with [`ContactError::Invoice`] as [`Wallet::pay_invoice`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn sealed_pay(
        &self,
        text: &str,
        request: PayRequest,
    ) -> Result<SealedPayment, ContactError> {
        let opened = self.sealed_open(text).await?;
        if opened.stage != Stage::I1 {
            return Err(ContactError::Stage(opened.stage));
        }
        let paid = self
            .pay_invoice(FILE, &opened.wire, request)
            .await
            .map_err(ContactError::Invoice)?;
        let answer = self
            .sealed_answer(opened.contact_id, paid.tx_id, &opened.wire, &paid.reply)
            .await?;
        Ok(SealedPayment { paid, answer })
    }

    /// Finalizes and posts the S2 or I2 in sealed text, as [`Wallet::finalize`] and
    /// [`Wallet::finalize_invoice`] do for a file.
    ///
    /// Fails as [`Wallet::sealed_open`] does, with [`ContactError::Stage`] for another stage,
    /// and with [`ContactError::Finalize`] or [`ContactError::Invoice`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn sealed_finalize(
        &self,
        text: &str,
        propagation: Propagation,
    ) -> Result<Finalized, ContactError> {
        let opened = self.sealed_open(text).await?;
        match opened.stage {
            Stage::S2 => self
                .finalize(FILE, &opened.wire, propagation)
                .await
                .map_err(ContactError::Finalize),
            Stage::I2 => self
                .finalize_invoice(FILE, &opened.wire, propagation)
                .await
                .map_err(ContactError::Invoice),
            stage => Err(ContactError::Stage(stage)),
        }
    }

    /// The answer for a plain S1 or I1 whose LEPIC marker carries a reply key (RFC 0002 5):
    /// `reply`, the S2 or I2 the wallet answered `incoming` with, sealed anonymously to that key.
    /// `None` when `incoming` has no valid reply key; the answer then goes plain.
    pub fn sealed_answer_to_marker(
        &self,
        incoming: &WireSlate,
        reply: &WireSlate,
    ) -> Result<Option<String>, ContactError> {
        self.marker_answer(incoming, reply)
    }

    /// The slate this wallet last wrote for `tx_id`, plain, to resend to a contact that cannot
    /// open sealed text (RFC 0002 9.3): the same slate id, inputs, outputs and signatures, never
    /// a second transaction. The contact it was sealed to has its seal set to degraded.
    ///
    /// Fails with [`ContactError::UnknownTransaction`] when the transaction has no slate to send.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn contact_plain_fallback(&self, tx_id: TxId) -> Result<WireSlate, ContactError> {
        let session = self.session()?;
        let bytes = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    let entry = repos
                        .transaction(tx_id)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    if entry.state != TxState::Sent && entry.state != TxState::Received {
                        return Err(ContactError::UnknownTransaction);
                    }
                    let slate_id = entry.slate_id.ok_or(ContactError::UnknownTransaction)?;
                    let stage = outgoing_stage(repos, slate_id, entry.direction)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    let stored = repos
                        .slate(slate_id, stage)?
                        .ok_or(ContactError::UnknownTransaction)?;
                    if let Some(contact_id) = repos
                        .setting(&tx_key(tx_id))?
                        .and_then(|text| contact_id_from_hex(&text))
                        && let Some(mut record) = repos.contact(contact_id)?
                    {
                        record.seal = SealMode::Degraded;
                        repos.put_contact(&record)?;
                    }
                    Ok(stored.bytes)
                })
            })
            .await?;
        info!("plain fallback written");
        wire_text(bytes)
    }

    /// The contact a transaction was sealed to or from, if any.
    pub async fn contact_of_transaction(
        &self,
        tx_id: TxId,
    ) -> Result<Option<ContactId>, ContactError> {
        let session = self.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .read(|repos| repos.setting(&tx_key(tx_id)))?
                .and_then(|text| contact_id_from_hex(&text)))
        })
        .await
    }

    /// Seals `reply`, the answer to `incoming`, for the channel `incoming` came by.
    async fn sealed_answer(
        &self,
        contact: Option<ContactId>,
        tx_id: TxId,
        incoming: &WireSlate,
        reply: &WireSlate,
    ) -> Result<SealedAnswer, ContactError> {
        if let Some(contact_id) = contact {
            let network = self.config().network;
            let net = contact_network(network);
            let session = self.session()?;
            let body = reply.as_bytes().to_vec();
            let armored = self
                .contact_work(move |ports, _| {
                    session.store.write(|repos| {
                        let record = repos
                            .contact(contact_id)?
                            .ok_or(ContactError::UnknownContact)?;
                        let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
                        let card = ContactCard::decode(&peer.bytes, net)
                            .map_err(ContactError::StoredData)?;
                        let own = ContactCard::decode(&record.own_card, net)
                            .map_err(ContactError::StoredData)?;
                        let keys = contact_keys(
                            &session.keychain,
                            network,
                            record.account,
                            record.slot,
                            record.box_salt,
                        )?;
                        let content = Content {
                            card: Some(own),
                            ..Content::new(MessageType::Slate, body)
                        };
                        let envelope = seal(
                            net,
                            card.enc_key(),
                            card.hint_rule(),
                            &content,
                            Some(&signing_key(&keys)),
                            &mut LockedRng(&mut **ports.rng.lock()),
                        )
                        .map_err(ContactError::Encode)?;
                        repos.put_setting(&tx_key(tx_id), &hex(&contact_id.0))?;
                        Ok(armor(&envelope))
                    })
                })
                .await?;
            return Ok(SealedAnswer::Sealed(armored));
        }
        Ok(match self.marker_answer(incoming, reply)? {
            Some(armored) => SealedAnswer::Sealed(armored),
            None => SealedAnswer::Plain(reply.clone()),
        })
    }

    /// `reply` sealed anonymously to the reply key in the marker of `incoming`, if it has one.
    fn marker_answer(
        &self,
        incoming: &WireSlate,
        reply: &WireSlate,
    ) -> Result<Option<String>, ContactError> {
        let Some(key) = lepic_marker_reply_key(incoming) else {
            return Ok(None);
        };
        let Ok(key) = EncPublicKey::from_bytes(key) else {
            return Ok(None);
        };
        let envelope = seal(
            contact_network(self.config().network),
            &key,
            HintRule::ReplyKey,
            &Content::new(MessageType::Slate, reply.as_bytes().to_vec()),
            None,
            &mut LockedRng(&mut **self.ports().rng.lock()),
        )
        .map_err(ContactError::Encode)?;
        Ok(Some(armor(&envelope)))
    }
}

/// The key whose hint matches: ours for a contact slot, then the reply key of a slate this
/// wallet started and waits on.
fn find_opening(
    repos: &dyn Repositories,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    hint: &Hint,
    enc: &[u8; 32],
) -> Result<Option<Opening>, ContactError> {
    let mut slots: Vec<(lepic_store::AccountIndex, u32, Vec<ContactRecord>)> = Vec::new();
    for record in repos.contacts()? {
        if record.peer.is_none() {
            continue;
        }
        match slots
            .iter_mut()
            .find(|(account, slot, _)| *account == record.account && *slot == record.slot)
        {
            Some((_, _, records)) => records.push(record),
            None => slots.push((record.account, record.slot, vec![record])),
        }
    }
    for (account, slot, records) in slots {
        let root = keychain
            .contact_root(&crate::account::parent_key_id(account)?, network)
            .map_err(ContactError::Keys)?;
        let hint_key = root.hint_key(slot).map_err(ContactError::Keys)?;
        if Hint::contact(&HintKey::from_bytes(*hint_key), enc) != *hint {
            continue;
        }
        let Some(first) = records.first() else {
            continue;
        };
        let keys = contact_keys(keychain, network, account, slot, first.box_salt)?;
        return Ok(Some(Opening::Contact {
            key: enc_secret(&keys),
            records,
        }));
    }
    for account in repos.accounts()? {
        let root = keychain
            .contact_root(&crate::account::parent_key_id(account.index)?, network)
            .map_err(ContactError::Keys)?;
        for stored in repos.transactions(account.index)? {
            let entry = &stored.entry;
            let waiting = matches!(
                (entry.direction, entry.state),
                (TxDirection::Outgoing, TxState::Sent) | (TxDirection::Incoming, TxState::Received)
            );
            let Some(slate_id) = entry.slate_id.filter(|_| waiting) else {
                continue;
            };
            let reply = root
                .reply_key(*slate_id.as_bytes())
                .map_err(ContactError::Keys)?;
            let key = EncSecretKey::from_bytes(*reply.expose_x25519_secret());
            if Hint::reply(&key.public_key(), enc) == *hint {
                return Ok(Some(Opening::Reply { key }));
            }
        }
    }
    Ok(None)
}
