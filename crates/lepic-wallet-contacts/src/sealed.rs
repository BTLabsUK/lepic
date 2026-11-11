// SPDX-License-Identifier: Apache-2.0
//! Sealed slates in files and pastes (RFC 0002 sections 5 and 9): sending to a paired contact
//! sealed and signed, opening what arrives by hint, answering on the same channel, the plain
//! fallback, and anonymous answers to the reply key in the LEPIC marker.

use lepic_wallet::contact_link::{link_tx, tx_contact};
use std::path::PathBuf;
use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::{
    Capabilities, ContactCard, Content, EncPublicKey, EncSecretKey, Hint, HintKey, HintRule,
    MessageType, Opened, PaymentFile, Purpose, SealedEnvelope, armor, classify, dearmor, seal,
    seal_padded,
};
use lepic_native_slate::{NativeSlate, SlateView};
use lepic_node::{NodeApi, Propagation};
use lepic_seal::{ArmorMarker, ClassifyError, TxContent, TxKey, dearmor_marked, seal_tx};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::stage::Stage;
use lepic_store::{
    ContactId, ContactRecord, ContactState, Repositories, SealMode, SlateStage, StoreError,
    TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::marker::v3::lepic_marker_reply_key;
use lepic_transport::transport::Location;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use super::direct::trial_open_accounts;
use super::epic1::Epic1Refusal;
use super::in_person::InPersonRefusal;
use super::keys::{contact_keys, contact_network, enc_secret, signing_key};
use super::{ContactError, LockedRng};
use crate::{ContactBook, file_method};
use lepic_wallet::SlateFormat;
use lepic_wallet::finalize::Finalized;
use lepic_wallet::invoice::{PaidInvoice, PayRequest};
use lepic_wallet::ports::{SecretVault, StoreOpener};
use lepic_wallet::receive::{ProofKey, ReceiveRequest, Received, legacy_codecs};
use lepic_wallet::send::{Delivery, SendError, SendRequest, SentSlate};

/// A contact with no envelope opened for this long is shown as lapsed (RFC 0002 9.4).
pub const SEAL_LAPSE: Duration = Duration::from_secs(90 * 24 * 60 * 60);

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
    /// The slate's messages whose signatures verify, as transaction details show them.
    pub messages: Vec<lepic_wallet::details::SlateMessage>,
}

/// A slate in sealed text as it arrived, for tools and the API (RFC 0003 5.10).
#[derive(Debug, Clone, PartialEq)]
pub struct EpictxView {
    /// The contact whose signature the envelope carries; `None` for an anonymous envelope.
    pub contact_id: Option<ContactId>,
    /// Whether the body is a `lepic.v1` slate.
    pub native: bool,
    /// The [`SlateView`] of a `lepic.v1` slate, or the V3 JSON of another.
    pub slate: serde_json::Value,
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
    /// of the slate's marker. Save it as `.epictx` when [`is_epictx`] says so, else as
    /// `.epicsealed`, or paste it back.
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

/// What sealed text opened to.
struct Envelope {
    content: Content,
    /// Whether the body is a `lepic.v1` slate.
    native: bool,
    /// The contact whose key signed it.
    contact: Option<ContactId>,
    /// The epic1 address it was sealed to, when it was.
    epic1: Option<Epic1Opening>,
}

/// The epic1 address an envelope was sealed to.
#[derive(Debug, Clone)]
struct Epic1Opening {
    /// The label of the address's account.
    label: String,
    /// The index of the address in its account.
    index: u32,
}

/// What [`ContactBook::open_text`] opened.
struct TextOpened {
    slate: SealedSlate,
    native: bool,
    epic1: Option<Epic1Opening>,
    /// The key the slate's answer is sealed to, as the envelope named it.
    reply_key: Option<EncPublicKey>,
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

/// What a payment file or paste holds, by its content (RFC 0003 5.12): armored text of either
/// marker pair, or a JSON slate.
///
/// Fails with [`ContactError::SavedTransaction`] for hex digits only, which another Epic
/// wallet keeps in its `saved_txs` directory, and [`ContactError::NotPaymentFile`] for
/// anything else.
pub fn payment_file(data: &[u8]) -> Result<PaymentFile, ContactError> {
    classify(data).map_err(|error| match error {
        ClassifyError::StockSavedTx => ContactError::SavedTransaction,
        ClassifyError::NotPaymentFile => ContactError::NotPaymentFile,
    })
}

/// Whether `text` is armored with the `BEGINEPICTX.` marker pair: a native slate, whose
/// answer is written as `.epictx`.
pub fn is_epictx(text: &str) -> bool {
    matches!(dearmor_marked(text), Ok((_, ArmorMarker::Tx)))
}

/// How a sealed slate leaves for a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    /// Armored text for a file or a paste, which the user could also send plain.
    Text,
    /// The contact's mailbox, which carries only sealed envelopes (RFC 0002 9.1 and 11.2).
    Mailbox,
}

/// Whether the contact can take a sealed send now on `channel`. The seal switch governs files
/// and pastes only: a mailbox send is sealed whatever it says.
fn check_sealable(
    record: &ContactRecord,
    card: &ContactCard,
    channel: Channel,
) -> Result<(), ContactError> {
    // Slates never travel over a private pairing.
    if super::private::is_private(record) {
        return Err(ContactError::WrongClass);
    }
    if !matches!(record.state, ContactState::Paired | ContactState::Verified) {
        return Err(ContactError::UnknownContact);
    }
    super::status::require_live(record)?;
    if (channel == Channel::Text && record.seal == SealMode::Off)
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

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Seals the slate this wallet last wrote for `tx_id` (its S1, I1, S2 or I2) to the paired
    /// contact `contact_id`, signed, with our current card (RFC 0002 9.1). Returns armored text
    /// for a file or a paste: an S1 or I1 goes native, `BEGINEPICTX.` for a `.epictx` file, when
    /// the host set `native_direct` and the contact claims native slates; anything else is
    /// `BEGINEPICSEALED.` for a `.epicsealed` file. `purpose` defaults to a payment for an S1 and a
    /// request for an I1. The transaction is remembered as the contact's, for
    /// [`ContactBook::contact_plain_fallback`].
    ///
    /// Fails with [`ContactError::UnknownContact`] for a contact that is not paired or whose keys
    /// changed, [`ContactError::Waiting`] before the contact was heard in the pairing,
    /// [`ContactError::Ended`] once it ended, [`ContactError::SealOff`] when sealing is off for it
    /// or its card says it cannot open sealed files, and [`ContactError::UnknownTransaction`] when
    /// the transaction has no slate to send.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name, tx_id = %tx_id))]
    pub async fn contact_seal_slate(
        &self,
        contact_id: ContactId,
        tx_id: TxId,
        purpose: Option<Purpose>,
    ) -> Result<String, ContactError> {
        Ok(self
            .seal_stored_slate(contact_id, tx_id, purpose, Channel::Text)
            .await?
            .0)
    }

    /// Checks that a slate can go to the contact `contact_id` through its mailbox, as
    /// [`ContactBook::contact_post_slate`] would check it, before anything is built or locked: the
    /// contact is paired or verified, its card says it opens sealed slates, and its mailbox is
    /// known. Reads only.
    ///
    /// Fails with [`ContactError::UnknownContact`] and [`ContactError::SealOff`] as
    /// [`ContactBook::contact_post_slate`] does.
    pub async fn contact_check_mailbox_send(
        &self,
        contact_id: ContactId,
    ) -> Result<(), ContactError> {
        let net = contact_network(self.wallet.config().network);
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.read(|repos| {
                let record = repos
                    .contact(contact_id)?
                    .ok_or(ContactError::UnknownContact)?;
                let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
                let card =
                    ContactCard::decode(&peer.bytes, net).map_err(ContactError::StoredData)?;
                check_sealable(&record, &card, Channel::Mailbox)?;
                repos
                    .contact_mailbox(contact_id)?
                    .ok_or(ContactError::UnknownContact)?;
                Ok(())
            })
        })
        .await
    }

    /// Seals the slate this wallet last wrote for `tx_id` to the contact for `channel`, as
    /// [`ContactBook::contact_seal_slate`] describes, with the format it was sealed in.
    async fn seal_stored_slate(
        &self,
        contact_id: ContactId,
        tx_id: TxId,
        purpose: Option<Purpose>,
        channel: Channel,
    ) -> Result<(String, SlateFormat), ContactError> {
        let network = self.wallet.config().network;
        let native_direct = self.wallet.config().native_direct;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let armored = self
            .contact_work(move |ports, _| {
                session.store.write(|repos| {
                    let record = repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
                    let card =
                        ContactCard::decode(&peer.bytes, net).map_err(ContactError::StoredData)?;
                    check_sealable(&record, &card, channel)?;
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
                        sent_at: super::collect::send_time(ports.clock.now()),
                        ..Content::new(MessageType::Slate, stored.bytes)
                    };
                    // A new slate goes native when both sides take it. An answer sealed here
                    // answers a request whose format is not stored, so it goes as V3, which
                    // every LEPIC build reads; one made by opening the request takes its format.
                    let native = matches!(stage, SlateStage::Standard1 | SlateStage::Invoice1)
                        && super::native::wants_native(native_direct, &record);
                    let mut guard = ports.rng.lock();
                    let mut rng = LockedRng(&mut **guard);
                    let envelope = if native {
                        super::native::seal_native(
                            network,
                            &card,
                            content,
                            &signing_key(&keys),
                            &mut rng,
                        )?
                    } else {
                        super::native::seal_v1(
                            native_direct,
                            network,
                            &card,
                            &content,
                            Some(&signing_key(&keys)),
                            &mut rng,
                        )?
                    };
                    drop(guard);
                    link_tx(repos, tx_id, contact_id)?;
                    let format = if native {
                        SlateFormat::Native
                    } else {
                        SlateFormat::Legacy
                    };
                    Ok((super::native::armor_slate(&envelope, native), format))
                })
            })
            .await?;
        info!("slate sealed for a contact");
        Ok(armored)
    }

    /// Sends the slate this wallet last wrote for `tx_id` through the contact's mailbox (RFC 0002
    /// 9.1, "Send through Anna's mailbox"; 12.5 for a withdrawal): sealed as
    /// [`ContactBook::contact_seal_slate`] seals it, queued in the outbox, and posted once when
    /// relays may be reached. The answer comes back to our mailbox and is taken by collecting. A
    /// mailbox carries only sealed envelopes, so the contact's seal switch does not apply.
    ///
    /// Returns the format the slate was sealed in.
    ///
    /// Fails as [`ContactBook::contact_seal_slate`] does, except that [`ContactError::SealOff`]
    /// means only that the contact's card says it cannot open sealed slates.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name, tx_id = %tx_id))]
    pub async fn contact_post_slate(
        &self,
        relays: &super::ContactRelays,
        contact_id: ContactId,
        tx_id: TxId,
        purpose: Option<Purpose>,
    ) -> Result<SlateFormat, ContactError> {
        self.post_stored_slate(relays, contact_id, tx_id, purpose)
            .await
    }

    /// Posts as [`ContactBook::contact_post_slate`] does, with the format the slate was sealed in.
    async fn post_stored_slate(
        &self,
        relays: &super::ContactRelays,
        contact_id: ContactId,
        tx_id: TxId,
        purpose: Option<Purpose>,
    ) -> Result<SlateFormat, ContactError> {
        let (armored, format) = self
            .seal_stored_slate(contact_id, tx_id, purpose, Channel::Mailbox)
            .await?;
        let session = self.wallet.session()?;
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
                    if !lepic_wallet::contact_link::link_slate(repos, slate_id, contact_id)? {
                        return Err(ContactError::UnknownTransaction);
                    }
                    Ok((slate_id, stage))
                })
            })
            .await?;
        self.enqueue_armored(contact_id, slate_id, stage, armored)
            .await?;
        self.deliver_soon(relays).await;
        Ok(format)
    }

    /// Pays the contact `contact_id` through its mailbox. The contact is checked as
    /// [`ContactBook::contact_check_mailbox_send`] checks it, so a send it cannot take locks
    /// nothing; then `request` is sent with its S1 written to `slate_file` on the way, and posted
    /// as [`ContactBook::contact_post_slate`] posts it. `slate_file` is a path in the wallet's
    /// directory that the caller removes afterwards.
    ///
    /// A send that was stored but could not be written or queued is cancelled, so it holds no
    /// inputs. When that cancel fails too, the error is [`ContactError::NotCancelled`] with the
    /// transaction, never a silent leftover. Fails with [`ContactError::Send`] when the send
    /// fails, and otherwise as [`ContactBook::contact_post_slate`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_send(
        &self,
        relays: &super::ContactRelays,
        contact_id: ContactId,
        request: SendRequest,
        slate_file: PathBuf,
        purpose: Option<Purpose>,
    ) -> Result<SentSlate, ContactError> {
        self.contact_check_mailbox_send(contact_id).await?;
        let delivery = Delivery::Export {
            to: Location::File(slate_file),
        };
        let sent = match self.wallet.send(&file_method(), request, delivery).await {
            Ok(sent) => sent,
            // Stored and locked, but the slate file was not written: nothing reaches the
            // contact, so the send is given up rather than left holding its inputs.
            Err(error @ SendError::Undelivered { tx_id, .. }) => {
                return Err(self.give_up_send(tx_id, ContactError::Send(error)).await);
            }
            Err(error) => return Err(ContactError::Send(error)),
        };
        let tx_id = sent.tx_id;
        match self
            .post_stored_slate(relays, contact_id, tx_id, purpose)
            .await
        {
            // The slate file is legacy JSON; what went to the contact is what was sealed.
            Ok(format) => Ok(SentSlate { format, ..sent }),
            Err(error) => Err(self.give_up_send(tx_id, error).await),
        }
    }

    /// Cancels the stored send `tx_id` after `cause` stopped it. A cancel that fails is logged
    /// and returned with the transaction, so the caller can cancel it again.
    pub(crate) async fn give_up_send(
        &self,
        tx_id: lepic_store::TxId,
        cause: ContactError,
    ) -> ContactError {
        match self.wallet.cancel(tx_id).await {
            Ok(()) => {
                info!(tx_id = %tx_id, "send to a contact cancelled, it was not delivered");
                cause
            }
            Err(cancel) => {
                warn!(tx_id = %tx_id, error = %cancel, "send to a contact not delivered nor cancelled");
                ContactError::NotCancelled {
                    tx_id,
                    cause: Box::new(cause),
                    cancel,
                }
            }
        }
    }

    /// Opens sealed text from a file or a paste (RFC 0002 3.4 and 9.2). The hint finds the key:
    /// ours for a paired contact, or the reply key of a slate this wallet started. A signed
    /// envelope is attributed to the contact whose recorded key signed it; a newer card in it
    /// refreshes the contact. Nothing else is stored.
    ///
    /// Fails with [`ContactError::SavedTransaction`] or [`ContactError::NotPaymentFile`] as
    /// [`payment_file`] does, [`ContactError::Decode`] for text that is not sealed, damaged or for
    /// the other network, [`ContactError::NotForThisInstall`] when no key of this wallet matches,
    /// or the signer is not the contact of the key that opened it (sealed for another wallet or
    /// install), [`ContactError::CannotOpen`], and [`ContactError::NotASlate`] for an envelope that
    /// holds no slate.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn sealed_open(&self, text: &str) -> Result<SealedSlate, ContactError> {
        Ok(self.open_text(text).await?.slate)
    }

    /// Opens sealed text as [`ContactBook::sealed_open`] does and stores nothing: a newer card
    /// in it does not refresh the contact, and the contact is not marked as heard from. For a
    /// look before acting on the text.
    ///
    /// Fails as [`ContactBook::sealed_open`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn sealed_peek(&self, text: &str) -> Result<SealedSlate, ContactError> {
        Ok(self.open_text_storing(text, false).await?.slate)
    }

    /// Opens sealed text with this wallet's keys and shows its slate as it arrived: the 1:1
    /// JSON view of a `lepic.v1` slate (RFC 0003 5.10), or the V3 JSON of any other. Nothing is
    /// stored and no contact is refreshed.
    ///
    /// Fails as [`ContactBook::sealed_open`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epictx_open(&self, text: &str) -> Result<EpictxView, ContactError> {
        let network = self.wallet.config().network;
        let Envelope {
            content,
            native,
            contact,
            ..
        } = self.open_envelope(text).await?;
        if content.kind != MessageType::Slate {
            return Err(ContactError::NotASlate);
        }
        let slate = if native {
            let native =
                NativeSlate::decode(network, &content.body).map_err(|_| ContactError::NotASlate)?;
            serde_json::to_value(SlateView::new(network, &native))
                .map_err(|_| ContactError::NotASlate)?
        } else {
            serde_json::from_slice(&content.body).map_err(|_| ContactError::NotASlate)?
        };
        Ok(EpictxView {
            contact_id: contact,
            native,
            slate,
            purpose: content.purpose,
            reference: content
                .reference
                .map(|reference| reference.as_str().to_owned()),
            expires: content.expires,
        })
    }

    /// The content of sealed text opened with this wallet's keys, whether its body is a
    /// `lepic.v1` slate, and the contact whose key signed it. An envelope with a zero hint that
    /// no other key opens is tried with the seal keys of the wallet's epic1 addresses
    /// ([`lepic_wallet::Wallet::epic1_trial_keys_all`]): nothing in it says which address it was
    /// sealed to.
    async fn open_envelope(&self, text: &str) -> Result<Envelope, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        payment_file(text.as_bytes())?;
        let envelope = dearmor(text).map_err(ContactError::Decode)?;
        let sealed = SealedEnvelope::decode(&envelope, net).map_err(ContactError::Decode)?;
        let hint = sealed.hint();
        let enc = *sealed.enc();
        let session = self.wallet.session()?;
        let opening = self
            .contact_work(move |_, _| {
                session
                    .store
                    .read(|repos| find_opening(repos, &session.keychain, network, &hint, &enc))
            })
            .await?;
        let Some(opening) = opening else {
            if hint != Hint::from_bytes([0; 8]) {
                return Err(ContactError::NotForThisInstall);
            }
            return self.open_epic1(envelope.clone(), net).await;
        };
        let (opened, contact) = match opening {
            Opening::Contact { key, records } => {
                let opened =
                    super::native::open_any(&sealed, &key).map_err(|_| ContactError::CannotOpen)?;
                let contact = match &opened.0.sender {
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
                let opened =
                    super::native::open_any(&sealed, &key).map_err(|_| ContactError::CannotOpen)?;
                (opened, None)
            }
        };
        let ((Opened { content, .. }, native), contact) = (opened, contact);
        Ok(Envelope {
            content,
            native,
            contact,
            epic1: None,
        })
    }

    /// `envelope`, a zero-hint envelope, opened with the seal key of one of the wallet's epic1
    /// addresses, every account tried in turn. A payment to an epic1 is anonymous: a signed one
    /// is refused.
    async fn open_epic1(
        &self,
        envelope: Vec<u8>,
        net: lepic_contact::Network,
    ) -> Result<Envelope, ContactError> {
        let accounts = self.wallet.epic1_trial_keys_all().await?;
        let (account, label, index, opened) = trial_open_accounts(envelope, net, accounts)
            .await
            .ok_or(ContactError::NotForThisInstall)?;
        if opened.sender.is_some() {
            return Err(ContactError::Epic1(Epic1Refusal::Signed));
        }
        info!(
            account = account.0,
            index, "sealed text opened at an epic1 address"
        );
        Ok(Envelope {
            content: super::native::opened_of(opened).content,
            native: true,
            contact: None,
            epic1: Some(Epic1Opening { label, index }),
        })
    }

    /// [`ContactBook::sealed_open`], whether the slate came native, the epic1 address it was sealed
    /// to, and the reply key it names.
    async fn open_text(&self, text: &str) -> Result<TextOpened, ContactError> {
        self.open_text_storing(text, true).await
    }

    /// [`Self::open_text`]; with `store` false, the contact is neither refreshed nor marked.
    async fn open_text_storing(&self, text: &str, store: bool) -> Result<TextOpened, ContactError> {
        let network = self.wallet.config().network;
        let Envelope {
            content,
            native,
            contact,
            epic1,
        } = self.open_envelope(text).await?;
        let reply_key = content.reply_key;
        if content.kind != MessageType::Slate {
            return Err(ContactError::NotASlate);
        }
        let body = if native {
            // An anonymous native invoice is never taken: it needs the payer's consent
            // (RFC 0003 5.9).
            if contact.is_none()
                && super::native::decode_native(network, &content.body)
                    .is_some_and(|slate| slate.stage() == Stage::I1)
            {
                return Err(ContactError::NotASlate);
            }
            self.v3_of_native(&content.body)
                .await?
                .ok_or(ContactError::NotASlate)?
        } else {
            content.body
        };
        let wire = wire_text(body)?;
        let slate = legacy_codecs(network)
            .map_err(|_| ContactError::NotASlate)?
            .decode(&wire)
            .map_err(|_| ContactError::NotASlate)?;
        if let Some(contact_id) = contact
            && store
        {
            if let Some(card) = content.card {
                self.refresh_card(contact_id, card, None).await?;
            }
            self.mark_sealed_in(contact_id).await?;
        }
        info!("sealed slate opened");
        let opened = SealedSlate {
            contact_id: contact,
            stage: slate.stage(),
            wire,
            purpose: content.purpose,
            reference: content
                .reference
                .map(|reference| reference.as_str().to_owned()),
            expires: content.expires,
            messages: lepic_wallet::details::verified_messages(&slate),
        };
        Ok(TextOpened {
            slate: opened,
            native,
            epic1,
            reply_key,
        })
    }

    /// Receives the S1 in sealed text as [`Wallet::receive`] receives one by file, and answers
    /// on the same channel (RFC 0002 9.2): sealed and signed to the contact that signed it, or
    /// sealed anonymously to its marker's reply key, or else plain.
    ///
    /// An S1 sealed to one of the wallet's epic1 addresses is received into that address's
    /// account with its proof key, whatever account `request` names, and its S2 is sealed to
    /// the reply key the envelope names.
    ///
    /// Fails as [`ContactBook::sealed_open`] does, with [`ContactError::Stage`] for another stage,
    /// [`ContactError::Epic1`] for a payment to an epic1 that names no reply key, and with
    /// [`ContactError::Receive`] as [`Wallet::receive`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn sealed_receive(
        &self,
        text: &str,
        mut request: ReceiveRequest,
    ) -> Result<SealedReceived, ContactError> {
        let TextOpened {
            slate: opened,
            native,
            epic1,
            reply_key,
        } = self.open_text(text).await?;
        if opened.stage != Stage::S1 {
            return Err(ContactError::Stage(opened.stage));
        }
        let epic1_reply = match epic1 {
            Some(epic1) => {
                let reply_key = reply_key.ok_or(ContactError::Epic1(Epic1Refusal::NoReplyKey))?;
                request.account = Some(epic1.label);
                request.proof_key = ProofKey::Epic1 { index: epic1.index };
                Some(reply_key)
            }
            None => None,
        };
        let received = self
            .wallet
            .receive(&file_method(), &opened.wire, request)
            .await
            .map_err(ContactError::Receive)?;
        if let Some(reply_key) = epic1_reply {
            let answer = self.epic1_answer(&received.reply, &reply_key)?;
            return Ok(SealedReceived { received, answer });
        }
        let answer = self
            .sealed_answer(
                opened.contact_id,
                received.tx_id,
                &opened.wire,
                &received.reply,
                native,
            )
            .await?;
        Ok(SealedReceived { received, answer })
    }

    /// Pays the I1 in sealed text as [`Wallet::pay_invoice`] pays one by file, and answers on the
    /// same channel as [`ContactBook::sealed_receive`] does. Paying is the user's decision: call it
    /// only after they approved the amount.
    ///
    /// Fails as [`ContactBook::sealed_open`] does, with [`ContactError::Stage`] for another stage,
    /// and with [`ContactError::Invoice`] as [`Wallet::pay_invoice`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn sealed_pay(
        &self,
        text: &str,
        request: PayRequest,
    ) -> Result<SealedPayment, ContactError> {
        let TextOpened {
            slate: opened,
            native,
            ..
        } = self.open_text(text).await?;
        if opened.stage != Stage::I1 {
            return Err(ContactError::Stage(opened.stage));
        }
        let paid = self
            .wallet
            .pay_invoice(&file_method(), &opened.wire, request)
            .await
            .map_err(ContactError::Invoice)?;
        let answer = self
            .sealed_answer(
                opened.contact_id,
                paid.tx_id,
                &opened.wire,
                &paid.reply,
                native,
            )
            .await?;
        Ok(SealedPayment { paid, answer })
    }

    /// Finalizes and posts the S2 or I2 in sealed text, as [`Wallet::finalize`] and
    /// [`Wallet::finalize_invoice`] do for a file.
    ///
    /// An answer to an in-person code this wallet showed is not finalized here: it is taken
    /// with its check code by [`ContactBook::in_person_take`].
    ///
    /// Fails as [`ContactBook::sealed_open`] does, with [`ContactError::Stage`] for another stage,
    /// [`ContactError::InPerson`] with [`InPersonRefusal::AnswerToCode`] for an answer to an
    /// in-person code, and with [`ContactError::Finalize`] or [`ContactError::Invoice`].
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn sealed_finalize(
        &self,
        text: &str,
        propagation: Propagation,
    ) -> Result<Finalized, ContactError> {
        let opened = self.sealed_open(text).await?;
        self.refuse_answer_to_code(&opened.wire).await?;
        match opened.stage {
            Stage::S2 => self
                .wallet
                .finalize(&file_method(), &opened.wire, propagation)
                .await
                .map_err(ContactError::Finalize),
            Stage::I2 => self
                .wallet
                .finalize_invoice(&file_method(), &opened.wire, propagation)
                .await
                .map_err(ContactError::Invoice),
            stage => Err(ContactError::Stage(stage)),
        }
    }

    /// Refuses with [`InPersonRefusal::AnswerToCode`] the slate `wire` when this wallet showed
    /// an in-person code for it: its answers are finalized only after their check code.
    async fn refuse_answer_to_code(&self, wire: &WireSlate) -> Result<(), ContactError> {
        let slate = legacy_codecs(self.wallet.config().network)
            .map_err(|_| ContactError::NotASlate)?
            .decode(wire)
            .map_err(|_| ContactError::NotASlate)?;
        let slate_id = slate.id();
        let session = self.wallet.session()?;
        let answers_code = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    Ok::<_, ContactError>(super::in_person::has_code(repos, slate_id)?)
                })
            })
            .await?;
        if answers_code {
            return Err(ContactError::InPerson(InPersonRefusal::AnswerToCode));
        }
        Ok(())
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
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name, tx_id = %tx_id))]
    pub async fn contact_plain_fallback(&self, tx_id: TxId) -> Result<WireSlate, ContactError> {
        let session = self.wallet.session()?;
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
                    if let Some(contact_id) = tx_contact(repos, tx_id)?
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
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| Ok(session.store.read(|repos| tx_contact(repos, tx_id))?))
            .await
    }

    /// Seals `reply`, the answer to `incoming`, for the channel `incoming` came by and in its
    /// format: `native` for a request that came as `lepic.v1`.
    async fn sealed_answer(
        &self,
        contact: Option<ContactId>,
        tx_id: TxId,
        incoming: &WireSlate,
        reply: &WireSlate,
        native: bool,
    ) -> Result<SealedAnswer, ContactError> {
        if let Some(contact_id) = contact {
            let network = self.wallet.config().network;
            let net = contact_network(network);
            let native_direct = self.wallet.config().native_direct;
            let session = self.wallet.session()?;
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
                            sent_at: super::collect::send_time(ports.clock.now()),
                            ..Content::new(MessageType::Slate, body)
                        };
                        let mut guard = ports.rng.lock();
                        let mut rng = LockedRng(&mut **guard);
                        let envelope = if native {
                            super::native::seal_native(
                                network,
                                &card,
                                content,
                                &signing_key(&keys),
                                &mut rng,
                            )?
                        } else {
                            super::native::seal_v1(
                                native_direct,
                                network,
                                &card,
                                &content,
                                Some(&signing_key(&keys)),
                                &mut rng,
                            )?
                        };
                        drop(guard);
                        link_tx(repos, tx_id, contact_id)?;
                        Ok(super::native::armor_slate(&envelope, native))
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

    /// `reply`, the S2 for a payment to an epic1 address, as `lepic.v1` sealed anonymously to
    /// `reply_key`, the key the payment named.
    fn epic1_answer(
        &self,
        reply: &WireSlate,
        reply_key: &EncPublicKey,
    ) -> Result<SealedAnswer, ContactError> {
        let network = self.wallet.config().network;
        let body = super::native::native_body(network, reply.as_bytes())?;
        let envelope = seal_tx(
            contact_network(network),
            reply_key,
            TxKey::Seal(HintRule::ReplyKey),
            &TxContent::new(body),
            None,
            &mut LockedRng(&mut **self.wallet.ports().rng.lock()),
        )
        .map_err(ContactError::Encode)?;
        Ok(SealedAnswer::Sealed(super::native::armor_slate(
            &envelope, true,
        )))
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
        let net = contact_network(self.wallet.config().network);
        let content = Content::new(MessageType::Slate, reply.as_bytes().to_vec());
        let rng = &mut LockedRng(&mut **self.wallet.ports().rng.lock());
        let envelope = if self.wallet.config().native_direct {
            seal_padded(net, &key, HintRule::ReplyKey, &content, None, rng)
        } else {
            seal(net, &key, HintRule::ReplyKey, &content, None, rng)
        }
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
        let root = crate::key_schedule::contact_root(
            keychain,
            &lepic_wallet::account::parent_key_id(account)?,
            network,
        )
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
        let root = crate::key_schedule::contact_root(
            keychain,
            &lepic_wallet::account::parent_key_id(account.index)?,
            network,
        )
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
