//! Invoices, withdrawals and notices between paired contacts through their mailboxes (RFC 0002
//! sections 11 and 12): a contact's invoice parks only when the contact is verified and allowed
//! to send invoices, payments and answers go through the outbox, and notices travel sealed.

use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::{Capabilities, ContactCard, Content, MessageType, Purpose, seal};
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::amount::Amount;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::SlateId;
use lepic_slate::stage::Stage;
use lepic_store::{
    ContactId, ContactRecord, ContactState, PendingInvoice, PendingInvoiceStatus, Repositories,
    SlateStage, StoreError, TxDirection, TxId, WalletStore,
};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::keys::{contact_keys, contact_network, signing_key};
use super::{ContactError, ContactRelays, LockedRng, RelayMode};
use crate::event::{ContactInvoiceEvent, ContactSlateEvent, Event};
use crate::inbox::ErrorChain;
use crate::invoice::{InvoiceError, InvoiceRequest, IssuedInvoice, PaidInvoice, PayRequest};
use crate::notice::{Notice, NoticeKind, Payload, classify_text};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::{ReceiveError, ReceiveRequest, legacy_codecs};
use crate::wallet::Wallet;

/// Requests for the same amount from one contact within this window are grouped, so the user
/// is asked before a second payment (RFC 0002 12.6).
pub const SAME_AMOUNT_WINDOW: Duration = Duration::from_secs(10 * 60);

const INVOICE_PREFIX: &str = "contact.invoice.";
const SLATE_PREFIX: &str = "contact.slate.";

/// What a contact's invoice says beyond the slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceDetails {
    pub purpose: Purpose,
    /// Our own reference, shown to the payer and never trusted for crediting.
    pub reference: Option<String>,
    /// When we stop honouring the invoice, in unix seconds; advisory.
    pub expires: Option<u64>,
}

/// A parked invoice from a contact, as the host shows it before the user approves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactInvoice {
    pub slate_id: SlateId,
    pub contact_id: ContactId,
    pub amount: Amount,
    pub purpose: Option<Purpose>,
    pub reference: Option<String>,
    pub expires: Option<u64>,
    pub received_at: Timestamp,
    /// Other parked invoices from the same contact for the same amount received within
    /// [`SAME_AMOUNT_WINDOW`]: ask "Pay both?" before a second payment.
    pub same_amount: Vec<SlateId>,
}

#[derive(Serialize, Deserialize)]
struct InvoiceNote {
    contact: String,
    purpose: Option<u8>,
    reference: Option<String>,
    expires: Option<u64>,
}

fn purpose_byte(purpose: Purpose) -> u8 {
    match purpose {
        Purpose::Payment => 1,
        Purpose::DepositRequest => 2,
        Purpose::Withdrawal => 3,
        Purpose::Refund => 4,
        Purpose::Request => 5,
    }
}

fn purpose_of(byte: u8) -> Option<Purpose> {
    Some(match byte {
        1 => Purpose::Payment,
        2 => Purpose::DepositRequest,
        3 => Purpose::Withdrawal,
        4 => Purpose::Refund,
        5 => Purpose::Request,
        _ => return None,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn contact_from_hex(text: &str) -> Option<ContactId> {
    let mut id = [0u8; 16];
    if text.len() != 32 {
        return None;
    }
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(ContactId(id))
}

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

/// Records that the slate `slate_id` belongs to an exchange with `contact`, so its notices and
/// answers go through the contact's mailbox.
pub(crate) fn link_slate(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    contact: ContactId,
) -> Result<(), StoreError> {
    repos.put_setting(&format!("{SLATE_PREFIX}{slate_id}"), &hex(&contact.0))
}

/// The contact the slate `slate_id` was exchanged with, if any.
pub(crate) fn slate_contact(
    repos: &dyn Repositories,
    slate_id: Uuid,
) -> Result<Option<ContactId>, StoreError> {
    Ok(repos
        .setting(&format!("{SLATE_PREFIX}{slate_id}"))?
        .and_then(|text| contact_from_hex(&text)))
}

/// Deletes every unpaid invoice parked from the contact, for a contact that lost the trust they
/// were parked under or is gone (RFC 0002 11.1). A paid one finishes as any paid invoice.
/// Returns their slate ids.
pub(crate) fn drop_contact_invoices(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
) -> Result<Vec<Uuid>, StoreError> {
    let mut dropped = Vec::new();
    for invoice in repos.pending_invoices()? {
        if invoice.status == PendingInvoiceStatus::Paid
            || slate_contact(repos, invoice.slate_id)? != Some(contact_id)
        {
            continue;
        }
        repos.delete_pending_invoice(invoice.slate_id)?;
        repos.delete_setting(&format!("{INVOICE_PREFIX}{}", invoice.slate_id))?;
        dropped.push(invoice.slate_id);
    }
    Ok(dropped)
}

/// The sender key a contact's parked invoices are stored and capped under: the contact, never
/// the mailbox its card names, which the contact chooses.
fn contact_sender_key(contact_id: ContactId) -> String {
    format!("contact:{}", hex(&contact_id.0))
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Issues an invoice to a paired contact (RFC 0002 11.5): the I1 is stored as by
    /// [`Wallet::issue_invoice`], sealed and signed with `details`, and queued for the contact's
    /// mailbox, then the outbox runs once when relays may be reached. The contact pays it only
    /// if it allows our invoices.
    ///
    /// Fails with [`ContactError::UnknownContact`] for a contact that is not paired or whose keys
    /// changed, [`ContactError::DoesNotPayInvoices`] when its card says it does not pay invoices,
    /// and [`ContactError::Invoice`] as [`Wallet::issue_invoice`] does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contact_issue_invoice(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        request: InvoiceRequest,
        details: InvoiceDetails,
    ) -> Result<IssuedInvoice, ContactError> {
        let net = contact_network(self.config().network);
        let session = self.session()?;
        let (record, peer_mailbox) = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    let record = repos
                        .contact(contact_id)?
                        .filter(|record| {
                            matches!(record.state, ContactState::Paired | ContactState::Verified)
                        })
                        .ok_or(ContactError::UnknownContact)?;
                    let mailbox = repos
                        .contact_mailbox(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    Ok((record, mailbox.peer_mailbox))
                })
            })
            .await?;
        let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
        let card = ContactCard::decode(&peer.bytes, net).map_err(ContactError::Decode)?;
        if !card.fields().caps.contains(Capabilities::PAYS_INVOICES) {
            return Err(ContactError::DoesNotPayInvoices);
        }
        let (tx_id, slate, wire) = self
            .issue_unsent(
                request,
                crate::send::Delivery::Deliver {
                    transport: FILE,
                    to: Destination::new(peer_mailbox),
                },
            )
            .await
            .map_err(ContactError::Invoice)?;
        let reference = details
            .reference
            .as_deref()
            .map(lepic_contact::Reference::new)
            .transpose()
            .map_err(ContactError::Name)?;
        let envelope = self
            .seal_for_contact(
                &record,
                Content {
                    purpose: Some(details.purpose),
                    reference,
                    expires: details.expires,
                    ..Content::new(MessageType::Slate, wire.as_bytes().to_vec())
                },
            )
            .await?;
        let slate_uuid = uuid(slate.id());
        let session = self.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .write(|repos| link_slate(repos, slate_uuid, contact_id))?)
        })
        .await?;
        self.enqueue_for_contact(contact_id, slate_uuid, SlateStage::Invoice1, &envelope)
            .await?;
        self.deliver_soon(relays).await;
        info!(tx_id = %tx_id, "invoice issued to a contact");
        Ok(IssuedInvoice {
            tx_id,
            slate_id: slate.id(),
            amount: slate.amount(),
        })
    }

    /// The parked invoices from contacts, oldest first.
    pub async fn contact_invoices(&self) -> Result<Vec<ContactInvoice>, ContactError> {
        let network = self.config().network;
        let session = self.session()?;
        let parked = self
            .contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    let mut parked = Vec::new();
                    for invoice in repos.pending_invoices()? {
                        if invoice.status != PendingInvoiceStatus::Parked {
                            continue;
                        }
                        let Some(note) = repos
                            .setting(&format!("{INVOICE_PREFIX}{}", invoice.slate_id))?
                            .and_then(|text| serde_json::from_str::<InvoiceNote>(&text).ok())
                        else {
                            continue;
                        };
                        parked.push((invoice, note));
                    }
                    Ok::<_, StoreError>(parked)
                })?)
            })
            .await?;
        let codecs = legacy_codecs(network).map_err(ContactError::Receive)?;
        let mut invoices: Vec<ContactInvoice> = parked
            .into_iter()
            .filter_map(|(invoice, note)| {
                let wire = WireSlate::binary(MediaType::JSON, invoice.bytes);
                let slate = codecs.decode(&wire).ok()?;
                Some(ContactInvoice {
                    slate_id: slate.id(),
                    contact_id: contact_from_hex(&note.contact)?,
                    amount: slate.amount(),
                    purpose: note.purpose.and_then(purpose_of),
                    reference: note.reference,
                    expires: note.expires,
                    received_at: invoice.received_at,
                    same_amount: Vec::new(),
                })
            })
            .collect();
        let all = invoices.clone();
        for invoice in &mut invoices {
            invoice.same_amount = all
                .iter()
                .filter(|other| {
                    other.slate_id != invoice.slate_id
                        && other.contact_id == invoice.contact_id
                        && other.amount == invoice.amount
                        && other
                            .received_at
                            .duration_since(invoice.received_at)
                            .unsigned_abs()
                            <= SAME_AMOUNT_WINDOW
                })
                .map(|other| other.slate_id)
                .collect();
        }
        Ok(invoices)
    }

    /// Pays a parked invoice from a contact after the user approved it (RFC 0002 12.3): the I2
    /// is stored as by [`Wallet::pay_invoice`], sealed and signed to the contact and queued for
    /// its mailbox, then the outbox runs once when relays may be reached.
    ///
    /// Fails with [`ContactError::Invoice`] carrying [`InvoiceError::NotParked`] when no invoice
    /// from a contact with that id waits, [`ContactError::NotVerified`] when its contact is no
    /// longer verified with invoices allowed (nothing is paid), and as [`Wallet::pay_invoice`]
    /// does.
    #[instrument(skip_all, fields(wallet = %self.config().name, slate_id = %slate_id))]
    pub async fn contact_pay_invoice(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
        request: PayRequest,
    ) -> Result<PaidInvoice, ContactError> {
        let network = self.config().network;
        let session = self.session()?;
        let slate_uuid = uuid(slate_id);
        let (parked, contact_id) = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    let parked = repos
                        .pending_invoice(slate_uuid)?
                        .filter(|invoice| invoice.status == PendingInvoiceStatus::Parked);
                    let contact = slate_contact(repos, slate_uuid)?;
                    let (Some(parked), Some(contact)) = (parked, contact) else {
                        return Err(ContactError::Invoice(InvoiceError::NotParked { slate_id }));
                    };
                    // The trust it was parked under must still hold (RFC 0002 11.1).
                    let trusted = repos.contact(contact)?.is_some_and(|record| {
                        record.state == ContactState::Verified && record.allow_invoices
                    });
                    if !trusted {
                        return Err(ContactError::NotVerified);
                    }
                    Ok((parked, contact))
                })
            })
            .await?;
        let codecs = legacy_codecs(network).map_err(ContactError::Receive)?;
        let i1 = codecs
            .decode(&WireSlate::binary(MediaType::JSON, parked.bytes))
            .map_err(|_| ContactError::NotASlate)?;
        let paid = self
            .pay_decoded(
                FILE,
                i1,
                request,
                Some(Destination::new(parked.sender_address)),
            )
            .await
            .map_err(ContactError::Invoice)?;
        self.answer_contact(
            contact_id,
            paid.tx_id,
            slate_uuid,
            SlateStage::Invoice2,
            &paid.reply,
        )
        .await?;
        self.deliver_soon(relays).await;
        info!(tx_id = %paid.tx_id, "contact invoice paid");
        Ok(paid)
    }

    /// Seals `reply` to the contact, signed, and queues it for the contact's mailbox.
    async fn answer_contact(
        &self,
        contact_id: ContactId,
        tx_id: TxId,
        slate_id: Uuid,
        stage: SlateStage,
        reply: &WireSlate,
    ) -> Result<(), ContactError> {
        let session = self.session()?;
        let record = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    link_slate(repos, slate_id, contact_id)?;
                    repos.put_setting(&format!("contact.tx.{tx_id}"), &hex(&contact_id.0))?;
                    repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownContact)
                })
            })
            .await?;
        let envelope = self
            .seal_for_contact(
                &record,
                Content::new(MessageType::Slate, reply.as_bytes().to_vec()),
            )
            .await?;
        self.enqueue_for_contact(contact_id, slate_id, stage, &envelope)
            .await?;
        Ok(())
    }

    /// `content` with our current card, sealed and signed to the contact of `record`.
    async fn seal_for_contact(
        &self,
        record: &ContactRecord,
        content: Content,
    ) -> Result<Vec<u8>, ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
        let card = ContactCard::decode(&peer.bytes, net).map_err(ContactError::Decode)?;
        let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::Decode)?;
        let session = self.session()?;
        let keys = contact_keys(
            &session.keychain,
            network,
            record.account,
            record.slot,
            record.box_salt,
        )?;
        seal(
            net,
            card.enc_key(),
            card.hint_rule(),
            &Content {
                card: Some(own),
                ..content
            },
            Some(&signing_key(&keys)),
            &mut LockedRng(&mut **self.ports().rng.lock()),
        )
        .map_err(ContactError::Encode)
    }

    /// Runs the outbox once when relays may be reached; a failure waits for the next run.
    pub(crate) async fn deliver_soon(&self, relays: &ContactRelays) {
        if relays.mode != RelayMode::Online {
            return;
        }
        if let Err(error) = self.contacts_outbox_deliver(relays).await {
            warn!(error = %ErrorChain(&error), "contact outbox not run");
        }
    }

    /// Takes a sealed slate from a contact's mailbox (RFC 0002 11.2 and 12.5). An I1 parks only
    /// from a verified contact that may send invoices; an S1 is received and answered through the
    /// outbox; an S2 or I2 is finalized and posted.
    pub(crate) async fn take_contact_slate(
        &self,
        record: &ContactRecord,
        content: Content,
    ) -> Result<lepic_epicbox::Handled, ContactError> {
        use lepic_epicbox::Handled;
        let network = self.config().network;
        let contact_id = record.contact_id;
        let Ok(text) = String::from_utf8(content.body) else {
            return Ok(Handled::Stored);
        };
        let wire = WireSlate::text(MediaType::JSON, text);
        let Ok(slate) = legacy_codecs(network)
            .map_err(ContactError::Receive)?
            .decode(&wire)
        else {
            debug!("undecodable slate from a contact dropped");
            return Ok(Handled::Stored);
        };
        match slate.stage() {
            Stage::I1 => {
                if record.state != ContactState::Verified || !record.allow_invoices {
                    debug!("invoice from a contact not allowed to send them dropped");
                    return Ok(Handled::Stored);
                }
                self.park_contact_invoice(
                    record,
                    &wire,
                    &slate,
                    content.purpose,
                    content
                        .reference
                        .map(|reference| reference.as_str().to_owned()),
                    content.expires,
                )
                .await?;
                Ok(Handled::Stored)
            }
            Stage::S1 => {
                if !self
                    .contact_receipt_room(contact_id, uuid(slate.id()))
                    .await?
                {
                    debug!("payment from a contact over the open receipt caps dropped");
                    return Ok(Handled::Stored);
                }
                let received = match self.receive(FILE, &wire, ReceiveRequest::default()).await {
                    Ok(received) => received,
                    Err(ReceiveError::Node(_) | ReceiveError::Wallet(_)) => {
                        return Ok(Handled::Later);
                    }
                    Err(error) => {
                        debug!(error = %ErrorChain(&error), "slate from a contact refused");
                        return Ok(Handled::Stored);
                    }
                };
                self.answer_contact(
                    contact_id,
                    received.tx_id,
                    uuid(slate.id()),
                    SlateStage::Standard2,
                    &received.reply,
                )
                .await?;
                let news = ContactSlateEvent {
                    contact_id,
                    tx_id: received.tx_id,
                    slate_id: slate.id(),
                    amount: slate.amount(),
                };
                self.emit(if content.purpose == Some(Purpose::Withdrawal) {
                    Event::WithdrawalFromContact(news)
                } else {
                    Event::SealedReceived(news)
                });
                Ok(Handled::Stored)
            }
            Stage::S2 => match self.finalize(FILE, &wire, Propagation::Stem).await {
                Err(crate::finalize::FinalizeError::Node(_)) => Ok(Handled::Later),
                Ok(_) | Err(_) => Ok(Handled::Stored),
            },
            Stage::I2 => match self.finalize_invoice(FILE, &wire, Propagation::Stem).await {
                Ok(finalized) => {
                    if let Some(kernel) = finalized.transaction.kernels().first() {
                        self.notify_posted(finalized.tx_id, finalized.slate.id(), kernel.excess)
                            .await;
                    }
                    Ok(Handled::Stored)
                }
                Err(InvoiceError::Node(_)) => Ok(Handled::Later),
                Err(error) => {
                    debug!(error = %ErrorChain(&error), "payment from a contact not finalized");
                    Ok(Handled::Stored)
                }
            },
            _ => Ok(Handled::Stored),
        }
    }

    /// Whether a new S1 `slate_id` from the contact fits the open receipt caps the inbox keeps
    /// for senders (RFC 0002 12.5): at most [`crate::inbox::MAX_OPEN_RECEIPTS_PER_SENDER`] open
    /// from this contact and [`crate::inbox::MAX_OPEN_RECEIPTS`] from all contacts. One received
    /// before always fits, so its stored S2 goes back again.
    async fn contact_receipt_room(
        &self,
        contact_id: ContactId,
        slate_id: Uuid,
    ) -> Result<bool, ContactError> {
        let session = self.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                if repos
                    .transaction_by_slate(slate_id, TxDirection::Incoming)?
                    .is_some()
                {
                    return Ok::<_, StoreError>(true);
                }
                let mut from_contact = 0usize;
                let mut from_contacts = 0usize;
                for receipt in repos.open_receipts(FILE.as_str())? {
                    let Some(slate) = repos
                        .transaction(receipt.id)?
                        .and_then(|entry| entry.slate_id)
                    else {
                        continue;
                    };
                    match slate_contact(repos, slate)? {
                        Some(other) if other == contact_id => {
                            from_contact = from_contact.saturating_add(1);
                            from_contacts = from_contacts.saturating_add(1);
                        }
                        Some(_) => from_contacts = from_contacts.saturating_add(1),
                        None => {}
                    }
                }
                Ok(from_contact < crate::inbox::MAX_OPEN_RECEIPTS_PER_SENDER
                    && from_contacts < crate::inbox::MAX_OPEN_RECEIPTS)
            })?)
        })
        .await
    }

    async fn park_contact_invoice(
        &self,
        record: &ContactRecord,
        wire: &WireSlate,
        slate: &lepic_slate::model::Slate,
        purpose: Option<Purpose>,
        reference: Option<String>,
        expires: Option<u64>,
    ) -> Result<(), ContactError> {
        let contact_id = record.contact_id;
        let session = self.session()?;
        let slate_uuid = uuid(slate.id());
        let bytes = wire.as_bytes().to_vec();
        let note = InvoiceNote {
            contact: hex(&contact_id.0),
            purpose: purpose.map(purpose_byte),
            reference: reference.clone(),
            expires,
        };
        let parked = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let mailbox = repos
                        .contact_mailbox(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    // The parking cap counts per contact, never per mailbox the contact names.
                    let sender_key = contact_sender_key(contact_id);
                    if repos.pending_invoice(slate_uuid)?.is_some() {
                        return Ok(false);
                    }
                    match repos.park_invoice(&PendingInvoice {
                        slate_id: slate_uuid,
                        sender_key,
                        sender_address: mailbox.peer_mailbox,
                        received_at: now,
                        status: PendingInvoiceStatus::Parked,
                        codec: lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON
                            .as_str()
                            .to_owned(),
                        bytes,
                    }) {
                        Ok(()) => {}
                        Err(StoreError::InvoiceCapReached { .. }) => {
                            warn!("invoice from a contact dropped over the parking cap");
                            return Ok(false);
                        }
                        Err(error) => return Err(error.into()),
                    }
                    let text = serde_json::to_string(&note).map_err(|_| StoreError::Corrupt {
                        record: lepic_store::Record::Contact,
                        field: "invoice note",
                    })?;
                    repos.put_setting(&format!("{INVOICE_PREFIX}{slate_uuid}"), &text)?;
                    link_slate(repos, slate_uuid, contact_id)?;
                    Ok(true)
                })
            })
            .await?;
        if parked {
            info!("invoice from a contact parked");
            self.emit(Event::InvoiceFromContact(ContactInvoiceEvent {
                contact_id,
                slate_id: slate.id(),
                amount: slate.amount(),
                purpose,
                reference,
                expires,
            }));
        }
        Ok(())
    }

    /// Takes a sealed notice from a contact's mailbox (RFC 0002 11.4), by the rules of ADR 0016
    /// with the contact as the counterparty. A `withdrawn` for an invoice this wallet paid
    /// cancels the payment and releases its inputs.
    pub(crate) async fn take_contact_notice(
        &self,
        record: &ContactRecord,
        body: &[u8],
    ) -> Result<lepic_epicbox::Handled, ContactError> {
        use lepic_epicbox::Handled;
        let Ok(text) = std::str::from_utf8(body) else {
            return Ok(Handled::Stored);
        };
        let Payload::Notice(notice) = classify_text(text) else {
            return Ok(Handled::Stored);
        };
        let Ok(effect) = self.apply_contact_notice(notice, record.contact_id).await else {
            return Ok(Handled::Later);
        };
        if let Some(tx_id) = effect {
            // A signed withdrawn for a paid invoice ends the payment (RFC 0002 11.4).
            if let Err(error) = self.cancel(tx_id).await {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "withdrawn payment not cancelled");
            } else {
                info!(tx_id = %tx_id, "payment cancelled on the contact's withdrawn notice");
            }
        }
        Ok(Handled::Stored)
    }

    /// Seals `notice` to the contact the slate was exchanged with and queues it for the
    /// contact's mailbox. The next outbox run delivers it.
    pub(crate) async fn queue_contact_notice(
        &self,
        contact_id: ContactId,
        notice: Notice,
    ) -> Result<(), ContactError> {
        let session = self.session()?;
        let record = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownContact)
                })
            })
            .await?;
        let body = notice.encode().as_bytes().to_vec();
        let envelope = self
            .seal_for_contact(&record, Content::new(MessageType::Notice, body))
            .await?;
        let stage = match notice.kind {
            NoticeKind::Posted { .. } | NoticeKind::Declined | NoticeKind::Withdrawn => {
                SlateStage::Invoice1
            }
        };
        self.enqueue_for_contact(contact_id, uuid(notice.slate_id), stage, &envelope)
            .await?;
        debug!("notice queued for a contact");
        Ok(())
    }

    /// Declines one invoice parked from a contact (RFC 0002 11.1): it is deleted and never paid,
    /// and a sealed `declined` for it is queued for the contact's mailbox, posted by the next
    /// outbox run or collecting cycle.
    ///
    /// Fails with [`ContactError::Invoice`] carrying [`InvoiceError::NotParked`] when no unpaid
    /// invoice from a contact with that id waits, and as the store does.
    #[instrument(skip_all, fields(wallet = %self.config().name, slate_id = %slate_id))]
    pub async fn contact_decline_invoice(&self, slate_id: SlateId) -> Result<(), ContactError> {
        let session = self.session()?;
        let slate_uuid = uuid(slate_id);
        let contact_id = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    let parked = repos
                        .pending_invoice(slate_uuid)?
                        .is_some_and(|invoice| invoice.status == PendingInvoiceStatus::Parked);
                    let Some(contact_id) = slate_contact(repos, slate_uuid)?.filter(|_| parked)
                    else {
                        return Err(ContactError::Invoice(InvoiceError::NotParked { slate_id }));
                    };
                    repos.delete_pending_invoice(slate_uuid)?;
                    repos.delete_setting(&format!("{INVOICE_PREFIX}{slate_uuid}"))?;
                    Ok(contact_id)
                })
            })
            .await?;
        info!("contact invoice declined");
        self.queue_contact_notice(
            contact_id,
            Notice {
                slate_id,
                kind: NoticeKind::Declined,
            },
        )
        .await
    }

    /// Declines and deletes every unpaid invoice parked from the contact (RFC 0002 11.1), each
    /// with a sealed `declined`. Returns how many.
    pub(crate) async fn decline_contact_invoices(
        &self,
        contact_id: ContactId,
    ) -> Result<usize, ContactError> {
        let session = self.session()?;
        let declined = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .write(|repos| drop_contact_invoices(repos, contact_id))?)
            })
            .await?;
        for slate_id in &declined {
            self.queue_contact_notice(
                contact_id,
                Notice {
                    slate_id: SlateId::from_bytes(slate_id.into_bytes()),
                    kind: NoticeKind::Declined,
                },
            )
            .await?;
        }
        Ok(declined.len())
    }
}
