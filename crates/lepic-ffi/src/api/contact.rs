//! Pairing with contacts (RFC 0002), and the sealed slates and invoices exchanged with them.
//!
//! Two wallets pair once, online by an invite link, pairing words or a pasted reply, or in
//! person by scanning each other's card, and then check four emoji words on both screens. A
//! paired contact gets its slates sealed so only its wallet opens them, and a verified one may
//! be allowed to send invoices; nothing from a contact ever pays without the user. Contacts
//! belong to the default account. Contact ids are 32 lowercase hex characters.
//!
//! Nothing else secret crosses: calls take links, armored text and names, and return public
//! card details, the words check and states. Two secrets reach the app (ADR 0014): an invite
//! link and its pairing words. Whoever has either can pair as the contact until the invite is
//! used or expires, so the app shows and shares them, and never stores or logs them; the
//! types holding them do not show them in `Debug`. Reply and confirm links are sealed to the
//! other side, and card links are public.
//!
//! Calls that take a [`ContactRelayMode`] reach relays through the wallet's Epicbox relay and
//! the home relays of contacts; with `Offline` or `EpicboxOff` the ones that must connect fail
//! with `ContactsOffline` or `EpicboxOff` before connecting, and the others work as they do
//! offline. Every call that takes a mode fails with `Unsupported` when the configuration names
//! no Epicbox relay. Every call fails with `Locked` on a locked wallet and with
//! `InvalidArgument` for an id that is not one.
//!
//! What arrives in contact mailboxes is taken by [`EpicWallet::contacts_collect`] and reported
//! as the `Pairing*`, `Contact*`, `InvoiceFromContact`, `WithdrawalFromContact`, `Sealed*` and
//! `Outbox*` events on [`EpicWallet::events`]. What the wallet sends to contacts waits in an
//! outbox that [`EpicWallet::contacts_outbox_deliver`] posts; run both when the app opens, on
//! a foreground tick and on a push wake-up.

use crate::api::error::WalletError;
use crate::api::types::{
    CollectTrigger, ContactCollectReport, ContactImportSummary, ContactInvoiceView, ContactKind,
    ContactPayloadView, ContactRelayMode, ContactView, FinalizedTx, FoundInvite, InviteExpiry,
    InvitePreview, IssuedInvoice, KeyCheckStart, KeysDecision, OutboxEntryView, OutboxReport,
    PaidInvoice, PairRequestView, PairingAnswer, PairingCard, PairingClass, PairingInvite,
    PairingLinkResult, PendingPairingView, SasDecision, SealedAnswer, SealedSlateView, SendOptions,
    SentTx, SlatePurpose,
};
use crate::api::wallet::EpicWallet;

impl EpicWallet {
    /// Makes an invite to pair, valid for `expiry`, whose messages go through this wallet's
    /// relay. The pending pairing is stored and listed by [`EpicWallet::pairings_pending`];
    /// [`EpicWallet::contacts_collect`] takes the reply and raises `PairingReplied`. Without
    /// words nothing is sent, so this works offline.
    ///
    /// With `offer_words` the invite lasts 10 minutes and is also posted under five pairing
    /// words, returned in `words`, for the other side to type, on every meeting relay whatever
    /// relay the wallet uses: the `meeting_relays`, each `domain[:port]` over TLS, which the
    /// app takes from its settings; LEPIC has none of its own. The other side must look on at
    /// least one of them. That needs `Online` and fails with `ContactsOffline` or `EpicboxOff`
    /// before anything is stored, with `PairingWordsUnavailable` when `meeting_relays` is
    /// empty, and with `TransportFailed` when no meeting relay takes the post, the invite then
    /// withdrawn. Without `offer_words`, `meeting_relays` is ignored and may be empty.
    ///
    /// The pairing's mailboxes live on `home_relay`, `domain[:port]` reached over TLS, or with
    /// `None` on the wallet's own Epicbox relay; the other side reaches them there whatever
    /// relay it uses.
    ///
    /// `pairing_class` `Private` makes a private pairing with another wallet of the user's
    /// ([`PairingClass`]): its invite must travel by QR or paste, so `offer_words` is refused
    /// with `WrongPairingClass`.
    ///
    /// With `expect_address` set, the reply must prove that Epicbox address, compared by key:
    /// a reply without the proof fails `AddressProofMissing`, one proving another key
    /// `OtherAddress`, with nothing stored, as `PairingFailed` in the collect or as the error
    /// of `pairing_enter_link`. A reply that proves it completes the pairing Verified.
    ///
    /// Fails with `InvalidArgument` for a meeting or home relay that is not `domain[:port]`,
    /// for more than 16 meeting relays or an `expect_address` that is not an Epicbox address of
    /// this network, with `InvalidContactName` for a `name` a card cannot carry, and with `Io`
    /// when 64 pairings are pending.
    #[allow(clippy::too_many_arguments)] // Mirrors the Dart call, one argument per choice.
    pub async fn pairing_invite(
        &self,
        name: String,
        kind: ContactKind,
        expiry: InviteExpiry,
        offer_words: bool,
        relay_mode: ContactRelayMode,
        meeting_relays: Vec<String>,
        home_relay: Option<String>,
        pairing_class: PairingClass,
        expect_address: Option<String>,
    ) -> Result<PairingInvite, WalletError> {
        self.run("pairing_invite", |session| async move {
            session
                .pairing_invite(
                    name,
                    kind,
                    expiry,
                    offer_words,
                    relay_mode,
                    meeting_relays,
                    home_relay,
                    pairing_class,
                    expect_address,
                )
                .await
        })
        .await
    }

    /// The standing invite (one per wallet, seven days, the wallet's own relay), made anew when
    /// there is none, when it was answered, when less than a day is left, when its relay is not
    /// the wallet's relay now, or when `name` differs from the name it carries; on a name change
    /// the old one is withdrawn. Sends nothing, so it works offline. The link is returned again
    /// on every call; never store it.
    ///
    /// Fails with `InvalidContactName`, and `Io` when 64 pairings are pending.
    pub async fn pairing_standing_invite(
        &self,
        name: String,
    ) -> Result<PairingInvite, WalletError> {
        self.run("pairing_standing_invite", |session| async move {
            session.pairing_standing_invite(name).await
        })
        .await
    }

    /// Asks the wallet at `to_address` to pair: a new invite of its own, good for seven days,
    /// which only that wallet can answer, posted to its payments address. The invite is kept
    /// only when the post went through; answered, the pairing completes Verified.
    ///
    /// Fails with `PeerNotProven` unless that key ran LEPIC lately, answered nothing unmarked
    /// since and claimed pair requests; `AlreadyPaired` for a live pairing with it;
    /// `PairingInProgress` for a pairing in progress or waiting with it, or a live request from
    /// it; `ContactsOffline`, `EpicboxOff`; `TransportFailed` when the post failed, with
    /// nothing kept; and `InvalidArgument` for an address of another network.
    pub async fn pairing_request_send(
        &self,
        to_address: String,
        name: String,
        relay_mode: ContactRelayMode,
    ) -> Result<PendingPairingView, WalletError> {
        self.run("pairing_request_send", |session| async move {
            session
                .pairing_request_send(to_address, name, relay_mode)
                .await
        })
        .await
    }

    /// The live pairing requests other wallets sent, oldest first: not dismissed, answered or
    /// expired. Answer one with [`EpicWallet::pairing_accept`], its `invite_link` and
    /// `from_address` as `expect_address`.
    pub async fn pairing_requests(&self) -> Result<Vec<PairRequestView>, WalletError> {
        self.run("pairing_requests", |session| async move {
            session.pairing_requests().await
        })
        .await
    }

    /// Hides a request. Its invite id is remembered until the invite expires, so a copy of it
    /// is dropped; a newer request from the same wallet shows again. Fails with
    /// `PairingNotFound` for no live request with that id.
    pub async fn pairing_request_dismiss(&self, request_id: String) -> Result<(), WalletError> {
        self.run("pairing_request_dismiss", |session| async move {
            session.pairing_request_dismiss(&request_id).await
        })
        .await
    }

    /// Gives every contact pairing that has not ended this wallet's card again, naming it
    /// `name`, as a contact update the next collect posts; private pairings are left alone.
    /// Returns how many were queued. Call it with `pairing_standing_invite(name)` when the
    /// user changes the name contacts see. Fails with `InvalidContactName`.
    pub async fn contacts_set_own_name(&self, name: String) -> Result<u32, WalletError> {
        self.run("contacts_set_own_name", |session| async move {
            session.contacts_set_own_name(name).await
        })
        .await
    }

    /// Moves this wallet's home relay for its contacts to `relay` (`domain[:port]`): every
    /// paired contact that has not ended gets this wallet's card naming its mailbox there,
    /// once, as a contact update, and this wallet reads only the new mailbox from then on.
    /// Returns how many contacts were told. The old mailboxes are not read again: a contact
    /// that takes the update sees `ContactRelayMoveRequested` and follows once the app on its
    /// side applies it; one that never takes it stops reaching this wallet and has to pair
    /// again, which `contact_check` shows as no answer. Private pairings and pairings in
    /// progress keep their relay. Switch the wallet's Epicbox relay to `relay` too, so new
    /// invites name it.
    ///
    /// Fails with `InvalidArgument` for a host that is not a relay's name.
    pub async fn contacts_move_home(&self, relay: String) -> Result<u32, WalletError> {
        self.run("contacts_move_home", |session| async move {
            session.contacts_move_home(relay).await
        })
        .await
    }

    /// Asks the paired contact `contact_id` to answer with its current card. The answer is
    /// collected as a contact update: it sets `peer_heard_at`, refreshes the card, and raises
    /// `ContactRelayMoveRequested` when the contact moved its relay. A contact answers at most
    /// as often as its host's policy allows (by default once an hour and three times a day);
    /// a wallet too old to know the check drops it unanswered. Which contacts to check, and
    /// how long to wait, are the app's.
    ///
    /// Fails with `ContactNotFound` for no such contact or one not paired, `PairingEnded` for
    /// an ended pairing, and `WrongPairingClass` for a private pairing.
    pub async fn contact_check(&self, contact_id: String) -> Result<(), WalletError> {
        self.run("contact_check", |session| async move {
            session.contact_check(&contact_id).await
        })
        .await
    }

    /// Reads an invite link for the "Pair with Anna?" sheet. Nothing is stored or sent.
    ///
    /// Fails with `InvalidPairingText` for text that is not an invite on the wallet's network,
    /// and `InviteExpired` for one past its expiry.
    pub async fn pairing_preview(&self, link: String) -> Result<InvitePreview, WalletError> {
        self.run("pairing_preview", |session| async move {
            session.pairing_preview(&link).await
        })
        .await
    }

    /// Finds the invite that five pairing words name, typed as names or emoji, on the
    /// meeting relays, and returns its link with its preview, for
    /// [`EpicWallet::pairing_accept`]. The meeting relays are `meeting_relays`, each
    /// `domain[:port]` over TLS, which the app takes from its settings; all are asked at once,
    /// each for at most 20 seconds, and
    /// the first invite that opens wins. That copy is taken off its relay, so nobody else finds
    /// it; copies on other relays expire.
    ///
    /// Fails with `InvalidPairingWords` for words not in the table, `PairingWordsNotFound`
    /// when no relay holds the invite, `TransportFailed` when no meeting relay could be
    /// reached, `PairingWordsUnavailable` when `meeting_relays` is empty, `InvalidArgument`
    /// for a meeting relay that is not `domain[:port]` or more than 16 of them, and
    /// `ContactsOffline` or `EpicboxOff`.
    pub async fn pairing_find_words(
        &self,
        words: Vec<String>,
        relay_mode: ContactRelayMode,
        meeting_relays: Vec<String>,
    ) -> Result<FoundInvite, WalletError> {
        self.run("pairing_find_words", |session| async move {
            session
                .pairing_find_words(words, relay_mode, meeting_relays)
                .await
        })
        .await
    }

    /// Answers an invite as `name`. The pending pairing is stored first, then the reply is
    /// posted unless `by_hand` is set or the mode is not `Online`; `reply_link` is returned
    /// either way, for "Send by hand" and for a post that failed (`posted` false).
    /// [`EpicWallet::contacts_collect`] takes the confirmation and raises `PairingConfirmed`.
    ///
    /// `pairing_class` is the class the user means to answer, from the preview: an invite of the
    /// other class is refused with `WrongPairingClass` before anything is stored.
    ///
    /// With `expect_address` set, from a pairing request's `from_address`, the confirmation
    /// must prove that address, and the request is marked answered. If this wallet's own
    /// request to the same wallet is out, the wallet with the lower key keeps its invite: when
    /// ours wins this fails `PairingCrossed`, otherwise our request is withdrawn.
    ///
    /// Fails as [`EpicWallet::pairing_preview`] does, with `AlreadyPaired` for an invite this
    /// wallet made or answered already or a live pairing with that address, `PairingInProgress`,
    /// `PairingCrossed`, `InviteDismissed` for a request dismissed here, and
    /// `InvalidContactName`.
    pub async fn pairing_accept(
        &self,
        link: String,
        name: String,
        by_hand: bool,
        relay_mode: ContactRelayMode,
        pairing_class: PairingClass,
        expect_address: Option<String>,
    ) -> Result<PairingAnswer, WalletError> {
        self.run("pairing_accept", |session| async move {
            session
                .pairing_accept(
                    link,
                    name,
                    by_hand,
                    relay_mode,
                    pairing_class,
                    expect_address,
                )
                .await
        })
        .await
    }

    /// The private pairings (two wallets of one owner), oldest first, in progress or paired;
    /// `state` tells which. They are never listed by [`EpicWallet::contacts`] or
    /// [`EpicWallet::pairings_pending`] and never exported. Remove one with
    /// [`EpicWallet::contact_remove`] or [`EpicWallet::contact_unpair`].
    pub async fn private_pairings(&self) -> Result<Vec<ContactView>, WalletError> {
        self.run("private_pairings", |session| async move {
            session.private_pairings().await
        })
        .await
    }

    /// Takes a reply or confirmation the user pasted, `epiccash://pair-reply/1/...` or
    /// `epiccash://pair-confirm/1/...`. A reply to one of this wallet's invites pairs the
    /// contact and returns the confirmation to send back by hand (`Confirm`); a confirmation
    /// finishes a pairing this wallet answered (`Paired`). Either way the words check follows.
    /// Reaches no relay unless the pairing has to tell the other side something.
    ///
    /// Fails with `InvalidPairingText` for any other text.
    pub async fn pairing_enter_link(
        &self,
        text: String,
        relay_mode: ContactRelayMode,
    ) -> Result<PairingLinkResult, WalletError> {
        self.run("pairing_enter_link", |session| async move {
            session.pairing_enter_link(&text, relay_mode).await
        })
        .await
    }

    /// Shows a card to pair in person: "Show my code". Its `link` goes in a QR code for the
    /// other phone; [`EpicWallet::pairing_scan_card`] with the same `contact_id` finishes the
    /// pairing with theirs. Nothing is sent, so this works offline. The pairing's mailboxes
    /// live on `home_relay` as [`EpicWallet::pairing_invite`] describes.
    ///
    /// Fails as [`EpicWallet::pairing_invite`] does.
    pub async fn pairing_show_card(
        &self,
        name: String,
        kind: ContactKind,
        relay_mode: ContactRelayMode,
        home_relay: Option<String>,
    ) -> Result<PairingCard, WalletError> {
        self.run("pairing_show_card", |session| async move {
            session
                .pairing_show_card(name, kind, relay_mode, home_relay)
                .await
        })
        .await
    }

    /// Finishes an in-person pairing with the card `link` scanned from the other phone:
    /// "Scan theirs". The contact is paired, not verified; show the words check from the
    /// returned view. Works offline.
    ///
    /// Fails with `ContactNotFound` when `contact_id` is not a card this wallet shows,
    /// `InvalidPairingText` for a link that is not a card on the wallet's network, and
    /// `AlreadyPaired` for a contact this wallet holds or its own card.
    pub async fn pairing_scan_card(
        &self,
        contact_id: String,
        link: String,
        relay_mode: ContactRelayMode,
    ) -> Result<ContactView, WalletError> {
        self.run("pairing_scan_card", |session| async move {
            session
                .pairing_scan_card(&contact_id, &link, relay_mode)
                .await
        })
        .await
    }

    /// Records the words check: `Match` makes the contact verified, `Mismatch` removes the
    /// pairing on this side and, when this wallet made the invite, tells the other side when
    /// the mode allows, `Skip` leaves it paired.
    ///
    /// Fails with `ContactNotFound` when no paired contact has that id.
    pub async fn pairing_sas(
        &self,
        contact_id: String,
        decision: SasDecision,
        relay_mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        self.run("pairing_sas", |session| async move {
            session.pairing_sas(&contact_id, decision, relay_mode).await
        })
        .await
    }

    /// Collects the pairing and contact mailboxes once and raises an event for what arrived:
    /// replies and confirmations pair, contacts' payments and withdrawals are received and
    /// answered through the outbox, their invoices wait in [`EpicWallet::contact_invoices`].
    /// Pairings past their time end with `PairingFailed`. A relay that does not answer is listed
    /// in `unreachable`, raises `HomeRelayUnreachable` and is tried again later, not returned as
    /// an error. Messages are taken off a relay only once their effect is stored, so a call
    /// cut short loses nothing.
    ///
    /// With `only`, just the mailboxes of those contact ids are drained, their pairings in
    /// progress included: a cheap look at a few pairings that leaves the others' turn as it
    /// was. The outbox and the expiry of pairings run as in a full collect.
    ///
    /// Fails with `ContactsOffline` or `EpicboxOff` before connecting, and with
    /// `InvalidArgument` for an id that is not one or more than 64 of them.
    pub async fn contacts_collect(
        &self,
        trigger: CollectTrigger,
        relay_mode: ContactRelayMode,
        only: Option<Vec<String>>,
    ) -> Result<ContactCollectReport, WalletError> {
        self.run("contacts_collect", |session| async move {
            session.contacts_collect(trigger, relay_mode, only).await
        })
        .await
    }

    /// The paired contacts, oldest first. Pairings in progress are in
    /// [`EpicWallet::pairings_pending`].
    pub async fn contacts(&self) -> Result<Vec<ContactView>, WalletError> {
        self.run(
            "contacts",
            |session| async move { session.contacts().await },
        )
        .await
    }

    /// One paired contact. Fails with `ContactNotFound`.
    pub async fn contact(&self, contact_id: String) -> Result<ContactView, WalletError> {
        self.run("contact", |session| async move {
            session.contact(&contact_id).await
        })
        .await
    }

    /// The paired contacts attached to the address-book entry `app_contact` with
    /// [`EpicWallet::contact_attach`], oldest first: usually one, two while a key check
    /// between an old and a new pairing runs.
    pub async fn pairings_for_app_contact(
        &self,
        app_contact: String,
    ) -> Result<Vec<ContactView>, WalletError> {
        self.run("pairings_for_app_contact", |session| async move {
            session.pairings_for_app_contact(&app_contact).await
        })
        .await
    }

    /// The pairings in progress, oldest first: invites waiting for a reply and replies waiting
    /// for the confirmation, for Contacts › Pending.
    pub async fn pairings_pending(&self) -> Result<Vec<PendingPairingView>, WalletError> {
        self.run("pairings_pending", |session| async move {
            session.pairings_pending().await
        })
        .await
    }

    /// Cancels a pairing in progress: an invite stops working, a reply is forgotten. The other
    /// side is not told. Fails with `PairingNotFound` unless `contact_id` is in
    /// [`EpicWallet::pairings_pending`]; a paired contact is removed with
    /// [`EpicWallet::contact_remove`].
    pub async fn pairing_cancel(&self, contact_id: String) -> Result<(), WalletError> {
        self.run("pairing_cancel", |session| async move {
            session.pairing_cancel(&contact_id).await
        })
        .await
    }

    /// "Remove pairing": the contact, its mailboxes and anything pending for it go, and the
    /// contact is not told. Returns whether anything was removed.
    pub async fn contact_remove(&self, contact_id: String) -> Result<bool, WalletError> {
        self.run("contact_remove", |session| async move {
            session.contact_remove(&contact_id).await
        })
        .await
    }

    /// "Remove pairing" that tells the contact: as [`EpicWallet::contact_remove`], after a
    /// signed unpaired notice to the contact's mailbox, best effort and waiting at most a few
    /// seconds for its relay, so the contact sees `ContactUnpaired` instead of sending to a
    /// pairing nobody reads. Nothing is sent with `relay_mode` Offline or Epicbox off, for a
    /// pairing in progress, or for one the contact removed first. Returns whether anything
    /// was removed.
    pub async fn contact_unpair(
        &self,
        contact_id: String,
        relay_mode: ContactRelayMode,
    ) -> Result<bool, WalletError> {
        self.run("contact_unpair", |session| async move {
            session.contact_unpair(&contact_id, relay_mode).await
        })
        .await
    }

    /// Sets the user's own name for a contact; an empty label clears it. A label follows the
    /// rule of card names: at most 48 bytes, no control or hidden formatting characters. Fails
    /// with `InvalidContactName` for another label and with `ContactNotFound`.
    pub async fn contact_set_label(
        &self,
        contact_id: String,
        label: String,
    ) -> Result<(), WalletError> {
        self.run("contact_set_label", |session| async move {
            session.contact_set_label(&contact_id, label).await
        })
        .await
    }

    /// Follows the contact `contact_id` to the relay it asked to move to, `relay` as
    /// `ContactRelayMoveRequested` and `ContactView::requested_relay` give it (`domain:port`):
    /// messages go to its mailbox there, this wallet's mailbox for the contact moves to that
    /// relay and the contact is told at the next collect, and the old mailbox is still
    /// collected for seven days. Which relays to follow is the app's choice; nothing here
    /// judges `relay`.
    ///
    /// Fails with `RelayMoveNotRequested` unless `relay` is the contact's `requested_relay`,
    /// `ContactNotFound` for an unknown contact, and `PairingEnded` for a pairing that ended.
    pub async fn contact_apply_relay_move(
        &self,
        contact_id: String,
        relay: String,
    ) -> Result<(), WalletError> {
        self.run("contact_apply_relay_move", |session| async move {
            session.contact_apply_relay_move(&contact_id, &relay).await
        })
        .await
    }

    /// "Seal payments" on or off for a contact. Fails with `ContactNotFound`.
    pub async fn contact_set_seal(
        &self,
        contact_id: String,
        seal: bool,
    ) -> Result<(), WalletError> {
        self.run("contact_set_seal", |session| async move {
            session.contact_set_seal(&contact_id, seal).await
        })
        .await
    }

    /// "Allow invoices" on or off for a contact. Turning it off declines the contact's unpaid
    /// invoices, queuing a `declined` for each in the outbox; a paid one finishes.
    ///
    /// Fails with `ContactNotVerified` when turning it on for a contact whose words were not
    /// checked, and `ContactNotFound`.
    pub async fn contact_set_allow_invoices(
        &self,
        contact_id: String,
        allow: bool,
    ) -> Result<(), WalletError> {
        self.run("contact_set_allow_invoices", |session| async move {
            session.contact_set_allow_invoices(&contact_id, allow).await
        })
        .await
    }

    /// Attaches a pairing to the app's address-book entry `app_contact`, an id the app
    /// chooses, or detaches it with `None`. Attaching a new pairing to an entry that has one
    /// already is when to offer [`EpicWallet::contact_key_check`]. The id is at most 256 bytes
    /// with no control characters. `app_address` is the entry's Epicbox address, if it has
    /// one; addresses are compared by key. Fails with `InvalidContactName` for another id, with
    /// `InvalidArgument` for an address not of the wallet's network, with `OtherAddress` when
    /// the pairing proves another address and `AddressProofMissing` when it proves none
    /// (nothing changes in either case), and with `ContactNotFound`.
    pub async fn contact_attach(
        &self,
        contact_id: String,
        app_contact: Option<String>,
        app_address: Option<String>,
    ) -> Result<(), WalletError> {
        self.run("contact_attach", |session| async move {
            session
                .contact_attach(&contact_id, app_contact, app_address)
                .await
        })
        .await
    }

    /// Starts the key check between the new pairing `new` and the old pairing `old` of the
    /// same address-book entry, for a contact that may have restored its wallet. The answer is
    /// collected: `ContactKeysRestored` when the old keys are back (the new pairing was folded
    /// into the old one), `ContactKeysChanged` when they are not or nothing answers within a
    /// day (the new pairing waits for [`EpicWallet::contact_keys_resolve`]).
    ///
    /// When no check may run (the new pairing is older than a day, or the old one's slot was
    /// checked in the last day) the new pairing goes to `KeysChanged` at once, as after an
    /// unanswered check, and this returns `KeysChanged`; asked again while a check is on its
    /// way it returns `Sent` and sends nothing.
    ///
    /// Fails with `ContactNotFound` unless both are paired and differ, `KeyCheckRefused` when
    /// the new pairing's check already ended, and `ContactsOffline` or `EpicboxOff`.
    pub async fn contact_key_check(
        &self,
        new: String,
        old: String,
        relay_mode: ContactRelayMode,
    ) -> Result<KeyCheckStart, WalletError> {
        self.run("contact_key_check", |session| async move {
            session.contact_key_check(&new, &old, relay_mode).await
        })
        .await
    }

    /// Decides for a new pairing in `KeysChanged`: `KeepOld` removes it, `UseNew` removes the
    /// old pairing and keeps this one. Fails with `ContactNotFound` when `new` is not in
    /// `KeysChanged`.
    pub async fn contact_keys_resolve(
        &self,
        new: String,
        decision: KeysDecision,
    ) -> Result<(), WalletError> {
        self.run("contact_keys_resolve", |session| async move {
            session.contact_keys_resolve(&new, decision).await
        })
        .await
    }

    /// The slate this wallet last wrote for `tx_id` (its S1, I1, S2 or I2) sealed to the
    /// contact, as armored text for a `.epicsealed` file or a paste; the app writes the file.
    /// `purpose` defaults to a payment for an S1 and a request for an I1. Nothing is sent.
    ///
    /// Fails with `ContactNotFound` for a contact that is not paired or whose keys changed,
    /// `SealingOff` when sealing is off for it or it cannot open sealed text, and
    /// `NoSlateToSend` when the transaction has no slate to send.
    pub async fn contact_seal_slate(
        &self,
        contact_id: String,
        tx_id: u32,
        purpose: Option<SlatePurpose>,
    ) -> Result<String, WalletError> {
        self.run("contact_seal_slate", |session| async move {
            session
                .contact_seal_slate(&contact_id, tx_id, purpose)
                .await
        })
        .await
    }

    /// Sends the slate of `tx_id` sealed through the contact's mailbox: queued in the outbox
    /// and posted once when the mode allows. The answer comes back by collecting: for an S1,
    /// the contact's S2 is finalized and posted with a `ContactPaymentFinalized` event. A
    /// mailbox carries only sealed slates, so the contact's "Seal payments" switch does not
    /// apply here; it governs files and pastes. For a new payment prefer
    /// [`EpicWallet::contact_send`], which checks the contact before it locks anything.
    ///
    /// Fails with `ContactNotFound` for a contact that is not paired or whose keys changed,
    /// `SealingOff` only when its wallet cannot open sealed slates, and `NoSlateToSend` when
    /// the transaction has no slate to send or belongs to another contact. A failure leaves
    /// the transaction as it was: `cancel_transaction` unlocks a send's inputs.
    pub async fn contact_post_slate(
        &self,
        contact_id: String,
        tx_id: u32,
        purpose: Option<SlatePurpose>,
        relay_mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        self.run("contact_post_slate", |session| async move {
            session
                .contact_post_slate(&contact_id, tx_id, purpose, relay_mode)
                .await
        })
        .await
    }

    /// "Send through Anna's mailbox": pays `amount` to a paired contact, which needs no
    /// payments address. The contact is checked first; then the send is built and its inputs
    /// locked as [`EpicWallet::create_send_slate`] does, and its S1 is sealed and queued for the
    /// contact's mailbox as [`EpicWallet::contact_post_slate`] queues it, posted once when the
    /// mode allows (offline it waits for [`EpicWallet::contacts_outbox_deliver`]). The contact's
    /// answer comes back by collecting, which finalizes and posts the payment and raises
    /// `ContactPaymentFinalized`. `purpose` defaults to a payment. A contact that never answers
    /// leaves the payment `Sent`: `cancel_transaction` gives it up and unlocks the inputs; if
    /// the contact's answer arrives after that, it is refused.
    ///
    /// Fails, with nothing locked, with `ContactNotFound` for a contact that is not paired or
    /// whose keys changed, `SealingOff` when its wallet cannot open sealed slates, and as
    /// `create_send_slate` does. A send that could not be queued is cancelled before the error
    /// returns.
    #[allow(clippy::too_many_arguments)] // The app's send form, one value per field.
    pub async fn contact_send(
        &self,
        contact_id: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        purpose: Option<SlatePurpose>,
        relay_mode: ContactRelayMode,
    ) -> Result<SentTx, WalletError> {
        self.run("contact_send", |session| async move {
            session
                .contact_send(
                    &contact_id,
                    amount,
                    minimum_confirmations,
                    message,
                    options,
                    purpose,
                    relay_mode,
                )
                .await
        })
        .await
    }

    /// Opens sealed text from a file or a paste, to show what it holds before the user acts on
    /// it with [`EpicWallet::sealed_receive`], [`EpicWallet::sealed_pay`] or
    /// [`EpicWallet::sealed_finalize`] by its `stage`. Nothing is stored, except that a newer
    /// card of the contact in it refreshes the contact.
    ///
    /// Fails with `InvalidPairingText` for text that is not sealed or is for the other network,
    /// `SealedForAnotherWallet`, `SealedUnopenable`, and `InvalidSlate` when it holds no slate.
    pub async fn sealed_open(&self, text: String) -> Result<SealedSlateView, WalletError> {
        self.run("sealed_open", |session| async move {
            session.sealed_open(&text).await
        })
        .await
    }

    /// Receives the S1 in sealed text, as `receive_slate` does, and returns the answer sealed
    /// to the sender when it can be, else plain; the app sends it back the way the slate came.
    /// `message` is signed into the answer.
    ///
    /// Fails as [`EpicWallet::sealed_open`] does, with `InvalidSlate` for another stage, and as
    /// `receive_slate` does.
    pub async fn sealed_receive(
        &self,
        text: String,
        message: Option<String>,
    ) -> Result<SealedAnswer, WalletError> {
        self.run("sealed_receive", |session| async move {
            session.sealed_receive(&text, message).await
        })
        .await
    }

    /// Pays the I1 in sealed text; call it only after the user approved `amount`, which must
    /// be the invoiced amount. `minimum_confirmations`, `message` and `options` are as in
    /// `create_send_slate`. Returns the answer as [`EpicWallet::sealed_receive`] does.
    ///
    /// Fails as [`EpicWallet::sealed_open`] does, with `InvalidSlate` for another stage,
    /// `AmountMismatch`, `PaymentExpired`, `NotEnoughFunds`, `InvoiceAlreadyPaid`,
    /// `InvoiceLockedAboveTip` and `NodeUnreachable`.
    pub async fn sealed_pay(
        &self,
        text: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SealedAnswer, WalletError> {
        self.run("sealed_pay", |session| async move {
            session
                .sealed_pay(&text, amount, minimum_confirmations, message, options)
                .await
        })
        .await
    }

    /// Finalizes and posts the S2 or I2 in sealed text, as `finalize_slate` does.
    ///
    /// Fails as [`EpicWallet::sealed_open`] does, with `InvalidSlate` for another stage, and as
    /// `finalize_slate` does.
    pub async fn sealed_finalize(&self, text: String) -> Result<FinalizedTx, WalletError> {
        self.run("sealed_finalize", |session| async move {
            session.sealed_finalize(&text).await
        })
        .await
    }

    /// The answer `reply` (the S2 or I2 JSON this wallet answered the plain slate `incoming`
    /// with) sealed to the reply key `incoming` carries when it came from LEPIC, or `None`
    /// when it carries none and the answer goes plain.
    pub async fn sealed_answer_to_marker(
        &self,
        incoming: String,
        reply: String,
    ) -> Result<Option<String>, WalletError> {
        self.run("sealed_answer_to_marker", |session| async move {
            session.sealed_answer_to_marker(incoming, reply)
        })
        .await
    }

    /// The slate this wallet last wrote for `tx_id` as plain JSON, for a contact that cannot
    /// open sealed text: the same transaction, never a second one. The contact's seal becomes
    /// `Degraded`. Fails with `NoSlateToSend`.
    pub async fn contact_plain_fallback(&self, tx_id: u32) -> Result<String, WalletError> {
        self.run("contact_plain_fallback", |session| async move {
            session.contact_plain_fallback(tx_id).await
        })
        .await
    }

    /// The contact a transaction was sealed to or from, if any.
    pub async fn contact_of_transaction(&self, tx_id: u32) -> Result<Option<String>, WalletError> {
        self.run("contact_of_transaction", |session| async move {
            session.contact_of_transaction(tx_id).await
        })
        .await
    }

    /// Issues an invoice for `amount` to a paired contact, sealed with `purpose`, `reference`
    /// and the advisory `expires` (Unix seconds), and queues it for the contact's mailbox; the
    /// outbox runs once when the mode allows. The contact pays it only when it allows this
    /// wallet's invoices; the payment comes back by collecting, finalized and posted with
    /// `InvoiceFinalized`.
    ///
    /// Fails with `ContactNotFound` for a contact that is not paired or whose keys changed,
    /// and `ContactRefusesInvoices`. Offline the invoice is stored and queued, and goes out with
    /// the next [`EpicWallet::contacts_outbox_deliver`].
    #[allow(clippy::too_many_arguments)] // The app's invoice form, one value per field.
    pub async fn contact_issue_invoice(
        &self,
        contact_id: String,
        amount: u64,
        message: Option<String>,
        purpose: SlatePurpose,
        reference: Option<String>,
        expires: Option<u64>,
        relay_mode: ContactRelayMode,
    ) -> Result<IssuedInvoice, WalletError> {
        self.run("contact_issue_invoice", |session| async move {
            session
                .contact_issue_invoice(
                    &contact_id,
                    amount,
                    message,
                    purpose,
                    reference,
                    expires,
                    relay_mode,
                )
                .await
        })
        .await
    }

    /// The invoices from contacts waiting for the user, oldest first.
    pub async fn contact_invoices(&self) -> Result<Vec<ContactInvoiceView>, WalletError> {
        self.run("contact_invoices", |session| async move {
            session.contact_invoices().await
        })
        .await
    }

    /// Pays the waiting contact invoice `slate_id` after the user approved `amount`, the
    /// invoiced amount; the payment is sealed to the contact and queued for its mailbox, and
    /// the outbox runs once when the mode allows. `minimum_confirmations`, `message` and
    /// `options` are as in `create_send_slate`.
    ///
    /// Fails with `InvoiceNotFound` when no contact invoice with that id waits,
    /// `ContactNotVerified` when its contact is no longer verified with invoices allowed, and
    /// as [`EpicWallet::sealed_pay`] does.
    pub async fn contact_pay_invoice(
        &self,
        slate_id: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        relay_mode: ContactRelayMode,
    ) -> Result<PaidInvoice, WalletError> {
        self.run("contact_pay_invoice", |session| async move {
            session
                .contact_pay_invoice(
                    &slate_id,
                    amount,
                    minimum_confirmations,
                    message,
                    options,
                    relay_mode,
                )
                .await
        })
        .await
    }

    /// Declines the waiting contact invoice `slate_id`: it is never paid, and a `declined` is
    /// queued for the contact. Fails with `InvoiceNotFound` when no contact invoice with that
    /// id waits.
    pub async fn contact_decline_invoice(&self, slate_id: String) -> Result<(), WalletError> {
        self.run("contact_decline_invoice", |session| async move {
            session.contact_decline_invoice(&slate_id).await
        })
        .await
    }

    /// The messages for a contact in the outbox, by id, for the payment timeline.
    pub async fn contact_outbox(
        &self,
        contact_id: String,
    ) -> Result<Vec<OutboxEntryView>, WalletError> {
        self.run("contact_outbox", |session| async move {
            session.contact_outbox(&contact_id).await
        })
        .await
    }

    /// "Send again": posts the outbox entry `id` once more, delivered or stuck, while its
    /// payment still waits for the contact. The contact treats a repeat as the same message.
    ///
    /// Fails with `NoSlateToSend` for an id the outbox does not hold or whose transaction
    /// finished, was cancelled or expired, `ContactsOffline` or
    /// `EpicboxOff`, and `TransportFailed` when the relay fails.
    pub async fn contact_outbox_resend(
        &self,
        id: u64,
        relay_mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        self.run("contact_outbox_resend", |session| async move {
            session.contact_outbox_resend(id, relay_mode).await
        })
        .await
    }

    /// Sends `payload`, at most 64 KiB, to the paired contact `contact_id`: sealed to its keys
    /// and signed with this pairing's, queued in the outbox and posted at once when the mode is
    /// `Online`; the outbox retries it as it retries slates and lists it with the returned id
    /// as `slate_id`. The contact's wallet keeps it once under that id, raises
    /// `ContactPayload` and returns it from [`EpicWallet::contact_payloads`]. LEPIC never reads
    /// the bytes; the app gives them their meaning.
    ///
    /// Fails with `InvalidArgument` for a larger payload, and `ContactNotFound` for a contact
    /// that is not paired.
    pub async fn contact_post_payload(
        &self,
        contact_id: String,
        payload: Vec<u8>,
        relay_mode: ContactRelayMode,
    ) -> Result<String, WalletError> {
        self.run("contact_post_payload", |session| async move {
            session
                .contact_post_payload(&contact_id, payload, relay_mode)
                .await
        })
        .await
    }

    /// The payloads contacts sent that the app has not acknowledged, oldest first, at most 256:
    /// while that many wait, newer ones stay on the relay. Kept across restarts.
    pub async fn contact_payloads(&self) -> Result<Vec<ContactPayloadView>, WalletError> {
        self.run("contact_payloads", |session| async move {
            session.contact_payloads().await
        })
        .await
    }

    /// Forgets the kept payloads `ids` names, once the app stored what it needs; ids not kept
    /// are ignored. Returns how many were forgotten. Fails with `InvalidArgument` for an id
    /// that is not one or more than 256 of them.
    pub async fn contact_payloads_ack(&self, ids: Vec<String>) -> Result<u32, WalletError> {
        self.run("contact_payloads_ack", |session| async move {
            session.contact_payloads_ack(ids).await
        })
        .await
    }

    /// Posts every outbox entry that is due, raising `OutboxDelivered` for each that reached
    /// its relay and `OutboxStuck` for one undelivered for a day, which stops retrying. A relay
    /// that fails is counted, not returned.
    ///
    /// Fails with `ContactsOffline` or `EpicboxOff` before connecting.
    pub async fn contacts_outbox_deliver(
        &self,
        relay_mode: ContactRelayMode,
    ) -> Result<OutboxReport, WalletError> {
        self.run("contacts_outbox_deliver", |session| async move {
            session.contacts_outbox_deliver(relay_mode).await
        })
        .await
    }

    /// The pairings as a versioned JSON document for the app's `.wfeh` history backup. It
    /// holds no secret: the keys come from the recovery phrase. Pairings in progress are left
    /// out.
    pub async fn contacts_export(&self) -> Result<String, WalletError> {
        self.run("contacts_export", |session| async move {
            session.contacts_export().await
        })
        .await
    }

    /// Restores the pairings of a document [`EpicWallet::contacts_export`] wrote, with the
    /// same keys, mailboxes and trust, marked as possibly living on another device too.
    /// Pairings this wallet holds already are kept as they are.
    ///
    /// Fails with `InvalidArgument` for a document over 32 MiB, and with `InvalidArgument` or
    /// `Io` for a document this build cannot read or that is for the other network; nothing is
    /// imported then. A pairing whose keys this wallet's seed does not derive is skipped as a
    /// conflict.
    pub async fn contacts_import(
        &self,
        document: String,
    ) -> Result<ContactImportSummary, WalletError> {
        self.run("contacts_import", |session| async move {
            session.contacts_import(document).await
        })
        .await
    }
}
