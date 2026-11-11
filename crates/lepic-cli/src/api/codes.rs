// SPDX-License-Identifier: Apache-2.0
//! The fine-grained `code` of each error a call can end with, and the status when it is not the
//! one its category gives. The codes name the same errors the app's `WalletErrorKind`s do
//! (`lepic-ffi`), in snake case, so no message the app tells apart is lost.
//!
//! The mapping from the errors a [`CliError`] wraps to a code is a copy of how
//! `crates/lepic-ffi/src/api/error.rs` maps them to a `WalletErrorKind` (`engine_kind`,
//! `From<SendError>`, `From<ReceiveError>`, `From<FinalizeError>`, `From<InvoiceError>`,
//! `From<InboxError>`, `From<ScanError>`, `From<RefreshError>`, `From<ContactError>`,
//! `From<DirectError>`, `in_person_kind`, `epic1_kind`, `contact_encode_kind`), plus the Tor and
//! http address mappings of `session/tor.rs` and `session/http.rs`. `lepic-cli` does not depend
//! on `lepic-ffi`; change both places together.
//!
//! One difference in names: the app's `NotEnoughFunds` is `insufficient_funds` here, as in the
//! API's own contract. `Other` has no code: the category's code stands.
//!
//! Kinds with no origin in a CLI error (so never produced here): `chain_busy`, `panic`,
//! `phrase_mismatch`, `not_ur_code`, `foreign_ur_code`,
//! `mixed_ur_codes`, `invalid_ur_code`, `ur_code_too_large`, `ur_code_incomplete`,
//! `relay_not_confirmed` from the app's own check (the contact errors below do give it).

use std::error::Error;

use hyper::StatusCode;
use lepic_keychain::AppDataError;
use lepic_methods::http::{PeerClientError, UrlError};
use lepic_methods::tor::{SendFailure, TorSendError};
use lepic_node::NodeError;
use lepic_store::StoreError;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::refresh::RefreshError;
use lepic_wallet::scan::ScanError;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::send::SendError;
use lepic_wallet::{ReceiveError, WalletError};
use lepic_wallet_contacts::{
    ContactEncodeError, ContactError, DirectError, Epic1Refusal, InPersonRefusal, NativeFailure,
};

use crate::exit::CliError;

/// What [`classify`] found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Classified {
    /// `None`: the category's code.
    pub(crate) code: Option<&'static str>,
    /// `None`: the category's status.
    pub(crate) status: Option<StatusCode>,
}

/// The code and status of `error`.
pub(crate) fn classify(error: &CliError) -> Classified {
    // As `SendError::SlateIdTaken`; the transaction it names exists, so 409.
    if matches!(error, CliError::SlateIdReused { .. }) {
        return Classified {
            code: Some("invalid_argument"),
            status: Some(StatusCode::CONFLICT),
        };
    }
    let chain = chain_of(error);
    if chain
        .iter()
        .any(|cause| matches!(cause.downcast_ref::<NodeError>(), Some(NodeError::Offline)))
    {
        return with_status("offline");
    }
    for cause in &chain {
        if let Some(tor) = cause.downcast_ref::<TorSendError>() {
            match tor.class() {
                SendFailure::TorOff => return with_status("tor_not_running"),
                SendFailure::Unreachable => return with_status("onion_unreachable"),
                _ => {}
            }
            break;
        }
    }
    let mut classified = fine(error)
        .filter(|code| *code != "other")
        .map_or_else(Classified::default, with_status);
    if chain
        .iter()
        .any(|cause| matches!(cause.downcast_ref::<NodeError>(), Some(NodeError::Timeout)))
    {
        classified.status = Some(StatusCode::GATEWAY_TIMEOUT);
    }
    classified
}

fn chain_of<'a>(error: &'a (dyn Error + 'static)) -> Vec<&'a (dyn Error + 'static)> {
    let mut chain = vec![error];
    let mut next = error.source();
    while let Some(cause) = next {
        chain.push(cause);
        next = cause.source();
    }
    chain
}

/// `code` with the status it asks for, if it is not its category's.
fn with_status(code: &'static str) -> Classified {
    let status = match code {
        "wallet_not_found" => StatusCode::NOT_FOUND,
        // Not ready: run `scan` to the end (proposal §8, 503).
        "restore_scan_required" | "tor_not_running" => StatusCode::SERVICE_UNAVAILABLE,
        // The user's own switches: the call conflicts with the wallet's state, not its config file.
        "offline" | "contacts_offline" | "epicbox_off" | "wrong_key" => StatusCode::CONFLICT,
        // Conflicts with the state of the transaction, invoice, pairing or link.
        "changed_during_cancel"
        | "on_chain"
        | "in_pool"
        | "not_releasable"
        | "invoice_already_paid"
        | "invoice_locked_above_tip"
        | "inputs_spent_elsewhere"
        | "inputs_spent_by_own_transaction"
        | "peer_inputs_spent"
        | "invite_expired"
        | "already_paired"
        | "contact_not_verified"
        | "pairing_words_unavailable"
        | "sealing_off"
        | "key_check_refused"
        | "other_address"
        | "address_proof_missing"
        | "peer_not_proven"
        | "pairing_in_progress"
        | "pairing_crossed"
        | "invite_dismissed"
        | "pairing_ended"
        | "pairing_waiting"
        | "pairing_kind_differs"
        | "relay_move_not_requested"
        | "pinned_no_advert"
        | "pin_changed"
        | "epic1_no_more_relays"
        | "printed_links_full"
        | "epic1_finalized"
        | "epic1_payment_pending" => StatusCode::CONFLICT,
        // Bad input that the CLI files under `rejected`.
        "epic1_relay_invalid" | "epic1_message_invalid" => StatusCode::BAD_REQUEST,
        _ => {
            return Classified {
                code: Some(code),
                status: None,
            };
        }
    };
    Classified {
        code: Some(code),
        status: Some(status),
    }
}

/// The code of the error, `None` for `Other` and for errors the app has no kind for.
#[allow(clippy::too_many_lines)] // One arm per variant that has a code.
fn fine(error: &CliError) -> Option<&'static str> {
    match error {
        CliError::Wallet(error) => engine(error),
        CliError::Send(error) => send(error),
        CliError::Receive(error) => receive(error),
        CliError::Finalize(error) => finalize(error),
        CliError::Invoice(error) => invoice(error),
        CliError::Inbox(error) => inbox(error),
        CliError::Refresh(RefreshError::Wallet(error))
        | CliError::Scan(ScanError::Wallet(error)) => engine(error),
        CliError::Refresh(RefreshError::Node(_))
        | CliError::Scan(ScanError::Node(_))
        | CliError::Node(_) => Some("node_unreachable"),
        CliError::Scan(ScanError::Cancelled) => Some("cancelled"),
        CliError::Contact(error) => contact(error),
        CliError::Direct(error) => direct(error),
        CliError::Store(error) => Some(store(error)),
        // As the app maps the engine's failures to read or write a slate file or reach a relay.
        CliError::Transport(_) | CliError::SlateFile { .. } => Some("transport_failed"),
        CliError::Address(_) => Some("invalid_argument"),
        CliError::HttpUrl(UrlError::PlainHttpNotAllowed) => Some("plain_http_not_allowed"),
        CliError::HttpUrl(_) | CliError::PeerOrigin(_) => Some("http_url_invalid"),
        CliError::OnionAddress(_) => Some("onion_address_invalid"),
        _ => None,
    }
}

fn store(error: &StoreError) -> &'static str {
    match error {
        StoreError::DamagedSetAside | StoreError::Damaged => "damaged_database",
        StoreError::WrongKey => "wrong_key",
        StoreError::SchemaTooNew { .. } => "wallet_too_new",
        _ => "io",
    }
}

fn engine(error: &WalletError) -> Option<&'static str> {
    Some(match error {
        WalletError::Config(_)
        | WalletError::WalletSeedFile(_)
        | WalletError::Account(_)
        | WalletError::UnknownTransaction(_)
        | WalletError::Transition(_)
        | WalletError::MinimumConfirmationsOutOfRange { .. }
        | WalletError::PartnerPosted { .. }
        | WalletError::InvalidListing => "invalid_argument",
        WalletError::WalletExists => "wallet_already_exists",
        WalletError::NoWallet => "wallet_not_found",
        WalletError::WrongPassword => "wrong_password",
        WalletError::Locked => "locked",
        WalletError::AlreadyOpen => "wallet_busy",
        WalletError::NetworkMismatch { .. } | WalletError::ForeignDatabase => "foreign_wallet",
        WalletError::Mnemonic(_) => "invalid_mnemonic",
        WalletError::Store(error) => store(error),
        WalletError::SecretVault(_) | WalletError::SecretStore(_) => "secret_store",
        WalletError::Implausible(_) | WalletError::Node(_) => "node_unreachable",
        WalletError::RestoreScanRequired => "restore_scan_required",
        WalletError::ChangedDuringCancel(_) => "changed_during_cancel",
        WalletError::OnChain(_) => "on_chain",
        WalletError::InPool(_) => "in_pool",
        WalletError::NotReleasable { .. } => "not_releasable",
        WalletError::AppData(error) => return app_data(error),
        _ => return None,
    })
}

fn app_data(error: &AppDataError) -> Option<&'static str> {
    match error {
        AppDataError::ForeignWallet => Some("foreign_app_data"),
        AppDataError::Damaged => Some("damaged_app_data"),
        AppDataError::UnsupportedVersion { .. } => Some("unsupported"),
        AppDataError::NotAppData | AppDataError::TooLong { .. } => Some("invalid_argument"),
        _ => None,
    }
}

fn send(error: &SendError) -> Option<&'static str> {
    Some(match error {
        SendError::Wallet(inner) => return engine(inner),
        SendError::Node(_) => "node_unreachable",
        SendError::Selection(SelectionError::NotEnoughFunds { .. }) => "insufficient_funds",
        SendError::Selection(SelectionError::ChangeTooSmall { .. }) => "change_too_small",
        SendError::Selection(SelectionError::TooHeavy { .. }) => "too_heavy",
        SendError::Selection(SelectionError::NothingToConsolidate { .. }) => {
            "nothing_to_consolidate"
        }
        SendError::Selection(_)
        | SendError::NotResendable { .. }
        | SendError::PayeeMismatch { .. }
        | SendError::UnknownTransport { .. }
        | SendError::CannotDeliver { .. }
        | SendError::CannotExport { .. }
        | SendError::SlateIdTaken { .. }
        | SendError::ProofAddress(_) => "invalid_argument",
        SendError::Undelivered { .. } => "transport_failed",
        SendError::Unrepresentable(_) => "invalid_slate",
        _ => return None,
    })
}

fn receive(error: &ReceiveError) -> Option<&'static str> {
    Some(match error {
        ReceiveError::Wallet(inner) => return engine(inner),
        ReceiveError::Decode(_)
        | ReceiveError::WrongStage { .. }
        | ReceiveError::AlreadyReceived { .. }
        | ReceiveError::AheadOfTip { .. }
        | ReceiveError::FeeBelowMinimum { .. }
        | ReceiveError::MessageSignature { .. }
        | ReceiveError::ZeroAmount
        | ReceiveError::FeeOverflow
        | ReceiveError::Slate(_) => "invalid_slate",
        ReceiveError::ForeignProofAddress => "foreign_proof_address",
        ReceiveError::Expired { .. } => "payment_expired",
        ReceiveError::Node(_) => "node_unreachable",
        ReceiveError::UnknownTransport { .. } => "invalid_argument",
        ReceiveError::OpenReceipts(_) => "wallet_busy",
        ReceiveError::Refused => "unsupported",
        _ => return None,
    })
}

fn finalize(error: &FinalizeError) -> Option<&'static str> {
    use FinalizeError as E;
    Some(match error {
        E::Wallet(inner) => return engine(inner),
        E::Decode(_)
        | E::WrongStage { .. }
        | E::UnknownSlate { .. }
        | E::AlreadyFinalized { .. }
        | E::Mismatch { .. }
        | E::MissingPaymentProof
        | E::ForeignSenderAddress
        | E::UnexpectedAnswerer { .. }
        | E::PaymentProofSignature
        | E::MessageSignature(_)
        | E::ReceiverSignature(_)
        | E::FeeBelowMinimum { .. }
        | E::InvalidTransaction(_)
        | E::FeeOverflow
        | E::Slate(_) => "invalid_slate",
        E::Expired { .. } => "payment_expired",
        E::Node(_) => "node_unreachable",
        E::NotPosted { .. } => "not_posted",
        E::InputsSpentElsewhere { .. } => "inputs_spent_elsewhere",
        E::InputsSpentByOwnTransaction { .. } => "inputs_spent_by_own_transaction",
        E::PeerInputsSpent { .. } => "peer_inputs_spent",
        E::NotFinalizable { .. } | E::NotPostable { .. } | E::UnknownTransport { .. } => {
            "invalid_argument"
        }
        _ => return None,
    })
}

fn inbox(error: &InboxError) -> Option<&'static str> {
    Some(match error {
        InboxError::Wallet(inner) => return engine(inner),
        InboxError::NetworkMismatch
        | InboxError::UnknownTransport { .. }
        | InboxError::Address(_)
        | InboxError::InvoiceExpiry
        | InboxError::NotHostFeature => "invalid_argument",
        InboxError::Subscription(_) | InboxError::Transport(_) => "transport_failed",
        _ => return None,
    })
}

fn invoice(error: &InvoiceError) -> Option<&'static str> {
    use InvoiceError as E;
    Some(match error {
        E::Wallet(inner) => return engine(inner),
        E::Node(_) => "node_unreachable",
        E::Selection(SelectionError::NotEnoughFunds { .. }) => "insufficient_funds",
        E::Selection(_)
        | E::UnknownTransport { .. }
        | E::CannotDeliver { .. }
        | E::CannotExport { .. }
        | E::SlateIdTaken { .. }
        | E::NotFinalizable { .. } => "invalid_argument",
        E::Decode(_)
        | E::WrongStage { .. }
        | E::UnknownSlate { .. }
        | E::MessageSignature { .. }
        | E::PayerSignature(_)
        | E::FeeBelowMinimum { .. }
        | E::FeeOverflow
        | E::InvalidTransaction(_)
        | E::Slate(_)
        | E::Encode(_)
        | E::Unrepresentable(_) => "invalid_slate",
        E::AheadOfTip { .. } | E::TtlTooFarAhead { .. } | E::TtlTooFarBehind { .. } => {
            "invoice_not_for_this_chain"
        }
        E::AlreadyPaid { .. } | E::AlreadyFinalized { .. } => "invoice_already_paid",
        E::LockedUntil { .. } => "invoice_locked_above_tip",
        E::Mismatch { .. } => "invoice_changed",
        E::AmountMismatch { .. } => "amount_mismatch",
        E::Expired { .. } => "payment_expired",
        E::NotParked { .. } => "invoice_not_found",
        E::Undelivered { .. } | E::PaymentUndelivered { .. } => "not_delivered",
        E::NotPosted { .. } => "not_posted",
        E::InputsSpentElsewhere { .. } => "inputs_spent_elsewhere",
        E::InputsSpentByOwnTransaction { .. } => "inputs_spent_by_own_transaction",
        E::PeerInputsSpent { .. } => "peer_inputs_spent",
        _ => return None,
    })
}

fn contact(error: &ContactError) -> Option<&'static str> {
    use ContactError as E;
    Some(match error {
        // What failed first names the code.
        E::NotCancelled { cause, .. } => return contact(cause),
        E::Wallet(inner) => return engine(inner),
        E::Receive(inner) => return receive(inner),
        E::Invoice(inner) => return invoice(inner),
        E::Finalize(inner) => return finalize(inner),
        E::Send(inner) => return send(inner),
        E::Offline => "contacts_offline",
        E::EpicboxOff => "epicbox_off",
        E::NetworkMismatch
        | E::RelayAddress
        | E::TooLarge { .. }
        | E::Domain(_)
        | E::NoDomainConfigured
        | E::NoDomainClaim => "invalid_argument",
        E::Decode(_) | E::NotPaymentFile => "invalid_pairing_text",
        E::Name(_) => "invalid_contact_name",
        E::InviteExpired => "invite_expired",
        E::AlreadyPaired => "already_paired",
        E::UnknownContact => "contact_not_found",
        E::UnknownPairing => "pairing_not_found",
        E::NotVerified => "contact_not_verified",
        E::Relay(_) | E::Post(_) => "transport_failed",
        E::WordsUnavailable => "pairing_words_unavailable",
        E::SealOff => "sealing_off",
        E::UnknownTransaction => "no_slate_to_send",
        E::NotForThisInstall => "sealed_for_another_wallet",
        E::CannotOpen => "sealed_unopenable",
        E::NotASlate | E::Stage(_) | E::Native(_) => "invalid_slate",
        E::KeyCheckRefused => "key_check_refused",
        E::WordsNotFound => "pairing_words_not_found",
        E::Words(_) => "invalid_pairing_words",
        E::DoesNotPayInvoices => "contact_refuses_invoices",
        E::WrongClass => "wrong_pairing_class",
        E::OtherAddress => "other_address",
        E::AddressProofMissing => "address_proof_missing",
        E::KindDiffers => "pairing_kind_differs",
        E::PeerNotProven => "peer_not_proven",
        E::PairingInProgress => "pairing_in_progress",
        E::Crossed => "pairing_crossed",
        E::InviteDismissed => "invite_dismissed",
        E::Ended => "pairing_ended",
        E::Waiting => "pairing_waiting",
        E::RelayMoveNotRequested => "relay_move_not_requested",
        E::InPerson(refusal) => in_person(*refusal),
        E::Epic1(refusal) => epic1(*refusal),
        E::Epic1Link(_) => "not_an_epic1_link",
        E::Encode(inner) => contact_encode(*inner),
        E::SavedTransaction => "saved_transaction",
        _ => return None,
    })
}

const fn contact_encode(error: ContactEncodeError) -> &'static str {
    use ContactEncodeError as E;
    match error {
        E::FieldTooLong { .. } | E::BodyTooLarge { .. } | E::Oversized { .. } | E::WrongNetwork => {
            "invalid_argument"
        }
        E::WrongClass => "wrong_pairing_class",
        // Defects of this wallet: no code but the category's, as the app's `Other`.
        E::ReplyMailbox | E::SigningKeyMismatch | E::Encapsulation | E::Encryption => "other",
    }
}

const fn in_person(refusal: InPersonRefusal) -> &'static str {
    use InPersonRefusal as R;
    match refusal {
        R::NoCode | R::NoAnswer => "in_person_not_found",
        R::RelayNotConfirmed => "relay_not_confirmed",
        R::NoMailbox => "in_person_no_mailbox",
        R::UrIncomplete => "ur_code_incomplete",
        R::StoredAnswer => "other",
        R::TtlTooShort { .. } => "invalid_argument",
        R::Ended => "cancelled",
        _ => "invalid_slate",
    }
}

const fn epic1(refusal: Epic1Refusal) -> &'static str {
    use Epic1Refusal as R;
    match refusal {
        R::CannotPay => "epic1_cannot_pay",
        R::NoMoreEntries => "epic1_no_more_relays",
        R::PrintedFull => "printed_links_full",
        R::NotIssued | R::NoPayment | R::AddressNotIssued => "epic1_not_found",
        R::RelayNotConfirmed => "relay_not_confirmed",
        R::OwnRelayLocal => "own_relay_local",
        R::LinkRelay | R::TooManyRelays => "epic1_relay_invalid",
        R::Message => "epic1_message_invalid",
        R::Finalized => "epic1_finalized",
        R::WrongNetwork => "epic1_wrong_network",
        R::PaymentPending => "epic1_payment_pending",
        _ => "invalid_slate",
    }
}

fn direct(error: &DirectError) -> Option<&'static str> {
    Some(match error {
        DirectError::Wallet(inner) => return engine(inner),
        DirectError::Send(inner) => return send(inner),
        DirectError::PinnedNoAdvert { .. } => "pinned_no_advert",
        DirectError::PinChanged { .. } => "pin_changed",
        DirectError::Probe { .. } => "peer_probe_failed",
        DirectError::ThisDevice { .. } => "this_computer",
        // The app also reads its session's dialer refusal; only the client's own check is here.
        DirectError::Native {
            source: NativeFailure::Post(PeerClientError::ThisComputer { .. }),
            ..
        } => "this_computer",
        DirectError::Native { .. } => "native_exchange_failed",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::problem::Category;

    /// The code and the status the API answers with.
    fn answer(error: &CliError) -> (&'static str, u16) {
        let classified = classify(error);
        let category = Category::of(error.kind());
        (
            classified.code.unwrap_or("-"),
            classified
                .status
                .unwrap_or_else(|| category.status())
                .as_u16(),
        )
    }

    fn contact(error: ContactError) -> CliError {
        CliError::Contact(error)
    }

    #[test]
    fn engine_errors_have_the_codes_of_the_app() {
        let cases = [
            (
                CliError::Wallet(WalletError::WrongPassword),
                "wrong_password",
                403,
            ),
            (
                CliError::Wallet(WalletError::WalletExists),
                "wallet_already_exists",
                409,
            ),
            (
                CliError::Wallet(WalletError::NoWallet),
                "wallet_not_found",
                404,
            ),
            (CliError::Wallet(WalletError::Locked), "locked", 409),
            (
                CliError::Wallet(WalletError::AlreadyOpen),
                "wallet_busy",
                409,
            ),
            (
                CliError::Wallet(WalletError::ForeignDatabase),
                "foreign_wallet",
                409,
            ),
            (
                CliError::Wallet(WalletError::RestoreScanRequired),
                "restore_scan_required",
                503,
            ),
            (
                CliError::Wallet(WalletError::Store(StoreError::WrongKey)),
                "wrong_key",
                409,
            ),
            (
                CliError::Wallet(WalletError::Store(StoreError::Damaged)),
                "damaged_database",
                500,
            ),
            (CliError::Store(StoreError::WrongKey), "wrong_key", 409),
            (
                CliError::Node(NodeError::Unauthorized),
                "node_unreachable",
                502,
            ),
            (CliError::Node(NodeError::Timeout), "node_unreachable", 504),
            (CliError::Node(NodeError::Offline), "offline", 409),
            (CliError::Scan(ScanError::Cancelled), "cancelled", 503),
            (
                CliError::SlateIdReused { tx_id: 1 },
                "invalid_argument",
                409,
            ),
        ];
        for (error, code, status) in cases {
            assert_eq!(answer(&error), (code, status), "{error:?}");
        }
    }

    #[test]
    fn contact_errors_have_the_codes_of_the_app() {
        let cases = [
            (ContactError::Offline, "contacts_offline", 409),
            (ContactError::EpicboxOff, "epicbox_off", 409),
            (ContactError::InviteExpired, "invite_expired", 409),
            (ContactError::AlreadyPaired, "already_paired", 409),
            (ContactError::UnknownContact, "contact_not_found", 404),
            (ContactError::UnknownPairing, "pairing_not_found", 404),
            (ContactError::NotVerified, "contact_not_verified", 409),
            (
                ContactError::WordsUnavailable,
                "pairing_words_unavailable",
                409,
            ),
            (ContactError::SealOff, "sealing_off", 409),
            (ContactError::UnknownTransaction, "no_slate_to_send", 404),
            (
                ContactError::NotForThisInstall,
                "sealed_for_another_wallet",
                422,
            ),
            (ContactError::CannotOpen, "sealed_unopenable", 422),
            (ContactError::WordsNotFound, "pairing_words_not_found", 404),
            (
                ContactError::DoesNotPayInvoices,
                "contact_refuses_invoices",
                422,
            ),
            (ContactError::WrongClass, "wrong_pairing_class", 400),
            (ContactError::PeerNotProven, "peer_not_proven", 409),
            (ContactError::PairingInProgress, "pairing_in_progress", 409),
            (ContactError::Crossed, "pairing_crossed", 409),
            (ContactError::Ended, "pairing_ended", 409),
            (ContactError::Waiting, "pairing_waiting", 409),
            (
                ContactError::RelayMoveNotRequested,
                "relay_move_not_requested",
                409,
            ),
            (ContactError::SavedTransaction, "saved_transaction", 400),
            (ContactError::NoDomainConfigured, "invalid_argument", 400),
            (
                ContactError::InPerson(InPersonRefusal::NoCode),
                "in_person_not_found",
                404,
            ),
            (
                ContactError::InPerson(InPersonRefusal::RelayNotConfirmed),
                "relay_not_confirmed",
                422,
            ),
            (
                ContactError::Epic1(Epic1Refusal::NotIssued),
                "epic1_not_found",
                404,
            ),
            (
                ContactError::Epic1(Epic1Refusal::Finalized),
                "epic1_finalized",
                409,
            ),
            (
                ContactError::Epic1(Epic1Refusal::Message),
                "epic1_message_invalid",
                400,
            ),
            (
                ContactError::Epic1(Epic1Refusal::LinkRelay),
                "epic1_relay_invalid",
                400,
            ),
            (
                ContactError::Epic1(Epic1Refusal::PaymentPending),
                "epic1_payment_pending",
                409,
            ),
        ];
        for (error, code, status) in cases {
            let error = contact(error);
            assert_eq!(answer(&error), (code, status), "{error:?}");
        }
    }

    #[test]
    fn errors_with_no_fine_code_keep_their_category() {
        for error in [
            CliError::Arguments("bad".into()),
            CliError::Interrupted,
            CliError::NoSendWithSlate,
            CliError::DataDirInUse,
        ] {
            assert_eq!(classify(&error), Classified::default(), "{error:?}");
        }
        // The app's `Other`.
        let other = contact(ContactError::Encode(ContactEncodeError::Encryption));
        assert_eq!(classify(&other), Classified::default());
    }

    #[test]
    fn every_code_is_snake_case() {
        let errors = [
            contact(ContactError::Offline),
            contact(ContactError::Ended),
            CliError::Wallet(WalletError::NoWallet),
        ];
        for error in &errors {
            let code = classify(error).code.unwrap_or_default();
            assert!(!code.is_empty());
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            );
        }
    }
}
