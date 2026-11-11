// SPDX-License-Identifier: Apache-2.0
//! One value of every variant of the errors the wallet's calls return, for the tests of the
//! code that turns them into exit codes and error kinds. Built only with the `test-support`
//! feature.
//!
//! Each list holds at least one value of each variant of its enum; a variant that maps by what
//! it wraps may appear more than once. A test of this crate reads the enums' sources and fails
//! when a variant has no value here, so a new variant reaches every mapper's test.

use std::time::Duration;

use lepic_crypto::CryptoError;
use lepic_keychain::vault::SecretNameError;
use lepic_keychain::{
    AppDataError, IdentifierError, KeychainError, MnemonicError, ProofError, SecretStoreError,
    WalletSeedError,
};
use lepic_methods::http::ProbeError;
use lepic_node::NodeError;
use lepic_peer::client::AddressClass;
use lepic_peer::{OriginError, PeerClientError, PeerFormatError};
use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_primitives::committed::KernelSumError;
use lepic_primitives::params::Network;
use lepic_primitives::validate::ValidationError;
use lepic_slate::codec::CodecId;
use lepic_slate::error::{
    DecodeError, EncodeError, ProofAddressError, RegistryError, SlateError, Unrepresentable,
};
use lepic_slate::model::SlateId;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{PIN_KEY_LEN, StoreError, TxId, TxState};
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::transport::TransportId;
use lepic_wallet::chain::ImplausibleNodeData;
use lepic_wallet::finalize::{FinalizeError, SlateField};
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::{InvoiceError, InvoiceField};
use lepic_wallet::receive::ReceiveError;
use lepic_wallet::release::ReleaseRefusal;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::send::SendError;
use lepic_wallet::state::InvalidTransition;
use lepic_wallet::{AccountError, ConfigError, SecretVaultError, WalletError};

use crate::key_schedule::ContactKeyError;
use crate::{ContactError, DirectError, Epic1Refusal, InPersonRefusal, NativeFailure};

const TX: TxId = TxId(1);
const OTHER_TX: TxId = TxId(2);
const SLATE: SlateId = SlateId::from_bytes([1; 16]);
const TRANSPORT: TransportId = TransportId::new("sample");
const CODEC: CodecId = CodecId::new("sample");
const ORIGIN: &str = "http://192.0.2.1:3415";
/// What a listener asks of a sender it is not ready for or has taken enough from.
pub const RETRY_AFTER: Duration = Duration::from_secs(30);

fn node() -> NodeError {
    NodeError::Timeout
}

fn crypto() -> CryptoError {
    CryptoError::InvalidSecretKey
}

fn transport() -> TransportError {
    TransportError::UnsupportedLocation {
        transport: TRANSPORT,
    }
}

fn slate() -> SlateError {
    SlateError::MissingParticipant {
        stage: Stage::S1,
        role: Role::Sender,
    }
}

fn unrepresentable() -> EncodeError {
    EncodeError::Unrepresentable {
        codec: CODEC,
        what: Unrepresentable::TimeToLive,
    }
}

fn method_failure() -> lepic_wallet::inbox::MethodFailure {
    Box::new(std::io::Error::other("sample"))
}

/// The error of a task that was cancelled; `None` when no runtime could be built for it.
fn cancelled_task() -> Option<tokio::task::JoinError> {
    let runtime = tokio::runtime::Builder::new_current_thread().build().ok()?;
    runtime.block_on(async {
        let task = tokio::spawn(std::future::pending::<()>());
        task.abort();
        task.await.err()
    })
}

/// Every variant of [`WalletError`].
#[must_use]
pub fn wallet_errors() -> Vec<WalletError> {
    let mut errors = vec![
        WalletError::Config(ConfigError::NodeEndpoint),
        WalletError::WalletExists,
        WalletError::NoWallet,
        WalletError::WrongPassword,
        WalletError::Locked,
        WalletError::AlreadyOpen,
        WalletError::NetworkMismatch {
            stored: "mainnet".to_owned(),
            configured: Network::Floonet,
        },
        WalletError::ForeignDatabase,
        WalletError::Mnemonic(MnemonicError::Checksum),
        WalletError::StoredSeed(MnemonicError::Checksum),
        WalletError::WalletSeedFile(WalletSeedError::Decryption),
        WalletError::Keychain(KeychainError::AddressParentTooDeep { depth: 0 }),
        WalletError::Identifier(IdentifierError::InvalidHex),
        WalletError::SecretVault(SecretVaultError::NotFound),
        WalletError::SecretStore(SecretStoreError::Unavailable),
        WalletError::SecretName(SecretNameError::Length { actual: 0 }),
        WalletError::Store(StoreError::WalUnavailable),
        WalletError::Store(StoreError::SchemaTooNew {
            found: 2,
            supported: 1,
        }),
        WalletError::Account(AccountError::LabelTaken),
        WalletError::Account(AccountError::UnknownLabel),
        WalletError::UnknownTransaction(TX),
        WalletError::Transition(InvalidTransition {
            from: TxState::Sent,
            to: TxState::Received,
        }),
        WalletError::PartnerPosted {
            tx_id: TX,
            partner: OTHER_TX,
        },
        WalletError::OnChain(TX),
        WalletError::InPool(TX),
        WalletError::NotReleasable {
            tx_id: TX,
            reason: ReleaseRefusal::KernelUnknown,
        },
        WalletError::ChangedDuringCancel(TX),
        WalletError::RestoreScanRequired,
        WalletError::Node(node()),
        WalletError::Implausible(ImplausibleNodeData::TipTooHigh {
            tip: Height::new(2),
            limit: Height::new(1),
        }),
        WalletError::AppData(AppDataError::NotAppData),
        WalletError::MinimumConfirmationsOutOfRange { count: 0 },
        WalletError::Balance(ArithmeticError::Overflow),
        WalletError::InvalidListing,
        WalletError::NoValidKey,
    ];
    errors.extend(cancelled_task().map(WalletError::Task));
    errors
}

/// Every variant of [`SendError`].
#[must_use]
pub fn send_errors() -> Vec<SendError> {
    vec![
        SendError::Wallet(WalletError::Locked),
        SendError::Node(node()),
        SendError::Selection(SelectionError::NotEnoughFunds {
            available: Amount::ZERO,
            needed: Amount::new(1),
        }),
        SendError::Selection(SelectionError::NothingToConsolidate { outputs: 0 }),
        SendError::UnknownTransport {
            transport: TRANSPORT,
        },
        SendError::CannotDeliver {
            transport: TRANSPORT,
        },
        SendError::CannotExport {
            transport: TRANSPORT,
        },
        SendError::Unrepresentable(unrepresentable()),
        SendError::CodecNotRegistered { codec: CODEC },
        SendError::InputKeyMismatch,
        SendError::KeyIdentifier(IdentifierError::InvalidHex),
        SendError::Proof(ProofError::InvalidNonce),
        SendError::Crypto(crypto()),
        SendError::ProofAddress(ProofAddressError::NotAPoint),
        SendError::Slate(slate()),
        SendError::Arithmetic(ArithmeticError::Overflow),
        SendError::StoredSlate(DecodeError::UnknownFormat),
        SendError::MalformedContext,
        SendError::NotResendable { tx_id: TX },
        SendError::PayeeMismatch { tx_id: TX },
        SendError::SlateIdTaken {
            slate_id: SLATE,
            sent: None,
        },
        SendError::Undelivered {
            tx_id: TX,
            slate_id: SLATE,
            source: transport(),
        },
    ]
}

/// Every variant of [`ReceiveError`].
#[must_use]
pub fn receive_errors() -> Vec<ReceiveError> {
    vec![
        ReceiveError::Wallet(WalletError::Locked),
        ReceiveError::UnknownTransport {
            transport: TRANSPORT,
        },
        ReceiveError::Decode(DecodeError::UnknownFormat),
        ReceiveError::WrongStage { stage: Stage::S2 },
        ReceiveError::ZeroAmount,
        ReceiveError::AlreadyReceived {
            slate_id: SLATE,
            tx_id: TX,
        },
        ReceiveError::Expired {
            cutoff: Height::new(1),
            tip: Height::new(2),
        },
        ReceiveError::AheadOfTip {
            height: Height::new(2),
            limit: Height::new(1),
        },
        ReceiveError::FeeBelowMinimum {
            fee: Fee::ZERO,
            minimum: Fee::new(1),
        },
        ReceiveError::FeeOverflow,
        ReceiveError::MessageSignature {
            role: Role::Sender,
            source: crypto(),
        },
        ReceiveError::ForeignProofAddress,
        ReceiveError::Node(node()),
        ReceiveError::Output(ProofError::InvalidNonce),
        ReceiveError::Signing(crypto()),
        ReceiveError::Excess(KernelSumError::Mismatch),
        ReceiveError::Slate(slate()),
        ReceiveError::Codecs(RegistryError::DuplicateCodec { codec: CODEC }),
        ReceiveError::Encode(FormatError::CodecNotRegistered { codec: CODEC }),
        ReceiveError::OpenReceipts(None),
        ReceiveError::Refused,
    ]
}

/// Every variant of [`FinalizeError`].
#[must_use]
pub fn finalize_errors() -> Vec<FinalizeError> {
    vec![
        FinalizeError::Wallet(WalletError::Locked),
        FinalizeError::UnknownTransport {
            transport: TRANSPORT,
        },
        FinalizeError::Decode(DecodeError::UnknownFormat),
        FinalizeError::WrongStage { stage: Stage::S1 },
        FinalizeError::UnknownSlate { slate_id: SLATE },
        FinalizeError::AlreadyFinalized {
            slate_id: SLATE,
            tx_id: TX,
        },
        FinalizeError::NotFinalizable {
            tx_id: TX,
            state: TxState::Received,
        },
        FinalizeError::Expired {
            cutoff: Height::new(1),
            tip: Height::new(2),
        },
        FinalizeError::Mismatch {
            field: SlateField::Id,
        },
        FinalizeError::MissingPaymentProof,
        FinalizeError::ForeignSenderAddress,
        FinalizeError::PaymentProofSignature,
        FinalizeError::MessageSignature(crypto()),
        FinalizeError::ReceiverSignature(crypto()),
        FinalizeError::FeeBelowMinimum {
            fee: Fee::ZERO,
            minimum: Fee::new(1),
        },
        FinalizeError::FeeOverflow,
        FinalizeError::Signing(crypto()),
        FinalizeError::Excess(KernelSumError::Mismatch),
        FinalizeError::InvalidTransaction(ValidationError::KernelSum(KernelSumError::Mismatch)),
        FinalizeError::Slate(slate()),
        FinalizeError::Codecs(RegistryError::DuplicateCodec { codec: CODEC }),
        FinalizeError::Encode(unrepresentable()),
        FinalizeError::StoredSlate(DecodeError::UnknownFormat),
        FinalizeError::MissingContext { slate_id: SLATE },
        FinalizeError::MalformedContext,
        FinalizeError::Node(node()),
        FinalizeError::UnexpectedAnswerer { tx_id: TX },
        FinalizeError::NotPostable {
            tx_id: TX,
            state: TxState::Received,
        },
        FinalizeError::NotPosted {
            tx_id: TX,
            source: node(),
        },
        FinalizeError::InputsSpentElsewhere {
            tx_id: TX,
            source: node(),
        },
        FinalizeError::InputsSpentByOwnTransaction {
            tx_id: TX,
            by: OTHER_TX,
            source: node(),
        },
        FinalizeError::PeerInputsSpent {
            tx_id: TX,
            source: node(),
        },
    ]
}

/// Every variant of [`InvoiceError`].
#[must_use]
// One sample per variant: the list is as long as the enum.
#[allow(clippy::too_many_lines)]
pub fn invoice_errors() -> Vec<InvoiceError> {
    vec![
        InvoiceError::Wallet(WalletError::Locked),
        InvoiceError::Node(node()),
        InvoiceError::UnknownTransport {
            transport: TRANSPORT,
        },
        InvoiceError::CannotDeliver {
            transport: TRANSPORT,
        },
        InvoiceError::CannotExport {
            transport: TRANSPORT,
        },
        InvoiceError::Decode(DecodeError::UnknownFormat),
        InvoiceError::WrongStage { stage: Stage::S2 },
        InvoiceError::Selection(SelectionError::NotEnoughFunds {
            available: Amount::ZERO,
            needed: Amount::new(1),
        }),
        InvoiceError::Selection(SelectionError::NothingToConsolidate { outputs: 0 }),
        InvoiceError::AmountMismatch {
            invoiced: Amount::new(1),
            approved: Amount::new(2),
        },
        InvoiceError::AlreadyPaid {
            slate_id: SLATE,
            tx_id: TX,
        },
        InvoiceError::Expired {
            cutoff: Height::new(1),
            tip: Height::new(2),
        },
        InvoiceError::LockedUntil {
            lock_height: Height::new(2),
            tip: Height::new(1),
        },
        InvoiceError::AheadOfTip {
            height: Height::new(2),
            limit: Height::new(1),
        },
        InvoiceError::TtlTooFarAhead {
            cutoff: Height::new(2),
            limit: Height::new(1),
        },
        InvoiceError::TtlTooFarBehind {
            cutoff: Height::new(1),
            limit: Height::new(2),
        },
        InvoiceError::MessageSignature {
            role: Role::Receiver,
            source: crypto(),
        },
        InvoiceError::Mismatch {
            field: InvoiceField::Id,
        },
        InvoiceError::InputKeyMismatch,
        InvoiceError::KeyIdentifier(IdentifierError::InvalidHex),
        InvoiceError::Output(ProofError::InvalidNonce),
        InvoiceError::Signing(crypto()),
        InvoiceError::PayerSignature(crypto()),
        InvoiceError::FeeBelowMinimum {
            fee: Fee::ZERO,
            minimum: Fee::new(1),
        },
        InvoiceError::FeeOverflow,
        InvoiceError::Excess(KernelSumError::Mismatch),
        InvoiceError::InvalidTransaction(ValidationError::KernelSum(KernelSumError::Mismatch)),
        InvoiceError::Slate(slate()),
        InvoiceError::Arithmetic(ArithmeticError::Overflow),
        InvoiceError::Codecs(RegistryError::DuplicateCodec { codec: CODEC }),
        InvoiceError::Encode(FormatError::CodecNotRegistered { codec: CODEC }),
        InvoiceError::Unrepresentable(unrepresentable()),
        InvoiceError::StoredSlate(DecodeError::UnknownFormat),
        InvoiceError::UnknownSlate { slate_id: SLATE },
        InvoiceError::AlreadyFinalized {
            slate_id: SLATE,
            tx_id: TX,
        },
        InvoiceError::NotFinalizable {
            tx_id: TX,
            state: TxState::Sent,
        },
        InvoiceError::MissingContext { slate_id: SLATE },
        InvoiceError::MalformedContext,
        InvoiceError::Undelivered {
            tx_id: TX,
            slate_id: SLATE,
            source: transport(),
        },
        InvoiceError::NotPosted {
            tx_id: TX,
            source: node(),
        },
        InvoiceError::InputsSpentElsewhere {
            tx_id: TX,
            source: node(),
        },
        InvoiceError::InputsSpentByOwnTransaction {
            tx_id: TX,
            by: OTHER_TX,
            source: node(),
        },
        InvoiceError::PeerInputsSpent {
            tx_id: TX,
            source: node(),
        },
        InvoiceError::NotParked { slate_id: SLATE },
        InvoiceError::PaymentUndelivered {
            tx_id: TX,
            slate_id: SLATE,
            source: transport(),
        },
    ]
}

/// Every variant of [`InboxError`].
#[must_use]
pub fn inbox_errors() -> Vec<InboxError> {
    vec![
        InboxError::Wallet(WalletError::Locked),
        InboxError::UnknownTransport {
            transport: TRANSPORT,
        },
        InboxError::NetworkMismatch,
        InboxError::Identity(method_failure()),
        InboxError::Subscription(method_failure()),
        InboxError::Transport(transport()),
        InboxError::Address(method_failure()),
        InboxError::InvoiceExpiry,
        InboxError::NotHostFeature,
    ]
}

/// Every variant of [`Epic1Refusal`].
#[must_use]
pub fn epic1_refusals() -> Vec<Epic1Refusal> {
    use Epic1Refusal as R;
    vec![
        R::CannotPay,
        R::WrongNetwork,
        R::Signed,
        R::HintNotZero,
        R::NoReplyKey,
        R::NoReplyMailbox,
        R::WrongStage,
        R::OtherSlate,
        R::PrintedFull,
        R::NotIssued,
        R::NoPayment,
        R::RelayNotConfirmed,
        R::NoMoreEntries,
        R::OwnRelayLocal,
        R::LinkRelay,
        R::TooManyRelays,
        R::Message,
        R::Finalized,
        R::AmountMismatch,
        R::AddressNotIssued,
        R::NoAddressLeft,
        R::NotIssuingInstall,
        R::PaymentPending,
    ]
}

/// Every variant of [`InPersonRefusal`].
#[must_use]
pub fn in_person_refusals() -> Vec<InPersonRefusal> {
    use InPersonRefusal as R;
    vec![
        R::Proof,
        R::NoReplyKey,
        R::NoTtl,
        R::TtlTooShort { margin: 1 },
        R::WrongStage,
        R::OtherSlate,
        R::Signed,
        R::ReplyMailboxTag,
        R::TooManyAnswers,
        R::NoCode,
        R::NoAnswer,
        R::StoredAnswer,
        R::Loopback,
        R::RelayNotConfirmed,
        R::NoMailbox,
        R::UrIncomplete,
        R::Ended,
        R::AnswerToCode,
    ]
}

/// Every variant of [`ContactError`], with each refusal of the in-person and `epic1` calls
/// and each build error of a card or envelope.
#[must_use]
pub fn contact_errors() -> Vec<ContactError> {
    use lepic_contact::{DecodeError as Decode, EncodeError as Encode};
    let mut errors = vec![
        ContactError::Wallet(WalletError::Locked),
        ContactError::Offline,
        ContactError::EpicboxOff,
        ContactError::NetworkMismatch,
        ContactError::Decode(Decode::Damaged),
        ContactError::Keys(ContactKeyError::Derivation),
        ContactError::Name(lepic_contact::TextError::Length { found: 0, max: 1 }),
        ContactError::RelayAddress,
        ContactError::InviteExpired,
        ContactError::AlreadyPaired,
        ContactError::OtherAddress,
        ContactError::AddressProofMissing,
        ContactError::UnknownContact,
        ContactError::UnknownPairing,
        ContactError::NotVerified,
        ContactError::Relay(lepic_epicbox::MailboxError::MissingMessageId),
        ContactError::WordsUnavailable,
        ContactError::SealOff,
        ContactError::UnknownTransaction,
        ContactError::NotForThisInstall,
        ContactError::CannotOpen,
        ContactError::NotASlate,
        ContactError::Stage(Stage::S3),
        ContactError::Receive(ReceiveError::ZeroAmount),
        ContactError::Invoice(InvoiceError::FeeOverflow),
        ContactError::Finalize(FinalizeError::FeeOverflow),
        ContactError::Send(SendError::NotResendable { tx_id: TX }),
        ContactError::NotCancelled {
            tx_id: TX,
            cause: Box::new(ContactError::Offline),
            cancel: WalletError::Locked,
        },
        ContactError::TooLarge { max: 1 },
        ContactError::StoredData(Decode::Damaged),
        ContactError::KeyCheckRefused,
        ContactError::WordsNotFound,
        ContactError::Words(lepic_contact::WordsError::Unknown),
        ContactError::DoesNotPayInvoices,
        ContactError::WrongClass,
        ContactError::NoFreeSlot,
        ContactError::Ended,
        ContactError::KindDiffers,
        ContactError::PeerNotProven,
        ContactError::PairingInProgress,
        ContactError::Crossed,
        ContactError::InviteDismissed,
        ContactError::Post(transport()),
        ContactError::Waiting,
        ContactError::RelayMoveNotRequested,
        ContactError::Domain(lepic_contact::DomainError::Name),
        ContactError::NoDomainConfigured,
        ContactError::NoDomainClaim,
        ContactError::Native(lepic_native_slate::NativeError::Magic),
        ContactError::Epic1Link(lepic_epic1::LinkError::NotAnEpic1Link),
        ContactError::SavedTransaction,
        ContactError::NotPaymentFile,
    ];
    errors.extend(
        [
            Encode::FieldTooLong { tag: 1 },
            Encode::BodyTooLarge { limit: 1, found: 2 },
            Encode::ReplyMailbox,
            Encode::Oversized { limit: 1, found: 2 },
            Encode::WrongNetwork,
            Encode::SigningKeyMismatch,
            Encode::Encapsulation,
            Encode::Encryption,
            Encode::WrongClass,
        ]
        .into_iter()
        .map(ContactError::Encode),
    );
    errors.extend(in_person_refusals().into_iter().map(ContactError::InPerson));
    errors.extend(epic1_refusals().into_iter().map(ContactError::Epic1));
    errors
}

/// Every variant of [`PeerClientError`].
#[must_use]
pub fn peer_client_errors() -> Vec<PeerClientError> {
    vec![
        PeerClientError::TlsConfig(rustls::Error::General("sample".to_owned())),
        PeerClientError::Target(OriginError::NoHost),
        PeerClientError::EnvelopeTooLarge { len: 2, max: 1 },
        PeerClientError::ThisComputer {
            class: AddressClass::Loopback,
        },
        PeerClientError::Unreachable(Box::new(std::io::Error::other("sample"))),
        PeerClientError::Timeout,
        PeerClientError::NotReady {
            retry_after: Some(RETRY_AFTER),
        },
        PeerClientError::NotReady { retry_after: None },
        PeerClientError::Refused,
        PeerClientError::TooLarge,
        PeerClientError::RateLimited {
            retry_after: Some(RETRY_AFTER),
        },
        PeerClientError::RateLimited { retry_after: None },
        PeerClientError::UnsupportedFormat,
        PeerClientError::NotFound,
        PeerClientError::Status { status: 500 },
        PeerClientError::ResponseTooLarge { max: 1 },
        PeerClientError::Format(PeerFormatError::Malformed),
        PeerClientError::NotEnvelope,
    ]
}

/// Every variant of [`NativeFailure`], with each failure of the post.
#[must_use]
pub fn native_failures() -> Vec<NativeFailure> {
    let mut failures = vec![
        NativeFailure::Target(OriginError::NoHost),
        NativeFailure::Key,
        NativeFailure::Seal(ContactError::SealOff),
        NativeFailure::Reply,
    ];
    failures.extend(peer_client_errors().into_iter().map(NativeFailure::Post));
    failures
}

/// Every variant of [`DirectError`], with each failure of a native exchange.
#[must_use]
pub fn direct_errors() -> Vec<DirectError> {
    let mut errors = vec![
        DirectError::Wallet(WalletError::Locked),
        DirectError::Send(SendError::NotResendable { tx_id: TX }),
        DirectError::Probe {
            origin: ORIGIN.to_owned(),
            source: ProbeError::Origin(OriginError::NoHost),
        },
        DirectError::PinnedNoAdvert {
            origin: ORIGIN.to_owned(),
        },
        DirectError::PinChanged {
            origin: ORIGIN.to_owned(),
            pinned: [1; PIN_KEY_LEN],
            shown: [2; PIN_KEY_LEN],
        },
        DirectError::ThisDevice {
            origin: ORIGIN.to_owned(),
        },
    ];
    errors.extend(
        native_failures()
            .into_iter()
            .map(|source| DirectError::Native {
                tx_id: TX,
                slate_id: SLATE,
                source,
            }),
    );
    errors
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::path::Path;

    use super::*;

    /// The names of the variants of `pub enum <name>` in the source at `path`, relative to
    /// this crate.
    fn variants(path: &str, name: &str) -> Vec<String> {
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
        let source = std::fs::read_to_string(&file).unwrap();
        let start = format!("pub enum {name} {{");
        let mut lines = source.lines().skip_while(|line| *line != start);
        assert!(lines.next().is_some(), "no `{start}` in {}", file.display());
        let found: Vec<String> = lines
            .take_while(|line| *line != "}")
            .filter_map(|line| line.strip_prefix("    "))
            .filter(|line| line.starts_with(|c: char| c.is_ascii_uppercase()))
            .map(|line| {
                line.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect()
            })
            .collect();
        assert!(
            !found.is_empty(),
            "no variants of {name} in {}",
            file.display()
        );
        found
    }

    /// Fails for each variant of `name` that no sample is a value of.
    fn covers<T: Debug>(path: &str, name: &str, samples: &[T], outer: &str) {
        let shown: Vec<String> = samples.iter().map(|sample| format!("{sample:?}")).collect();
        for variant in variants(path, name) {
            let prefix = format!("{outer}{variant}");
            let found = shown.iter().any(|shown| {
                shown
                    .strip_prefix(&prefix)
                    .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric()))
            });
            assert!(found, "no sample of {name}::{variant}");
        }
    }

    #[test]
    fn every_variant_has_a_sample() {
        covers(
            "../lepic-wallet/src/error.rs",
            "WalletError",
            &wallet_errors(),
            "",
        );
        covers(
            "../lepic-wallet/src/send.rs",
            "SendError",
            &send_errors(),
            "",
        );
        covers(
            "../lepic-wallet/src/receive.rs",
            "ReceiveError",
            &receive_errors(),
            "",
        );
        covers(
            "../lepic-wallet/src/finalize.rs",
            "FinalizeError",
            &finalize_errors(),
            "",
        );
        covers(
            "../lepic-wallet/src/invoice.rs",
            "InvoiceError",
            &invoice_errors(),
            "",
        );
        covers(
            "../lepic-wallet/src/inbox.rs",
            "InboxError",
            &inbox_errors(),
            "",
        );
        covers("src/lib.rs", "ContactError", &contact_errors(), "");
        covers("src/epic1.rs", "Epic1Refusal", &contact_errors(), "Epic1(");
        covers(
            "src/in_person.rs",
            "InPersonRefusal",
            &contact_errors(),
            "InPerson(",
        );
        covers("src/direct.rs", "DirectError", &direct_errors(), "");
        covers("src/direct.rs", "NativeFailure", &native_failures(), "");
        covers(
            "../lepic-peer/src/error.rs",
            "PeerClientError",
            &peer_client_errors(),
            "",
        );
        covers(
            "../lepic-seal/src/error.rs",
            "EncodeError",
            &contact_errors(),
            "Encode(",
        );
    }

    #[test]
    fn a_cancelled_task_is_among_the_wallet_errors() {
        assert!(
            wallet_errors()
                .iter()
                .any(|error| matches!(error, WalletError::Task(_)))
        );
    }
}
