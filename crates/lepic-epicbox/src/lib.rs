// SPDX-License-Identifier: Apache-2.0
//! The Epicbox relay protocol as `epic-wallet` speaks it (ADR 0004): addresses, message crypto,
//! protocol frames, and the client that sends, listens and drains mailboxes.
//!
//! The crate's `README.md` describes the message format, the frames and the subscriptions.

mod address;
mod address_signature;
mod client;
mod client_inbox;
mod crypto;
mod frame;
mod json;
mod mailbox;
#[cfg(feature = "mock-relay")]
pub mod mock_mux;
#[cfg(feature = "mock-relay")]
pub mod mock_relay;
mod mux;
mod mux_frame;
mod prefilter;
mod session;
pub mod sessions;
#[cfg(any(test, feature = "mock-relay"))]
pub mod testing;
pub mod tunnel;

pub use address::{
    AddressError, DEFAULT_PORT, Domain, EpicboxAddress, MAX_ADDRESS_LEN, MAX_DOMAIN_LEN, Network,
};
pub use address_signature::{
    MAX_SERVICE_DOMAIN_LEN, ServiceDomain, ServiceDomainError, listing_message_verifies,
    listing_message_verifies_hex, sign_listing_message,
};
pub use client::{
    Awaiting, Backoff, CancelOutcome, CancelReport, ClientError, ClientSettings, ClientTimings,
    EpicboxClient, Identity, ListenOptions, PostReceipt, RETRY_IN, TRANSPORT_ID, retry_in,
};
pub use client_inbox::{
    ConnectionState, Disconnect, DrainConnection, InboxCounters, Mode, RELAY_RETENTION, Rejection,
    RejectionReason, Subscription,
};
pub use crypto::{
    Destination, EncryptedMessage, KEY_LEN, MAX_MESSAGE_LEN, MessageError, MessageField,
    MessageKey, NONCE_LEN, Nonce, Plaintext, RELAY_MAX_STR_BYTES, ReceivedMessage, SALT_LEN, Salt,
    SignedMessage, TAG_LEN, sealed_str_len, sign_text, verify_text,
};
pub use frame::{
    CANCEL_FORM_EXTENSION, CANCEL_PROTOCOL_VERSION, CANCEL_SIGNATURE_PREFIX, CancelSignature,
    ClientFrame, EPICBOX_TXID_LEN, EpicboxTxId, FrameError, InvalidEpicboxTxId,
    InvalidRelayMessageId, MAX_CHALLENGE_LEN, MAX_FRAME_LEN, MAX_FRAME_TYPE_LEN,
    MAX_REFUSAL_DESCRIPTION_LEN, MAX_RELAY_MESSAGE_ID_LEN, PROTOCOL_VERSION, RelayErrorKind,
    RelayFrame, RelayMessageId, SlateFrame, WalletMode,
};
pub use json::JsonProblem;
pub use mailbox::{
    DrainLimits, DrainReport, Handled, MAX_MAILBOXES_PER_DRAIN, MAX_MESSAGES_PER_MAILBOX,
    MailboxClient, MailboxContent, MailboxEnd, MailboxError, MailboxHandler, MailboxMessage,
    MailboxReport, RelayedMail,
};
pub use mux::{
    Claimed, MailboxProbe, MuxCancelOutcome, MuxCounters, MuxError, MuxEvent, MuxOptions,
    MuxPostError, MuxPostNotSent, MuxSession, MuxState, MuxWaiting, ProbeStep, probe_mailbox,
};
pub use mux_frame::{
    ATTACH_HOST_EXTENSION, ATTACH_SIGNATURE_PREFIX, MAX_ACK_IDS, MAX_ATTACH_PER_FRAME,
    MAX_HOLD_SECS, MAX_MAILBOXES_PER_SOCKET, MUX_EXTENSION, MuxCode, MuxLimits, TXCANCEL_EXTENSION,
};
pub use prefilter::{Admission, Prefilter};
pub use session::{
    Connector, DEFAULT_PLAIN_PORT, EndpointError, ProtocolVersion, RelayEndpoint, RelayStream,
    Security, TcpConnector, UntrustedHosts,
};
