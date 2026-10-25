//! Epicbox addresses, message crypto, protocol frames and relay transport.

mod address;
mod client;
mod client_inbox;
mod crypto;
mod frame;
mod json;
mod mailbox;
#[cfg(feature = "mock-relay")]
pub mod mock_relay;
mod prefilter;
mod push;
mod relays;
mod session;
pub mod transport;
pub mod tunnel;

pub use address::{
    AddressError, DEFAULT_DOMAIN, DEFAULT_PORT, Domain, EpicboxAddress, MAX_ADDRESS_LEN,
    MAX_DOMAIN_LEN, Network,
};
pub use client::{
    Awaiting, Backoff, ClientError, ClientSettings, EpicboxClient, Identity, TRANSPORT_ID,
};
pub use client_inbox::{
    ConnectionState, Disconnect, InboxCounters, Mode, RELAY_RETENTION, Rejection, RejectionReason,
    Subscription,
};
pub use crypto::{
    Destination, EncryptedMessage, KEY_LEN, MAX_MESSAGE_LEN, MessageError, MessageField,
    MessageKey, NONCE_LEN, Nonce, Plaintext, ReceivedMessage, SALT_LEN, Salt, SignedMessage,
    TAG_LEN, sign_text, verify_text,
};
pub use frame::{
    ClientFrame, FrameError, InvalidRelayMessageId, MAX_CHALLENGE_LEN, MAX_FRAME_LEN,
    MAX_FRAME_TYPE_LEN, MAX_RELAY_MESSAGE_ID_LEN, PROTOCOL_VERSION, RelayErrorKind, RelayFrame,
    RelayMessageId, SlateFrame, WalletMode,
};
pub use json::JsonProblem;
pub use mailbox::{
    DEFAULT_DRAIN_TIMEOUT, DrainLimits, DrainReport, Handled, MAX_MAILBOXES_PER_DRAIN,
    MAX_MESSAGES_PER_MAILBOX, MailboxClient, MailboxContent, MailboxEnd, MailboxError,
    MailboxHandler, MailboxMessage, MailboxReport,
};
pub use prefilter::{Admission, Prefilter};
pub use push::{MAX_PUSH_TOKEN_LEN, PushAction, PushError, PushRequest};
pub use relays::{BUILT_IN_RELAYS, built_in_relays, is_built_in_relay};
pub use session::{
    Connector, DEFAULT_PLAIN_PORT, EndpointError, ProtocolVersion, RelayEndpoint, RelayStream,
    Security, TcpConnector,
};
