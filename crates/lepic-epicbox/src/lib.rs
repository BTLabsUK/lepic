//! Epicbox addresses, message crypto, protocol frames and relay transport.

mod address;
mod client;
mod client_inbox;
mod crypto;
mod frame;
#[cfg(feature = "mock-relay")]
pub mod mock_relay;
mod session;

pub use address::{
    AddressError, DEFAULT_DOMAIN, DEFAULT_PORT, Domain, EpicboxAddress, MAX_ADDRESS_LEN,
    MAX_DOMAIN_LEN, Network,
};
pub use client::{
    Awaiting, Backoff, ClientError, ClientSettings, EpicboxClient, Identity, TRANSPORT_ID,
};
pub use client_inbox::{ConnectionState, Mode, Rejection, RejectionReason, Subscription};
pub use crypto::{
    Destination, EncryptedMessage, KEY_LEN, MAX_MESSAGE_LEN, MessageError, MessageField,
    MessageKey, NONCE_LEN, Nonce, Plaintext, ReceivedMessage, SALT_LEN, Salt, SignedMessage,
    TAG_LEN, sign_text, verify_text,
};
pub use frame::{
    ClientFrame, FrameError, MAX_FRAME_LEN, PROTOCOL_VERSION, RelayErrorKind, RelayFrame,
    SlateFrame, WalletMode,
};
pub use session::{
    Connector, DEFAULT_PLAIN_PORT, ProtocolVersion, RelayEndpoint, RelayStream, Security,
    TcpConnector,
};
