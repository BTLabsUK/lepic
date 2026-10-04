//! Plain data exchanged with Dart. Amounts are in the smallest unit (1 EPIC = 100_000_000).

use lepic_primitives::params::Network;
use lepic_store::TxState;

/// Which Epic chain the wallet talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Mainnet,
    Floonet,
}

impl Chain {
    pub(crate) const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Floonet => Network::Floonet,
        }
    }
}

/// Everything needed to locate a wallet on disk and reach its node and Epicbox relay.
#[derive(Clone)]
pub struct WalletConfig {
    /// Directory owned by this wallet; it must exist. The database is `wallet.sqlite3` in it.
    pub data_dir: String,
    pub chain: Chain,
    /// Node API root, such as `https://node.example:3413`. Credentials never go in the URL.
    pub node_url: String,
    /// Basic-auth secret for the node, when it needs one.
    pub node_api_secret: Option<String>,
    /// Epicbox relay domain, such as `epicbox.epiccash.com`. Empty disables Epicbox. A loopback
    /// host (`localhost` or `127.x.x.x`) is reached over a plain websocket, any other over TLS.
    pub epicbox_domain: String,
    pub epicbox_port: u16,
}

impl std::fmt::Debug for WalletConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletConfig")
            .field("data_dir", &self.data_dir)
            .field("chain", &self.chain)
            .field("node_url", &self.node_url)
            .field(
                "node_api_secret",
                &self.node_api_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("epicbox_domain", &self.epicbox_domain)
            .field("epicbox_port", &self.epicbox_port)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct NodeTip {
    pub height: u64,
    pub node_version: String,
}

/// The balance of the default account, in the categories `epic-wallet info` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSummary {
    pub last_confirmed_height: u64,
    /// The confirmations an output needs to count as spendable.
    pub minimum_confirmations: u64,
    pub total: u64,
    pub spendable: u64,
    pub awaiting_confirmation: u64,
    pub awaiting_finalization: u64,
    pub immature: u64,
    pub locked: u64,
    /// False when the numbers come from an earlier refresh instead of one that just ended.
    pub validated_with_node: bool,
}

/// A slate as the text exchanged with the other wallet, and the local transaction it belongs to.
#[derive(Debug, Clone)]
pub struct Slate {
    pub tx_id: u32,
    pub slate_id: String,
    pub json: String,
}

/// The answer to a received slate, from `EpicWallet::receive_slate` and
/// `EpicWallet::receive_file`.
#[derive(Debug, Clone)]
pub struct ReceivedSlate {
    pub tx_id: u32,
    pub slate_id: String,
    /// The reply for the sender.
    pub json: String,
    /// The slate was received before: `tx_id` is the transaction that receive created and
    /// `json` the reply it stored, byte for byte. Nothing was stored this time; show it as
    /// already answered, not as a second payment.
    pub repeated: bool,
}

/// A send that was stored and handed to its transport.
#[derive(Debug, Clone)]
pub struct SentTx {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: u64,
    pub fee: u64,
}

/// A send that was finalized and accepted by the node.
#[derive(Debug, Clone)]
pub struct FinalizedTx {
    pub tx_id: u32,
    pub slate_id: String,
}

/// Where a transaction stands, as stored by the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    /// Our send, waiting for the recipient's answer.
    Sent,
    /// A payment we signed, waiting for the sender to post it.
    Received,
    /// Our send, finalized but not yet accepted by the node.
    Finalized,
    Posted,
    Confirmed,
    Cancelled,
    /// The time to live passed before the transaction completed.
    Expired,
}

impl From<TxState> for TxStatus {
    fn from(state: TxState) -> Self {
        match state {
            TxState::Sent => Self::Sent,
            TxState::Received => Self::Received,
            TxState::Finalized => Self::Finalized,
            TxState::Posted => Self::Posted,
            TxState::Confirmed => Self::Confirmed,
            TxState::Cancelled => Self::Cancelled,
            TxState::Expired => Self::Expired,
        }
    }
}

/// Which way a transaction moves funds, seen from this wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDirection {
    /// A send of ours, or a payment of an invoice.
    Outgoing,
    /// A payment to us, or an output a scan restored.
    Incoming,
}

impl From<lepic_store::TxDirection> for TxDirection {
    fn from(direction: lepic_store::TxDirection) -> Self {
        match direction {
            lepic_store::TxDirection::Outgoing => Self::Outgoing,
            lepic_store::TxDirection::Incoming => Self::Incoming,
        }
    }
}

/// One stored transaction of the default account. Times are milliseconds since the Unix epoch,
/// by the device clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    pub tx_id: u32,
    pub direction: TxDirection,
    pub status: TxStatus,
    /// `None` for an output a scan restored.
    pub slate_id: Option<String>,
    /// The transport that carried the slate, such as `epicbox` or `file`, when known.
    pub transport: Option<String>,
    pub amount_credited: u64,
    pub amount_debited: u64,
    /// `None` when this wallet did not learn the fee, as for a restored output.
    pub fee: Option<u64>,
    pub created_at_ms: i64,
    /// When this wallet saw the transaction confirmed. `None` unless it is confirmed.
    pub confirmed_at_ms: Option<i64>,
    /// The height of the block that confirmed it. `None` while unconfirmed.
    pub confirmed_height: Option<u64>,
    /// Hex of the final kernel's excess, once this wallet has seen the final transaction. `None`
    /// before that, for a payment taken by receive, and for a restored output.
    pub kernel_excess: Option<String>,
    /// The other party's Epicbox address: where a send went or where a slate came from. `None`
    /// for files, slates passed in as text and restored outputs.
    pub counterparty: Option<String>,
    /// The height from which the slate may no longer be completed. `None` when it sets none.
    pub ttl_cutoff_height: Option<u64>,
    /// For a finalized or posted send, the height from which a refresh that still finds its
    /// kernel nowhere on chain makes it releasable: 1440 blocks after it was finalized. `None`
    /// for every other transaction.
    pub releasable_from: Option<u64>,
    /// Whether `release_transaction` may release the send now. A refresh at or above
    /// `releasable_from` missed its kernel; the release asks the node once more.
    pub releasable: bool,
    /// The parties' messages whose signatures verify, in the order the parties joined, as the
    /// latest stored stage of the slate carries them. Empty for a restored output.
    pub messages: Vec<SlateMessage>,
}

/// What a send would take and pay, from `EpicWallet::estimate_fee` and
/// `EpicWallet::estimate_max`. Nothing is locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeEstimate {
    /// What the receiver gets; `fee` comes on top.
    pub amount: u64,
    pub fee: u64,
    /// How many of the wallet's outputs the send spends.
    pub input_count: u32,
    /// What comes back to the wallet as change.
    pub change: u64,
}

/// How far a slate has progressed: `S` stages are a send, `I` stages an invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlateStage {
    /// A send to the recipient: sign it with `receive_slate`.
    S1,
    /// The recipient's answer to a send: finalize it with `finalize_and_post`.
    S2,
    /// A finalized send.
    S3,
    /// An invoice, asking the payer to pay.
    I1,
    /// A paid invoice, for the issuer to finalize.
    I2,
    /// A finalized invoice.
    I3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlateRole {
    Sender,
    Receiver,
}

impl From<lepic_wallet::slate::Role> for SlateRole {
    fn from(role: lepic_wallet::slate::Role) -> Self {
        match role {
            lepic_wallet::slate::Role::Sender => Self::Sender,
            lepic_wallet::slate::Role::Receiver => Self::Receiver,
        }
    }
}

/// A participant's free-text message as the slate carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlateMessage {
    pub role: SlateRole,
    pub text: String,
}

/// What a slate says, from `inspect_slate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlateInfo {
    pub slate_id: String,
    /// The `version_info.version` the slate declares, 2 or 3, which decides how it is read.
    pub version: u16,
    pub stage: SlateStage,
    pub amount: u64,
    pub fee: u64,
    /// The height from which the slate may no longer be completed. `None` when it sets none.
    pub ttl_cutoff_height: Option<u64>,
    /// In the order the participants joined.
    pub messages: Vec<SlateMessage>,
}

/// Progress of `EpicWallet::scan`.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// 0..=100.
    pub percent: Option<u8>,
    /// Block height reached so far.
    pub height: u64,
    /// Height the scan ends at.
    pub target_height: u64,
    pub message: String,
    /// Set on the last event of a scan that completed.
    pub finished: bool,
}

/// Progress of `EpicWallet::refresh`. Only the last event of a successful refresh has `summary`.
#[derive(Debug, Clone)]
pub struct RefreshProgress {
    /// 0..=100, never falling.
    pub percent: u8,
    pub message: String,
    pub summary: Option<WalletSummary>,
}

/// What one Epicbox drain did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxReport {
    /// Payments signed and answered.
    pub received: u32,
    /// Answers to our sends that were finalized and posted.
    pub finalized: u32,
    /// Messages already handled before.
    pub repeated: u32,
    /// Messages refused for good.
    pub rejected: u32,
    /// Messages left on the relay for a later drain.
    pub held: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerEventKind {
    /// Subscribed at the relay.
    Connected,
    /// The connection dropped or could not be made; the listener retries with backoff.
    Disconnected,
    /// Signed an incoming payment and answered it.
    Received,
    /// A payment signed before arrived again and was answered with the reply stored then.
    /// Nothing changed; it is not a second payment.
    Repeated,
    /// Finalized and posted one of our sends.
    Finalized,
    /// The listener failed; `message` says why. `Stopped` follows.
    Error,
    /// The listener ended; no more events follow.
    Stopped,
}

#[derive(Debug, Clone)]
pub struct ListenerEvent {
    pub kind: ListenerEventKind,
    /// Local id of the transaction, for `Received`, `Repeated` and `Finalized`.
    pub tx_id: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Unlocked,
    Locked,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Connecting,
    Connected,
    Disconnected,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletEventKind {
    /// `session` is set.
    Session,
    /// The balance of one account after a refresh: `account` and `balance` are set.
    Balance,
    /// A transaction changed state: `tx_id`, `from` and `to` are set. A transaction a received
    /// slate just created has `to` set to `Received` and no `from`.
    Transaction,
    /// Scan progress: `height` and `target_height` are set.
    Sync,
    /// A transport's connection changed: `transport` and `transport_state` are set.
    Transport,
    /// The stream fell behind and `missed` events were dropped. Refresh to catch up.
    Missed,
}

/// What the wallet reports while it runs, from `EpicWallet::events`. Only the fields its
/// `kind` names are set.
#[derive(Debug, Clone)]
pub struct WalletEvent {
    pub kind: WalletEventKind,
    pub session: Option<SessionState>,
    pub account: Option<u32>,
    pub balance: Option<WalletSummary>,
    pub tx_id: Option<u32>,
    pub from: Option<TxStatus>,
    pub to: Option<TxStatus>,
    pub height: Option<u64>,
    pub target_height: Option<u64>,
    pub transport: Option<String>,
    pub transport_state: Option<TransportState>,
    pub missed: Option<u64>,
}

impl WalletEvent {
    pub(crate) const fn of(kind: WalletEventKind) -> Self {
        Self {
            kind,
            session: None,
            account: None,
            balance: None,
            tx_id: None,
            from: None,
            to: None,
            height: None,
            target_height: None,
            transport: None,
            transport_state: None,
            missed: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_config_debug_redacts_the_node_api_secret() {
        let config = WalletConfig {
            data_dir: "/data".to_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:3413".to_owned(),
            node_api_secret: Some("node-secret-value".to_owned()),
            epicbox_domain: String::new(),
            epicbox_port: 443,
        };
        let printed = format!("{config:?}");
        assert!(!printed.contains("node-secret-value"));
        assert!(printed.contains("[redacted]"));
    }
}
