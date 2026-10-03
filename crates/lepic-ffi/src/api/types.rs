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
    /// Local id of the transaction, for `Received` and `Finalized`.
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
