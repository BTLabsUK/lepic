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
    /// Epicbox relay domain, such as `relay.example.org`. Empty disables Epicbox. A loopback
    /// host (`localhost` or `127.x.x.x`) is reached over a plain websocket, any other over TLS.
    pub epicbox_domain: String,
    pub epicbox_port: u16,
    /// The hosts known to be onion services, from the app's settings, in effect from the
    /// wallet's first connection. Read when a wallet is created, restored or opened, checked
    /// as `EpicWallet::set_onion_routes` checks them (an invalid one fails the call with
    /// `InvalidArgument`), and replaced later only by that call:
    /// `set_servers` and `node_tip_for` ignore them. Empty leaves no route. Ignored in a build
    /// without tor.
    pub onion_routes: Vec<crate::api::tor::OnionRoute>,
    /// Timeouts, retries and limits for the node, the relay, HTTP and tor, from the app's
    /// configuration. Read when a wallet is created, restored or opened, and by `node_tip`;
    /// `set_servers` and `node_tip_for` keep the open wallet's. A zero, or a minimum above its
    /// maximum, fails the call with `InvalidArgument`.
    pub tuning: NetTuning,
    /// An offline session, for a cold wallet. Every call to the node or the Epicbox relay fails
    /// at once with `Offline`, before any name lookup or connect. Sending, receiving and
    /// finalizing by slate text or file, and their invoice stages, use the highest chain tip
    /// the last refresh confirmed (with none, they fail with `Offline`); finalizing stores the
    /// transaction `finalized` without posting it, with `FinalizedTx.posted` false. Read when a
    /// wallet is created, restored or opened; changing it means opening the wallet again, and
    /// `set_servers` and `node_tip_for` fail with `InvalidArgument` for another value.
    pub offline: bool,
    /// The app will start the wallet's tor for this session. Node requests, the Epicbox relay
    /// connection and HTTP sends then wait for tor from the session's first connection, and
    /// never go directly until `stop_tor` (or tor is never started and they time out), as
    /// after `expect_tor`. With `false` they go directly until tor is expected or started,
    /// unless the last session on `data_dir` expected tor and was not stopped. Read when a
    /// wallet is created, restored or opened. Ignored on iOS and in a build without tor.
    pub tor_wanted: bool,
    /// The feature bits the app claims to other LEPIC wallets: one constant of the app's
    /// build, the same for every user, never a setting. LEPIC keeps only the host bits, 4
    /// (linked-device forwarding) and 5 (directory), and ignores the rest. Read when a wallet
    /// is created, restored or opened.
    pub host_features: u32,
}

/// The app configuration's `[node]`, `[epicbox]`, `[http]` and `[tor]` tuning keys. Every
/// field is required: LEPIC has no defaults of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetTuning {
    pub node: NodeTuning,
    pub epicbox: EpicboxTuning,
    pub http: HttpTuning,
    pub tor: TorTuning,
}

/// Requests to the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeTuning {
    pub connect_timeout_s: u32,
    /// From sending a request to the last byte of its answer.
    pub request_timeout_s: u32,
    /// How long an idle connection is kept; below the node server's keep-alive timeout.
    pub idle_timeout_s: u32,
    /// Tries of a read, the first included.
    pub retry_attempts: u32,
    pub retry_backoff_min_ms: u32,
    pub retry_backoff_max_ms: u32,
    /// Outputs asked for in one request.
    pub outputs_per_request: u32,
    /// Output requests in flight at once.
    pub concurrent_requests: u32,
}

/// The Epicbox relay connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpicboxTuning {
    /// The TCP, TLS and websocket handshakes together.
    pub connect_timeout_s: u32,
    /// Each relay answer.
    pub response_timeout_s: u32,
    /// Below the relay proxy's idle timeout.
    pub ping_interval_s: u32,
    pub reconnect_min_s: u32,
    pub reconnect_max_s: u32,
    /// One whole mailbox drain.
    pub drain_timeout_s: u32,
    /// The least a relay connection through tor is given.
    pub tor_connect_timeout_s: u32,
    /// Asking a relay for its onion through tor.
    pub onion_discovery_timeout_s: u32,
    /// How long a relay that could not be asked is not asked again.
    pub onion_discovery_retry_s: u32,
}

/// The wallet's HTTP listener, which tor's onion forwards to too, and sends to other
/// wallets' listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTuning {
    pub header_timeout_s: u32,
    pub body_timeout_s: u32,
    pub request_timeout_s: u32,
    pub answer_timeout_s: u32,
    pub max_connections: u32,
    pub max_connections_per_address: u32,
    pub requests_per_minute: u32,
    pub receives_per_minute: u32,
    pub send_connect_timeout_s: u32,
    pub send_request_timeout_s: u32,
}

/// The wallet's tor. Ignored in a build without tor, but still checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TorTuning {
    pub bootstrap_timeout_s: u32,
    /// Bootstrap without a cached consensus.
    pub cold_bootstrap_timeout_s: u32,
    /// Bootstrap progress unchanged this long is a network failure.
    pub stall_timeout_s: u32,
    pub cold_stall_timeout_s: u32,
    /// The onion's descriptor uploaded.
    pub publish_timeout_s: u32,
    /// Reaching a host or an onion through tor.
    pub connect_timeout_s: u32,
    /// One send to an onion, to the last byte of its answer.
    pub request_timeout_s: u32,
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
            .field("onion_routes", &self.onion_routes)
            .field("tuning", &self.tuning)
            .field("offline", &self.offline)
            .field("host_features", &self.host_features)
            .finish()
    }
}

/// What `node_tip` learns from a node's foreign API, which needs no API secret.
#[derive(Debug, Clone)]
pub struct NodeTip {
    pub height: u64,
    pub node_version: String,
    /// Whether the node is synced and takes transactions, as epic-server 4.1.0 and later
    /// answer. `None` from an older node, which does not know the question, or when the
    /// question failed.
    pub ready_for_txs: Option<bool>,
    /// When the tip block was mined, in milliseconds since the Unix epoch, as its header
    /// says. `None` when the header could not be fetched.
    pub tip_time_ms: Option<i64>,
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

/// A send or issued invoice that was finalized and, unless the session is offline, accepted by
/// the node.
#[derive(Debug, Clone)]
pub struct FinalizedTx {
    pub tx_id: u32,
    pub slate_id: String,
    /// `false` in an offline session: the transaction is stored `finalized` and nothing went to
    /// the node. `EpicWallet::finished_payment` gives its final slate to post elsewhere.
    pub posted: bool,
}

/// An output of the wallet, from `EpicWallet::outputs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletOutput {
    /// The Pedersen commitment, 66 lowercase hex characters: the output's id on chain.
    pub commitment: String,
    pub value: u64,
    pub status: OutputStatus,
    /// Where it counts in `WalletSummary`; `None` for a spent output and an unconfirmed
    /// coinbase output, which count nowhere.
    pub category: Option<OutputCategory>,
    /// A mining reward, spendable only from `lock_height`.
    pub is_coinbase: bool,
    /// The height it was mined at, or for an output not on chain yet, the tip it was made at.
    pub height: u64,
    /// The first height at which it may be spent.
    pub lock_height: u64,
    /// Its position in the chain's output set, once a scan or refresh found it there.
    pub mmr_index: Option<u64>,
    /// At `WalletSummary.last_confirmed_height`; zero while unconfirmed.
    pub confirmations: u64,
    /// The transaction that made the output or, once a send locks or spends it, that send.
    pub tx_id: Option<u32>,
}

/// An output's state, as `epic-wallet outputs` shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStatus {
    /// Not on chain yet: change or a received output of a transaction in progress.
    Unconfirmed,
    Unspent,
    /// An input of a send that is not confirmed yet.
    Locked,
    Spent,
}

/// Where an output counts in `WalletSummary`. Values are only added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputCategory {
    Spendable,
    AwaitingConfirmation,
    AwaitingFinalization,
    Immature,
    Locked,
    /// The output an invoice this wallet issued asks for, while nobody has paid it. It counts
    /// in no figure of `WalletSummary`; once a payment is finalized it is
    /// `AwaitingFinalization`.
    UnpaidInvoice,
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

/// Which slate flow a transaction belongs to. With `TxDirection` it tells the four kinds
/// apart: an incoming payment was received and an outgoing one sent; an incoming invoice was
/// issued by this wallet and an outgoing one paid by it. Values are only added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxFlow {
    /// The sender started it. Also an output a scan restored.
    Payment,
    /// The receiver started it with an invoice.
    Invoice,
}

impl From<lepic_wallet::details::TxFlow> for TxFlow {
    fn from(flow: lepic_wallet::details::TxFlow) -> Self {
        match flow {
            lepic_wallet::details::TxFlow::Payment => Self::Payment,
            lepic_wallet::details::TxFlow::Invoice => Self::Invoice,
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
    /// A send waiting for its answer whose slate no delivery attempt got to the other party
    /// yet: every attempt failed, or none finished, as when the app was killed before the
    /// first. Show it as not delivered and offer
    /// [`crate::api::wallet::EpicWallet::resend_epicbox`] (or the resend of the transport it
    /// used). Also `true` while the send call that makes it is still running; `false` once an
    /// attempt delivered it, and for any other transaction.
    pub undelivered: bool,
    /// The parties' messages whose signatures verify, in the order the parties joined, as the
    /// latest stored stage of the slate carries them. Empty for a restored output.
    pub messages: Vec<SlateMessage>,
    /// Whether it is a payment or an invoice, from the slate stages the wallet stored.
    pub flow: TxFlow,
    /// Made by this wallet, imported from an old wallet's history, or an output a scan found
    /// with no record of who sent it.
    pub origin: TxOrigin,
    /// What the old wallet recorded of an imported transaction. `None` for any other.
    pub imported: Option<ImportedTx>,
    /// For origin `FoundByScan`: which scan found it and how it is dated. `None` for any other
    /// origin, and for an entry a scan stored before LEPIC recorded this.
    pub found: Option<ScanFound>,
    /// Hex of the commitments of the outputs the transaction created for this wallet, change
    /// included, spent or not. The same after the outputs are spent, and for an output a scan
    /// found, the same after a restore finds it again. For an imported entry, and for one a
    /// scan stored before LEPIC recorded this, only the outputs no transaction has spent yet.
    /// Empty when the wallet stores none, as for a cancelled send.
    pub output_commits: Vec<String>,
    /// Hex of the commitments of this wallet's outputs the transaction spent: for a send or an
    /// invoice payment made here, its inputs; for origin `OtherWallet` outgoing, the outputs
    /// the other wallet spent. Empty for any other.
    pub spent_commits: Vec<String>,
    /// For a payment received over Epicbox that still waits for its sender: when the sender
    /// reported that it posted the transaction (`PaymentPosted`), while that report is under an
    /// hour old. Advisory: show it as the sender's report, never as received; the payment
    /// confirms when a refresh finds the kernel. `None` for every other transaction.
    pub sender_reported_posted_at_ms: Option<i64>,
    /// For a received payment this wallet answered and that is not confirmed: when its sender
    /// reported that it cancelled the payment (`PaymentCancelled`). Kept after the payment
    /// ended here; cleared once the chain confirms it. Advisory: nothing was released on the
    /// report; a cancel here still runs its own checks. `None` for every other transaction.
    pub sender_reported_cancelled_at_ms: Option<i64>,
    /// For origin `OtherWallet` outgoing: no completed scan has covered its blocks yet, so the
    /// node's answers are its only evidence. Show it as unverified until a scan confirms it.
    /// `false` for every other transaction.
    pub unverified: bool,
}

/// Which scan stored an entry for an output it found with no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundDuring {
    /// The first scan from the beginning of the chain after the wallet was created from a
    /// recovery phrase or a `wallet.seed` file: an output the wallet held before that.
    Restore,
    /// Any other scan: a later rescan, or the first scan of a wallet created with a new seed.
    /// The output may still be older than the scan.
    Rescan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanFound {
    pub during: FoundDuring,
    /// `created_at_ms` is the time of the output's block. False when the node did not give
    /// the block's header and the time of the scan was used.
    pub dated_by_block: bool,
}

/// Where a transaction in the list came from. Values are only added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxOrigin {
    Wallet,
    /// Imported by `EpicWallet::import_legacy_history`. Its `created_at_ms` and
    /// `confirmed_at_ms` are the old wallet's.
    Imported,
    /// An output a scan found that no record explains. `created_at_ms` is the time of its
    /// block when the node told it, else the time of the scan.
    FoundByScan,
    /// What another wallet on the same recovery phrase did, as the chain shows it. Outgoing:
    /// outputs of this wallet a refresh found spent with no transaction here; `amount_debited`
    /// is their value, `amount_credited` the outputs in the same blocks taken for its change,
    /// `fee` unknown, `spent_commits` the outputs spent. Incoming: an output a refresh's
    /// update scan found with no record here, one entry per output, `created_at_ms` its block's
    /// time. A restore or a scan from genesis stores such outputs as `FoundByScan` instead.
    OtherWallet,
}

/// The type the old wallet's log gave an imported transaction. Values are only added, at the
/// end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportedTxKind {
    Coinbase,
    Received,
    Sent,
    ReceivedCancelled,
    SentCancelled,
    SentMempool,
    ReceivedMempool,
    SentCreated,
}

impl From<lepic_store::ImportedKind> for ImportedTxKind {
    fn from(kind: lepic_store::ImportedKind) -> Self {
        use lepic_store::ImportedKind as Kind;
        match kind {
            Kind::Coinbase => Self::Coinbase,
            Kind::Received => Self::Received,
            Kind::Sent => Self::Sent,
            Kind::ReceivedCancelled => Self::ReceivedCancelled,
            Kind::SentCancelled => Self::SentCancelled,
            Kind::SentMempool => Self::SentMempool,
            Kind::ReceivedMempool => Self::ReceivedMempool,
            Kind::SentCreated => Self::SentCreated,
        }
    }
}

/// How the chain scan judged an imported transaction. Values are only added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainCheck {
    /// Nothing on chain confirmed or contradicted it yet.
    Unchecked,
    /// A scan found an output it created, or the node holds its kernel.
    OnChain,
    /// The old wallet had it cancelled, but a scan found an output it created: the chain has
    /// it, and the funds count.
    CancelledButOnChain,
    /// The old wallet held an output of it as unspent that a full scan did not find, for
    /// example because another copy of the wallet spent it. The balance does not count it.
    UnspentNotOnChain,
}

impl From<lepic_store::ChainCheck> for ChainCheck {
    fn from(check: lepic_store::ChainCheck) -> Self {
        match check {
            lepic_store::ChainCheck::Unchecked => Self::Unchecked,
            lepic_store::ChainCheck::OnChain => Self::OnChain,
            lepic_store::ChainCheck::CancelledButOnChain => Self::CancelledButOnChain,
            lepic_store::ChainCheck::UnspentNotOnChain => Self::UnspentNotOnChain,
        }
    }
}

/// What the old wallet recorded of an imported transaction beyond the common fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedTx {
    /// The old wallet's own transaction id, as its list showed it.
    pub source_id: u32,
    pub kind: ImportedTxKind,
    pub input_count: u32,
    pub output_count: u32,
    pub check: ChainCheck,
}

/// Why `EpicWallet::import_legacy_history` imported nothing, or that it did. Values are only
/// added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyImportStatus {
    Imported,
    /// This history was imported before; links and dates were brought up to date.
    AlreadyImported,
    /// The folder holds no wallet database.
    NoHistory,
    /// The folder holds an older wallet database format, from an epic-wallet older than 3.3,
    /// which is not read. The scan restores its funds.
    OldFormat,
    /// The database is encrypted, damaged or not an epic-wallet database.
    Unreadable,
    /// The database kept changing while it was copied: close the old wallet and try again.
    SourceBusy,
    TooLarge,
    /// No output of the history is one this wallet's recovery phrase makes, so it cannot be
    /// shown to be this wallet's: another wallet's, or one with no output to check.
    OtherWallet,
    /// This wallet already holds a different imported history.
    OtherHistory,
}

/// What `EpicWallet::import_legacy_history` did. Counts are of records, not of money.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyImport {
    pub status: LegacyImportStatus,
    pub transactions: u32,
    pub outputs: u32,
    pub accounts_named: u32,
    /// Outputs a scan had already found, now shown under the imported transaction.
    pub linked: u32,
    /// Records of the old wallet left out: unreadable, of another seed, or outside the
    /// wallet's accounts.
    pub skipped: u32,
    /// Unfinished imported transactions the node showed on chain, now confirmed.
    pub confirmed_by_kernel: u32,
    /// Outputs found by a scan with no record, now dated by their block.
    pub dated: u32,
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
    /// The value of the outputs the send spends, `amount + fee + change`: locked from the send
    /// until it confirms.
    pub locked: u64,
    /// The outputs `change` comes back in; zero when there is no change.
    pub change_outputs: u32,
}

/// A send to the wallet itself, from `EpicWallet::split_outputs` and
/// `EpicWallet::consolidate_outputs`, finalized and posted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSentTx {
    /// The outgoing transaction: it spent the inputs and holds the change outputs.
    pub tx_id: u32,
    /// The incoming transaction: it holds the output of `amount`.
    pub received_tx_id: u32,
    pub amount: u64,
    pub fee: u64,
    /// How many outputs it spent.
    pub input_count: u32,
    /// How many outputs it made: the received one and the change.
    pub output_count: u32,
}

/// How a send chooses the outputs it spends, as `epic-wallet send --selection_strategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// The fewest of the smallest outputs that cover amount and fee, so the rest of the balance
    /// stays spendable while the send confirms. The default, as in `epic-wallet send` and the
    /// Epic GUI wallet.
    Smallest,
    /// Every spendable output, up to 500: the whole balance is locked until the send confirms,
    /// and the wallet holds fewer, larger outputs afterwards. Suits sending everything.
    All,
}

/// How a send chooses its inputs and change. A call given `None` uses `Smallest` with one
/// change output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOptions {
    pub strategy: SelectionStrategy,
    /// The outputs the change is split into, in equal parts with the remainder on the last,
    /// from 1 to 10; each one adds to the fee. A send whose inputs cover amount and fee
    /// exactly makes no change output.
    pub change_outputs: u32,
    /// Commitments, 66 hex characters each, of outputs the send or estimate must not take,
    /// for example ones another wallet on the same phrase is spending. At most 500; an
    /// output this wallet does not hold is ignored.
    pub exclude_outputs: Vec<String>,
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

/// How far the QR parts scanned so far got, from `decode_ur_slate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrSlateProgress {
    /// Set once every fragment is recovered; `json` then holds the slate text.
    pub complete: bool,
    /// Fragments recovered so far, from pure parts and fountain parts.
    pub received_fragments: u32,
    /// Fragments of the code; 0 when no part was given.
    pub fragment_count: u32,
    /// The slate JSON text, not yet checked as a slate: pass it to `inspect_slate`.
    pub json: Option<String>,
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
    /// What the scan did, on the last event of a scan that completed only.
    pub result: Option<ScanResult>,
}

/// What a completed `EpicWallet::scan` did. Counts are outputs of this wallet. A
/// `start_height` above `end_height` means the start was above the chain tip and nothing was
/// scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub start_height: u64,
    pub end_height: u64,
    /// The scan continued one that was cancelled or failed instead of starting over; the
    /// counts cover only the part scanned this time.
    pub resumed: bool,
    /// Found on chain, whether stored before or not.
    pub found: u64,
    /// Found on chain but not stored, now stored with a received transaction each.
    pub restored: u64,
    /// Stored as spent but found unspent; their transactions were cancelled.
    pub revived: u64,
    /// Locked outputs made spendable again: found on chain by a scan with
    /// `delete_unconfirmed`, or inputs of a transaction the scan cancelled.
    pub unlocked: u64,
    /// Outputs not on chain that were deleted: not found by a scan with
    /// `delete_unconfirmed`, or the change of a transaction the scan cancelled.
    pub deleted: u64,
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    /// Notices about invoices accepted from the other party: `posted`, `declined` and
    /// `withdrawn`, each also reported as its event.
    pub notices: u32,
    /// Invoices this wallet issued that the payer sent back unpaid, as a stock `epic-wallet`
    /// does: that payer does not pay invoices and is sent nothing but slates from now on.
    /// Nothing changed; cancel the invoice with `cancel_transaction`.
    pub bounced: u32,
    /// Messages acknowledged and forgotten: notices not from the other party of their invoice,
    /// of a kind this version does not know, oversize or malformed.
    pub dropped: u32,
}

/// An invoice this wallet issued to a contact, from `EpicWallet::contact_issue_invoice`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedInvoice {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: u64,
}

/// A paid invoice, from `EpicWallet::contact_pay_invoice`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidInvoice {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: u64,
    pub fee: u64,
}

/// An invoice paid by file, from `EpicWallet::pay_invoice_slate` and
/// `EpicWallet::pay_invoice_file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidInvoiceSlate {
    pub tx_id: u32,
    pub slate_id: String,
    /// What the issuer receives.
    pub amount: u64,
    /// What this wallet pays on top.
    pub fee: u64,
    /// The I2 for the issuer.
    pub json: String,
}

/// What one `EpicWallet::sweep_invoices` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceSweep {
    /// Slate ids of waiting invoices deleted unpaid, and of declined ones.
    pub deleted: Vec<String>,
    /// Invoices this wallet issued that were cancelled unpaid; a late payment is refused.
    pub cancelled: Vec<u32>,
    /// Payments of invoices whose time to live passed with the transaction neither on chain
    /// nor in the node's pool. Nothing was changed: offer the user `cancel_transaction`.
    pub cancellable: Vec<u32>,
}

/// Whether contact calls may reach relays, as the user set the app: `Online`, `Offline`
/// (nothing connects anywhere) or Epicbox switched off (no relay is reached, home relays of
/// contacts included). Calls that need a relay fail with `ContactsOffline` or `EpicboxOff`
/// before connecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactRelayMode {
    Online,
    Offline,
    EpicboxOff,
}

/// What a contact says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactKind {
    Person,
    Shop,
    Exchange,
}

/// How long an invite may be used. An invite with pairing words lasts 10 minutes instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteExpiry {
    OneHour,
    OneDay,
    SevenDays,
}

/// Where a contact stands in pairing (RFC 0002 10.2). Values are only added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// An invite of ours waits for a reply.
    PendingInvite,
    /// Our reply waits for the inviter's confirmation.
    PendingReply,
    /// Paired, the words not checked: show the outline shield.
    Paired,
    /// The user confirmed the words: show the shield with a check.
    Verified,
    /// A key check found other keys for a contact the user already has: this pairing seals
    /// nothing and takes no invoices until the user keeps the old keys or uses the new ones.
    KeysChanged,
}

/// Whether sends to a contact are sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealState {
    On,
    Off,
    /// The last send went plain because the contact could not open sealed text; the next one
    /// is sealed again.
    Degraded,
}

/// One entry of the words check or of pairing words: an emoji and its English name. Show both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasEntry {
    pub emoji: String,
    pub name: String,
}

/// What this wallet learned about the software behind an Epicbox key from that key's own
/// messages, from `EpicWallet::peer_compat`, with what follows from it now. Times are
/// milliseconds since the Unix epoch. Everything is `None`, 0 or false for a key nothing is
/// known about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCompat {
    /// The last message from the key that carried the LEPIC marker, or the last notice from it
    /// this wallet accepted.
    pub last_marked_at_ms: Option<i64>,
    /// The last slate from the key without the marker, or an invoice it sent back.
    pub last_unmarked_at_ms: Option<i64>,
    /// The feature bits its latest marked message claimed.
    pub claimed: u32,
    /// The feature bits that worked with it.
    pub works: u32,
    /// When `claimed` was last written from a message that carried feature bits.
    pub features_at_ms: Option<i64>,
    /// Derived: its last marked message is newer than its last unmarked one.
    pub lepic: bool,
    /// Derived: `lepic`, with a marked message in the last 30 days, so this wallet tells it of
    /// the end of an exchange that came marked.
    pub notices: bool,
    /// Derived: `notices`, and no unmarked slate in the last 30 days.
    pub fresh: bool,
}

/// A paired contact, from `EpicWallet::contacts` and `EpicWallet::contact`. Holds no key.
/// Times are milliseconds since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    /// 32 lowercase hex characters; the id every contact call takes.
    pub contact_id: String,
    /// The user's own name for the contact.
    pub label: String,
    /// The name the contact gives itself, unverified: show it only as "calls themselves".
    pub claimed_name: Option<String>,
    pub kind: Option<ContactKind>,
    pub state: PairingState,
    /// The four entries of the words check, to show it again; empty before the pairing
    /// completed.
    pub sas: Vec<SasEntry>,
    pub verified_at_ms: Option<i64>,
    pub allow_invoices: bool,
    pub seal: SealState,
    /// The app's address-book entry this pairing is attached to.
    pub app_contact: Option<String>,
    /// `domain:port` of the relay the contact's messages to this wallet go through, for
    /// "Delivered via ...".
    pub home_relay: Option<String>,
    /// The pairing came from a backup and may also live on another device.
    pub imported_from_backup: bool,
    /// Nothing sealed from the contact opened for 90 days: warn before a sealed send that the
    /// contact needs LEPIC to open it.
    pub lapsed: bool,
    /// When an envelope from the contact was last opened (Unix milliseconds), if ever: of the
    /// pairings attached to one address-book contact, the one heard from last is the one the
    /// contact still uses.
    pub last_sealed_in_ms: Option<i64>,
    /// The contact removed this pairing on its side and said so: nothing sent through it
    /// arrives any more. Offer to remove it here too.
    pub removed_by_peer: bool,
    pub created_at_ms: i64,
}

/// A new invite, from `EpicWallet::pairing_invite`. `link` lets anyone who sees it pair as
/// this contact until it is used or expires: share it, show it as a QR code, never store it.
/// The words are as secret as the link. `Debug` shows neither.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingInvite {
    pub contact_id: String,
    /// `epiccash://pair/1/...`.
    pub link: String,
    pub expires_at_ms: i64,
    /// The five pairing words when they were asked for; empty otherwise.
    pub words: Vec<SasEntry>,
}

/// What an invite claims, for the "Pair with Anna?" sheet, from `EpicWallet::pairing_preview`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePreview {
    /// The inviter's own name for itself, not checked.
    pub claimed_name: String,
    pub kind: ContactKind,
    pub expires_at_ms: i64,
    /// `domain:port` of the relay the pairing's messages go through.
    pub home_relay: String,
    /// The invite comes from a service, such as an exchange.
    pub service: bool,
    /// Answer it with this class in `EpicWallet::pairing_accept`.
    pub pairing_class: PairingClass,
}

/// Which kind of pairing an invite makes. Values are only added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingClass {
    /// A contact: slates, invoices and notices, listed by `EpicWallet::contacts`.
    Contact,
    /// Two wallets of one owner: only the app's payloads (`EpicWallet::contact_post_payload`),
    /// listed by `EpicWallet::private_pairings` and nowhere else. Its invite travels by QR or
    /// paste only, never as words. Its keys and channel come from random secrets the two
    /// wallets exchange while pairing, so the recovery phrase alone neither finds, reads nor
    /// writes it. Payloads pass once both sides matched the words check.
    Private,
}

/// An invite found by its pairing words, from `EpicWallet::pairing_find_words`. Answer it
/// with `link`; do not store it. `Debug` does not show the link.
#[derive(Clone, PartialEq, Eq)]
pub struct FoundInvite {
    pub link: String,
    pub preview: InvitePreview,
}

impl std::fmt::Debug for PairingInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingInvite")
            .field("contact_id", &self.contact_id)
            .field("link", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("words", &format_args!("<{} redacted>", self.words.len()))
            .finish()
    }
}

impl std::fmt::Debug for FoundInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FoundInvite")
            .field("link", &"<redacted>")
            .field("preview", &self.preview)
            .finish()
    }
}

/// An answered invite, from `EpicWallet::pairing_accept`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAnswer {
    pub contact_id: String,
    /// `epiccash://pair-reply/1/...`, for "Send by hand" and for a post that failed.
    pub reply_link: String,
    /// The reply reached the relay; the confirmation is collected later.
    pub posted: bool,
}

/// A card shown to pair in person, from `EpicWallet::pairing_show_card`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCard {
    pub contact_id: String,
    /// `epiccash://contact/1/...`, shown as a QR code for the other phone.
    pub link: String,
}

/// What a pasted reply or confirm link did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingLinkOutcome {
    /// A reply to one of this wallet's invites paired the contact: send `link`, the
    /// confirmation, back by hand.
    Confirm,
    /// A confirmation finished a pairing this wallet answered.
    Paired,
    /// The link answers nothing this wallet waits for.
    Ignored,
}

/// The result of `EpicWallet::pairing_enter_link`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingLinkResult {
    pub outcome: PairingLinkOutcome,
    /// Set for `Confirm` and `Paired`.
    pub contact_id: Option<String>,
    /// The confirmation link, for `Confirm`.
    pub link: Option<String>,
}

/// The user's answer to the words check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasDecision {
    /// "They match": the contact becomes verified.
    Match,
    /// "They don't match": the pairing is removed on this side.
    Mismatch,
    /// "Skip for now": paired, not verified.
    Skip,
}

/// A pairing in progress, from `EpicWallet::pairings_pending`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPairingView {
    pub contact_id: String,
    /// `true`: an invite of ours waits for a reply. `false`: our reply waits for the
    /// confirmation.
    pub inviter: bool,
    /// The name in the invite: ours as inviter, the inviter's own, unverified, as invitee.
    pub invite_name: String,
    pub label: String,
    /// When it stops waiting; it may still take a late reply or confirm at the first drain of
    /// its relay after that, for up to an hour.
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
    /// The relay where the pairing's mailboxes live, `domain:port`, as `HomeRelayUnreachable`
    /// names it.
    pub home_relay: String,
}

/// What started a collecting cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectTrigger {
    /// The app opened or resumed, or the wallet was unlocked: every mailbox.
    Open,
    /// The foreground tick: the mailboxes of contacts with something pending.
    Foreground,
    /// The user pulled to refresh: every mailbox.
    Pull,
    /// A push wake-up: every mailbox.
    Push,
}

/// What one `EpicWallet::contacts_collect` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCollectReport {
    pub mailboxes: u32,
    pub messages: u32,
    /// Pairings that completed.
    pub paired: u32,
    /// Pairings in progress that ended with nothing stored in this cycle; each also raised
    /// `PairingFailed`.
    pub failed: Vec<FailedPairing>,
    /// Outbox entries that reached their relay in this cycle.
    pub delivered: u32,
    /// `domain:port` of the relays that did not answer; collecting from them backs off.
    pub unreachable: Vec<String>,
}

/// A pairing in progress that ended with nothing stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedPairing {
    /// The id of the pairing's record, now removed.
    pub contact_id: String,
    pub reason: PairingFailureReason,
}

/// Whether the user keeps the old keys or uses the new ones after keys changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysDecision {
    /// The new pairing is removed; the old one stays as it was.
    KeepOld,
    /// The old pairing is removed; the new one goes on as paired.
    UseNew,
}

/// What a sealed slate or a contact invoice is for, as its sender says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlatePurpose {
    Payment,
    /// An invoice from a service, such as an exchange deposit.
    DepositRequest,
    Withdrawal,
    Refund,
    /// A request between people.
    Request,
}

/// Sealed text opened by `EpicWallet::sealed_open`: who it is from and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSlateView {
    /// The contact that signed it; `None` for an answer sealed to a slate this wallet started.
    pub contact_id: Option<String>,
    pub stage: SlateStage,
    pub slate_id: String,
    pub amount: u64,
    pub fee: u64,
    pub purpose: Option<SlatePurpose>,
    /// The sender's reference, such as an order number; shown as it is, never trusted.
    pub reference: Option<String>,
    /// Unix seconds; advisory.
    pub expires: Option<u64>,
    /// The messages whose signatures verify, in the order the participants joined, as
    /// `TransactionDetails.messages` shows them: control characters, bidirectional formatting
    /// and zero-width characters removed. Written by the other side; show them as quoted text.
    pub messages: Vec<SlateMessage>,
}

/// A sealed S1 received or a sealed I1 paid, with the answer to send back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAnswer {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: u64,
    pub fee: u64,
    /// Armored sealed text when `sealed`, else plain slate JSON.
    pub answer: String,
    pub sealed: bool,
}

/// An invoice a contact sent, waiting for the user to pay or decline it, from
/// `EpicWallet::contact_invoices`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactInvoiceView {
    pub slate_id: String,
    pub contact_id: String,
    /// What the contact asks for; the fee comes on top.
    pub amount: u64,
    pub purpose: Option<SlatePurpose>,
    pub reference: Option<String>,
    /// Unix seconds; advisory.
    pub expires: Option<u64>,
    /// The issuer's message, only when its signature verifies, with control characters,
    /// bidirectional formatting and zero-width characters removed. Written by the contact;
    /// show it as quoted text.
    pub message: Option<String>,
    pub received_at_ms: i64,
    /// Other waiting invoices for the same amount from the same contact within 10 minutes:
    /// warn before paying twice.
    pub same_amount: Vec<String>,
}

/// Where a message for a contact stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxState {
    Queued,
    Delivered,
    /// Undelivered for a day; retrying stopped. Offer "Send again".
    Stuck,
}

/// A payload a paired contact sent, from `EpicWallet::contact_payloads`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactPayloadView {
    /// The sender's id for it, 32 hex characters; a repeat is kept once.
    pub id: String,
    pub contact_id: String,
    pub received_at_ms: i64,
    /// The bytes as the contact's app sent them; LEPIC does not read them.
    pub payload: Vec<u8>,
}

/// A message for a contact's mailbox, from `EpicWallet::contact_outbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntryView {
    /// The id `EpicWallet::contact_outbox_resend` takes.
    pub id: u64,
    pub contact_id: String,
    pub slate_id: String,
    pub stage: SlateStage,
    pub state: OutboxState,
    pub attempts: u32,
    pub created_at_ms: i64,
    pub delivered_at_ms: Option<i64>,
    /// A payment delivered two hours ago or more that the contact has not posted: offer
    /// "Send again".
    pub not_posted_yet: bool,
}

/// What one `EpicWallet::contacts_outbox_deliver` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxReport {
    pub delivered: u32,
    pub failed: u32,
    /// Entries that became stuck in this run.
    pub stuck: u32,
}

/// What `EpicWallet::contacts_import` restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactImportSummary {
    pub imported: u32,
    /// Pairings this wallet holds already; they were kept as they are.
    pub skipped_existing: u32,
    /// Pairings whose contact this wallet holds under another pairing; kept as they are.
    pub skipped_conflict: u32,
}

/// Why a pairing in progress ended, for `PairingFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingFailureReason {
    /// Something changed the invite on the way. Nothing was stored; pair again.
    ChangedOnTheWay,
    /// The invite expired before a reply came.
    Expired,
    /// This wallet answered and no confirmation came in time, or, as the inviter, its
    /// confirmation never reached the relay in time: the other side cannot have finished, so
    /// nothing of the pairing is kept. Pair again.
    NotConfirmed,
    /// The inviter refused the reply: the invite was used, expired or cancelled.
    Refused,
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
    /// A payer sent back unpaid an invoice this wallet issued, as a wallet that does not pay
    /// invoices does: `tx_id` and `slate_id` name the invoice. Nothing changed; cancel it with
    /// `cancel_transaction`, or send that payer a slate file instead. A repeat for the same
    /// `tx_id` is the same bounce, redelivered.
    InvoiceBounced,
}

#[derive(Debug, Clone)]
pub struct ListenerEvent {
    pub kind: ListenerEventKind,
    /// Local id of the transaction, for `Received`, `Repeated`, `Finalized` and
    /// `InvoiceBounced`.
    pub tx_id: Option<u32>,
    /// The slate id, for `InvoiceBounced`.
    pub slate_id: Option<String>,
    pub message: String,
    /// For `Disconnected`: why the connection ended (close frame, I/O error, timeout), as text
    /// without secrets. `None` for other kinds.
    pub reason: Option<String>,
    /// For `Disconnected`: milliseconds until the listener tries again. `None` for other kinds
    /// and when it does not retry.
    pub retry_in_ms: Option<u64>,
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

/// Which of a transport's connections changed. A drain connects on its own beside a running
/// listener; only `Listener` says anything about the listener's health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConnection {
    /// The connection the Epicbox listener holds.
    Listener,
    /// A one-time drain of the payments address.
    PaymentsDrain,
    /// Retired with the invoice address; never reported.
    InvoicesDrain,
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
    /// A transport's connection changed: `transport`, `transport_connection` and
    /// `transport_state` are set.
    Transport,
    /// The stream fell behind and `missed` events were dropped. Refresh to catch up.
    Missed,
    /// An invoice from an allowed sender is waiting to be paid or declined: `slate_id` and
    /// `amount` are set. Nothing was paid.
    InvoiceReceived,
    /// An invoice this wallet issued was paid and finalized: `tx_id` and `slate_id` are set.
    /// Its posting follows as `Transaction`.
    InvoiceFinalized,
    /// An invoice expired unpaid: `slate_id` is set, and `tx_id` for one this wallet issued,
    /// which was cancelled. A waiting invoice was deleted.
    InvoiceExpired,
    /// The issuer of an invoice this wallet paid reports that it posted the transaction:
    /// `tx_id` (the payment), `slate_id` and `kernel_excess` are set. Advisory; the payment
    /// confirms when a refresh finds the kernel.
    InvoicePosted,
    /// The payer declined an invoice this wallet issued: `tx_id` and `slate_id` are set.
    /// Nothing changed; cancel the invoice with `cancel_transaction` to free its output.
    InvoiceDeclined,
    /// The issuer withdrew an invoice: `slate_id` is set. A waiting one was deleted. For one
    /// this wallet already paid, `tx_id` names the payment: offer the user
    /// `cancel_transaction`; nothing was cancelled.
    InvoiceWithdrawn,
    /// A payer sent back unpaid an invoice this wallet issued, as a wallet that does not pay
    /// invoices does: `tx_id` and `slate_id` name the invoice. The payer is recorded as not
    /// paying invoices. Nothing changed; cancel the invoice with `cancel_transaction`. A bounce
    /// redelivered before its relay message was settled raises this again for the same
    /// `tx_id`; treat a repeat as the same bounce.
    InvoiceBounced,
    /// A split or consolidation was stored and finalized: `tx_id` names its outgoing
    /// transaction, `account` and `amount` are set. Nothing was received from anyone, so
    /// it is never a `Transaction` event with `to` `received`; the posting and confirmation
    /// of both of its transactions follow as `Transaction`.
    SelfSend,
    /// An answer arrived over Epicbox for a slate this wallet does not know: `slate_id`,
    /// `slate_stage` (`S2`, the answer to a send, or `I2`, the payment of an invoice) and
    /// `sender` are set. Another install of the same wallet, on the same recovery phrase, may
    /// have made that send or issued that invoice. The answer is left on the relay and
    /// requeued for that install for up to a day, so tell the user to open it there to finish
    /// the payment. Nothing changed here. Raised once per answer; treat a repeat for the same
    /// `slate_id` as one. Nothing
    /// verifies `slate_id` or `sender`: anyone who knows the payments address can raise this
    /// with any id. Only inform the user; never act on it or show the sender as trusted.
    UnknownSlate,
    /// A received payment that waited for its sender can never complete and was ended as a
    /// cancel ends it: `tx_id` and `slate_id` are set, after the `Transaction` event that
    /// moved it to `Cancelled`. The sender's inputs were spent by another transaction, most
    /// likely the answer another install of this wallet, on the same recovery phrase, gave
    /// to the same payment. Tell the user that another install took this payment and offer a
    /// rescan to see it in the balance.
    ReceiveSuperseded,
    /// The sender of a payment this wallet received over Epicbox reports that it posted the
    /// transaction: `tx_id`, `slate_id` and `kernel_excess` are set. Raised once per payment,
    /// while it waits for its sender, and only from that payment's sender with the kernel this
    /// wallet's answer implies. Advisory: nothing changed. Refresh now; the payment confirms
    /// when a refresh finds the kernel. Until then its `sender_reported_posted_at_ms` is set.
    PaymentPosted,
    /// A reply to one of this wallet's invites paired a contact: `contact_id` is set. Show the
    /// words check.
    PairingReplied,
    /// A pairing this wallet answered, or one in person, completed: `contact_id` is set. Show
    /// the words check.
    PairingConfirmed,
    /// A pairing in progress ended without a contact: `contact_id` names the pairing, which is
    /// gone, and `pairing_failure` says why.
    PairingFailed,
    /// A contact sent newer details, such as its relay; its keys did not change:
    /// `contact_id` is set.
    ContactUpdated,
    /// A contact's relay did not answer; collecting from it backs off: `relay` is set,
    /// `domain:port`. Turn "Delivered via" into a notice.
    HomeRelayUnreachable,
    /// A key check proved the contact still holds its old keys: the old pairing, `contact_id`,
    /// keeps its keys and trust, and the new pairing was folded into it ("Anna's keys are
    /// back").
    ContactKeysRestored,
    /// A key check found no old keys, or went unanswered for a day: the new pairing,
    /// `contact_id`, is in `KeysChanged` until the user decides with `contact_keys_resolve`.
    ContactKeysChanged,
    /// A verified contact that may send invoices sent one; it waits in `contact_invoices`:
    /// `contact_id`, `slate_id`, `amount` and, when the contact gave them, `purpose`,
    /// `reference`, `expires` and `message` are set. Nothing was paid.
    InvoiceFromContact,
    /// A contact's withdrawal arrived and was received; the answer is queued for the contact:
    /// `contact_id`, `tx_id`, `slate_id` and `amount` are set.
    WithdrawalFromContact,
    /// A contact's sealed payment arrived in its mailbox and was received; the answer is
    /// queued for the contact: `contact_id`, `tx_id`, `slate_id` and `amount` are set.
    SealedReceived,
    /// Something in a contact's mailbox did not open with this wallet's keys and was dropped:
    /// `contact_id` is set. Anyone who knows the mailbox can cause this: only inform the user,
    /// for example that pairing again checks the keys.
    SealedUnopenable,
    /// A message reached the contact's relay: `contact_id` and `slate_id` are set.
    OutboxDelivered,
    /// A message could not be delivered for a day and stopped retrying: `contact_id` and
    /// `slate_id` are set. Offer "Send again".
    OutboxStuck,
    /// The contact answered a payment this wallet sent through its mailbox and the payment
    /// was finalized: `contact_id`, `tx_id`, `slate_id` and `amount` are set. Its posting
    /// follows as `Transaction`. An answer the contact sent again raises it again for the same
    /// `tx_id`; treat a repeat as the same payment.
    ContactPaymentFinalized,
    /// The contact `contact_id` removed this pairing on its side and said so in a signed
    /// notice: nothing sent through it arrives any more. The pairing stays, with
    /// `ContactView::removed_by_peer` set, until the user removes it too. Raised once.
    ContactUnpaired,
    /// The contact `contact_id` sent a payload; read it with `EpicWallet::contact_payloads`.
    ContactPayload,
    /// The sender of a payment this wallet received and answered, over Epicbox or as a paired
    /// contact, reports that it cancelled the payment: `tx_id` and `slate_id` are set. Raised
    /// once per payment, while it waits for its sender, and only from that payment's sender.
    /// Advisory: nothing changed and nothing was released. The payment's
    /// `sender_reported_cancelled_at_ms` is set from now on; whether to cancel it here is the
    /// app's choice, and `EpicWallet::cancel` keeps its own checks.
    PaymentCancelled,
}

/// How a key check from `EpicWallet::contact_key_check` stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheckStart {
    /// On its way, or already; the answer comes with a collect.
    Sent,
    /// No check may run now (one a day per slot, within a day of the new pairing): the new
    /// pairing is in `KeysChanged` already and `ContactKeysChanged` was raised.
    KeysChanged,
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
    pub transport_connection: Option<TransportConnection>,
    pub missed: Option<u64>,
    pub slate_id: Option<String>,
    pub amount: Option<u64>,
    /// Hex of the kernel excess, for `InvoicePosted` and `PaymentPosted`.
    pub kernel_excess: Option<String>,
    /// The Epicbox address a message came from, for `UnknownSlate`.
    pub sender: Option<String>,
    /// The slate's stage, `S2` or `I2`, for `UnknownSlate`.
    pub slate_stage: Option<String>,
    /// The contact or pairing a contact event is about.
    pub contact_id: Option<String>,
    /// Why a pairing ended, for `PairingFailed`.
    pub pairing_failure: Option<PairingFailureReason>,
    /// `domain:port`, for `HomeRelayUnreachable`.
    pub relay: Option<String>,
    /// For `InvoiceFromContact`, as the contact gave them.
    pub purpose: Option<SlatePurpose>,
    pub reference: Option<String>,
    /// Unix seconds; advisory.
    pub expires: Option<u64>,
    /// For `InvoiceFromContact`, the issuer's message as `ContactInvoiceView.message` gives it.
    pub message: Option<String>,
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
            transport_connection: None,
            missed: None,
            slate_id: None,
            amount: None,
            kernel_excess: None,
            sender: None,
            slate_stage: None,
            contact_id: None,
            pairing_failure: None,
            relay: None,
            purpose: None,
            reference: None,
            expires: None,
            message: None,
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
            onion_routes: Vec::new(),
            tuning: crate::tuning::shipped(),
            offline: false,
            tor_wanted: false,
            host_features: 0,
        };
        let printed = format!("{config:?}");
        assert!(!printed.contains("node-secret-value"));
        assert!(printed.contains("[redacted]"));
    }
}
