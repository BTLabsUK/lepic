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

/// A send that was finalized and accepted by the node.
#[derive(Debug, Clone)]
pub struct FinalizedTx {
    pub tx_id: u32,
    pub slate_id: String,
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
    /// The wallet was made by an epic-wallet older than 3.3 (GUI 5.3 or older), whose
    /// database is not read. The scan restores its funds.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOptions {
    pub strategy: SelectionStrategy,
    /// The outputs the change is split into, in equal parts with the remainder on the last,
    /// from 1 to 10; each one adds to the fee. A send whose inputs cover amount and fee
    /// exactly makes no change output.
    pub change_outputs: u32,
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
    /// What the scan did, on the last event of a scan that completed only.
    pub result: Option<ScanResult>,
}

/// What a completed `EpicWallet::scan` did. Counts are outputs of this wallet.
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

/// What the wallet learned from a peer's own messages, from `EpicWallet::peer_capability`.
/// Values are only added, at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCapability {
    /// Nothing yet: no marked slate or notice from it, and no invoice sent back.
    Unknown,
    /// It proved it runs LEPIC: it pays invoices and is sent notices.
    Lepic,
    /// It sent an invoice back unpaid, as a stock `epic-wallet` does: it does not pay
    /// invoices. Send it a slate file, or ask it to send instead.
    NoInvoices,
}

/// A sender whose invoices the invoice address accepts, from `EpicWallet::invoice_senders`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceSender {
    /// The full address the user added, where payments of its invoices go.
    pub address: String,
    pub label: String,
    /// Milliseconds since the Unix epoch, by the device clock.
    pub added_at_ms: i64,
}

/// An invoice this wallet issued and handed to the relay, from
/// `EpicWallet::issue_invoice_epicbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedInvoice {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: u64,
}

/// An invoice waiting on the invoice address for the user to pay or decline, from
/// `EpicWallet::pending_invoices`. Times are milliseconds since the Unix epoch, by the device
/// clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingInvoice {
    pub slate_id: String,
    /// The allowed address of the sender, where the payment goes.
    pub sender_address: String,
    /// What the sender asks for; the fee comes on top.
    pub amount: u64,
    /// The sender's message when its signature verifies, with control, bidirectional and
    /// zero-width characters removed and cut to 256 bytes. Safe to display as it is.
    pub message: Option<String>,
    pub received_at_ms: i64,
    /// When `EpicWallet::sweep_invoices` with the same expiry deletes it unpaid.
    pub expires_at_ms: i64,
}

/// A paid invoice, from `EpicWallet::pay_invoice`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidInvoice {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: u64,
    pub fee: u64,
}

/// What one drain of the invoice address did, from `EpicWallet::drain_invoices`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvoiceReport {
    /// Invoices from allowed senders stored for the user to pay or decline.
    pub parked: u32,
    /// Payments of invoices this wallet issued that were finalized.
    pub finalized: u32,
    /// Messages handled before and acknowledged again, such as an invoice parked before.
    pub repeated: u32,
    /// Messages refused for good.
    pub rejected: u32,
    /// Messages left on the relay for a later drain.
    pub held: u32,
    /// Messages acknowledged and forgotten unopened: from senders that are not allowed, or
    /// invoices over the limit of waiting invoices. Also notices not from the other party of
    /// their invoice, or of a kind this version does not know.
    pub dropped: u32,
    /// Notices about invoices accepted from the other party, each also reported as its event.
    pub notices: u32,
    /// Invoices this wallet issued that came back unpaid from the address they went to: that
    /// payer does not pay invoices. Nothing changed; cancel the invoice with
    /// `cancel_transaction`.
    pub bounced: u32,
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
    /// An answer arrived over Epicbox for a slate this wallet does not know and was refused:
    /// `slate_id`, `slate_stage` (`S2`, the answer to a send, or `I2`, the payment of an
    /// invoice) and `sender` are set. Another install of the same wallet, on the same recovery
    /// phrase, may have made that send or issued that invoice; it will never receive this
    /// answer, so tell the user to finish it there or have the other side cancel and send
    /// again. Nothing changed here.
    UnknownSlate,
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
    pub slate_id: Option<String>,
    pub amount: Option<u64>,
    /// Hex of the kernel excess, for `InvoicePosted`.
    pub kernel_excess: Option<String>,
    /// The Epicbox address a message came from, for `UnknownSlate`.
    pub sender: Option<String>,
    /// The slate's stage, `S2` or `I2`, for `UnknownSlate`.
    pub slate_stage: Option<String>,
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
            slate_id: None,
            amount: None,
            kernel_excess: None,
            sender: None,
            slate_stage: None,
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
