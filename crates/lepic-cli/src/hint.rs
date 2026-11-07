// SPDX-License-Identifier: Apache-2.0
//! The line a human error ends with, saying what to try next. It is built from the error's
//! typed fields and the settings the command ran with, so it can name the data directory, the
//! node or the relay the command used. JSON errors carry no hint; scripts branch on `kind`.

use lepic_epicbox::DEFAULT_PORT;
use lepic_node::NodeError;
use lepic_store::TxId;
use lepic_transport::error::TransportError;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::refresh::RefreshError;
use lepic_wallet::release::ReleaseRefusal;
use lepic_wallet::scan::ScanError;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::send::SendError;
use lepic_wallet::{ReceiveError, WalletError};

use crate::amount::format_amount;
use crate::exit::{CliError, ErrorKind};
use crate::settings::Settings;

/// What to try next, when there is something better to say than the error itself.
pub fn hint(error: &CliError, settings: Option<&Settings>) -> Option<String> {
    if let Some(wallet) = wallet_error(error) {
        return wallet_hint(wallet, settings);
    }
    if let Some(SelectionError::NotEnoughFunds { available, needed }) = selection_error(error) {
        return Some(format!(
            "{} EPIC is spendable and {} EPIC is needed with the fee. Outputs become spendable \
             after --min-confirmations blocks, and change stays locked until its transaction \
             confirms; `lepic wallet info` shows the balance",
            format_amount(*available),
            format_amount(*needed)
        ));
    }
    match error {
        CliError::Invoice(invoice) => {
            if let Some(text) = invoice_hint(invoice) {
                return Some(text);
            }
        }
        CliError::Send(SendError::Undelivered { tx_id, source, .. }) => {
            return Some(undelivered_send_hint(*tx_id, source, settings));
        }
        CliError::HttpReplyLost { tx_id } => {
            return Some(format!(
                "the receiver answered but the answer was lost; `lepic tx resend {tx_id} --to \
                 <ADDRESS>` asks for it again, and the receiver answers the same way"
            ));
        }
        CliError::TorBinaryNeeded => {
            return Some(
                "give --tor-binary with the path of the tor binary from the Tor Expert Bundle, \
                 and --lib-dir with its library directory on Linux"
                    .to_owned(),
            );
        }
        CliError::Tor(failure) => return tor_hint(failure.kind).map(str::to_owned),
        CliError::HttpUrl(lepic_foreign::UrlError::PlainHttpNotAllowed) => {
            return Some(
                "use https, or add --allow-plain-http to send this slate unencrypted".to_owned(),
            );
        }
        CliError::Finalize(FinalizeError::NotPosted { tx_id, .. }) => {
            return Some(not_posted_hint(*tx_id));
        }
        CliError::Finalize(FinalizeError::InputsSpentElsewhere { tx_id, .. }) => {
            return Some(spent_elsewhere_hint(*tx_id));
        }
        CliError::Finalize(FinalizeError::InputsSpentByOwnTransaction { tx_id, by, .. }) => {
            return Some(spent_by_own_hint(*tx_id, *by));
        }
        CliError::Finalize(FinalizeError::PeerInputsSpent { tx_id, .. }) => {
            return Some(peer_inputs_spent_hint(*tx_id));
        }
        CliError::Inbox(InboxError::Subscription(_) | InboxError::Transport(_)) => {
            return settings.map(|settings| {
                format!(
                    "check that the relay {} is reachable; set another with epicbox_relay in the \
                     config file or LEPIC_EPICBOX_RELAY",
                    settings.relay.url()
                )
            });
        }
        CliError::DataDirInUse => {
            return Some(
                "another lepic command, such as `lepic epicbox listen`, is using this wallet; \
                 stop it or wait for it to end. If it is `lepic serve`, run this command with \
                 --service; to take payments over HTTP next to it, start `lepic serve --http`"
                    .to_owned(),
            );
        }
        CliError::ServiceUnavailable { .. } => {
            return Some(
                "start `lepic serve` for this data directory, or give the socket it listens on \
                 as --service=SOCKET"
                    .to_owned(),
            );
        }
        CliError::SocketPathTooLong { .. } => {
            return Some(
                "give a shorter path: --socket for serve, --service=SOCKET for a client".to_owned(),
            );
        }
        CliError::SocketPathTaken { .. } => {
            return Some("remove the file or give another path with --socket".to_owned());
        }
        CliError::SharedDataDir => {
            return settings.map(|settings| {
                format!(
                    "make it private with `chmod 700 {}`",
                    settings.data_dir.display()
                )
            });
        }
        _ => {}
    }
    if error.kind() == ErrorKind::Node {
        return settings.map(|settings| node_hint(error, settings));
    }
    None
}

fn invoice_hint(error: &InvoiceError) -> Option<String> {
    match error {
        InvoiceError::Undelivered { tx_id, .. } => Some(format!(
            "the invoice is stored but the payer did not get it; withdraw it with `lepic tx \
             cancel {tx_id}` and issue it again"
        )),
        InvoiceError::PaymentUndelivered { tx_id, .. } => Some(format!(
            "the payment is stored and its inputs stay locked; deliver it again with `lepic tx \
             resend {tx_id} --to <ADDRESS>`, the invoice sender's address that `lepic tx show \
             {tx_id}` names, or give up with `lepic tx cancel {tx_id}`"
        )),
        InvoiceError::NotParked { .. } => Some(
            "`lepic invoice list` shows the invoices waiting to be paid; a request from a paired \
             contact is in `lepic contact invoices`, paid with `lepic contact pay-invoice` or \
             declined with `lepic contact decline`"
                .to_owned(),
        ),
        InvoiceError::NotPosted { tx_id, .. } => Some(not_posted_hint(*tx_id)),
        InvoiceError::InputsSpentElsewhere { tx_id, .. } => Some(spent_elsewhere_hint(*tx_id)),
        InvoiceError::InputsSpentByOwnTransaction { tx_id, by, .. } => {
            Some(spent_by_own_hint(*tx_id, *by))
        }
        InvoiceError::PeerInputsSpent { tx_id, .. } => Some(peer_inputs_spent_hint(*tx_id)),
        InvoiceError::AmountMismatch { invoiced, approved } => Some(format!(
            "the invoice asks for {} EPIC and {} EPIC was approved; nothing was paid",
            format_amount(*invoiced),
            format_amount(*approved)
        )),
        _ => None,
    }
}

fn not_posted_hint(tx_id: TxId) -> String {
    format!(
        "the transaction is stored, and the node neither took it nor holds its kernel; `lepic \
         tx post {tx_id}` sends it again"
    )
}

fn spent_elsewhere_hint(tx_id: TxId) -> String {
    format!(
        "another wallet on the same recovery phrase spent the coins of transaction {tx_id}, so \
         it was cancelled; `lepic tx list` shows that wallet's spend"
    )
}

fn spent_by_own_hint(tx_id: TxId, by: TxId) -> String {
    format!(
        "transaction {by} of this wallet spent the same coins first, so transaction {tx_id} was \
         cancelled; `lepic tx show {by}` shows the one that went through"
    )
}

fn peer_inputs_spent_hint(tx_id: TxId) -> String {
    format!(
        "the other party spent the coins of this payment elsewhere, so it can never be mined; \
         transaction {tx_id} was cancelled, and a refresh still confirms it if it is mined"
    )
}

fn undelivered_send_hint(
    tx_id: TxId,
    source: &TransportError,
    settings: Option<&Settings>,
) -> String {
    let mut text = format!(
        "the inputs stay locked; deliver it again with `lepic tx resend {tx_id} --to <ADDRESS>` \
         or `--to-file <FILE>`, or give up with `lepic tx cancel {tx_id}`"
    );
    if let Some(settings) = settings
        && !matches!(source, TransportError::File(_))
        && !matches!(
            source,
            TransportError::Backend { transport, .. }
                if *transport == lepic_foreign::TRANSPORT_ID
                    || *transport == lepic_tor::TRANSPORT_ID
        )
        && settings.relay.port() != DEFAULT_PORT
    {
        text.push_str(&format!(
            ". Addresses on {} must name its port, as in <key>@{}:{}",
            settings.relay.url(),
            settings.relay.domain(),
            settings.relay.port()
        ));
    }
    text
}

fn wallet_hint(error: &WalletError, settings: Option<&Settings>) -> Option<String> {
    let settings = settings?;
    let dir = settings.data_dir.display();
    let network = settings.network;
    match error {
        WalletError::NoWallet => Some(format!(
            "no {network} wallet in {dir}. Create one with `lepic wallet init` or `lepic wallet \
             restore`, or point --data-dir and --network at an existing one"
        )),
        WalletError::WalletExists => Some(format!(
            "{dir} already holds a wallet; give --data-dir to create another"
        )),
        WalletError::NetworkMismatch { stored, .. } => Some(format!(
            "{dir} holds a {stored} wallet; run with --network {stored}, or give --data-dir for \
             a {network} wallet"
        )),
        WalletError::Node(_) | WalletError::Implausible(_) => Some(node_hint_text(settings)),
        WalletError::RestoreScanRequired => Some(
            "the wallet was restored, or its database rebuilt, without a scan of the chain, so \
             the keys already in use are not known; `lepic wallet scan` scans it from where the \
             restore started"
                .to_owned(),
        ),
        WalletError::NotReleasable {
            reason: ReleaseRefusal::TooEarly { from },
            ..
        } => Some(format!(
            "a send is releasable once a refresh at height {from} or above still misses its \
             kernel; `lepic wallet info` refreshes, and `lepic tx show` tells when it is"
        )),
        WalletError::InPool(_) => Some(
            "the node may still mine the transaction; refresh with `lepic wallet info` later"
                .to_owned(),
        ),
        _ => None,
    }
}

fn node_hint(error: &CliError, settings: &Settings) -> String {
    let unauthorized = matches!(
        error,
        CliError::Node(NodeError::Unauthorized)
            | CliError::Refresh(RefreshError::Node(NodeError::Unauthorized))
            | CliError::Scan(ScanError::Node(NodeError::Unauthorized))
    );
    if unauthorized {
        return format!(
            "the node at {} refused the api secret; point node_api_secret_file or \
             LEPIC_NODE_API_SECRET_FILE at its .foreign_api_secret",
            settings.node.as_str()
        );
    }
    node_hint_text(settings)
}

fn node_hint_text(settings: &Settings) -> String {
    format!(
        "check that the {} node at {} is running and synced; set another with node_url in the \
         config file or LEPIC_NODE_URL",
        settings.network,
        settings.node.as_str()
    )
}

/// The wallet error under any of the engine errors that wrap one.
fn wallet_error(error: &CliError) -> Option<&WalletError> {
    match error {
        CliError::Wallet(error)
        | CliError::Send(SendError::Wallet(error))
        | CliError::Receive(ReceiveError::Wallet(error))
        | CliError::Finalize(FinalizeError::Wallet(error))
        | CliError::Invoice(InvoiceError::Wallet(error))
        | CliError::Inbox(InboxError::Wallet(error))
        | CliError::Refresh(RefreshError::Wallet(error))
        | CliError::Scan(ScanError::Wallet(error)) => Some(error),
        _ => None,
    }
}

fn selection_error(error: &CliError) -> Option<&SelectionError> {
    match error {
        CliError::Send(SendError::Selection(error))
        | CliError::Invoice(InvoiceError::Selection(error)) => Some(error),
        _ => None,
    }
}

fn tor_hint(kind: lepic_tor::FailureKind) -> Option<&'static str> {
    use lepic_tor::FailureKind as K;
    match kind {
        K::Missing => Some("no tor binary at the --tor-binary path"),
        K::Network => Some(
            "tor could not connect to the Tor network; check the internet connection, or whether \
             this network blocks Tor",
        ),
        K::Clock => Some("tor reports the computer's clock as wrong; correct it and try again"),
        K::Start => Some(
            "tor did not start; check that --tor-binary is a tor binary for this computer and \
             --lib-dir holds its libraries",
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use lepic_primitives::amount::Amount;

    use super::*;
    use crate::cli::GlobalArgs;
    use crate::settings::Env;

    fn settings(relay: &str) -> Settings {
        let env = Env::new([
            ("HOME".to_owned(), "/home/u".to_owned()),
            ("LEPIC_NETWORK".to_owned(), "floonet".to_owned()),
            ("LEPIC_DATA_DIR".to_owned(), "/w".to_owned()),
            ("LEPIC_EPICBOX_RELAY".to_owned(), relay.to_owned()),
        ]);
        Settings::resolve(&GlobalArgs::default(), &env).unwrap()
    }

    fn hint_for(error: &CliError) -> String {
        hint(error, Some(&settings("ws://localhost:3423"))).unwrap()
    }

    #[test]
    fn a_missing_wallet_names_the_directory_and_the_commands_that_create_one() {
        for error in [
            CliError::Wallet(WalletError::NoWallet),
            CliError::Send(SendError::Wallet(WalletError::NoWallet)),
        ] {
            let text = hint_for(&error);
            let wallet_dir = std::path::absolute("/w").unwrap();
            let named = format!("no floonet wallet in {}", wallet_dir.display());
            assert!(text.contains(&named), "{text}");
            assert!(text.contains("lepic wallet init"), "{text}");
        }
    }

    #[test]
    fn a_wallet_of_another_network_names_the_flag_that_opens_it() {
        let text = hint_for(&CliError::Wallet(WalletError::NetworkMismatch {
            stored: "mainnet".to_owned(),
            configured: lepic_primitives::params::Network::Floonet,
        }));
        assert!(text.contains("--network mainnet"), "{text}");
    }

    #[test]
    fn missing_funds_show_what_is_spendable_and_what_is_needed() {
        let text = hint_for(&CliError::Send(SendError::Selection(
            SelectionError::NotEnoughFunds {
                available: Amount::new(150_000_000),
                needed: Amount::new(200_800_000),
            },
        )));
        assert!(
            text.starts_with("1.50000000 EPIC is spendable and 2.00800000 EPIC"),
            "{text}"
        );
    }

    #[test]
    fn a_post_whose_coins_were_spent_says_who_spent_them() {
        let own = hint_for(&CliError::Finalize(
            FinalizeError::InputsSpentByOwnTransaction {
                tx_id: TxId(7),
                by: TxId(5),
                source: NodeError::Timeout,
            },
        ));
        assert!(own.contains("lepic tx show 5"), "{own}");
        let peer = hint_for(&CliError::Invoice(InvoiceError::PeerInputsSpent {
            tx_id: TxId(7),
            source: NodeError::Timeout,
        }));
        assert!(peer.contains("other party"), "{peer}");
    }

    #[test]
    fn a_finalized_transaction_the_node_refused_names_tx_post() {
        let text = hint_for(&CliError::Finalize(FinalizeError::NotPosted {
            tx_id: TxId(7),
            source: NodeError::Timeout,
        }));
        assert!(text.contains("lepic tx post 7"), "{text}");
        assert!(text.contains("nor holds its kernel"), "{text}");
    }

    fn undelivered() -> TransportError {
        TransportError::UnknownDestination {
            transport: lepic_epicbox::TRANSPORT_ID,
        }
    }

    #[test]
    fn an_undelivered_invoice_names_tx_cancel_not_tx_resend() {
        let text = hint_for(&CliError::Invoice(InvoiceError::Undelivered {
            tx_id: TxId(5),
            slate_id: lepic_wallet::event::SlateId::from_bytes([2; 16]),
            source: undelivered(),
        }));
        assert!(text.contains("`lepic tx cancel 5`"), "{text}");
        assert!(!text.contains("resend"), "{text}");
    }

    #[test]
    fn an_undelivered_invoice_payment_names_tx_resend_and_the_allowlist() {
        let text = hint_for(&CliError::Invoice(InvoiceError::PaymentUndelivered {
            tx_id: TxId(6),
            slate_id: lepic_wallet::event::SlateId::from_bytes([3; 16]),
            source: undelivered(),
        }));
        assert!(
            text.contains("`lepic tx resend 6 --to <ADDRESS>`"),
            "{text}"
        );
        assert!(text.contains("`lepic tx show 6`"), "{text}");
    }

    #[test]
    fn node_failures_name_the_node_and_the_setting() {
        let text = hint_for(&CliError::Node(NodeError::Timeout));
        assert!(text.contains("http://127.0.0.1:13413"), "{text}");
        assert!(text.contains("LEPIC_NODE_URL"), "{text}");
        let refused = hint_for(&CliError::Node(NodeError::Unauthorized));
        assert!(refused.contains("node_api_secret_file"), "{refused}");
    }

    #[test]
    fn a_pending_restore_scan_names_wallet_scan() {
        for error in [
            CliError::Wallet(WalletError::RestoreScanRequired),
            CliError::Receive(ReceiveError::Wallet(WalletError::RestoreScanRequired)),
            CliError::Send(SendError::Wallet(WalletError::RestoreScanRequired)),
        ] {
            let text = hint_for(&error);
            assert!(text.contains("`lepic wallet scan`"), "{text}");
        }
    }

    #[test]
    fn errors_that_say_everything_get_no_hint() {
        assert_eq!(
            hint(
                &CliError::Interrupted,
                Some(&settings("ws://localhost:3423"))
            ),
            None
        );
        assert_eq!(hint(&CliError::Wallet(WalletError::NoWallet), None), None);
    }
}
