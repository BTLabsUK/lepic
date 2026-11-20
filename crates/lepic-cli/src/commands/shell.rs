// SPDX-License-Identifier: Apache-2.0
//! The wallet the interactive shell holds open between its commands, and the calls the shell
//! makes on it outside a command: unlock and lock, the balance its status line shows, the review
//! before a send, and `serve start`.

use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use lepic_epicbox::TRANSPORT_ID as EPICBOX;
use lepic_methods::http::TRANSPORT_ID as HTTP;
use lepic_methods::tor::TRANSPORT_ID as TOR;
use lepic_primitives::amount::{Amount, Height};
use lepic_transport::file::FILE;
use lepic_wallet::event::Balance;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::{DEFAULT_ACCOUNT_LABEL, Event, WalletError, WordCount};
use lepic_wallet_contacts::WalletContacts as _;
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

use super::contact::relays_in_mode;
use super::{
    Opened, Payee, Reviewed, Run, Spend, abort_on, password_from, send_amount,
    start_from_confirmed_tip,
};
use crate::Console;
use crate::amount::parse_amount;
use crate::cli::{Command, Epic1PayArgs, SendArgs};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::Report;
use crate::secret::SecretInput;
use crate::settings::{Env, Settings};
use crate::shell::review::Review;
use crate::vault::VAULT_FILE;

/// A console whose output goes nowhere and which has no secrets to read: for the calls the shell
/// makes outside a command, and for commands that print through their report only.
pub(crate) fn quiet_console(env: Env) -> Console {
    Console {
        env,
        secrets: SecretInput::new(
            Box::new(BufReader::new(std::io::empty())),
            false,
            Box::new(std::io::sink()),
        ),
        stdout: Box::new(std::io::sink()),
        stderr: Box::new(std::io::sink()),
        ansi: false,
        stdout_terminal: false,
    }
}

/// The shell's wallet: one handle on the data directory, held with its lock for the whole
/// session, unlocked and locked in place.
pub(crate) struct Held<H: Host> {
    opened: Arc<Opened<HostNode<H>>>,
}

impl<H: Host> Held<H> {
    /// A locked handle on the wallet in `settings.data_dir`, which takes the data directory's
    /// lock until it is dropped. A directory without a wallet is reported here.
    pub(crate) async fn prepare(host: &H, settings: &Settings, env: Env) -> Result<Self, CliError> {
        if !Self::wallet_exists(settings) {
            return Err(WalletError::NoWallet.into());
        }
        Ok(Self {
            opened: Arc::new(Self::locked(host, settings, env, false).await?),
        })
    }

    /// Whether the data directory holds a wallet.
    pub(crate) fn wallet_exists(settings: &Settings) -> bool {
        settings.data_dir.join(VAULT_FILE).exists()
    }

    /// Creates the wallet of the data directory from new entropy, under `password`, and holds
    /// it unlocked. Returns the recovery phrase with it, which is shown once.
    pub(crate) async fn create(
        host: &H,
        settings: &Settings,
        env: Env,
        password: Zeroizing<String>,
    ) -> Result<(Self, Zeroizing<String>), CliError> {
        let opened = Self::locked(host, settings, env, true).await?;
        let phrase = opened
            .wallet
            .create(password_from(password), WordCount::default())
            .await?;
        let phrase = Zeroizing::new(phrase.expose().to_owned());
        Ok((
            Self {
                opened: Arc::new(opened),
            },
            phrase,
        ))
    }

    /// Recreates the wallet of the data directory from `phrase`, under `password`, and holds it
    /// unlocked. Its outputs are found by the scan that follows, from genesis.
    pub(crate) async fn restore(
        host: &H,
        settings: &Settings,
        env: Env,
        password: Zeroizing<String>,
        phrase: Zeroizing<String>,
    ) -> Result<Self, CliError> {
        let opened = Self::locked(host, settings, env, true).await?;
        opened
            .wallet
            .restore_from_height(password_from(password), phrase.trim(), Height::new(0))
            .await?;
        Ok(Self {
            opened: Arc::new(opened),
        })
    }

    /// A locked handle on the data directory, which a new wallet creates.
    async fn locked(
        host: &H,
        settings: &Settings,
        env: Env,
        create_dir: bool,
    ) -> Result<Opened<HostNode<H>>, CliError> {
        let mut console = quiet_console(env);
        let (_signal, interrupt) = watch::channel(false);
        let run = Run {
            host,
            settings,
            console: &mut console,
            interrupt,
            graceful: Arc::new(AtomicBool::new(false)),
            held: None,
            reviewed: None,
        };
        run.prepare(create_dir).await
    }

    /// Unlocks the wallet with `password`, which is dropped, and wiped, here.
    pub(crate) async fn unlock(&self, password: Zeroizing<String>) -> Result<(), CliError> {
        self.opened.wallet.open(password_from(password)).await?;
        start_from_confirmed_tip(&self.opened.wallet)
    }

    pub(crate) fn lock(&self) {
        self.opened.wallet.lock();
    }

    pub(crate) fn is_unlocked(&self) -> bool {
        self.opened.wallet.is_unlocked()
    }

    /// The wallet's events, for the status line.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.opened.wallet.subscribe()
    }

    /// The balance of the default account, as last refreshed; `None` when locked.
    pub(crate) fn balance(&self) -> Option<Balance> {
        let account = self.opened.wallet.account(DEFAULT_ACCOUNT_LABEL).ok()?;
        self.opened.wallet.balance(account.index).ok()
    }

    /// The height of the highest tip the wallet confirmed; `None` when locked or before the
    /// first one.
    pub(crate) fn tip_height(&self) -> Option<u64> {
        let tip = self.opened.wallet.confirmed_tip().ok()??;
        Some(tip.height.value())
    }

    /// Brings the outputs up to the node's tip, for the status line, and returns the height of
    /// that tip; `None` when the node did not answer, which leaves the status as it was.
    pub(crate) async fn refresh(&self) -> Option<u64> {
        match self.opened.wallet.refresh().await.ok()? {
            RefreshOutcome::Refreshed(summary) => Some(summary.height.value()),
            RefreshOutcome::NodeBehind { tip, .. } => Some(tip.value()),
        }
    }

    /// Runs `command` on the held wallet with `settings`, until it ends or `interrupt` turns
    /// true, as [`super::execute`] runs one. A send that was `reviewed` takes no more than the
    /// review showed.
    pub(crate) async fn run(
        &self,
        host: &H,
        settings: &Settings,
        command: Command,
        console: &mut Console,
        interrupt: watch::Receiver<bool>,
        reviewed: Option<Reviewed>,
    ) -> Result<Report, CliError> {
        let graceful = Arc::new(AtomicBool::new(false));
        let mut run = Run {
            host,
            settings,
            console,
            interrupt: interrupt.clone(),
            graceful: Arc::clone(&graceful),
            held: Some(Arc::clone(&self.opened)),
            reviewed,
        };
        tokio::select! {
            result = run.dispatch(command) => result,
            () = abort_on(interrupt, &graceful) => Err(CliError::Interrupted),
        }
    }

    /// What `tx send` with `args` would do: its fee estimate on the held wallet, checked as the
    /// send checks it before it stores anything.
    pub(crate) async fn review(
        &self,
        host: &H,
        settings: &Settings,
        env: Env,
        args: &SendArgs,
    ) -> Result<Review, CliError> {
        let amount = parse_amount(send_amount(args)?)?;
        let spend = Spend::from_args(&args.spend)?;
        let mut console = quiet_console(env);
        let (_signal, interrupt) = watch::channel(false);
        let run = Run {
            host,
            settings,
            console: &mut console,
            interrupt,
            graceful: Arc::new(AtomicBool::new(false)),
            held: None,
            reviewed: None,
        };
        let (payee, _) = run.payee(args.destination.clone(), args.plain_http.allow_plain_http)?;
        let destination = &args.destination;
        let to = destination
            .to
            .clone()
            .or_else(|| {
                destination
                    .to_file
                    .as_ref()
                    .map(|path| path.display().to_string())
            })
            .or_else(|| destination.to_contact.clone())
            .unwrap_or_default();
        self.priced(
            settings,
            &args.account.account,
            spend,
            amount,
            to,
            delivery_name(&payee),
        )
        .await
    }

    /// What a `tx send` to `to`, an epic1 address or link, would do as the payment `args`
    /// describes: the amount given, else the one the link asks, with its fee estimate on the
    /// held wallet. `None` when there is neither amount, which the payment itself refuses.
    pub(crate) async fn review_epic1(
        &self,
        settings: &Settings,
        args: &Epic1PayArgs,
        to: String,
    ) -> Result<Option<Review>, CliError> {
        let amount = match &args.amount {
            Some(amount) => parse_amount(amount)?,
            None => {
                let relays =
                    relays_in_mode(&self.opened, false, &settings.servers.mailboxes.current());
                let read = self
                    .opened
                    .wallet
                    .contact_book()
                    .epic1_read(&relays, &args.link.link)?;
                let Some(amount) = read.amount else {
                    return Ok(None);
                };
                amount
            }
        };
        let spend = Spend::from_args(&args.spend)?;
        self.priced(settings, &args.account.account, spend, amount, to, "epic1")
            .await
            .map(Some)
    }

    /// The review of sending `amount` from `account` to `to` by `delivery`: the fee the held
    /// wallet estimates with `spend`, and the spendable balance before the send.
    async fn priced(
        &self,
        settings: &Settings,
        account: &str,
        spend: Spend,
        amount: Amount,
        to: String,
        delivery: &'static str,
    ) -> Result<Review, CliError> {
        let wallet = &self.opened.wallet;
        let account = wallet.account(account)?;
        let request = spend.send_request(account.index, amount, None);
        let selection = wallet
            .estimate_fee(request.amount, request.selection_options())
            .await?;
        let spendable = wallet.balance(account.index)?.spendable.value();
        Ok(Review {
            to,
            amount: selection.amount.value(),
            fee: selection.fee.value(),
            spendable,
            delivery,
            network: settings.network.to_string(),
        })
    }

    /// Checks `args` and returns the socket path and the future that serves the API on the held
    /// wallet until `stop` completes, then drains it and returns the report. Output goes to
    /// `console`. The future is not `Send`: the shell polls it on its own thread beside its
    /// commands. It never locks the wallet.
    #[cfg(unix)]
    pub(crate) fn serve<'a>(
        &self,
        host: &'a H,
        settings: &'a Settings,
        args: crate::cli::ServeArgs,
        mut console: Console,
        stop: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<
        (
            std::path::PathBuf,
            futures_util::future::LocalBoxFuture<'a, Result<Report, CliError>>,
        ),
        CliError,
    > {
        use futures_util::FutureExt as _;

        let path = args
            .socket
            .clone()
            .unwrap_or_else(|| crate::service::default_socket(&settings.data_dir));
        crate::service::check_socket_path(&path)?;
        let owner_tls = args
            .owner_tls
            .then(|| {
                settings
                    .servers
                    .owner_tls
                    .ok_or(CliError::OwnerTlsNotConfigured)
            })
            .transpose()?;
        let opened = Arc::clone(&self.opened);
        let socket = path.clone();
        let serving = async move {
            // Serve stops on `stop` only: the sender lives as long as the future, so the run's
            // interrupt never fires.
            let (_signal, interrupt) = watch::channel(false);
            let mut run = Run {
                host,
                settings,
                console: &mut console,
                interrupt,
                graceful: Arc::new(AtomicBool::new(false)),
                held: Some(Arc::clone(&opened)),
                reviewed: None,
            };
            let stopped = async {
                let _ = stop.await;
            };
            run.serve_opened(&opened, &path, owner_tls, &args, stopped)
                .await
        };
        Ok((socket, serving.boxed_local()))
    }
}

/// How a send to `payee` travels, as the review names it.
fn delivery_name(payee: &Payee) -> &'static str {
    match payee {
        Payee::Contact(_) => "contact",
        Payee::Delivery(transport, _) => {
            if *transport == EPICBOX {
                "epicbox"
            } else if *transport == TOR {
                "tor"
            } else if *transport == HTTP {
                "http"
            } else if *transport == FILE {
                "file"
            } else {
                "other"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Epic1Command};
    use crate::commands::serve::support;

    /// The `epic1 pay` arguments `tx send` to `to` with `amount` resolves to.
    fn pay_args(to: &str, amount: Option<&str>) -> Epic1PayArgs {
        let mut line = vec!["lepic", "tx", "send"];
        line.extend(amount);
        line.extend(["--to", to]);
        match crate::recipient::resolve(Cli::try_parse_from(line).unwrap().command).unwrap() {
            Command::Epic1(crate::cli::Epic1Args {
                command: Epic1Command::Pay(pay),
                ..
            }) => pay,
            other => panic!("not an epic1 payment: {other:?}"),
        }
    }

    #[test]
    fn an_epic1_send_is_reviewed_at_its_amount_and_estimated_fee() {
        let (host, wallet) = support::funded();
        let payee = support::new_wallet(&host, "payee password");
        let address = payee.run(&host, &["epic1", "address"]).ok().json()["address"]
            .as_str()
            .unwrap()
            .to_owned();
        let link = payee.run(&host, &["epic1", "link", "2"]).ok().json()["link"]
            .as_str()
            .unwrap()
            .to_owned();
        let cli = Cli::try_parse_from(["lepic", "wallet", "info"]).unwrap();
        let env = Env::new(wallet.env());
        let settings = Settings::resolve(&cli.global, &env)
            .unwrap()
            .on_host_network(host.network());
        std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let mut console = quiet_console(env);
                    let (_keep, interrupt) = watch::channel(false);
                    let mut run = Run {
                        host: &host,
                        settings: &settings,
                        console: &mut console,
                        interrupt,
                        graceful: Arc::new(AtomicBool::new(false)),
                        held: None,
                        reviewed: None,
                    };
                    let held: Held<support::TestHost> = Held {
                        opened: run.open().await.unwrap(),
                    };
                    let estimated = |base: u64| {
                        let wallet = &held.opened.wallet;
                        async move {
                            let spend = Spend::from_args(&pay_args("epic1qq", Some("1")).spend);
                            let account = wallet.account(DEFAULT_ACCOUNT_LABEL).unwrap().index;
                            let request =
                                spend
                                    .unwrap()
                                    .send_request(account, Amount::new(base), None);
                            let selection = wallet
                                .estimate_fee(request.amount, request.selection_options())
                                .await
                                .unwrap();
                            selection.fee.value()
                        }
                    };

                    let given = held
                        .review_epic1(&settings, &pay_args(&address, Some("1.5")), address.clone())
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(given.delivery, "epic1");
                    assert_eq!(given.to, address);
                    assert_eq!(given.amount, 150_000_000);
                    assert_eq!(given.fee, estimated(150_000_000).await);

                    let asked = held
                        .review_epic1(&settings, &pay_args(&link, None), link.clone())
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(asked.delivery, "epic1");
                    assert_eq!(asked.amount, 200_000_000);
                    assert_eq!(asked.fee, estimated(200_000_000).await);

                    let neither = held
                        .review_epic1(&settings, &pay_args(&address, None), address.clone())
                        .await
                        .unwrap();
                    assert_eq!(neither, None);
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
