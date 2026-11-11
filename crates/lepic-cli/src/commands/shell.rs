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
use lepic_transport::file::FILE;
use lepic_wallet::event::Balance;
use lepic_wallet::{DEFAULT_ACCOUNT_LABEL, Event, WalletError};
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

use super::{Opened, Payee, Run, Spend, abort_on, password_from, start_from_confirmed_tip};
use crate::Console;
use crate::amount::parse_amount;
use crate::cli::{Command, SendArgs};
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
        if !settings.data_dir.join(VAULT_FILE).exists() {
            return Err(WalletError::NoWallet.into());
        }
        let mut console = quiet_console(env);
        let (_signal, interrupt) = watch::channel(false);
        let run = Run {
            host,
            settings,
            console: &mut console,
            interrupt,
            graceful: Arc::new(AtomicBool::new(false)),
            held: None,
        };
        let opened = run.prepare(false).await?;
        Ok(Self {
            opened: Arc::new(opened),
        })
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

    /// Brings the outputs up to the node's tip, for the status line; false when that failed,
    /// which only leaves the status as it was.
    pub(crate) async fn refresh(&self) -> bool {
        self.opened.wallet.refresh().await.is_ok()
    }

    /// Runs `command` on the held wallet with `settings`, until it ends or `interrupt` turns
    /// true, as [`super::execute`] runs one.
    pub(crate) async fn run(
        &self,
        host: &H,
        settings: &Settings,
        command: Command,
        console: &mut Console,
        interrupt: watch::Receiver<bool>,
    ) -> Result<Report, CliError> {
        let graceful = Arc::new(AtomicBool::new(false));
        let mut run = Run {
            host,
            settings,
            console,
            interrupt: interrupt.clone(),
            graceful: Arc::clone(&graceful),
            held: Some(Arc::clone(&self.opened)),
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
        let amount = parse_amount(&args.amount)?;
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
        };
        let (payee, _) = run.payee(args.destination.clone(), args.plain_http.allow_plain_http)?;
        let wallet = &self.opened.wallet;
        let account = wallet.account(&args.account.account)?;
        let request = spend.send_request(account.index, amount, None);
        let selection = wallet
            .estimate_fee(request.amount, request.selection_options())
            .await?;
        let spendable = wallet.balance(account.index)?.spendable.value();
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
        Ok(Review {
            to,
            amount: selection.amount.value(),
            fee: selection.fee.value(),
            spendable,
            delivery: delivery_name(&payee),
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
