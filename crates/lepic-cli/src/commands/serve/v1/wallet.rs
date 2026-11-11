// SPDX-License-Identifier: Apache-2.0
//! The wallet, its accounts and the node: `/wallet`, `/wallet/password`, `/wallet/scan`, `/sync`, `/accounts`, `/node`.

use std::cell::RefCell;
use std::convert::Infallible;

use hyper::StatusCode;
use lepic_node::NodeApi as _;
use lepic_store::AccountIndex;
use lepic_wallet::event::Event;
use lepic_wallet_contacts::{CollectTrigger, WalletContacts as _};
use serde::Deserialize;
use tokio::sync::{Notify, broadcast};
use zeroize::Zeroizing;

use super::super::Service;
use super::Reply;
use crate::api::list::{ListQuery, Order, Page, number_key};
use crate::api::model::{Account, Balance, Node, Wallet};
use crate::api::{Category, Context, Problem, Request, accepted, no_content, ok};
use crate::cli::{Command, WalletCommand, WalletScanArgs};
use crate::commands::{contact, rekey};
use crate::exit::CliError;
use crate::host::Host;

/// The phase of the latest scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Phase {
    #[default]
    Idle,
    Running,
    Done,
    Failed,
}

/// A scan asked for and not yet started.
#[derive(Debug)]
struct Job {
    args: WalletScanArgs,
    links: bool,
}

#[derive(Debug, Default)]
struct Slot {
    phase: Phase,
    /// The phase before `claim`, until the job is queued.
    claimed: Option<Phase>,
    pending: Option<Job>,
    height: u64,
    target: u64,
}

/// The scan of the wallet: what `POST /wallet/scan` asked for, and how far it has come. One
/// scan runs at a time; [`drive`] runs it beside the other tasks of serve.
#[derive(Debug, Default)]
pub(in crate::commands::serve) struct Scans {
    slot: RefCell<Slot>,
    wake: Notify,
}

impl Scans {
    fn running(&self) -> bool {
        self.slot.borrow().phase == Phase::Running
    }

    /// Takes the running phase when no scan has it; false when one does. The caller gives it back
    /// with [`Scans::release`] if it then fails before it queues the job.
    fn claim(&self) -> bool {
        let mut slot = self.slot.borrow_mut();
        if slot.phase == Phase::Running {
            return false;
        }
        slot.claimed = Some(slot.phase);
        slot.phase = Phase::Running;
        true
    }

    fn release(&self) {
        let mut slot = self.slot.borrow_mut();
        if let Some(phase) = slot.claimed.take() {
            slot.phase = phase;
        }
    }

    fn state(&self) -> Option<(&'static str, u64, u64)> {
        let slot = self.slot.borrow();
        let name = match slot.phase {
            Phase::Idle => return None,
            Phase::Running => "running",
            Phase::Done => "done",
            Phase::Failed => "failed",
        };
        Some((name, slot.height, slot.target))
    }
}

/// Runs the scans `POST /wallet/scan` asks for, one after the other, until serve stops.
pub(in crate::commands::serve) async fn drive<H: Host>(service: &Service<'_, H>) -> Infallible {
    loop {
        service.scans.wake.notified().await;
        let Some(job) = service.scans.slot.borrow_mut().pending.take() else {
            continue;
        };
        let result = run(service, job).await;
        let mut slot = service.scans.slot.borrow_mut();
        match result {
            Ok(()) => {
                slot.phase = Phase::Done;
                slot.height = slot.target;
            }
            Err(error) => {
                slot.phase = Phase::Failed;
                tracing::warn!(
                    error = %lepic_telemetry::ErrorChain(&error),
                    "wallet scan failed"
                );
            }
        }
    }
}

async fn run<H: Host>(service: &Service<'_, H>, job: Job) -> Result<(), CliError> {
    let Job { args, links } = job;
    let mut events = Some(service.held.wallet.subscribe());
    {
        // Boxed and erased: `command` runs the dispatcher, which runs serve, which runs this.
        let mut command: std::pin::Pin<Box<dyn std::future::Future<Output = _> + '_>> =
            Box::pin(service.command(Command::Wallet(WalletCommand::Scan(args))));
        loop {
            tokio::select! {
                result = command.as_mut() => {
                    result?;
                    break;
                }
                event = recv(events.as_mut()), if events.is_some() => match event {
                    Ok(Event::Sync(progress)) => {
                        let mut slot = service.scans.slot.borrow_mut();
                        slot.height = progress.height.value();
                        slot.target = progress.target.value();
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => events = None,
                },
            }
        }
    }
    if links {
        let relays = contact::relays_in_mode(
            &service.held,
            false,
            false,
            &service.settings.servers.meeting_relays,
        );
        service
            .held
            .wallet
            .contact_book()
            .epic1_restore(&relays)
            .await?;
    }
    Ok(())
}

async fn recv(
    events: Option<&mut broadcast::Receiver<Event>>,
) -> Result<Event, broadcast::error::RecvError> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

/// A scan is running: calls that need the wallet scanned wait for it.
pub(super) fn scanning<H: Host>(service: &Service<'_, H>) -> bool {
    service.scans.running()
}

fn scan_running() -> Problem {
    Problem::new(
        StatusCode::SERVICE_UNAVAILABLE,
        Category::WalletState,
        "scan_running",
        "a scan is running; try again when it ends",
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchBody {
    issues_addresses: bool,
}

pub(super) async fn get_wallet<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    ok(&current(service).await?)
}

/// The wallet with `node_behind` read from the node; a node that does not answer leaves it false.
async fn current<H: Host>(service: &Service<'_, H>) -> Result<Wallet, Problem> {
    let mut wallet = wallet_object(service).await?;
    if let Ok(tip) = tip(service).await {
        wallet.node_behind = tip < wallet.height;
    }
    Ok(wallet)
}

pub(super) async fn update_wallet<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: PatchBody = request.json()?;
    if !body.issues_addresses {
        return Err(Problem::invalid(
            "/issues_addresses",
            "only true is accepted: an install that issues addresses cannot stop",
        ));
    }
    service
        .held
        .wallet
        .contact_book()
        .epic1_issue_here()
        .await
        .map_err(CliError::from)?;
    ok(&wallet_object(service).await?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    #[serde(deserialize_with = "secret")]
    current: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    new: Zeroizing<String>,
}

fn secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub(super) async fn change_password<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: PasswordBody = request.json()?;
    if body.new.is_empty() {
        return Err(Problem::invalid(
            "/new",
            "a new wallet password cannot be empty",
        ));
    }
    let kdf = service.host.vault_kdf();
    let data_dir = service.settings.data_dir.clone();
    let PasswordBody { current, new } = body;
    tokio::task::spawn_blocking(move || rekey(kdf, &data_dir, current, new))
        .await
        .map_err(|error| CliError::Io {
            what: "change the password",
            source: std::io::Error::other(error),
        })??;
    no_content()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanBody {
    #[serde(default)]
    from_height: Option<u64>,
    #[serde(default)]
    delete_unconfirmed: bool,
    #[serde(default)]
    reset_chain: bool,
    #[serde(default)]
    links: bool,
}

pub(super) async fn scan<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: ScanBody = request.json()?;
    if body.from_height.is_some() && body.reset_chain {
        return Err(Problem::invalid(
            "/reset_chain",
            "reset_chain scans from genesis and excludes from_height",
        ));
    }
    if !service.scans.claim() {
        return Err(Problem::conflict(
            "scan_running",
            "a scan is already running",
        ));
    }
    if let Some(start) = body.from_height {
        let checked = match tip(service).await {
            Ok(tip) if start > tip => Err(Problem::invalid(
                "/from_height",
                CliError::StartAboveTip { start, tip }.to_string(),
            )),
            Ok(_) => Ok(()),
            Err(error) => Err(Problem::new(
                StatusCode::SERVICE_UNAVAILABLE,
                Category::Node,
                "node_unreachable",
                error.chain().join(": "),
            )),
        };
        if let Err(problem) = checked {
            service.scans.release();
            return Err(problem);
        }
    }
    let target = {
        let mut slot = service.scans.slot.borrow_mut();
        slot.phase = Phase::Running;
        slot.claimed = None;
        slot.height = body.from_height.unwrap_or(0);
        slot.target = slot.height;
        slot.pending = Some(Job {
            args: WalletScanArgs {
                start_height: body.from_height,
                delete_unconfirmed: body.delete_unconfirmed,
                reset_chain: body.reset_chain,
            },
            links: body.links,
        });
        slot.height
    };
    service.scans.wake.notify_one();
    let wallet = wallet_object(service).await?;
    accepted(&wallet.with_scan("running", target, target))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncBody {
    #[serde(default = "yes")]
    node: bool,
    #[serde(default = "yes")]
    relays: bool,
}

const fn yes() -> bool {
    true
}

pub(super) async fn sync<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: SyncBody = request.json()?;
    if scanning(service) {
        return Err(scan_running());
    }
    let opened = &*service.held;
    if body.node {
        opened.wallet.refresh().await.map_err(CliError::from)?;
    }
    if body.relays {
        contact::collect_online(
            opened,
            &service.settings.servers.meeting_relays,
            CollectTrigger::Foreground,
        )
        .await?;
    }
    ok(&current(service).await?)
}

pub(super) async fn list_accounts<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let list = ListQuery::parse(request.query())?;
    let mut accounts = Vec::new();
    for account in service.held.wallet.accounts().map_err(CliError::from)? {
        accounts.push(account_of(service, account)?);
    }
    ok(&Page::of(accounts, &list, Order::Ascending, |account| {
        number_key(u64::from(account.index))
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccountBody {
    label: String,
}

pub(super) async fn create_account<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: CreateAccountBody = request.json()?;
    let wallet = &service.held.wallet;
    if wallet
        .accounts()
        .map_err(CliError::from)?
        .iter()
        .any(|account| account.label == body.label)
    {
        return Err(
            Problem::conflict("account_exists", "an account has this label").with_param("/label"),
        );
    }
    let account = wallet.create_account(&body.label).map_err(|error| {
        // A bad label is the caller's: the wallet names it.
        Problem::invalid("/label", error.to_string())
    })?;
    crate::api::created(&account_of(service, account)?)
}

pub(super) async fn get_node<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    let node = service.host.node(service.settings)?;
    let version = node.get_version().await.map_err(CliError::from)?;
    let tip = node.get_tip().await.map_err(CliError::from)?.height.value();
    let height = wallet_object(service).await?.height;
    ok(&Node {
        version: version.node_version,
        tip_height: tip,
        syncing: tip > height,
    })
}

async fn tip<H: Host>(service: &Service<'_, H>) -> Result<u64, CliError> {
    let node = service.host.node(service.settings)?;
    Ok(node.get_tip().await?.height.value())
}

/// The wallet, for `GET /wallet` and the `wallet.progress` event. It reads what is stored and
/// the latest scan, and asks nobody; `node_behind` needs the node, so `GET /wallet` sets it.
pub(super) async fn wallet_object<H: Host>(service: &Service<'_, H>) -> Result<Wallet, Problem> {
    let wallet = &service.held.wallet;
    let mut height: Option<u64> = None;
    for account in wallet.accounts().map_err(CliError::from)? {
        let at = wallet
            .balance(account.index)
            .map_err(CliError::from)?
            .height
            .value();
        height = Some(height.map_or(at, |lowest| lowest.min(at)));
    }
    let issues_addresses = wallet
        .contact_book()
        .epic1_issuing()
        .await
        .map_err(CliError::from)?;
    let object = Wallet {
        network: wallet.config().network.to_string(),
        height: height.unwrap_or(0),
        node_behind: false,
        issues_addresses,
        scan: None,
    };
    Ok(match service.scans.state() {
        Some((state, at, target)) => object.with_scan(state, at, target),
        None => object,
    })
}

/// The account `index`, for `GET /accounts` and the `account.balance_changed` event; `None`
/// when there is none.
pub(super) async fn account_object<H: Host>(
    service: &Service<'_, H>,
    index: AccountIndex,
) -> Result<Option<Account>, Problem> {
    let found = service
        .held
        .wallet
        .accounts()
        .map_err(CliError::from)?
        .into_iter()
        .find(|account| account.index == index);
    found
        .map(|account| account_of(service, account))
        .transpose()
}

fn account_of<H: Host>(
    service: &Service<'_, H>,
    account: lepic_wallet::Account,
) -> Result<Account, Problem> {
    let balance = service
        .held
        .wallet
        .balance(account.index)
        .map_err(CliError::from)?;
    let text = |amount: lepic_primitives::amount::Amount| crate::amount::format_amount(amount);
    Ok(Account {
        label: account.label,
        index: account.index.0,
        balance: Balance {
            spendable: text(balance.spendable),
            confirming: text(balance.awaiting_confirmation),
            pending: text(balance.awaiting_finalization),
            maturing: text(balance.immature),
            locked: text(balance.locked),
            total: text(balance.total),
        },
    })
}

/// The account a body or query names by label, the default one when it names none.
pub(super) fn resolve<H: Host>(
    service: &Service<'_, H>,
    label: Option<&str>,
    param: &str,
) -> Result<lepic_wallet::Account, Problem> {
    let accounts = service.held.wallet.accounts().map_err(CliError::from)?;
    match label {
        Some(label) => accounts
            .into_iter()
            .find(|account| account.label == label)
            .ok_or_else(|| Problem::invalid(param, "no account has this label")),
        None => accounts
            .into_iter()
            .find(|account| account.index.0 == 0)
            .ok_or_else(|| Problem::invalid(param, "the wallet has no default account")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_call_takes_the_scan_and_a_failed_one_gives_it_back() {
        let scans = Scans::default();
        assert!(scans.claim());
        assert!(scans.running());
        // A second call, also one that would still await the node tip, is refused.
        assert!(!scans.claim());
        scans.release();
        assert!(!scans.running());
        assert!(scans.claim());
        // The job is queued: the phase stays and a release changes nothing.
        scans.slot.borrow_mut().claimed = None;
        scans.release();
        assert!(scans.running());
    }

    #[test]
    fn a_released_claim_restores_the_phase_of_the_scan_before() {
        let scans = Scans::default();
        scans.slot.borrow_mut().phase = Phase::Done;
        assert!(scans.claim());
        scans.release();
        assert_eq!(scans.slot.borrow().phase, Phase::Done);
    }
}
