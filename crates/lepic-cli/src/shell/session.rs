// SPDX-License-Identifier: Apache-2.0
//! The interactive shell's session: it opens the wallet once, reads lines on the reader thread,
//! runs each as a `lepic` command on the held wallet with its output above the live area, and
//! locks the wallet when it ends or sits idle.

use std::future::Future;
use std::io::{self, BufReader};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::error::ErrorKind as ClapErrorKind;
use clap::{CommandFactory as _, Parser as _};
use futures_util::FutureExt as _;
use futures_util::future::LocalBoxFuture;
use lepic_telemetry::{LogFilter, host_dispatch};
use lepic_wallet::Event;
use lepic_wallet::event::SessionState;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::amount::format_units;
use crate::cli::{Cli, Command, Epic1Args, Epic1Command, GlobalArgs, TxCommand};
use crate::commands::Reviewed;
use crate::commands::shell::Held;
use crate::exit::{CliError, ErrorKind};
use crate::host::{Host, Interrupt};
use crate::output::{Report, render, render_error};
use crate::recipient;
use crate::secret::{PASSWORD_ENV, SecretError, SecretInput, Shown};
use crate::settings::{Env, OutputFormat, RelayTor, Settings};
use crate::shell::ask;
use crate::shell::card::{CardInfo, sweep, welcome};
use crate::shell::editor::{LivePrompt, Shared, columns, line_editor};
use crate::shell::history::FilteredHistory;
use crate::shell::live::{
    Look, NodeMark, Status, SyncMark, ansi_works, footer, grouped, printable, progress_spans,
    short_amount,
};
use crate::shell::node::{self, Nodes, Switch};
use crate::shell::paint::{self, Tone};
use crate::shell::reader::{Ask, Read, Reader, Reply};
use crate::shell::screen::{Queue, Screen, ScreenWriter, ShellLog};
use crate::shell::seal::{self, Seal};
use crate::shell::setup::{FirstRun, first_run};
use crate::shell::words::{self, Line, SHELL_WORDS};
use crate::{Console, hint};

/// The wallet the shell names; a data directory holds one.
const WALLET: &str = "default";
/// How often the editor looks for queued lines and the footer redraws.
const TICK: Duration = Duration::from_millis(100);
/// How long a frame of the welcome card's sweep stays.
const SWEEP_FRAME: Duration = Duration::from_millis(90);
/// A command that ends sooner shows no footer.
const FOOTER_AFTER: Duration = Duration::from_millis(200);
/// How often an unlocked wallet is brought up to the node's tip for the status line.
const REFRESH_EVERY: Duration = Duration::from_secs(60);

/// Runs the shell until the user leaves it; the exit code is 0 unless it could not start.
pub(crate) fn run<H: Host>(
    host: &H,
    global: &GlobalArgs,
    settings: &Settings,
    console: &mut Console,
) -> u8 {
    let screen = Screen::new(Box::new(io::stdout()));
    let _echo = QuietControlKeys::start();
    match start(host, global, settings, console, &screen) {
        Ok(()) => 0,
        Err(error) => {
            screen.direct();
            crate::report_error(console, settings.output, &error, Some(settings))
        }
    }
}

fn start<H: Host>(
    host: &H,
    global: &GlobalArgs,
    settings: &Settings,
    console: &mut Console,
    screen: &Screen,
) -> Result<(), CliError> {
    let filter = LogFilter::parse(&settings.log_filter)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::io("start the async runtime"))?;
    let look = Look::of(&console.env, ansi_works());
    let log = ShellLog::new(screen.clone(), look);
    let dispatch = host_dispatch(Arc::new(log), filter);
    tracing::dispatcher::with_default(&dispatch, || {
        runtime.block_on(session(host, global, settings, console, screen, look))
    })
}

/// How the session came by its wallet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Start {
    /// The wallet was there, locked.
    Found,
    /// The first run created it; it is unlocked.
    Created,
    /// The first run restored it; it is unlocked and its outputs are not scanned for yet.
    Restored,
}

async fn session<H: Host>(
    host: &H,
    global: &GlobalArgs,
    settings: &Settings,
    console: &mut Console,
    screen: &Screen,
    look: Look,
) -> Result<(), CliError> {
    let network = settings.network.to_string();
    let info = CardInfo {
        version: env!("CARGO_PKG_VERSION"),
        wallet: WALLET,
        network: &network,
    };
    show_card(screen, &info, look).await;
    // A password given ahead is read first, and taken out of the environment the wallet and
    // the commands see.
    let mut given = if settings.password_file.is_some() || console.env.get(PASSWORD_ENV).is_some() {
        Some(
            console
                .secrets
                .wallet_password(&mut console.env, settings.password_file.as_deref(), false)
                .await,
        )
    } else {
        None
    };
    let mut env = console.env.clone();
    let mut settings = settings.clone();
    let nodes = Nodes {
        host,
        global,
        settings: &settings,
        env: &env,
        screen,
        look,
        at_start: true,
    };
    if let Some(switch) = nodes.at_start().await {
        settings = switch.settings;
        env = switch.env;
    }
    let Some((mut held, mut start)) = wallet_at_start(host, &settings, &env, screen, look).await?
    else {
        return Ok(());
    };
    if start != Start::Found {
        given = None;
    }
    // One sitting per node: a switch locks the wallet and opens it again on the new node.
    loop {
        let switch = {
            let shell = Shell {
                host,
                global,
                settings: &settings,
                env: env.clone(),
                held,
                screen: screen.clone(),
                status: Shared::new(Status {
                    wallet: WALLET.to_owned(),
                    network: network.clone(),
                    locked: true,
                    tor: !matches!(settings.relay_tor, RelayTor::Off),
                    ..Status::default()
                }),
                look,
            };
            shell.sit(start, given.take()).await?
        };
        let Some(switch) = switch else {
            return Ok(());
        };
        settings = switch.settings;
        env = switch.env;
        held = Held::prepare(host, &settings, env.clone()).await?;
        start = Start::Found;
    }
}

/// The wallet of the data directory, locked, or the one the first run makes there. `None` when
/// the first run was left with no wallet made.
async fn wallet_at_start<H: Host>(
    host: &H,
    settings: &Settings,
    env: &Env,
    screen: &Screen,
    look: Look,
) -> Result<Option<(Held<H>, Start)>, CliError> {
    if Held::<H>::wallet_exists(settings) {
        let held = Held::prepare(host, settings, env.clone()).await?;
        return Ok(Some((held, Start::Found)));
    }
    Ok(match first_run(host, settings, env, screen, look).await? {
        FirstRun::Created(held) => Some((held, Start::Created)),
        FirstRun::Restored(held) => Some((held, Start::Restored)),
        FirstRun::Left => {
            screen.print(&look.tint(
                "No wallet was made. Starting lepic again offers the choice again.",
                Tone::Dim,
            ));
            None
        }
    })
}

/// Prints the welcome card, drawn in by the sweep where the shell animates and the card has
/// room above the cursor.
async fn show_card(screen: &Screen, info: &CardInfo<'_>, look: Look) {
    let (columns, rows) = crossterm::terminal::size().unwrap_or((80, 0));
    let card = welcome(info, columns, look.marks.glyphs, look.paint);
    if !look.motion || usize::from(rows) <= card.len().saturating_add(1) {
        screen.print(&card.join("\n"));
        return;
    }
    let mut over = 0;
    for frame in sweep(info, columns, look.marks.glyphs, look.paint) {
        screen.redraw(&frame, over);
        over = frame.len();
        tokio::time::sleep(SWEEP_FRAME).await;
    }
}

/// What the session holds for its whole length.
struct Shell<'a, H: Host> {
    host: &'a H,
    /// The global flags the shell started with; a line's own flags go on top.
    global: &'a GlobalArgs,
    settings: &'a Settings,
    /// The environment without the wallet password.
    env: Env,
    held: Held<H>,
    screen: Screen,
    status: Shared,
    /// How the shell draws at this terminal.
    look: Look,
}

/// `serve start` running beside the commands.
struct Serving<'a> {
    stop: tokio::sync::oneshot::Sender<()>,
    future: LocalBoxFuture<'a, Result<Report, CliError>>,
    socket: String,
}

/// What runs in the background of the session, polled at the prompt and beside a command.
struct Live<'a> {
    events: broadcast::Receiver<Event>,
    events_open: bool,
    serving: Option<Serving<'a>>,
    refreshing: Option<LocalBoxFuture<'a, Option<u64>>>,
    next_refresh: Instant,
    /// Ctrl+C as a signal, which comes while no raw-mode read holds the terminal: it cancels
    /// the step or command that runs.
    ctrl_c: CtrlC,
    /// The process told to end; once it fired the session ends.
    terminate: Interrupt,
    leaving: bool,
    /// When the last command was entered, for the idle lock.
    last_command: Instant,
}

/// What happened in the background.
// A served report is moved once per command; boxing it buys nothing.
#[allow(clippy::large_enum_variant)]
enum Background {
    Event(Result<Event, RecvError>),
    Served(Result<Report, CliError>),
    /// A refresh ended: the height of the node's tip, or `None` when the node did not answer.
    Refreshed(Option<u64>),
    RefreshDue,
    IdleLock,
    /// Ctrl+C as a signal.
    Interrupt,
    /// The process told to end.
    Terminate,
}

/// The process's Ctrl+C, listened for afresh: one that came before [`CtrlC::clear`] is not seen.
struct CtrlC(LocalBoxFuture<'static, ()>);

impl CtrlC {
    fn new() -> Self {
        let mut listener = async {
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
        .boxed_local();
        // The first poll installs the listener, so a Ctrl+C from here on is kept for `next`.
        if listener.as_mut().now_or_never().is_some() {
            return Self::new();
        }
        Self(listener)
    }

    /// Forgets a Ctrl+C that came before now.
    fn clear(&mut self) {
        *self = Self::new();
    }

    /// The next Ctrl+C; the listener is renewed before this returns.
    async fn next(&mut self) {
        (&mut self.0).await;
        self.clear();
    }
}

/// While the shell runs, the terminal does not echo control keys such as `^C`: Ctrl+C during a
/// step would otherwise leave `^C` in the middle of the output. The setting comes back on drop.
struct QuietControlKeys {
    #[cfg(unix)]
    before: Option<rustix::termios::Termios>,
}

impl QuietControlKeys {
    fn start() -> Self {
        #[cfg(unix)]
        {
            use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
            let stdin = io::stdin();
            let before = tcgetattr(&stdin).ok().filter(|termios| {
                termios.local_modes.contains(LocalModes::ECHOCTL) && {
                    let mut quiet = termios.clone();
                    quiet.local_modes.remove(LocalModes::ECHOCTL);
                    tcsetattr(&stdin, OptionalActions::Now, &quiet).is_ok()
                }
            });
            Self { before }
        }
        #[cfg(not(unix))]
        {
            // The Windows console does not echo Ctrl+C.
            Self {}
        }
    }
}

impl Drop for QuietControlKeys {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(before) = &self.before {
            use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
            let stdin = io::stdin();
            // Only the one flag goes back; anything else changed since stays as it is.
            if let Ok(mut now) = tcgetattr(&stdin) {
                now.local_modes.set(
                    LocalModes::ECHOCTL,
                    before.local_modes.contains(LocalModes::ECHOCTL),
                );
                let _ = tcsetattr(&stdin, OptionalActions::Now, &now);
            }
        }
    }
}

/// What follows a line.
enum Flow {
    Next,
    Exit,
    /// The sitting ends and the next one runs on another node.
    Switch(Box<Switch>),
}

impl<'a, H: Host> Shell<'a, H> {
    /// One sitting: the wallet opens as `start` says, lines are read until the user leaves or
    /// switches the node, and the wallet locks. `Some` when the next sitting runs on another
    /// node.
    async fn sit(
        &self,
        start: Start,
        given: Option<Result<Zeroizing<String>, SecretError>>,
    ) -> Result<Option<Switch>, CliError> {
        let mut live = Live {
            events: self.held.subscribe(),
            events_open: true,
            serving: None,
            refreshing: None,
            next_refresh: Instant::now(),
            ctrl_c: CtrlC::new(),
            terminate: self.host.terminated(),
            leaving: false,
            last_command: Instant::now(),
        };
        match start {
            Start::Found => {
                self.unlock(given, &mut live).await;
            }
            Start::Created => {
                self.opened(&mut live);
                self.screen.print(&self.first_steps());
            }
            Start::Restored => self.opened(&mut live),
        }
        let mut reader = self.reader()?;
        if start == Start::Restored {
            let scan = vec!["wallet".to_owned(), "scan".to_owned()];
            self.command(scan, false, &mut reader, &mut live).await;
        }
        let result = self.read_loop(&mut reader, &mut live).await;
        self.leave(&mut live, matches!(result, Ok(Some(_)))).await;
        drop(reader);
        result.map(|switch| switch.map(|switch| *switch))
    }

    /// Starts the line editor on its thread, with the history of the data directory.
    fn reader(&self) -> Result<Reader, CliError> {
        let history: Box<dyn reedline::History> =
            match FilteredHistory::open(&self.settings.data_dir) {
                Ok(history) => Box::new(history),
                Err(error) => {
                    self.say(
                        &format!("The history is kept in memory only: {error}"),
                        Tone::Yellow,
                    );
                    Box::new(FilteredHistory::in_memory())
                }
            };
        let stop_read = Arc::new(AtomicBool::new(false));
        let mut editor = line_editor(&self.status, self.look, history)
            .with_external_printer(Queue(self.screen.clone()))
            .with_poll_interval(TICK)
            .with_break_signal(Arc::clone(&stop_read));
        self.screen.set_repaint(editor.repaint_signal());
        let prompt = LivePrompt {
            status: self.status.clone(),
            look: self.look,
        };
        Reader::start(editor, prompt, stop_read).map_err(CliError::io("start the line editor"))
    }

    /// The seal for `command`, when it sends a sealed payment.
    fn seal(&self, command: &Command, settings: &Settings) -> Option<Seal> {
        Seal::of(
            command,
            settings.output,
            self.look.paint,
            self.look.motion,
            self.look.marks.glyphs,
        )
    }

    /// Reads lines until the user leaves, `None`, or switches the node.
    async fn read_loop<'s>(
        &'s self,
        reader: &mut Reader,
        live: &mut Live<'s>,
    ) -> Result<Option<Box<Switch>>, CliError> {
        loop {
            if live.leaving {
                return Ok(None);
            }
            self.screen.editing();
            reader.ask(Ask::ReadLine);
            let read = loop {
                tokio::select! {
                    reply = reader.replies.recv() => match reply {
                        Some(Reply::Line(read)) => break read,
                        Some(_) => {}
                        None => break Read::Failed("the line editor stopped".to_owned()),
                    },
                    background = self.next_background(live, true) => {
                        self.on_background(live, background);
                        if live.leaving {
                            reader.break_read();
                        }
                        self.screen.repaint();
                    }
                }
            };
            self.screen.direct();
            match read {
                Read::Line(line) => {
                    let flow = self.line(&line, reader, live).await;
                    // Idle counts from the end of the last command.
                    live.last_command = Instant::now();
                    match flow {
                        Flow::Next => {}
                        Flow::Exit => return Ok(None),
                        Flow::Switch(switch) => return Ok(Some(switch)),
                    }
                }
                Read::CtrlC | Read::Break => {}
                Read::CtrlD => return Ok(None),
                Read::Failed(message) => {
                    return Err(CliError::Io {
                        what: "read a line",
                        source: io::Error::other(message),
                    });
                }
            }
        }
    }

    /// Waits for the next thing that happens in the background. The idle lock counts only at
    /// the prompt.
    async fn next_background(&self, live: &mut Live<'_>, at_prompt: bool) -> Background {
        let idle_at = if at_prompt {
            idle_lock_at(
                self.settings.shell_idle_lock_minutes,
                live.serving.is_some(),
                self.held.is_unlocked(),
                live.last_command,
            )
        } else {
            None
        };
        let unlocked = self.held.is_unlocked();
        let Live {
            events,
            events_open,
            serving,
            refreshing,
            next_refresh,
            ctrl_c,
            terminate,
            leaving,
            ..
        } = live;
        // A refresh starts only at the prompt; one already running may finish beside a command.
        let refresh_due = at_prompt && refreshing.is_none() && unlocked;
        let served = async {
            match serving {
                Some(serving) => (&mut serving.future).await,
                None => std::future::pending().await,
            }
        };
        let refreshed = async {
            match refreshing {
                Some(refreshing) => refreshing.await,
                None => std::future::pending().await,
            }
        };
        let far = Instant::now()
            .checked_add(Duration::from_secs(86_400))
            .unwrap_or_else(Instant::now);
        tokio::select! {
            event = events.recv(), if *events_open => Background::Event(event),
            report = served => Background::Served(report),
            tip = refreshed => Background::Refreshed(tip),
            () = tokio::time::sleep_until(*next_refresh), if refresh_due => Background::RefreshDue,
            () = tokio::time::sleep_until(idle_at.unwrap_or(far)), if idle_at.is_some() => {
                Background::IdleLock
            }
            () = ctrl_c.next() => Background::Interrupt,
            () = terminate, if !*leaving => Background::Terminate,
        }
    }

    fn on_background<'s>(&'s self, live: &mut Live<'s>, background: Background) {
        match background {
            Background::Event(Ok(event)) => self.on_event(&event),
            Background::Event(Err(RecvError::Lagged(_))) => self.read_balance(),
            Background::Event(Err(RecvError::Closed)) => live.events_open = false,
            Background::Served(result) => {
                live.serving = None;
                self.status.update(|status| status.api = false);
                self.screen.print("Serve stopped.");
                self.print_result(result, self.settings);
            }
            Background::Refreshed(tip) => {
                live.refreshing = None;
                live.next_refresh = Instant::now()
                    .checked_add(REFRESH_EVERY)
                    .unwrap_or_else(Instant::now);
                let before = self.status.get().node;
                if let Some(tip) = tip {
                    self.read_balance();
                    self.status.update(|status| {
                        status.sync = SyncMark::Synced;
                        status.node = NodeMark::Reached;
                        status.height = Some(tip);
                    });
                    if before == NodeMark::Unreached {
                        self.say("The node answers again.", Tone::Green);
                    }
                } else {
                    self.status
                        .update(|status| status.node = NodeMark::Unreached);
                    if before != NodeMark::Unreached {
                        self.say(
                            &format!(
                                "The node {} does not answer. Balance and height are as last seen.",
                                printable(self.settings.node.host())
                            ),
                            Tone::Yellow,
                        );
                        self.say(
                            "It is asked again every minute. node use switches to another node.",
                            Tone::Dim,
                        );
                    }
                }
            }
            Background::RefreshDue => {
                live.refreshing = Some(self.held.refresh().boxed_local());
            }
            Background::IdleLock => {
                self.held.lock();
                self.status.update(|status| status.locked = true);
                self.screen.print(&format!(
                    "Wallet {WALLET} locked after {} idle.",
                    minutes(self.settings.shell_idle_lock_minutes)
                ));
            }
            // At the prompt the editor reads Ctrl+C as a key; a signal there ends nothing.
            Background::Interrupt => {}
            Background::Terminate => live.leaving = true,
        }
    }

    /// Runs one step of a line, a prompt or the wallet's work, with the background going on
    /// beside it. Ctrl+C as a signal, or the session ending, drops the step: `None`, and a
    /// note of what was cancelled unless the session ends.
    async fn step<'s, T>(
        &'s self,
        live: &mut Live<'s>,
        cancelled: &str,
        work: impl Future<Output = T>,
    ) -> Option<T> {
        live.ctrl_c.clear();
        // The work is dropped at the end of this block, which stops its prompt thread, before
        // the wait for that thread below.
        let done = {
            let mut work = std::pin::pin!(work);
            loop {
                tokio::select! {
                    done = &mut work => break Some(done),
                    background = self.next_background(live, false) => {
                        if matches!(background, Background::Interrupt) {
                            break None;
                        }
                        self.on_background(live, background);
                        if live.leaving {
                            break None;
                        }
                    }
                }
            }
        };
        if done.is_none() {
            ask::prompts_ended().await;
            self.screen.direct();
            if !live.leaving {
                self.say(cancelled, Tone::Yellow);
            }
        }
        done
    }

    fn on_event(&self, event: &Event) {
        match event {
            Event::Balance(_) => self.read_balance(),
            Event::Sync(progress) => {
                let (height, target) = (progress.height.value(), progress.target.value());
                self.status.update(|status| {
                    status.height = Some(height);
                    status.node = NodeMark::Reached;
                    status.sync = if height >= target {
                        SyncMark::Synced
                    } else {
                        SyncMark::Syncing
                    };
                });
            }
            Event::Session(SessionState::Unlocked) => {
                self.status.update(|status| status.locked = false);
            }
            Event::Session(SessionState::Locked | SessionState::Closed) => {
                self.status.update(|status| status.locked = true);
            }
            _ => {}
        }
    }

    /// The balance of the default account into the status line.
    fn read_balance(&self) {
        if let Some(balance) = self.held.balance() {
            self.status.update(|status| {
                status.balance = Some(short_amount(&format_units(balance.total.value())));
                status.spendable = Some(short_amount(&format_units(balance.spendable.value())));
                // A wallet that has not heard from a node yet has no height to show.
                status.height = self
                    .held
                    .tip_height()
                    .max(Some(balance.height.value()))
                    .filter(|height| *height > 0);
            });
        }
    }

    /// Unlocks the wallet with the password `given`, or asks for it until one opens the wallet.
    /// An empty or a wrong password typed at the prompt is asked for again; Esc or Ctrl+C at
    /// the prompt, or Ctrl+C while the unlock runs, leaves the wallet locked.
    async fn unlock<'s>(
        &'s self,
        given: Option<Result<Zeroizing<String>, SecretError>>,
        live: &mut Live<'s>,
    ) -> bool {
        const CANCELLED: &str = "The wallet stays locked; unlock opens it.";
        let typed = given.is_none();
        let mut given = given;
        loop {
            let password = match given.take() {
                Some(password) => password,
                None => {
                    let prompt = format!("Password for wallet {WALLET}: ");
                    let shown = Shown::Marks(self.look.marks.mask);
                    let asking = ask::secret("wallet password", prompt, shown);
                    match self.step(live, CANCELLED, asking).await {
                        Some(password) => password,
                        None => return false,
                    }
                }
            };
            let password = match password {
                Ok(password) if typed && password.is_empty() => {
                    self.say(
                        "A password is needed. Type it, or press Esc to leave the wallet locked.",
                        Tone::Yellow,
                    );
                    continue;
                }
                Ok(password) => password,
                Err(SecretError::Cancelled { .. } | SecretError::Missing { .. }) => {
                    self.say(CANCELLED, Tone::Yellow);
                    return false;
                }
                Err(error) => {
                    self.print_error(&error.into(), self.settings);
                    return false;
                }
            };
            let unlocking = self
                .screen
                .busy(self.look, "Unlocking", self.held.unlock(password));
            match self.step(live, CANCELLED, unlocking).await {
                None => return false,
                Some(Err(error)) if typed && error.kind() == ErrorKind::WrongPassword => {
                    self.say(
                        "That password does not open the wallet. Try again, or press Esc.",
                        Tone::Red,
                    );
                }
                Some(Err(error)) => {
                    self.print_error(&error, self.settings);
                    return false;
                }
                Some(Ok(())) => break,
            }
        }
        self.opened(live);
        let minutes_idle = self.settings.shell_idle_lock_minutes;
        let unlocked = if minutes_idle == 0 {
            format!("Wallet {WALLET} unlocked.")
        } else {
            format!(
                "Wallet {WALLET} unlocked. It locks after {} idle.",
                minutes(minutes_idle)
            )
        };
        self.say(
            &format!("{} {unlocked}", self.look.marks.synced),
            Tone::Green,
        );
        true
    }

    /// The wallet is open: the status shows it and its balance, and the idle clock starts now,
    /// not at the prompt before.
    fn opened(&self, live: &mut Live<'_>) {
        self.status.update(|status| status.locked = false);
        self.read_balance();
        live.last_command = Instant::now();
        live.next_refresh = Instant::now();
    }

    /// What a new wallet's holder most likely does first, as a short list of commands.
    fn first_steps(&self) -> String {
        let rows = [
            ("wallet address", "the address payments arrive at"),
            ("wallet info", "the balance"),
            ("tx send", "pay an address or a contact"),
            ("help", "every command"),
        ];
        let mut lines = vec![String::new()];
        for (index, (command, what)) in rows.iter().enumerate() {
            let lead = if index == 0 { "Try" } else { "   " };
            lines.push(format!(
                "  {}  {}  {}",
                self.look.tint(lead, Tone::Dim),
                self.look.tint(&format!("{command:<14}"), Tone::CyanBold),
                self.look.tint(what, Tone::Dim)
            ));
        }
        lines.join("\n")
    }

    /// Runs one line.
    async fn line<'s>(&'s self, text: &str, reader: &mut Reader, live: &mut Live<'s>) -> Flow {
        let line = match words::parse(text) {
            Ok(line) => line,
            Err(message) => {
                self.print_error(&CliError::Arguments(message), self.settings);
                return Flow::Next;
            }
        };
        match line {
            Line::Empty => {}
            Line::Help(words) => self.help(&words),
            Line::Lock => self.lock(live).await,
            Line::Unlock => {
                if self.held.is_unlocked() {
                    self.screen
                        .print(&format!("Wallet {WALLET} is unlocked already."));
                } else if self.unlock(None, live).await {
                    live.next_refresh = Instant::now();
                }
            }
            Line::Clear => reader.ask(Ask::Clear),
            Line::History => {
                reader.ask(Ask::History);
                let lines = loop {
                    match reader.replies.recv().await {
                        Some(Reply::History(lines)) => break lines,
                        Some(_) => {}
                        None => break Vec::new(),
                    }
                };
                let numbered: Vec<String> = lines
                    .iter()
                    .enumerate()
                    .map(|(i, line)| format!("{:>5}  {}", i.saturating_add(1), printable(line)))
                    .collect();
                self.screen.print(&numbered.join("\n"));
            }
            Line::Status => {
                let lines = paint::labels(&self.status_text(live), self.look.paint);
                self.screen.print(&lines.join("\n"));
            }
            Line::Exit => return Flow::Exit,
            Line::NodeUse(address) => {
                if let Some(switch) = self.node_use(address, live).await {
                    return Flow::Switch(Box::new(switch));
                }
            }
            Line::ServeStart(args) => self.serve_start(args, live),
            Line::ServeStop => {
                if live.serving.is_some() {
                    self.stop_serving(live).await;
                } else {
                    self.print_error(
                        &CliError::Arguments("serve does not run in this session".to_owned()),
                        self.settings,
                    );
                }
            }
            Line::Command { args, yes } => self.command(args, yes, reader, live).await,
        }
        Flow::Next
    }

    fn help(&self, words: &[String]) {
        if words.is_empty() {
            let lines = words::help_lines(&Cli::command());
            self.screen
                .print(&paint::help(&lines, self.look.paint).join("\n"));
            return;
        }
        let asked = words.join(" ");
        if let Some((word, about)) = SHELL_WORDS
            .iter()
            .find(|(word, _)| *word == asked || (*word == "exit" && asked == "quit"))
        {
            self.screen.print(&format!(
                "{}: {about}",
                self.look.tint(word, Tone::CyanBold)
            ));
            return;
        }
        let mut root = Cli::command();
        root.build();
        let mut command = &mut root;
        for word in words {
            match command.find_subcommand_mut(word) {
                Some(sub) => command = sub,
                None => {
                    self.unknown(words);
                    return;
                }
            }
        }
        self.screen.print(&self.styled(&command.render_long_help()));
    }

    /// Prints that `words` name no command, with the nearest one.
    fn unknown(&self, words: &[String]) {
        let (typed, nearest) = words::unknown_command(&Cli::command(), words)
            .unwrap_or_else(|| (words.join(" "), None));
        let nearest = words::meant(&typed).map(str::to_owned).or(nearest);
        let mut text = format!("error: unknown command: {}", printable(&typed));
        if let Some(nearest) = nearest {
            text.push_str(&format!("\nhint: did you mean {nearest}?"));
        }
        self.screen
            .print(&paint::output(&text, false, self.look.paint));
    }

    /// `node use`: switches to the node at `address`, or to one picked from the known nodes.
    /// `Some` once the new node answered; the sitting then ends and the next runs on it.
    async fn node_use<'s>(
        &'s self,
        address: Option<String>,
        live: &mut Live<'s>,
    ) -> Option<Switch> {
        if live.serving.is_some() {
            self.say(
                "Serve answers with the node in use: serve stop, then node use.",
                Tone::Yellow,
            );
            return None;
        }
        let target = match address {
            None => None,
            Some(text) => match node::parse(&text) {
                Some(target) => Some(target),
                None => {
                    self.say(
                        "That is not a node address. One looks like https://node.example.org.",
                        Tone::Red,
                    );
                    return None;
                }
            },
        };
        let nodes = Nodes {
            host: self.host,
            global: self.global,
            settings: self.settings,
            env: &self.env,
            screen: &self.screen,
            look: self.look,
            at_start: false,
        };
        self.step(live, "The node stays as it is.", nodes.switch(target))
            .await
            .flatten()
    }

    async fn lock<'s>(&'s self, live: &mut Live<'s>) {
        if live.serving.is_some() {
            self.say(
                "Serve stops first: it answers with the unlocked wallet.",
                Tone::Yellow,
            );
            self.stop_serving(live).await;
        }
        let was_unlocked = self.held.is_unlocked();
        self.held.lock();
        self.status.update(|status| status.locked = true);
        self.screen.print(&if was_unlocked {
            format!("Wallet {WALLET} locked.")
        } else {
            format!("Wallet {WALLET} is locked already.")
        });
    }

    fn status_text(&self, live: &Live<'_>) -> Vec<String> {
        let status = self.status.get();
        let on_off = |on: bool| if on { "on" } else { "off" };
        let mut lines = vec![
            format!(
                "Wallet     {WALLET}, {}",
                if status.locked { "locked" } else { "unlocked" }
            ),
            format!("Network    {}", status.network),
        ];
        if let (Some(balance), Some(spendable)) = (&status.balance, &status.spendable) {
            lines.push(format!("Balance    {balance}, {spendable} spendable"));
        }
        if let Some(height) = status.height {
            let state = match status.sync {
                SyncMark::Synced => ", synced",
                SyncMark::Syncing => ", syncing",
                SyncMark::Unknown => "",
            };
            lines.push(format!("Height     {}{state}", grouped(height)));
        }
        lines.push(format!(
            "Node       {}{}",
            printable(self.settings.node.host()),
            match status.node {
                NodeMark::Unknown => "",
                NodeMark::Reached => ", answers",
                NodeMark::Unreached => ", does not answer",
            }
        ));
        lines.push(format!("Tor        {}", on_off(status.tor)));
        lines.push(match &live.serving {
            Some(serving) => format!("API        serving on {}", serving.socket),
            None => "API        off".to_owned(),
        });
        let idle = self.settings.shell_idle_lock_minutes;
        lines.push(if idle == 0 {
            "Idle lock  off".to_owned()
        } else {
            format!("Idle lock  after {}", minutes(idle))
        });
        lines
    }

    #[cfg(unix)]
    fn serve_start<'s>(&'s self, args: Vec<String>, live: &mut Live<'s>) {
        if live.serving.is_some() {
            self.print_error(
                &CliError::Arguments("serve runs already; serve stop stops it".to_owned()),
                self.settings,
            );
            return;
        }
        if !self.held.is_unlocked() {
            self.print_error(
                &CliError::Arguments("the wallet is locked; unlock opens it".to_owned()),
                self.settings,
            );
            return;
        }
        let argv = ["lepic", "serve"]
            .into_iter()
            .map(str::to_owned)
            .chain(args)
            .collect::<Vec<_>>();
        let serve_args = match Cli::try_parse_from(&argv) {
            Ok(Cli {
                global,
                command: Command::Serve(serve_args),
            }) => {
                if let Some(flag) = given_flag(&global) {
                    self.print_error(
                        &CliError::Arguments(format!(
                            "{flag} does not apply to serve start: serve takes the session's settings"
                        )),
                        self.settings,
                    );
                    return;
                }
                serve_args
            }
            Ok(_) => return,
            Err(error) => {
                self.screen.print(&self.styled(&error.render()));
                return;
            }
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let console = self.console();
        match self
            .held
            .serve(self.host, self.settings, serve_args, console, stopped)
        {
            Ok((socket, future)) => {
                let socket = socket.display().to_string();
                self.say(
                    &format!("Serving the wallet API on {}", printable(&socket)),
                    Tone::Green,
                );
                self.status.update(|status| status.api = true);
                live.serving = Some(Serving {
                    stop,
                    future,
                    socket,
                });
            }
            Err(error) => self.print_error(&error, self.settings),
        }
    }

    #[cfg(not(unix))]
    fn serve_start(&self, _args: Vec<String>, _live: &mut Live<'_>) {
        self.print_error(
            &CliError::Arguments("serve is not available on Windows yet".to_owned()),
            self.settings,
        );
    }

    /// Stops serve and waits for it to drain.
    async fn stop_serving(&self, live: &mut Live<'_>) {
        if let Some(serving) = live.serving.take() {
            let _ = serving.stop.send(());
            let result = serving.future.await;
            self.status.update(|status| status.api = false);
            self.screen.print("Serve stopped.");
            self.print_result(result, self.settings);
        }
    }

    async fn command<'s>(
        &'s self,
        args: Vec<String>,
        yes: bool,
        reader: &mut Reader,
        live: &mut Live<'s>,
    ) {
        let argv = std::iter::once("lepic".to_owned())
            .chain(args.iter().cloned())
            .collect::<Vec<_>>();
        let mut cli = match Cli::try_parse_from(&argv) {
            Ok(cli) => cli,
            Err(error) => {
                let informational = matches!(
                    error.kind(),
                    ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
                );
                let no_command = matches!(
                    error.kind(),
                    ClapErrorKind::MissingSubcommand
                        | ClapErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                );
                if !informational && words::unknown_command(&Cli::command(), &args).is_some() {
                    self.unknown(&args);
                } else if no_command && let Some(lines) = words::group_lines(&Cli::command(), &args)
                {
                    self.screen
                        .print(&paint::help(&lines, self.look.paint).join("\n"));
                } else {
                    self.screen.print(&self.styled(&error.render()));
                }
                return;
            }
        };
        // A `tx send` to an epic1 recipient runs as `epic1 pay` and is reviewed as a send, and
        // so is `epic1 pay` itself.
        let reviewing = gets_review(&cli.command, yes);
        let sent_to = match &cli.command {
            Command::Tx(TxCommand::Send(send)) => send.destination.to.clone(),
            Command::Epic1(Epic1Args {
                command: Epic1Command::Pay(pay),
                ..
            }) => Some(pay.link.link.clone()),
            _ => None,
        };
        cli.command = match recipient::resolve(cli.command) {
            Ok(command) => command,
            Err(error) => return self.print_error(&error, self.settings),
        };
        if let Some(reason) = words::refusal(&cli.command, &args, live.serving.is_some()) {
            self.print_error(&CliError::Arguments(reason), self.settings);
            return;
        }
        let settings = match self.line_settings(&cli.global) {
            Ok(settings) => settings,
            Err(error) => {
                self.print_error(&error, self.settings);
                return;
            }
        };
        let mut reviewed = None;
        if reviewing {
            match self.review(live, &settings, &cli.command, sent_to).await {
                Some(held) => reviewed = held,
                None => return,
            }
        }
        let what = command_name(&args);
        let mut result = self
            .run_command(
                cli.command.clone(),
                &what,
                &settings,
                reviewed,
                reader,
                live,
            )
            .await;
        let locked_out = matches!(&result, Err(error) if error.kind() == ErrorKind::WalletState)
            && !self.held.is_unlocked();
        if locked_out && !live.leaving {
            if !self.unlock_for_command(live).await {
                return;
            }
            result = self
                .run_command(cli.command, &what, &settings, reviewed, reader, live)
                .await;
        }
        self.print_result(result, &settings);
    }

    /// Shows what a send on the line would do and asks before it runs: a `tx send`, also one to
    /// an epic1 recipient (`sent_to`) that runs as `epic1 pay`, and an `epic1 pay` to the link
    /// or address `sent_to`. `None` when the line stops here;
    /// otherwise the review a classic send is held to. A payment without an amount to show is
    /// not reviewed: it refuses itself.
    async fn review<'s>(
        &'s self,
        live: &mut Live<'s>,
        settings: &Settings,
        command: &Command,
        sent_to: Option<String>,
    ) -> Option<Option<Reviewed>> {
        const NOT_SENT: &str = "Not sent.";
        let reviewing = match (command, sent_to) {
            (Command::Tx(TxCommand::Send(send)), _) => self
                .held
                .review(self.host, settings, self.env.clone(), send)
                .map(|review| review.map(Some))
                .boxed_local(),
            (
                Command::Epic1(Epic1Args {
                    command: Epic1Command::Pay(pay),
                    ..
                }),
                Some(to),
            ) => self.held.review_epic1(settings, pay, to).boxed_local(),
            _ => return Some(None),
        };
        if !self.held.is_unlocked() && !self.unlock_for_command(live).await {
            return None;
        }
        let review = match self.step(live, NOT_SENT, reviewing).await {
            None => return None,
            Some(Ok(Some(review))) => review,
            Some(Ok(None)) => return Some(None),
            Some(Err(error)) => {
                self.print_error(&error, settings);
                return None;
            }
        };
        self.screen
            .print(&paint::review(&review.lines(), self.look.paint).join("\n"));
        let question = self.look.tint(&review.question(), Tone::Bold);
        match self.step(live, NOT_SENT, ask::yes(question)).await {
            None => None,
            Some(false) => {
                self.say(NOT_SENT, Tone::Yellow);
                None
            }
            Some(true) => {
                Some(matches!(command, Command::Tx(TxCommand::Send(_))).then(|| review.reviewed()))
            }
        }
    }

    async fn unlock_for_command<'s>(&'s self, live: &mut Live<'s>) -> bool {
        self.say(
            &format!("Wallet {WALLET} is locked; its password opens it."),
            Tone::Yellow,
        );
        self.unlock(None, live).await
    }

    /// The settings for one line: the session's, with the line's own global flags on top. Flags
    /// that pick another wallet are refused.
    fn line_settings(&self, line: &GlobalArgs) -> Result<Settings, CliError> {
        let fixed = [
            (line.data_dir.is_some(), "--data-dir"),
            (line.network.is_some(), "--network"),
            (line.config.is_some(), "--config"),
            (line.settings.is_some(), "--settings"),
        ];
        if let Some((_, flag)) = fixed.iter().find(|(given, _)| *given) {
            return Err(CliError::Arguments(format!(
                "{flag} holds for the whole session: exit, then start lepic with it"
            )));
        }
        let mut merged = self.global.clone();
        if line.log_level.is_some() {
            merged.log_level.clone_from(&line.log_level);
        }
        if line.log_format.is_some() {
            merged.log_format.clone_from(&line.log_format);
        }
        if line.output.is_some() {
            merged.output.clone_from(&line.output);
        }
        if line.profile.is_some() {
            merged.profile.clone_from(&line.profile);
        }
        if line.profile_bits.is_some() {
            merged.profile_bits.clone_from(&line.profile_bits);
        }
        if line.domain.is_some() {
            merged.domain.clone_from(&line.domain);
        }
        Ok(Settings::resolve(&merged, &self.env)?.on_host_network(self.host.network()))
    }

    /// Runs `command` with the footer under its output once it takes longer than a glance,
    /// until it ends or Ctrl+C cancels it. A send that was `reviewed` takes no more than that.
    async fn run_command<'s>(
        &'s self,
        command: Command,
        what: &str,
        settings: &Settings,
        reviewed: Option<Reviewed>,
        reader: &mut Reader,
        live: &mut Live<'s>,
    ) -> Result<Report, CliError> {
        // A Ctrl+C from before the command started does not cancel it.
        live.ctrl_c.clear();
        let mut seal = self.seal(&command, settings);
        let fake = seal::fake_send(&self.env, seal.as_ref());
        let mut frames = tokio::time::interval(seal::FRAME);
        let (cancel, interrupt) = watch::channel(false);
        let stop_watch = Arc::new(AtomicBool::new(false));
        reader.ask(Ask::Watch(Arc::clone(&stop_watch)));
        let mut console = self.console();
        let started = Instant::now();
        let mut ticker = tokio::time::interval(TICK);
        let mut tick = 0_usize;
        let mut doing = what.to_owned();
        let mut shown = false;
        let result = {
            // Boxed: the command's future is deep, and the session's would pass the compiler's
            // layout depth with it inline.
            let running = self
                .held
                .run(
                    self.host,
                    settings,
                    command,
                    &mut console,
                    interrupt,
                    reviewed,
                )
                .boxed_local();
            let mut running = fake.unwrap_or(running);
            loop {
                let mut redraw = false;
                tokio::select! {
                    result = &mut running => break result,
                    _ = ticker.tick() => {
                        tick = tick.wrapping_add(1);
                        redraw = true;
                    }
                    _ = frames.tick(), if seal.as_ref().is_some_and(Seal::moving) => {}
                    reply = reader.replies.recv() => match reply {
                        Some(Reply::Interrupt) => {
                            seal::skip(&mut seal);
                            cancel.send_replace(true);
                            doing = format!("{what}, cancelling");
                            redraw = true;
                        }
                        Some(Reply::Resize) => redraw = true,
                        Some(Reply::Key) => seal::skip(&mut seal),
                        _ => {}
                    },
                    background = self.next_background(live, false) => {
                        if let Background::Event(Ok(Event::Sync(progress))) = &background {
                            doing = format!(
                                "{what} {}/{}",
                                grouped(progress.height.value()),
                                grouped(progress.target.value())
                            );
                        }
                        let interrupted = matches!(background, Background::Interrupt);
                        self.on_background(live, background);
                        if interrupted || live.leaving {
                            cancel.send_replace(true);
                            doing = format!("{what}, cancelling");
                        }
                        redraw = true;
                    }
                }
                if let Some(seal) = &mut seal {
                    self.screen.art(seal.rows(columns()));
                }
                if redraw && started.elapsed() >= FOOTER_AFTER {
                    let rows = self.footer(tick, &doing, started.elapsed());
                    if shown {
                        self.screen.footer(rows);
                    } else {
                        self.screen.running(rows);
                        shown = true;
                    }
                }
            }
        };
        drop(console);
        if let Some(seal) = &mut seal
            && result.is_ok()
        {
            seal.finish(&self.screen, &mut reader.replies).await;
        }
        stop_watch.store(true, Ordering::SeqCst);
        loop {
            match reader.replies.recv().await {
                Some(Reply::Watched) | None => break,
                Some(_) => {}
            }
        }
        self.screen.direct();
        if let Some(line) = seal.and_then(|seal| seal.last_line(&result)) {
            self.screen.print(&line);
        }
        result
    }

    fn footer(&self, tick: usize, doing: &str, elapsed: Duration) -> [String; 4] {
        let columns = columns();
        let progress = progress_spans(tick, doing, elapsed.as_secs(), columns, &self.look.marks);
        footer(
            &self.status.get(),
            &progress,
            columns,
            &self.look.marks,
            self.look.paint,
        )
    }

    /// Clap's text, coloured as the shell draws it. Clap is built without its own colour, so
    /// the rest of the CLI prints as before.
    fn styled(&self, text: &clap::builder::StyledStr) -> String {
        paint::clap_text(&without_lepic(&text.to_string()), self.look.paint)
    }

    /// Prints `text` in `tone`.
    fn say(&self, text: &str, tone: Tone) {
        let room = usize::from(columns().saturating_sub(1));
        for line in paint::wrapped(text, room) {
            self.screen.print(&self.look.tint(&line, tone));
        }
    }

    /// A console whose output goes to the screen and which reads no secrets.
    fn console(&self) -> Console {
        Console {
            env: self.env.clone(),
            secrets: SecretInput::new(
                Box::new(BufReader::new(io::empty())),
                false,
                Box::new(io::sink()),
            ),
            stdout: Box::new(ScreenWriter::new(self.screen.clone())),
            stderr: Box::new(ScreenWriter::new(self.screen.clone())),
            ansi: self.look.paint.on(),
            stdout_terminal: false,
        }
    }

    fn print_result(&self, result: Result<Report, CliError>, settings: &Settings) {
        match result {
            Ok(report) => {
                let text = render(&report, settings.output);
                if text.is_empty() {
                    return;
                }
                if settings.output == OutputFormat::Human {
                    let done = did_something(&report);
                    self.screen
                        .print(&paint::output(&text, done, self.look.paint));
                    let columns = super::editor::columns();
                    let glyphs = self.look.marks.glyphs;
                    if let Some(qr) = crate::qr::for_shell(
                        &report,
                        settings.output,
                        columns,
                        glyphs,
                        self.look.paint,
                    ) {
                        self.screen.print(&qr);
                    }
                } else {
                    self.screen.print(&text);
                }
            }
            Err(error) => self.print_error(&error, settings),
        }
    }

    fn print_error(&self, error: &CliError, settings: &Settings) {
        let hint = match settings.output {
            OutputFormat::Human => hint::hint(error, Some(settings)),
            OutputFormat::Json => None,
        };
        let text = Zeroizing::new(render_error(error, settings.output, hint.as_deref()));
        if settings.output == OutputFormat::Human {
            self.screen.print(&Zeroizing::new(paint::output(
                &text,
                false,
                self.look.paint,
            )));
        } else {
            self.screen.print(&text);
        }
    }

    /// Ends the sitting: serve stops, the wallet locks. `switching` when the next sitting
    /// follows on another node, which opens the wallet again.
    async fn leave<'s>(&'s self, live: &mut Live<'s>, switching: bool) {
        self.screen.direct();
        self.stop_serving(live).await;
        let was_unlocked = self.held.is_unlocked();
        self.held.lock();
        let said = match (switching, was_unlocked) {
            (true, true) => {
                format!("Wallet {WALLET} locked for the switch; its password opens it again.")
            }
            (true, false) => return,
            (false, true) => format!("Wallet {WALLET} locked. Session closed."),
            (false, false) => "Session closed.".to_owned(),
        };
        self.screen.print(&said);
    }
}

/// When the idle lock fires, `minutes` after the `last` line: never while serve runs or the
/// wallet is locked, nor when the setting is 0.
fn idle_lock_at(minutes: u64, serving: bool, unlocked: bool, last: Instant) -> Option<Instant> {
    if minutes == 0 || serving || !unlocked {
        return None;
    }
    last.checked_add(Duration::from_secs(minutes.saturating_mul(60)))
}

/// The first global flag `global` gives, as typed.
#[cfg(unix)]
fn given_flag(global: &GlobalArgs) -> Option<&'static str> {
    [
        (global.data_dir.is_some(), "--data-dir"),
        (global.network.is_some(), "--network"),
        (global.config.is_some(), "--config"),
        (global.settings.is_some(), "--settings"),
        (global.log_level.is_some(), "--log-level"),
        (global.log_format.is_some(), "--log-format"),
        (global.output.is_some(), "--output"),
        (global.profile.is_some(), "--profile"),
        (global.profile_bits.is_some(), "--profile-bits"),
        (global.domain.is_some(), "--domain"),
    ]
    .into_iter()
    .find_map(|(given, flag)| given.then_some(flag))
}

/// The command words of a line, as the footer names what runs: `tx send`.
fn command_name(args: &[String]) -> String {
    args.iter()
        .take_while(|word| !word.starts_with('-'))
        .take(2)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `15 minutes`, `1 minute`.
fn minutes(count: u64) -> String {
    if count == 1 {
        "1 minute".to_owned()
    } else {
        format!("{count} minutes")
    }
}

/// Whether `report` tells of something done, whose first line the shell shows in green.
const fn did_something(report: &Report) -> bool {
    matches!(
        report,
        Report::Init(_)
            | Report::Restore(_)
            | Report::Scan(_)
            | Report::Password(_)
            | Report::Backup(_)
            | Report::Send(_)
            | Report::Resend(_)
            | Report::Receive(_)
            | Report::SlateReceive(_)
            | Report::Finalize(_)
            | Report::Post(_)
            | Report::Cancel(_)
            | Report::Recover(_)
            | Report::InvoiceIssue(_)
            | Report::InvoicePay(_)
            | Report::InvoiceDecline(_)
            | Report::ImportHistory(_)
            | Report::ContactAccept(_)
            | Report::ContactRemove(_)
            | Report::ProfileSet(_)
    )
}

/// Clap's text with `lepic ` taken out of its usage and error lines: in the shell commands are
/// typed without it.
fn without_lepic(text: &str) -> String {
    text.replace("Usage: lepic ", "Usage: ")
        .replace("'lepic ", "'")
}

/// Whether a line that parsed to `command`, before an epic1 recipient is resolved, is reviewed
/// and asked about before it runs: a `tx send`, to any recipient, and an `epic1 pay`, unless
/// the line has `--yes`.
fn gets_review(command: &Command, yes: bool) -> bool {
    !yes && matches!(
        command,
        Command::Tx(TxCommand::Send(_))
            | Command::Epic1(Epic1Args {
                command: Epic1Command::Pay(_),
                ..
            })
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_send_or_epic1_pay_without_yes_is_reviewed() {
        let reviews = |line: &str, yes: bool| {
            let cli = Cli::try_parse_from(line.split(' ')).unwrap();
            gets_review(&cli.command, yes)
        };
        let epic1 = "lepic tx send 1 --to epic1qq";
        assert!(reviews(epic1, false), "an epic1 send");
        assert!(!reviews(epic1, true), "an epic1 send with --yes");
        assert!(
            reviews("lepic tx send 1 --to https://example.org", false),
            "a classic send"
        );
        assert!(
            !reviews("lepic tx send 1 --to https://example.org", true),
            "a classic send with --yes"
        );
        assert!(reviews("lepic epic1 pay epic1qq 1", false), "epic1 pay");
        assert!(
            reviews("lepic epic1 pay epic1qq", false),
            "epic1 pay at the link's amount"
        );
        assert!(
            !reviews("lepic epic1 pay epic1qq 1", true),
            "epic1 pay with --yes"
        );
        assert!(!reviews("lepic epic1 post-next 00", false), "not a payment");
        assert!(!reviews("lepic wallet info", false), "not a send");
    }

    #[test]
    fn the_footer_names_the_command_words() {
        let words = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(command_name(&words("tx send 1.5 --to x")), "tx send");
        assert_eq!(command_name(&words("epicbox listen")), "epicbox listen");
        assert_eq!(command_name(&words("wallet info --verbose")), "wallet info");
    }

    #[test]
    fn the_idle_lock_waits_for_an_unlocked_wallet_with_no_serve() {
        let last = Instant::now();
        let at = |minutes, serving, unlocked| idle_lock_at(minutes, serving, unlocked, last);
        assert_eq!(at(15, true, true), None);
        assert_eq!(at(15, false, false), None);
        assert_eq!(at(0, false, true), None);
        assert_eq!(
            at(15, false, true),
            last.checked_add(Duration::from_secs(900))
        );
        // Too far to name: no lock.
        assert_eq!(at(u64::MAX, false, true), None);
    }

    #[cfg(unix)]
    #[test]
    fn serve_start_names_the_first_global_flag_given() {
        assert_eq!(given_flag(&GlobalArgs::default()), None);
        let global = GlobalArgs {
            output: Some(crate::cli::OutputArg::Json),
            domain: Some("example.com".to_owned()),
            ..GlobalArgs::default()
        };
        assert_eq!(given_flag(&global), Some("--output"));
    }

    /// A Ctrl+C from before `clear` is forgotten; one after it is seen.
    #[cfg(unix)]
    #[test]
    fn a_cleared_ctrl_c_cancels_nothing() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let interrupt = || {
            let sent = std::process::Command::new("kill")
                .args(["-INT", &std::process::id().to_string()])
                .status()
                .unwrap();
            assert!(sent.success());
        };
        runtime.block_on(async {
            let mut ctrl_c = CtrlC::new();
            interrupt();
            tokio::time::timeout(Duration::from_secs(10), ctrl_c.next())
                .await
                .expect("the Ctrl+C is seen");
            interrupt();
            // Long enough for the runtime to take the signal in.
            tokio::time::sleep(Duration::from_millis(300)).await;
            ctrl_c.clear();
            assert!(
                tokio::time::timeout(Duration::from_millis(300), ctrl_c.next())
                    .await
                    .is_err(),
                "the cleared Ctrl+C is not seen"
            );
        });
    }

    #[test]
    fn usage_lines_lose_the_program_name() {
        assert_eq!(
            without_lepic(
                "Usage: lepic tx send [OPTIONS]\n\nFor more information, try 'lepic tx send --help'."
            ),
            "Usage: tx send [OPTIONS]\n\nFor more information, try 'tx send --help'."
        );
        assert_eq!(
            without_lepic("error: 'lepic tx send' requires an amount"),
            "error: 'tx send' requires an amount"
        );
    }
}
