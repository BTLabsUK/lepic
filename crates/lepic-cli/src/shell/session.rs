// SPDX-License-Identifier: Apache-2.0
//! The interactive shell's session: it opens the wallet once, reads lines on the reader thread,
//! runs each as a `lepic` command on the held wallet with its output above the live area, and
//! locks the wallet when it ends or sits idle.

use std::io::{self, BufReader, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::error::ErrorKind as ClapErrorKind;
use clap::{CommandFactory as _, Parser as _};
use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
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
use crate::cli::{Cli, Command, GlobalArgs, TxCommand};
use crate::commands::shell::Held;
use crate::exit::{CliError, ErrorKind};
use crate::host::{Host, Interrupt};
use crate::output::{Report, render, render_error};
use crate::secret::{PASSWORD_ENV, SecretError, SecretInput, read_hidden_line};
use crate::settings::{Env, OutputFormat, RelayTor, Settings};
use crate::shell::card::{CardInfo, Glyphs, welcome};
use crate::shell::editor::{LivePrompt, Shared, columns, line_editor};
use crate::shell::history::FilteredHistory;
use crate::shell::live::{
    Marks, Status, SyncMark, colour, footer, glyphs, grouped, printable, progress_row, short_amount,
};
use crate::shell::reader::{Ask, Read, Reader, Reply};
use crate::shell::screen::{Queue, Screen, ScreenWriter, ShellLog};
use crate::shell::words::{self, Line, SHELL_WORDS};
use crate::{Console, hint};

/// The wallet the shell names; a data directory holds one.
const WALLET: &str = "default";
/// How often the editor looks for queued lines and the footer redraws.
const TICK: Duration = Duration::from_millis(100);
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
    let dispatch = host_dispatch(Arc::new(ShellLog(screen.clone())), filter);
    tracing::dispatcher::with_default(&dispatch, || {
        runtime.block_on(session(host, global, settings, console, screen))
    })
}

async fn session<H: Host>(
    host: &H,
    global: &GlobalArgs,
    settings: &Settings,
    console: &mut Console,
    screen: &Screen,
) -> Result<(), CliError> {
    let marks = Marks::new(glyphs(&console.env));
    let network = settings.network.to_string();
    let card = welcome(
        &CardInfo {
            version: env!("CARGO_PKG_VERSION"),
            wallet: WALLET,
            network: &network,
        },
        columns(),
        marks.glyphs,
        colour(&console.env, true),
    );
    screen.print(&card.join("\n"));
    // A password given ahead is read first, and taken out of the environment the wallet and
    // the commands see.
    let given = if settings.password_file.is_some() || console.env.get(PASSWORD_ENV).is_some() {
        Some(
            console
                .secrets
                .wallet_password(&mut console.env, settings.password_file.as_deref(), false)
                .await,
        )
    } else {
        None
    };
    let held = Held::prepare(host, settings, console.env.clone()).await?;
    let status = Shared::new(Status {
        wallet: WALLET.to_owned(),
        network,
        locked: true,
        tor: !matches!(settings.relay_tor, RelayTor::Off),
        ..Status::default()
    });
    let shell = Shell {
        host,
        global,
        settings,
        env: console.env.clone(),
        held,
        screen: screen.clone(),
        status,
        marks,
    };
    shell.unlock(given).await;

    let history: Box<dyn reedline::History> = match FilteredHistory::open(&settings.data_dir) {
        Ok(history) => Box::new(history),
        Err(error) => {
            screen.print(&format!("The history is kept in memory only: {error}"));
            Box::new(FilteredHistory::in_memory())
        }
    };
    let stop_read = Arc::new(AtomicBool::new(false));
    let mut editor = line_editor(&shell.status, marks, history)
        .with_external_printer(Queue(screen.clone()))
        .with_poll_interval(TICK)
        .with_break_signal(Arc::clone(&stop_read));
    screen.set_repaint(editor.repaint_signal());
    let mut reader = Reader::start(editor, LivePrompt, stop_read)
        .map_err(CliError::io("start the line editor"))?;
    let mut live = Live {
        events: shell.held.subscribe(),
        events_open: true,
        serving: None,
        refreshing: None,
        next_refresh: Instant::now(),
        signal: host.interrupted(),
        leaving: false,
        last_command: Instant::now(),
    };
    let result = shell.read_loop(&mut reader, &mut live).await;
    shell.leave(&mut live).await;
    drop(reader);
    result
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
    marks: Marks,
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
    refreshing: Option<LocalBoxFuture<'a, bool>>,
    next_refresh: Instant,
    /// The process's interrupt or terminate signal; once it fired the session ends.
    signal: Interrupt,
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
    Refreshed(bool),
    RefreshDue,
    IdleLock,
    Signal,
}

/// What follows a line.
#[derive(PartialEq, Eq)]
enum Flow {
    Next,
    Exit,
}

impl<'a, H: Host> Shell<'a, H> {
    async fn read_loop<'s>(
        &'s self,
        reader: &mut Reader,
        live: &mut Live<'s>,
    ) -> Result<(), CliError> {
        loop {
            if live.leaving {
                return Ok(());
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
                    if flow == Flow::Exit {
                        return Ok(());
                    }
                }
                Read::CtrlC | Read::Break => {}
                Read::CtrlD => return Ok(()),
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
            self.idle_lock_at(live)
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
            signal,
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
            ok = refreshed => Background::Refreshed(ok),
            () = tokio::time::sleep_until(*next_refresh), if refresh_due => Background::RefreshDue,
            () = tokio::time::sleep_until(idle_at.unwrap_or(far)), if idle_at.is_some() => {
                Background::IdleLock
            }
            () = signal, if !*leaving => Background::Signal,
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
            Background::Refreshed(ok) => {
                live.refreshing = None;
                live.next_refresh = Instant::now()
                    .checked_add(REFRESH_EVERY)
                    .unwrap_or_else(Instant::now);
                if ok {
                    self.status.update(|status| status.sync = SyncMark::Synced);
                    self.read_balance();
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
            Background::Signal => live.leaving = true,
        }
    }

    /// When the idle lock fires: never while serve runs, the wallet is locked or the setting is
    /// 0.
    fn idle_lock_at(&self, live: &Live<'_>) -> Option<Instant> {
        let minutes = self.settings.shell_idle_lock_minutes;
        if minutes == 0 || live.serving.is_some() || !self.held.is_unlocked() {
            return None;
        }
        live.last_command
            .checked_add(Duration::from_secs(minutes.saturating_mul(60)))
    }

    fn on_event(&self, event: &Event) {
        match event {
            Event::Balance(_) => self.read_balance(),
            Event::Sync(progress) => {
                let (height, target) = (progress.height.value(), progress.target.value());
                self.status.update(|status| {
                    status.height = Some(height);
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
                status.height = Some(balance.height.value());
            });
        }
    }

    /// Unlocks the wallet with the password `given`, or asks for it.
    async fn unlock(&self, given: Option<Result<Zeroizing<String>, SecretError>>) -> bool {
        let password = match given {
            Some(password) => password,
            None => ask_password().await,
        };
        let password = match password {
            Ok(password) => password,
            Err(error) => {
                self.print_error(&error.into(), self.settings);
                return false;
            }
        };
        let dots = match self.marks.glyphs {
            Glyphs::Unicode => "…",
            Glyphs::Ascii => "...",
        };
        self.screen.print(&format!("Unlocking{dots}"));
        if let Err(error) = self.held.unlock(password).await {
            self.print_error(&error, self.settings);
            return false;
        }
        self.status.update(|status| status.locked = false);
        self.read_balance();
        let minutes_idle = self.settings.shell_idle_lock_minutes;
        self.screen.print(&if minutes_idle == 0 {
            format!("Wallet {WALLET} unlocked.")
        } else {
            format!(
                "Wallet {WALLET} unlocked. It locks after {} idle.",
                minutes(minutes_idle)
            )
        });
        true
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
                } else if self.unlock(None).await {
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
            Line::Status => self.screen.print(&self.status_text(live).join("\n")),
            Line::Exit => return Flow::Exit,
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
            self.screen
                .print(&words::help_lines(&Cli::command()).join("\n"));
            return;
        }
        let asked = words.join(" ");
        if let Some((word, about)) = SHELL_WORDS
            .iter()
            .find(|(word, _)| *word == asked || (*word == "exit" && asked == "quit"))
        {
            self.screen.print(&format!("{word}: {about}"));
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
        self.screen
            .print(&without_lepic(&command.render_long_help().to_string()));
    }

    /// Prints that `words` name no command, with the nearest one.
    fn unknown(&self, words: &[String]) {
        let (typed, nearest) = words::unknown_command(&Cli::command(), words)
            .unwrap_or_else(|| (words.join(" "), None));
        let mut text = format!("error: unknown command: {}", printable(&typed));
        if let Some(nearest) = nearest {
            text.push_str(&format!("\nhint: did you mean {nearest}?"));
        }
        self.screen.print(&text);
    }

    async fn lock<'s>(&'s self, live: &mut Live<'s>) {
        if live.serving.is_some() {
            self.screen
                .print("Serve stops first: it answers with the unlocked wallet.");
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
                command: Command::Serve(serve_args),
                ..
            }) => serve_args,
            Ok(_) => return,
            Err(error) => {
                self.screen
                    .print(&without_lepic(&error.render().to_string()));
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
                self.screen
                    .print(&format!("Serving the wallet API on {}", printable(&socket)));
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
        let cli = match Cli::try_parse_from(&argv) {
            Ok(cli) => cli,
            Err(error) => {
                let informational = matches!(
                    error.kind(),
                    ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
                );
                if !informational && words::unknown_command(&Cli::command(), &args).is_some() {
                    self.unknown(&args);
                } else {
                    self.screen
                        .print(&without_lepic(&error.render().to_string()));
                }
                return;
            }
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
        if let Command::Tx(TxCommand::Send(send)) = &cli.command
            && !yes
        {
            if !self.held.is_unlocked() && !self.unlock_for_command().await {
                return;
            }
            let review = match self
                .held
                .review(self.host, &settings, self.env.clone(), send)
                .boxed_local()
                .await
            {
                Ok(review) => review,
                Err(error) => {
                    self.print_error(&error, &settings);
                    return;
                }
            };
            self.screen.print(&review.lines().join("\n"));
            let question = review.question();
            let answer = tokio::task::spawn_blocking(move || confirm(&question))
                .await
                .unwrap_or(false);
            if !answer {
                self.screen.print("Not sent.");
                return;
            }
        }
        let what = command_name(&args);
        let mut result = self
            .run_command(cli.command.clone(), &what, &settings, reader, live)
            .await;
        let locked_out = matches!(&result, Err(error) if error.kind() == ErrorKind::WalletState)
            && !self.held.is_unlocked();
        if locked_out && !live.leaving {
            if !self.unlock_for_command().await {
                return;
            }
            result = self
                .run_command(cli.command, &what, &settings, reader, live)
                .await;
        }
        self.print_result(result, &settings);
    }

    async fn unlock_for_command(&self) -> bool {
        self.screen.print(&format!(
            "Wallet {WALLET} is locked; its password opens it."
        ));
        self.unlock(None).await
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
        Ok(Settings::resolve(&merged, &self.env)?)
    }

    /// Runs `command` with the footer under its output once it takes longer than a glance,
    /// until it ends or Ctrl+C cancels it.
    async fn run_command<'s>(
        &'s self,
        command: Command,
        what: &str,
        settings: &Settings,
        reader: &mut Reader,
        live: &mut Live<'s>,
    ) -> Result<Report, CliError> {
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
            let mut running = self
                .held
                .run(self.host, settings, command, &mut console, interrupt)
                .boxed_local();
            loop {
                let mut redraw = false;
                tokio::select! {
                    result = &mut running => break result,
                    _ = ticker.tick() => {
                        tick = tick.wrapping_add(1);
                        redraw = true;
                    }
                    reply = reader.replies.recv() => match reply {
                        Some(Reply::Interrupt) => {
                            cancel.send_replace(true);
                            doing = format!("{what}, cancelling");
                            redraw = true;
                        }
                        Some(Reply::Resize) => redraw = true,
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
                        self.on_background(live, background);
                        if live.leaving {
                            cancel.send_replace(true);
                        }
                        redraw = true;
                    }
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
        stop_watch.store(true, Ordering::SeqCst);
        loop {
            match reader.replies.recv().await {
                Some(Reply::Watched) | None => break,
                Some(_) => {}
            }
        }
        self.screen.direct();
        result
    }

    fn footer(&self, tick: usize, doing: &str, elapsed: Duration) -> [String; 4] {
        let columns = columns();
        let progress = progress_row(tick, doing, elapsed.as_secs(), columns, &self.marks);
        footer(&self.status.get(), &progress, columns, &self.marks)
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
            ansi: colour(&self.env, true),
        }
    }

    fn print_result(&self, result: Result<Report, CliError>, settings: &Settings) {
        match result {
            Ok(report) => {
                let text = render(&report, settings.output);
                if !text.is_empty() {
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
        self.screen.print(&text);
    }

    /// Ends the session: serve stops, the wallet locks.
    async fn leave<'s>(&'s self, live: &mut Live<'s>) {
        self.screen.direct();
        self.stop_serving(live).await;
        let was_unlocked = self.held.is_unlocked();
        self.held.lock();
        self.screen.print(&if was_unlocked {
            format!("Wallet {WALLET} locked. Session closed.")
        } else {
            "Session closed.".to_owned()
        });
    }
}

/// Asks for the wallet password at the terminal, on a thread of its own.
async fn ask_password() -> Result<Zeroizing<String>, SecretError> {
    let prompt = format!("Password for wallet {WALLET}: ");
    tokio::task::spawn_blocking(move || read_hidden_line(&prompt))
        .await
        .unwrap_or(Err(SecretError::Cancelled {
            what: "wallet password",
        }))
}

/// Asks `question` and reads one key: only `y` answers yes.
fn confirm(question: &str) -> bool {
    let mut out = io::stdout();
    let _ = out.write_all(question.as_bytes());
    let _ = out.flush();
    if enable_raw_mode().is_err() {
        let _ = out.write_all(b"\r\n");
        return false;
    }
    let yes = loop {
        match event::read() {
            Ok(TermEvent::Key(key)) if key.kind == KeyEventKind::Press => {
                let control = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Char('y' | 'Y') if !control => break true,
                    KeyCode::Char(_) | KeyCode::Enter | KeyCode::Esc => break false,
                    _ => {}
                }
            }
            Ok(_) => {}
            Err(_) => break false,
        }
    };
    let _ = disable_raw_mode();
    let _ = out.write_all(if yes { b"y\r\n" } else { b"N\r\n" });
    let _ = out.flush();
    yes
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

/// Clap's text with `lepic ` taken out of its usage lines: in the shell commands are typed
/// without it.
fn without_lepic(text: &str) -> String {
    text.replace("Usage: lepic ", "Usage: ")
        .replace("try 'lepic ", "try '")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_footer_names_the_command_words() {
        let words = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(command_name(&words("tx send 1.5 --to x")), "tx send");
        assert_eq!(command_name(&words("epicbox listen")), "epicbox listen");
        assert_eq!(command_name(&words("wallet info --verbose")), "wallet info");
    }

    #[test]
    fn usage_lines_lose_the_program_name() {
        assert_eq!(
            without_lepic(
                "Usage: lepic tx send [OPTIONS]\n\nFor more information, try 'lepic tx send --help'."
            ),
            "Usage: tx send [OPTIONS]\n\nFor more information, try 'tx send --help'."
        );
    }
}
