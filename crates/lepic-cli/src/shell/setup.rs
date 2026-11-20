// SPDX-License-Identifier: Apache-2.0
//! The first run: a data directory without a wallet gets one in the shell, created from new
//! entropy or restored from its recovery phrase, instead of a refusal. The recovery phrase of a
//! new wallet is shown once, on the terminal's alternate screen, so it does not stay in the
//! scrollback.

use lepic_keychain::{MnemonicError, Seed};
use zeroize::Zeroizing;

use crate::commands::shell::Held;
use crate::exit::CliError;
use crate::host::Host;
use crate::secret::{SecretError, Shown};
use crate::settings::{Env, Settings};
use crate::shell::ask::{self, Choice};
use crate::shell::editor::columns;
use crate::shell::live::{Look, printable};
use crate::shell::paint::{Tone, cells, wrapped};
use crate::shell::screen::Screen;

/// How the first run ended.
pub(crate) enum FirstRun<H: Host> {
    /// A new wallet, unlocked.
    Created(Held<H>),
    /// A restored wallet, unlocked; the scan for its outputs has not run.
    Restored(Held<H>),
    /// No wallet: the user left.
    Left,
}

/// The rows a line of the first run starts after.
const INDENT: &str = "  ";

/// Asks whether to create or restore a wallet in the data directory, and does it.
pub(crate) async fn first_run<H: Host>(
    host: &H,
    settings: &Settings,
    env: &Env,
    screen: &Screen,
    look: Look,
) -> Result<FirstRun<H>, CliError> {
    let setup = Setup {
        host,
        settings,
        env,
        screen,
        look,
    };
    screen.print("");
    setup.say("No wallet in this data directory yet.", Tone::Bold);
    setup.say(
        &format!(
            "{} {} {}",
            printable(&settings.data_dir.display().to_string()),
            look.marks.sep,
            settings.network
        ),
        Tone::Dim,
    );
    loop {
        screen.print("");
        let picked = ask::choose(
            vec![
                Choice {
                    label: "Create a wallet".to_owned(),
                    about: "a new recovery phrase of 24 words".to_owned(),
                },
                Choice {
                    label: "Restore a wallet".to_owned(),
                    about: "from its recovery phrase".to_owned(),
                },
                Choice {
                    label: "Leave".to_owned(),
                    about: String::new(),
                },
            ],
            look,
        )
        .await;
        screen.print("");
        match picked {
            Some(0) => {
                if let Some(held) = setup.create().await? {
                    return Ok(FirstRun::Created(held));
                }
            }
            Some(1) => {
                if let Some(held) = setup.restore().await? {
                    return Ok(FirstRun::Restored(held));
                }
            }
            _ => return Ok(FirstRun::Left),
        }
    }
}

struct Setup<'a, H: Host> {
    host: &'a H,
    settings: &'a Settings,
    env: &'a Env,
    screen: &'a Screen,
    look: Look,
}

impl<H: Host> Setup<'_, H> {
    fn say(&self, text: &str, tone: Tone) {
        let room = usize::from(columns().saturating_sub(1)).saturating_sub(cells(INDENT));
        for line in wrapped(text, room) {
            self.screen
                .print(&format!("{INDENT}{}", self.look.tint(&line, tone)));
        }
    }

    /// A new wallet under a password typed twice. `None` when the password prompt was left.
    async fn create(&self) -> Result<Option<Held<H>>, CliError> {
        let Some(password) = self.new_password().await? else {
            return Ok(None);
        };
        let creating = Held::create(self.host, self.settings, self.env.clone(), password);
        let (held, phrase) = self
            .screen
            .busy(self.look, "Creating the wallet", creating)
            .await?;
        ask::page(phrase_page(&phrase, columns(), self.look)).await;
        drop(phrase);
        self.done(&format!("Wallet created on {}.", self.settings.network));
        self.say(
            "Its recovery phrase was shown once and is stored nowhere else.",
            Tone::Dim,
        );
        Ok(Some(held))
    }

    /// A wallet from a recovery phrase, under a new password. `None` when a prompt was left.
    async fn restore(&self) -> Result<Option<Held<H>>, CliError> {
        self.say(
            "Type or paste the recovery phrase, its words separated by blanks. It stays hidden.",
            Tone::Dim,
        );
        let phrase = loop {
            let prompt = format!("{INDENT}Recovery phrase: ");
            let Some(typed) = self
                .secret("recovery phrase", prompt, Shown::WordCount)
                .await?
            else {
                return Ok(None);
            };
            let phrase = Zeroizing::new(typed.to_lowercase());
            match Seed::from_mnemonic(&phrase) {
                Ok(_) => break phrase,
                Err(error) => self.say(&phrase_fault(&error), Tone::Yellow),
            }
        };
        let Some(password) = self.new_password().await? else {
            return Ok(None);
        };
        let restoring = Held::restore(self.host, self.settings, self.env.clone(), password, phrase);
        let held = self
            .screen
            .busy(self.look, "Restoring the wallet", restoring)
            .await?;
        self.done(&format!("Wallet restored on {}.", self.settings.network));
        self.say(
            "The chain is scanned for its funds now. Ctrl+C stops the scan; wallet scan runs it again.",
            Tone::Dim,
        );
        Ok(Some(held))
    }

    fn done(&self, text: &str) {
        let mark = self.look.tint(self.look.marks.synced, Tone::Green);
        self.screen.print(&format!(
            "{INDENT}{mark} {}",
            self.look.tint(text, Tone::Green)
        ));
    }

    /// A new password, typed twice until both entries are the same and not empty. `None` when
    /// the prompt was left with Esc or Ctrl+C.
    async fn new_password(&self) -> Result<Option<Zeroizing<String>>, CliError> {
        self.say(
            "Choose a password. It encrypts the wallet on this computer and opens it at each start.",
            Tone::Dim,
        );
        let shown = Shown::Marks(self.look.marks.mask);
        loop {
            let first = format!("{INDENT}New password: ");
            let Some(password) = self.secret("wallet password", first, shown).await? else {
                return Ok(None);
            };
            if password.is_empty() {
                self.say("A password cannot be empty.", Tone::Yellow);
                continue;
            }
            let second = format!("{INDENT}Repeat it:    ");
            let Some(again) = self.secret("wallet password", second, shown).await? else {
                return Ok(None);
            };
            if *again == *password {
                return Ok(Some(password));
            }
            self.say("The two entries differ. Once more.", Tone::Yellow);
        }
    }

    /// One hidden line. `None` when the prompt was left with Esc or Ctrl+C.
    async fn secret(
        &self,
        what: &'static str,
        prompt: String,
        shown: Shown,
    ) -> Result<Option<Zeroizing<String>>, CliError> {
        match ask::secret(what, prompt, shown).await {
            Ok(secret) => Ok(Some(secret)),
            Err(SecretError::Cancelled { .. } | SecretError::Missing { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// What is wrong with a typed recovery phrase, in a line.
fn phrase_fault(error: &MnemonicError) -> String {
    match error {
        MnemonicError::WordCount { actual } => {
            format!("A recovery phrase has 12, 15, 18, 21 or 24 words; this one has {actual}.")
        }
        MnemonicError::UnknownWord { position } => format!(
            "Word {} is not a recovery phrase word. Check its spelling.",
            position.saturating_add(1)
        ),
        _ => "These words do not make a recovery phrase: one is wrong or out of place.".to_owned(),
    }
}

/// The cells one numbered word takes on the page: `12 abandon   `.
const WORD_CELL: usize = 14;

/// The page that shows the recovery phrase: what it is for, the words numbered in columns, and
/// the key that leaves the page.
fn phrase_page(phrase: &str, columns: u16, look: Look) -> Zeroizing<String> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let room = usize::from(columns.saturating_sub(1)).saturating_sub(cells(INDENT));
    let across = (room / WORD_CELL).clamp(1, 4);
    let down = words.len().div_ceil(across);
    let mut page = Zeroizing::new(String::new());
    let mut line = |text: &str| {
        page.push_str(text);
        page.push('\n');
    };
    line("");
    line(&format!(
        "{INDENT}{}{}  {}",
        look.tint(look.marks.prompt, Tone::Green),
        look.tint("epic", Tone::Bold),
        look.tint("recovery phrase", Tone::Dim)
    ));
    line("");
    for text in wrapped(
        &format!(
            "These {} words are the wallet. Whoever holds them can spend its funds, and a lost \
             wallet comes back only from them. Write them down in this order and keep the paper \
             offline. They are not shown again.",
            words.len()
        ),
        room.min(76),
    ) {
        line(&format!("{INDENT}{text}"));
    }
    line("");
    for row in 0..down {
        let mut text = Zeroizing::new(String::from(INDENT));
        for column in 0..across {
            let index = column.saturating_mul(down).saturating_add(row);
            let Some(word) = words.get(index) else {
                continue;
            };
            let number = look.tint(&format!("{:>2}", index.saturating_add(1)), Tone::Dim);
            let fill = " ".repeat(WORD_CELL.saturating_sub(3).saturating_sub(cells(word)));
            text.push_str(&format!("{number} {}{fill}", look.tint(word, Tone::Amount)));
        }
        line(text.trim_end());
    }
    line("");
    line(&format!(
        "{INDENT}{} {}",
        look.tint("Enter", Tone::Plain),
        look.tint("once written down", Tone::Dim)
    ));
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::card::Glyphs;
    use crate::shell::live::Marks;
    use crate::shell::paint::{Paint, strip};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon art";

    fn look(glyphs: Glyphs, paint: Paint) -> Look {
        Look {
            marks: Marks::new(glyphs),
            paint,
            motion: false,
        }
    }

    #[test]
    fn the_page_numbers_every_word_and_fits_the_terminal() {
        for columns in [30, 40, 80, 112] {
            for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
                let page = phrase_page(PHRASE, columns, look(glyphs, Paint::Night));
                let shown = strip(&page);
                for number in 1..=24 {
                    assert!(
                        shown.contains(&format!("{number:>2} a")),
                        "{columns}: {shown}"
                    );
                }
                assert_eq!(shown.matches("abandon").count(), 23);
                assert!(shown.contains("24 art"), "{shown}");
                for line in shown.lines() {
                    assert!(cells(line) < usize::from(columns), "{columns}: {line}");
                }
                assert_eq!(shown.is_ascii(), glyphs == Glyphs::Ascii);
            }
        }
        let plain = phrase_page(PHRASE, 112, look(Glyphs::Unicode, Paint::Off));
        assert!(!plain.contains('\u{1b}'));
        // Four columns of six, numbered down each column.
        assert!(plain.contains("   1 abandon     7 abandon    13 abandon    19 abandon"));
    }

    #[test]
    fn a_wrong_phrase_is_named_in_a_line() {
        let fault = |phrase: &str| phrase_fault(&Seed::from_mnemonic(phrase).err().unwrap());
        assert!(fault("abandon abandon").contains("this one has 2"));
        assert!(fault(&PHRASE.replace("art", "arx")).starts_with("Word 24 is not"));
        assert!(fault(&PHRASE.replace("art", "abandon")).starts_with("These words do not"));
        assert!(Seed::from_mnemonic(PHRASE).is_ok());
    }
}
