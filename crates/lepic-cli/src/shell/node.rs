// SPDX-License-Identifier: Apache-2.0
//! The node of the session: whether it answers, and the switch to another one. A node that
//! does not answer at the start is said so before the wallet opens, with the other known nodes
//! to pick from; `node use` switches later. The node picked is kept as `node_url` in the config
//! file, so the next start uses it too.

use std::time::Duration;

use futures_util::future::join_all;
use lepic_node::{NodeApi as _, RetryPolicy};
use lepic_wallet::NodeEndpoint;

use crate::cli::GlobalArgs;
use crate::host::Host;
use crate::settings::{Env, NODE_URL_ENV, Settings, save_node_url};
use crate::shell::ask::{self, Choice};
use crate::shell::editor::columns;
use crate::shell::live::{Look, grouped, printable};
use crate::shell::paint::{Tone, wrapped};
use crate::shell::screen::Screen;

/// How long a node is given to say its tip before it counts as not answering.
const ANSWER_WITHIN: Duration = Duration::from_secs(8);
/// How long each node of the list to pick from is given to say its tip.
const LISTED_WITHIN: Duration = Duration::from_secs(4);

/// The settings and the environment of a session on another node.
pub(crate) struct Switch {
    pub settings: Settings,
    pub env: Env,
}

/// What asking about the node, and switching it, needs of the session.
pub(crate) struct Nodes<'a, H: Host> {
    pub host: &'a H,
    pub global: &'a GlobalArgs,
    pub settings: &'a Settings,
    pub env: &'a Env,
    pub screen: &'a Screen,
    pub look: Look,
    /// Before the shell's prompt: what is said names `node use` as a word of the shell.
    pub at_start: bool,
}

impl<H: Host> Nodes<'_, H> {
    /// Asks the node of the session for its tip before the wallet opens. When it does not
    /// answer, the other known nodes are offered; `Some` when one was picked and answers. A
    /// node reached through Tor is not asked here: its first answer takes a Tor start.
    pub(crate) async fn at_start(&self) -> Option<Switch> {
        if self.settings.node_over_tor {
            return None;
        }
        let asking = self.tip(self.settings);
        if let Some(height) = self.screen.busy(self.look, "Asking the node", asking).await {
            self.answers(&self.settings.node, height);
            return None;
        }
        self.screen.print("");
        self.say(
            &format!("The node {} does not answer.", name(&self.settings.node)),
            Tone::Yellow,
        );
        self.say(
            "The wallet needs a node for the balance, sends and receipts.",
            Tone::Dim,
        );
        let others = self.others();
        if others.is_empty() {
            self.say(
                "In the shell, node use <address> switches to another node.",
                Tone::Dim,
            );
            return None;
        }
        match self.pick(others).await {
            Some(node) => self.switch_to(&node).await,
            None => {
                self.kept();
                None
            }
        }
    }

    /// Switches to `target`, or to the node picked from the known ones when none is named.
    /// `None` when the node stays as it is, which is said.
    pub(crate) async fn switch(&self, target: Option<NodeEndpoint>) -> Option<Switch> {
        let target = match target {
            Some(target) => target,
            None => {
                let others = self.others();
                if others.is_empty() {
                    self.say(
                        "No other node is known. node use <address> names one.",
                        Tone::Yellow,
                    );
                    return None;
                }
                let Some(picked) = self.pick(others).await else {
                    self.kept();
                    return None;
                };
                picked
            }
        };
        if target.as_str() == self.settings.node.as_str() {
            self.say(
                &format!("{} is the node in use already.", name(&target)),
                Tone::Dim,
            );
            return None;
        }
        self.switch_to(&target).await
    }

    /// The known nodes that are not the one in use.
    fn others(&self) -> Vec<NodeEndpoint> {
        others(self.settings)
    }

    /// The list to pick a node from, the node in use last. `None` when it is kept.
    async fn pick(&self, others: Vec<NodeEndpoint>) -> Option<NodeEndpoint> {
        self.say(
            "A node on another computer sees which outputs the wallet asks about.",
            Tone::Dim,
        );
        let said = self.listed(&others).await;
        self.screen.print("");
        let mut choices: Vec<Choice> = others
            .iter()
            .zip(said)
            .map(|(node, about)| Choice {
                label: format!("Use {}", name(node)),
                about,
            })
            .collect();
        choices.push(Choice {
            label: format!("Keep {}", name(&self.settings.node)),
            about: String::new(),
        });
        let picked = ask::choose(choices, self.look).await?;
        others.into_iter().nth(picked)
    }

    /// What each of `nodes` says when asked for its tip now, for the list: its height, or
    /// that it does not answer. Nothing is asked, and nothing said, while node calls go
    /// through Tor.
    async fn listed(&self, nodes: &[NodeEndpoint]) -> Vec<String> {
        if self.settings.node_over_tor {
            return vec![String::new(); nodes.len()];
        }
        let asked = nodes.iter().map(|node| {
            let mut settings = self.settings.clone();
            settings.node = node.clone();
            async move {
                tokio::time::timeout(LISTED_WITHIN, self.tip(&settings))
                    .await
                    .ok()
                    .flatten()
            }
        });
        let heights = self
            .screen
            .busy(self.look, "Asking the known nodes", join_all(asked))
            .await;
        heights
            .into_iter()
            .map(|height| {
                height.map_or_else(
                    || "no answer".to_owned(),
                    |height| format!("height {}", grouped(height)),
                )
            })
            .collect()
    }

    /// Says that `node` answers, with the height of its tip.
    fn answers(&self, node: &NodeEndpoint, height: u64) {
        let mark = self.look.tint(self.look.marks.synced, Tone::Green);
        let said = format!(
            "Node {} {} height {}",
            name(node),
            self.look.marks.sep,
            grouped(height)
        );
        self.screen
            .print(&format!("{mark} {}", self.look.tint(&said, Tone::Dim)));
    }

    fn kept(&self) {
        let stays = format!("The node stays {}.", name(&self.settings.node));
        // Before the shell's prompt, the word that switches later is not known yet.
        let said = if self.at_start {
            format!("{stays} In the shell, node use switches to another.")
        } else {
            stays
        };
        self.say(&said, Tone::Dim);
    }

    /// The session's settings with `target` as the node, once it answers; it is kept in the
    /// config file unless a variable names the node, which would win over the file.
    async fn switch_to(&self, target: &NodeEndpoint) -> Option<Switch> {
        let mut env = self.env.clone();
        env.set(NODE_URL_ENV, target.as_str());
        let settings = match Settings::resolve(self.global, &env) {
            Ok(settings) => settings.on_host_network(self.host.network()),
            Err(error) => {
                self.say(
                    &format!("The settings do not load with that node: {error}"),
                    Tone::Red,
                );
                return None;
            }
        };
        let label = format!("Asking {}", name(target));
        let asking = self.tip(&settings);
        let Some(height) = self.screen.busy(self.look, &label, asking).await else {
            self.say(
                &format!(
                    "{} does not answer. The node stays {}.",
                    name(target),
                    name(&self.settings.node)
                ),
                Tone::Yellow,
            );
            return None;
        };
        self.answers(target, height);
        if self.env.get(NODE_URL_ENV).is_some() {
            self.say(
                &format!("{NODE_URL_ENV} names the node at the next start."),
                Tone::Dim,
            );
        } else {
            match save_node_url(self.global, self.env, target.as_str()) {
                Ok(path) => self.say(
                    &format!(
                        "Kept as node_url in {}.",
                        printable(&path.display().to_string())
                    ),
                    Tone::Dim,
                ),
                Err(error) => self.say(
                    &format!(
                        "It holds for this session only; the config file was not written: {error}"
                    ),
                    Tone::Yellow,
                ),
            }
        }
        Some(Switch { settings, env })
    }

    /// The height of the tip the node of `settings` names, asked once; `None` when it does
    /// not answer in time.
    async fn tip(&self, settings: &Settings) -> Option<u64> {
        let mut once = settings.clone();
        once.tuning.call_policy.retry = RetryPolicy::NONE;
        let node = self.host.node(&once).ok()?;
        let tip = tokio::time::timeout(ANSWER_WITHIN, node.get_tip())
            .await
            .ok()?
            .ok()?;
        Some(tip.height.value())
    }

    fn say(&self, text: &str, tone: Tone) {
        let room = usize::from(columns().saturating_sub(1));
        for line in wrapped(text, room) {
            self.screen.print(&self.look.tint(&line, tone));
        }
    }
}

/// The known nodes of `settings` that are not the one in use.
fn others(settings: &Settings) -> Vec<NodeEndpoint> {
    settings
        .servers
        .nodes
        .iter()
        .filter(|node| node.as_str() != settings.node.as_str())
        .cloned()
        .collect()
}

/// The node as a line names it: its address without the scheme, `node.example:3413`.
pub(crate) fn name(node: &NodeEndpoint) -> String {
    let url = node.as_str();
    let bare = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    printable(bare.trim_end_matches('/'))
}

/// The node `text` names: an address as typed, `https://` put before one that has no scheme.
pub(crate) fn parse(text: &str) -> Option<NodeEndpoint> {
    let url = if text.contains("://") {
        text.to_owned()
    } else {
        format!("https://{text}")
    };
    NodeEndpoint::parse(&url).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_node_is_named_without_its_scheme() {
        let named = |url: &str| name(&NodeEndpoint::parse(url).unwrap());
        assert_eq!(named("https://node.example.org"), "node.example.org");
        assert_eq!(named("http://127.0.0.1:3413"), "127.0.0.1:3413");
    }

    #[test]
    fn a_typed_address_without_a_scheme_is_taken_as_https() {
        let parsed = |text: &str| parse(text).map(|node| node.as_str().to_owned());
        assert_eq!(
            parsed("node.example.org").as_deref(),
            Some("https://node.example.org")
        );
        assert_eq!(
            parsed("http://127.0.0.1:3413").as_deref(),
            Some("http://127.0.0.1:3413")
        );
        assert_eq!(parsed("not a node"), None);
    }

    #[test]
    fn the_nodes_offered_are_the_known_ones_but_the_one_in_use() {
        let home = tempfile::tempdir().unwrap();
        let env = Env::new([("HOME".to_owned(), home.path().display().to_string())]);
        let settings = Settings::resolve(&GlobalArgs::default(), &env).unwrap();
        assert_eq!(settings.node.as_str(), "http://127.0.0.1:3413");
        let offered: Vec<String> = others(&settings)
            .iter()
            .map(|node| node.as_str().to_owned())
            .collect();
        assert_eq!(
            offered,
            [
                "https://node.btlabs.uk",
                "https://node.epiccash.com:3413",
                "https://node.epicnet.us:3413",
                "https://epic.stackwallet.com:3413"
            ]
        );

        let mut public = env.clone();
        public.set(NODE_URL_ENV, "https://node.btlabs.uk");
        let settings = Settings::resolve(&GlobalArgs::default(), &public).unwrap();
        let offered: Vec<String> = others(&settings)
            .iter()
            .map(|node| node.as_str().to_owned())
            .collect();
        assert_eq!(
            offered.first().map(String::as_str),
            Some("http://127.0.0.1:3413")
        );
        assert_eq!(offered.len(), 4);
        assert!(!offered.iter().any(|node| node == "https://node.btlabs.uk"));
    }
}
