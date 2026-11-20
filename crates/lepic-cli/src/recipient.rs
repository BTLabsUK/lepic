// SPDX-License-Identifier: Apache-2.0
//! What a recipient names: the address decides the protocol, the same way for the command line
//! and the serve API.

use crate::cli::{
    Command, Epic1Args, Epic1Command, Epic1LinkArg, Epic1PayArgs, SendArgs, TorBinaryArgs,
    TxCommand,
};
use crate::exit::CliError;

/// `command` as it runs: a `tx send` to an epic1 address or link is the payment `epic1 pay`
/// makes, with its checks and its report. A flag that payment has no use for is refused, before
/// anything is built. Both commands take a bare epic1 address as the link that pays it.
pub(crate) fn resolve(command: Command) -> Result<Command, CliError> {
    let send = match command {
        Command::Tx(TxCommand::Send(send)) => send,
        Command::Epic1(Epic1Args {
            command: Epic1Command::Pay(mut pay),
            offline,
        }) => {
            if let Some(link) = epic1_link(&pay.link.link) {
                pay.link.link = link;
            }
            return Ok(Command::Epic1(Epic1Args {
                command: Epic1Command::Pay(pay),
                offline,
            }));
        }
        command => return Ok(command),
    };
    let Some(link) = send.destination.to.as_deref().and_then(epic1_link) else {
        if !send.mailboxes.mailboxes.is_empty() {
            return Err(CliError::Arguments(
                "--mailbox has a use only for a payment to an epic1 address".to_owned(),
            ));
        }
        return Ok(Command::Tx(TxCommand::Send(send)));
    };
    let SendArgs {
        amount,
        plain_http,
        tor: TorBinaryArgs { tor_binary, .. },
        fluff,
        account,
        message,
        spend,
        slate_id,
        mailboxes,
        ..
    } = send;
    let unused = [
        (plain_http.allow_plain_http, "--allow-plain-http"),
        (tor_binary.is_some(), "--tor-binary"),
        (fluff.fluff, "--fluff"),
    ];
    if let Some((_, flag)) = unused.iter().find(|(given, _)| *given) {
        return Err(CliError::Arguments(format!(
            "{flag} has no use for a payment to an epic1 address"
        )));
    }
    Ok(Command::Epic1(Epic1Args {
        command: Epic1Command::Pay(Epic1PayArgs {
            link: Epic1LinkArg { link },
            amount,
            account,
            message,
            spend,
            slate_id,
            mailboxes,
        }),
        // `tx` has no `--offline`: a send always reaches the relays.
        offline: false,
    }))
}

/// The epic1 link `to` names: an epic1 link as given, a bare epic1 address as the link without
/// terms that pays it; `None` for any other recipient.
pub(crate) fn epic1_link(to: &str) -> Option<String> {
    if is_epic1(to) {
        return Some(to.to_owned());
    }
    let link = format!("epic:{to}");
    is_epic1(&link).then_some(link)
}

/// `text` after its `epic:` scheme, in either case; `None` when it has none.
pub(crate) fn after_scheme(text: &str) -> Option<&str> {
    text.get(.."epic:".len())
        .filter(|scheme| scheme.eq_ignore_ascii_case("epic:"))
        .and_then(|_| text.get("epic:".len()..))
}

/// Whether `text` is an `epic:` link to an epic1 address, in either case: card QRs write
/// epic1 links in upper case.
pub(crate) fn is_epic1(text: &str) -> bool {
    after_scheme(text).is_some_and(|rest| starts_with(rest, "epic1") || starts_with(rest, "tepic1"))
}

fn starts_with(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use clap::Parser as _;

    use super::{epic1_link, is_epic1, resolve};
    use crate::cli::{Cli, Command, Epic1Args, Epic1Command};
    use crate::exit::CliError;

    #[test]
    fn each_flag_an_epic1_payment_has_no_use_for_is_refused_by_name() {
        let refused = [
            (&["--allow-plain-http"][..], "--allow-plain-http"),
            (&["--tor-binary", "tor"][..], "--tor-binary"),
            (
                &["--tor-binary", "tor", "--lib-dir", "lib"][..],
                "--tor-binary",
            ),
            (&["--fluff"][..], "--fluff"),
        ];
        for (flags, named) in refused {
            let mut line = vec!["lepic", "tx", "send", "1", "--to", "epic1qq"];
            line.extend_from_slice(flags);
            let cli = Cli::try_parse_from(&line).unwrap();
            match resolve(cli.command) {
                Err(CliError::Arguments(message)) => {
                    assert!(message.starts_with(named), "{line:?}: {message}");
                }
                other => panic!("{line:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_mailbox_goes_to_an_epic1_payment_and_is_refused_for_any_other_send() {
        let line = [
            "lepic",
            "tx",
            "send",
            "1",
            "--to",
            "epic1qq",
            "--mailbox",
            "a.example",
            "--mailbox",
            "b.example:8443",
        ];
        let command = resolve(Cli::try_parse_from(line).unwrap().command).unwrap();
        let Command::Epic1(Epic1Args {
            command: Epic1Command::Pay(pay),
            ..
        }) = command
        else {
            panic!("{command:?}");
        };
        assert_eq!(pay.mailboxes.mailboxes, ["a.example", "b.example:8443"]);

        let line = [
            "lepic",
            "tx",
            "send",
            "1",
            "--to",
            "abc@epicbox.example",
            "--mailbox",
            "a.example",
        ];
        match resolve(Cli::try_parse_from(line).unwrap().command) {
            Err(CliError::Arguments(message)) => assert!(message.starts_with("--mailbox")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_epic1_link_is_known_in_either_case() {
        assert!(is_epic1("epic:epic1qq?amount=1"));
        assert!(is_epic1("epic:tepic1qq"));
        assert!(is_epic1("EPIC:TEPIC1QQ?AMOUNT=1"));
    }

    #[test]
    fn a_bare_epic1_address_is_paid_as_its_link_and_others_are_not_epic1() {
        assert_eq!(epic1_link("epic1qq").as_deref(), Some("epic:epic1qq"));
        assert_eq!(
            epic1_link("EPIC:TEPIC1QQ?AMOUNT=1").as_deref(),
            Some("EPIC:TEPIC1QQ?AMOUNT=1")
        );
        assert_eq!(epic1_link("abc@epicbox.example"), None);
        assert_eq!(epic1_link("epic:abc@epicbox.example"), None);
        assert_eq!(epic1_link("https://host.example"), None);
    }
}
