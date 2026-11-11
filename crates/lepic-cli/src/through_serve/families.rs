// SPDX-License-Identifier: Apache-2.0
//! The contact, in-person, epic1, epictx and profile domain commands serve can run (ADR 0053).
//!
//! serve runs these online, so a command given `--offline` or `--epicbox-off` runs here. serve
//! spends with the smallest-first selection and writes no `--out` file, so a command that asks for
//! another selection or a file runs here too. A command that reads a file or standard input is
//! sent with the content in its inline form.

use crate::cli::{
    Command, ContactArgs, ContactCommand, ContactExportArgs, ContactImportArgs, ContactInviteArgs,
    ContactPayloadAckArgs, ContactPayloadArgs, ContactPayloadCommand, ContactPayloadPostArgs,
    DomainCommand, DomainFileArgs, Epic1Args, Epic1Command, Epic1PayArgs, EpictxCommand,
    EpictxOpenArgs, InPersonArgs, InPersonCodeArg, InPersonCommand, InPersonInvoiceArgs,
    InPersonPayArgs, InPersonReadArgs, InPersonReceiveArgs, InPersonSendArgs, InPersonTakeArgs,
    OutFileArg, SelectionArg, SpendArgs,
};
use crate::commands::files;

use super::{Call, CliCall, Finish};

/// Whether the spending options are the ones serve takes: the default selection, and no TTL for a
/// command that has none to give.
const fn plain_spend(spend: &SpendArgs, with_ttl: bool) -> bool {
    matches!(spend.selection, SelectionArg::Smallest) && (with_ttl || spend.ttl_blocks.is_none())
}

pub(super) fn contact(command: &Command, args: &ContactArgs) -> Option<Call> {
    let ContactArgs {
        command: contact,
        offline,
        epicbox_off,
    } = args;
    if *offline || *epicbox_off {
        return None;
    }
    match contact {
        ContactCommand::Invite(ContactInviteArgs { kind: None, .. })
        | ContactCommand::Request(_)
        | ContactCommand::Requests
        | ContactCommand::RequestAccept(_)
        | ContactCommand::RequestDismiss(_)
        | ContactCommand::RequestCancel(_)
        | ContactCommand::Open(_)
        | ContactCommand::Accept(_)
        | ContactCommand::Enter(_)
        | ContactCommand::Collect
        | ContactCommand::Sas(_)
        | ContactCommand::List
        | ContactCommand::Remove(_)
        | ContactCommand::Label(_)
        | ContactCommand::AllowInvoices(_)
        | ContactCommand::Move(_)
        | ContactCommand::MoveHome(_)
        | ContactCommand::Check(_)
        | ContactCommand::KeyCheck(_)
        | ContactCommand::Keys(_)
        | ContactCommand::Invoices
        | ContactCommand::Quarantine => Call::command(command),
        ContactCommand::Export(ContactExportArgs { file }) => {
            Some(Call::ready(CliCall::ContactExport).finish(Finish::ContactBackup(file.clone())))
        }
        ContactCommand::Import(ContactImportArgs { file }) => {
            let file = file.clone();
            Some(Call::read(move || {
                Ok(CliCall::ContactImport {
                    document: files::backup_text(&file)?,
                })
            }))
        }
        ContactCommand::Payload(ContactPayloadArgs { command: payload }) => {
            self::payload(command, payload)
        }
        ContactCommand::Invite(_)
        | ContactCommand::Invoice(_)
        | ContactCommand::PayInvoice(_)
        | ContactCommand::Decline(_)
        | ContactCommand::Seal(_)
        | ContactCommand::OpenSealed(_)
        | ContactCommand::SendSlate(_)
        | ContactCommand::Plain(_) => None,
    }
}

fn payload(command: &Command, payload: &ContactPayloadCommand) -> Option<Call> {
    match payload {
        ContactPayloadCommand::Post(ContactPayloadPostArgs { file: None, .. }) => {
            Call::command(command)
        }
        ContactPayloadCommand::Post(given) => {
            let given = given.clone();
            Some(Call::read(move || {
                let hex = files::payload_hex(&given)?;
                Ok(CliCall::of(Command::Contact(ContactArgs {
                    command: ContactCommand::Payload(ContactPayloadArgs {
                        command: ContactPayloadCommand::Post(ContactPayloadPostArgs {
                            hex: Some(hex),
                            file: None,
                            ..given
                        }),
                    }),
                    offline: false,
                    epicbox_off: false,
                })))
            }))
        }
        ContactPayloadCommand::List => Call::command(command),
        ContactPayloadCommand::Ack(ContactPayloadAckArgs { ids }) => match ids.as_slice() {
            [_] => Call::command(command),
            _ => None,
        },
    }
}

/// `command` with the scanned code `code` read here, when it names a file; as it is otherwise.
fn coded(
    command: &Command,
    code: &InPersonCodeArg,
    rebuilt: impl FnOnce(InPersonCodeArg) -> InPersonCommand + Send + 'static,
) -> Option<Call> {
    if code.file.is_none() {
        return Call::command(command);
    }
    let code = code.clone();
    Some(Call::read(move || {
        let hex = files::code_hex(&code)?;
        Ok(CliCall::of(Command::InPerson(InPersonArgs {
            command: rebuilt(InPersonCodeArg {
                hex: Some(hex),
                file: None,
            }),
            offline: false,
            epicbox_off: false,
        })))
    }))
}

/// `in-person pay`: the scanned code is read here when it names a file.
fn in_person_pay(command: &Command, pay: &InPersonPayArgs) -> Option<Call> {
    let InPersonPayArgs {
        amount,
        code,
        account,
        message,
        spend,
        out: OutFileArg { out: None },
    } = pay
    else {
        return None;
    };
    if !plain_spend(spend, false) {
        return None;
    }
    let (amount, account, message, spend) = (
        amount.clone(),
        account.clone(),
        message.clone(),
        spend.clone(),
    );
    coded(command, code, move |code| {
        InPersonCommand::Pay(InPersonPayArgs {
            amount,
            code,
            account,
            message,
            spend,
            out: OutFileArg { out: None },
        })
    })
}

/// `in-person receive`: the scanned code is read here when it names a file.
fn in_person_receive(command: &Command, receive: &InPersonReceiveArgs) -> Option<Call> {
    let InPersonReceiveArgs {
        code,
        account,
        message,
        out: OutFileArg { out: None },
    } = receive
    else {
        return None;
    };
    let (account, message) = (account.clone(), message.clone());
    coded(command, code, move |code| {
        InPersonCommand::Receive(InPersonReceiveArgs {
            code,
            account,
            message,
            out: OutFileArg { out: None },
        })
    })
}

pub(super) fn in_person(command: &Command, args: &InPersonArgs) -> Option<Call> {
    let InPersonArgs {
        command: in_person,
        offline,
        epicbox_off,
    } = args;
    if *offline || *epicbox_off {
        return None;
    }
    match in_person {
        InPersonCommand::Invoice(InPersonInvoiceArgs {
            out: OutFileArg { out: None },
            ..
        })
        | InPersonCommand::Post(_)
        | InPersonCommand::Answers(_)
        | InPersonCommand::Finalize(_) => Call::command(command),
        InPersonCommand::Send(InPersonSendArgs {
            spend,
            out: OutFileArg { out: None },
            ..
        }) => plain_spend(spend, true).then(|| Call::command(command))?,
        InPersonCommand::Read(InPersonReadArgs {
            code,
            account,
            spend,
        }) => {
            if !plain_spend(spend, false) {
                return None;
            }
            let (account, spend) = (account.clone(), spend.clone());
            coded(command, code, move |code| {
                InPersonCommand::Read(InPersonReadArgs {
                    code,
                    account,
                    spend,
                })
            })
        }
        InPersonCommand::Pay(pay) => in_person_pay(command, pay),
        InPersonCommand::Receive(receive) => in_person_receive(command, receive),
        InPersonCommand::Take(InPersonTakeArgs { file: None, .. }) => Call::command(command),
        InPersonCommand::Take(InPersonTakeArgs {
            file: Some(path), ..
        }) => {
            let path = path.clone();
            Some(Call::read(move || {
                Ok(CliCall::of(Command::InPerson(InPersonArgs {
                    command: InPersonCommand::Take(InPersonTakeArgs {
                        input: vec![files::answer_hex(&path)?],
                        file: None,
                    }),
                    offline: false,
                    epicbox_off: false,
                })))
            }))
        }
        InPersonCommand::Invoice(_) | InPersonCommand::Send(_) => None,
    }
}

pub(super) fn epic1(command: &Command, args: &Epic1Args) -> Option<Call> {
    let Epic1Args {
        command: epic1,
        offline,
        epicbox_off,
    } = args;
    if *offline || *epicbox_off {
        return None;
    }
    match epic1 {
        Epic1Command::Pay(Epic1PayArgs { spend, .. }) => {
            plain_spend(spend, false).then(|| Call::command(command))?
        }
        Epic1Command::Address(_)
        | Epic1Command::NewAddress(_)
        | Epic1Command::Addresses(_)
        | Epic1Command::Link(_)
        | Epic1Command::Retire(_)
        | Epic1Command::Links
        | Epic1Command::Read(_)
        | Epic1Command::PostNext(_)
        | Epic1Command::Answers
        | Epic1Command::PostAnswer(_)
        | Epic1Command::Restore
        | Epic1Command::IssueHere => Call::command(command),
    }
}

/// `epictx open`: a file or standard input is read here; text given directly is serve's own.
pub(super) fn epictx(command: &Command, args: &EpictxCommand) -> Option<Call> {
    let EpictxCommand::Open(EpictxOpenArgs { input, text }) = args;
    if text.is_some() {
        return Call::command(command);
    }
    let input = input.clone();
    Some(Call::read(move || {
        let text = Some(files::sealed_text(&input)?);
        Ok(CliCall::of(Command::Epictx(EpictxCommand::Open(
            EpictxOpenArgs { input, text },
        ))))
    }))
}

pub(super) fn domain(command: &Command, args: &DomainCommand) -> Option<Call> {
    match args {
        DomainCommand::Show | DomainCommand::Attach => Call::command(command),
        DomainCommand::File(DomainFileArgs { path, relay, force }) => Some(
            Call::ready(CliCall::DomainFile {
                relays: relay.clone(),
            })
            .finish(Finish::DomainFile {
                path: path.clone(),
                force: *force,
            }),
        ),
    }
}
