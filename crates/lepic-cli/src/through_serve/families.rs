// SPDX-License-Identifier: Apache-2.0
//! The routes of the contact, in-person, epic1, epictx and profile domain commands (ADR 0053).
//!
//! The routes run online, so a command given `--offline` or `--epicbox-off` runs here. A route
//! spends with the smallest-first selection and has no `--out` file, so a command that asks for
//! another selection or a file runs here too.

use std::path::PathBuf;

use hyper::Method;
use serde_json::json;

use crate::cli::{
    AccountArg, ContactAcceptArgs, ContactArgs, ContactCardArgs, ContactCommand, ContactEnterArgs,
    ContactExportArgs, ContactIdArg, ContactImportArgs, ContactInviteArgs, ContactKeyCheckArgs,
    ContactKeysArgs, ContactLabelArgs, ContactLinkArg, ContactMoveArgs, ContactMoveHomeArgs,
    ContactNameArg, ContactPayloadAckArgs, ContactPayloadArgs, ContactPayloadCommand,
    ContactPayloadPostArgs, ContactRequestAcceptArgs, ContactRequestArgs, ContactRequestIdArg,
    ContactSasArgs, ContactScanArgs, ContactSwitchArgs, DomainCommand, DomainFileArgs, Epic1Args,
    Epic1Command, Epic1LinkArg, Epic1LinkArgs, Epic1PayArgs, Epic1PostAnswerArgs,
    Epic1PostNextArgs, Epic1RetireArgs, EpictxCommand, EpictxOpenArgs, InPersonArgs,
    InPersonCodeArg, InPersonCommand, InPersonFinalizeArgs, InPersonInvoiceArgs, InPersonPayArgs,
    InPersonPostArgs, InPersonReadArgs, InPersonReceiveArgs, InPersonSendArgs, InPersonSlateArg,
    InPersonTakeArgs, MessageArg, OnOffArg, OutFileArg, SelectionArg, SpendArgs,
};
use crate::commands::files;

use super::{Call, Finish, encode};

fn post(target: impl Into<String>) -> Option<Call> {
    Some(Call::new(Method::POST, target.into()))
}

fn post_json(target: impl Into<String>, body: serde_json::Value) -> Option<Call> {
    Some(Call::new(Method::POST, target.into()).json(body))
}

fn get(target: impl Into<String>) -> Option<Call> {
    Some(Call::new(Method::GET, target.into()))
}

fn delete(target: impl Into<String>) -> Option<Call> {
    Some(Call::new(Method::DELETE, target.into()))
}

/// The spending options a route takes: the default selection, and no TTL for a command that has
/// none to give.
fn plain_spend(spend: &SpendArgs, with_ttl: bool) -> Option<(u64, usize, Option<u64>)> {
    let SpendArgs {
        min_confirmations,
        change_outputs,
        selection,
        ttl_blocks,
    } = spend;
    if !matches!(selection, SelectionArg::Smallest) || (ttl_blocks.is_some() && !with_ttl) {
        return None;
    }
    Some((*min_confirmations, *change_outputs, *ttl_blocks))
}

/// A copy of a scanned code that the request body can read once the connection is open.
fn owned_code(code: &InPersonCodeArg) -> InPersonCodeArg {
    InPersonCodeArg {
        hex: code.hex.clone(),
        file: code.file.clone(),
    }
}

#[allow(clippy::too_many_lines)] // one exhaustive match over the command enum
pub(super) fn contact(args: &ContactArgs) -> Option<Call> {
    let ContactArgs {
        command,
        offline,
        epicbox_off,
    } = args;
    if *offline || *epicbox_off {
        return None;
    }
    match command {
        ContactCommand::Invite(ContactInviteArgs {
            name: ContactNameArg { name },
            expiry,
            kind: None,
            pairing_words,
        }) => post_json(
            "/v1/contacts/invites",
            json!({ "name": name, "expiry": expiry, "pairing_words": pairing_words }),
        ),
        ContactCommand::Request(ContactRequestArgs {
            address,
            name: ContactNameArg { name },
        }) => post_json(
            "/v1/contacts/requests",
            json!({ "address": address, "name": name }),
        ),
        ContactCommand::Requests => get("/v1/contacts/requests"),
        ContactCommand::RequestAccept(ContactRequestAcceptArgs {
            request,
            name: ContactNameArg { name },
        }) => post_json(
            format!("/v1/contacts/requests/{}/accept", encode(request)),
            json!({ "name": name }),
        ),
        ContactCommand::RequestDismiss(ContactRequestIdArg { request }) => {
            delete(format!("/v1/contacts/requests/{}", encode(request)))
        }
        ContactCommand::RequestCancel(ContactIdArg { contact }) => {
            delete(format!("/v1/contacts/{}/request", encode(contact)))
        }
        ContactCommand::Open(ContactLinkArg { link }) => {
            post_json("/v1/contacts/preview", json!({ "link": link }))
        }
        ContactCommand::Accept(ContactAcceptArgs {
            link: ContactLinkArg { link },
            name: ContactNameArg { name },
            by_hand,
        }) => post_json(
            "/v1/contacts/accept",
            json!({ "link": link, "name": name, "by_hand": by_hand }),
        ),
        ContactCommand::Enter(ContactEnterArgs { input }) => {
            post_json("/v1/contacts/enter", json!({ "input": input }))
        }
        ContactCommand::Collect => post("/v1/contacts/collect"),
        ContactCommand::Sas(ContactSasArgs {
            contact: ContactIdArg { contact },
            result,
        }) => post_json(
            format!("/v1/contacts/{}/sas", encode(contact)),
            json!({ "result": result }),
        ),
        ContactCommand::ShowCard(ContactCardArgs {
            name: ContactNameArg { name },
            kind: None,
        }) => post_json("/v1/contacts/card", json!({ "name": name })),
        ContactCommand::ScanCard(ContactScanArgs {
            contact: ContactIdArg { contact },
            link,
        }) => post_json(
            "/v1/contacts/cards/scan",
            json!({ "contact": contact, "link": link }),
        ),
        ContactCommand::List => get("/v1/contacts"),
        ContactCommand::Remove(ContactIdArg { contact }) => {
            delete(format!("/v1/contacts/{}", encode(contact)))
        }
        ContactCommand::Label(ContactLabelArgs {
            contact: ContactIdArg { contact },
            label,
        }) => Some(
            Call::new(Method::PATCH, format!("/v1/contacts/{}", encode(contact)))
                .json(json!({ "label": label })),
        ),
        ContactCommand::AllowInvoices(ContactSwitchArgs {
            contact: ContactIdArg { contact },
            state,
        }) => Some(
            Call::new(Method::PATCH, format!("/v1/contacts/{}", encode(contact)))
                .json(json!({ "allow_invoices": matches!(state, OnOffArg::On) })),
        ),
        ContactCommand::Move(ContactMoveArgs {
            contact: ContactIdArg { contact },
            apply,
        }) => post_json(
            format!("/v1/contacts/{}/move", encode(contact)),
            json!({ "host": apply }),
        ),
        ContactCommand::MoveHome(ContactMoveHomeArgs { host, drain_days }) => post_json(
            "/v1/contacts/move-home",
            json!({ "host": host, "drain_days": drain_days }),
        ),
        ContactCommand::Check(ContactIdArg { contact }) => {
            post(format!("/v1/contacts/{}/check", encode(contact)))
        }
        ContactCommand::KeyCheck(ContactKeyCheckArgs { new, old }) => post_json(
            format!("/v1/contacts/{}/key-check", encode(new)),
            json!({ "old": old }),
        ),
        ContactCommand::Keys(ContactKeysArgs { new, choice }) => post_json(
            format!("/v1/contacts/{}/keys", encode(new)),
            json!({ "choice": choice }),
        ),
        ContactCommand::Invoices => get("/v1/contact-invoices"),
        ContactCommand::Quarantine => get("/v1/contacts/quarantine"),
        ContactCommand::Export(ContactExportArgs { file }) => Some(
            Call::new(Method::POST, "/v1/contacts/export".to_owned())
                .finish(Finish::ContactBackup(file.clone())),
        ),
        ContactCommand::Import(ContactImportArgs { file }) => {
            let file = file.clone();
            Some(
                Call::new(Method::POST, "/v1/contacts/import".to_owned())
                    .read(move || Ok(json!({ "backup": files::backup_text(&file)? }))),
            )
        }
        ContactCommand::Payload(ContactPayloadArgs { command }) => payload(command),
        ContactCommand::Invite(_)
        | ContactCommand::ShowCard(_)
        | ContactCommand::Invoice(_)
        | ContactCommand::PayInvoice(_)
        | ContactCommand::Decline(_)
        | ContactCommand::Seal(_)
        | ContactCommand::OpenSealed(_)
        | ContactCommand::SendSlate(_)
        | ContactCommand::Plain(_) => None,
    }
}

fn payload(command: &ContactPayloadCommand) -> Option<Call> {
    match command {
        ContactPayloadCommand::Post(ContactPayloadPostArgs {
            contact: ContactIdArg { contact },
            hex,
            file,
        }) => {
            let target = format!("/v1/contacts/{}/payloads", encode(contact));
            let given = ContactPayloadPostArgs {
                contact: ContactIdArg {
                    contact: contact.clone(),
                },
                hex: hex.clone(),
                file: file.clone(),
            };
            Some(
                Call::new(Method::POST, target)
                    .read(move || Ok(json!({ "payload": files::payload_hex(&given)? }))),
            )
        }
        ContactPayloadCommand::List => get("/v1/payloads"),
        ContactPayloadCommand::Ack(ContactPayloadAckArgs { ids }) => match ids.as_slice() {
            [id] => post(format!("/v1/payloads/{}/ack", encode(id))),
            _ => None,
        },
    }
}

#[allow(clippy::too_many_lines)] // one exhaustive match over the command enum
pub(super) fn in_person(args: &InPersonArgs) -> Option<Call> {
    let InPersonArgs {
        command,
        offline,
        epicbox_off,
    } = args;
    if *offline || *epicbox_off {
        return None;
    }
    match command {
        InPersonCommand::Invoice(InPersonInvoiceArgs {
            amount,
            account: AccountArg { account },
            message: MessageArg { message },
            ttl_blocks,
            out: OutFileArg { out: None },
        }) => post_json(
            "/v1/in-person/invoices",
            json!({
                "amount": amount,
                "account": account,
                "message": message,
                "ttl_blocks": ttl_blocks,
            }),
        ),
        InPersonCommand::Send(InPersonSendArgs {
            amount,
            account: AccountArg { account },
            message: MessageArg { message },
            spend,
            out: OutFileArg { out: None },
        }) => {
            let (min_confirmations, change_outputs, ttl_blocks) = plain_spend(spend, true)?;
            post_json(
                "/v1/in-person/sends",
                json!({
                    "amount": amount,
                    "account": account,
                    "message": message,
                    "ttl_blocks": ttl_blocks,
                    "min_confirmations": min_confirmations,
                    "change_outputs": change_outputs,
                }),
            )
        }
        InPersonCommand::Read(InPersonReadArgs {
            code,
            account: AccountArg { account },
            spend,
        }) => {
            let (min_confirmations, change_outputs, _) = plain_spend(spend, false)?;
            let (code, account) = (owned_code(code), account.clone());
            Some(
                Call::new(Method::POST, "/v1/in-person/read".to_owned()).read(move || {
                    Ok(json!({
                        "code": files::code_hex(&code)?,
                        "account": account,
                        "min_confirmations": min_confirmations,
                        "change_outputs": change_outputs,
                    }))
                }),
            )
        }
        InPersonCommand::Pay(InPersonPayArgs {
            amount,
            code,
            account: AccountArg { account },
            message: MessageArg { message },
            spend,
            out: OutFileArg { out: None },
        }) => {
            let (min_confirmations, change_outputs, _) = plain_spend(spend, false)?;
            let (code, amount, account, message) = (
                owned_code(code),
                amount.clone(),
                account.clone(),
                message.clone(),
            );
            Some(
                Call::new(Method::POST, "/v1/in-person/pay".to_owned()).read(move || {
                    Ok(json!({
                        "amount": amount,
                        "code": files::code_hex(&code)?,
                        "account": account,
                        "message": message,
                        "min_confirmations": min_confirmations,
                        "change_outputs": change_outputs,
                    }))
                }),
            )
        }
        InPersonCommand::Receive(InPersonReceiveArgs {
            code,
            account: AccountArg { account },
            message: MessageArg { message },
            out: OutFileArg { out: None },
        }) => {
            let (code, account, message) = (owned_code(code), account.clone(), message.clone());
            Some(
                Call::new(Method::POST, "/v1/in-person/receive".to_owned()).read(move || {
                    Ok(json!({
                        "code": files::code_hex(&code)?,
                        "account": account,
                        "message": message,
                    }))
                }),
            )
        }
        InPersonCommand::Post(InPersonPostArgs {
            slate: InPersonSlateArg { slate_id },
            relay_ok,
        }) => post_json(
            format!("/v1/in-person/{}/post", encode(slate_id)),
            json!({ "relay_ok": relay_ok }),
        ),
        InPersonCommand::Take(InPersonTakeArgs { input, file }) => {
            let call = Call::new(Method::POST, "/v1/in-person/take".to_owned());
            Some(match file {
                Some(path) => {
                    let path: PathBuf = path.clone();
                    call.read(move || Ok(json!({ "answer": [files::answer_hex(&path)?] })))
                }
                None => call.json(json!({ "answer": input })),
            })
        }
        InPersonCommand::Answers(InPersonSlateArg { slate_id }) => {
            get(format!("/v1/in-person/{}/answers", encode(slate_id)))
        }
        InPersonCommand::Finalize(InPersonFinalizeArgs {
            slate: InPersonSlateArg { slate_id },
            answer,
            fluff,
        }) => post_json(
            format!("/v1/in-person/{}/finalize", encode(slate_id)),
            json!({ "answer": answer, "fluff": fluff.fluff }),
        ),
        InPersonCommand::Invoice(_)
        | InPersonCommand::Send(_)
        | InPersonCommand::Pay(_)
        | InPersonCommand::Receive(_) => None,
    }
}

pub(super) fn epic1(args: &Epic1Args) -> Option<Call> {
    let Epic1Args {
        command,
        offline,
        epicbox_off,
    } = args;
    if *offline || *epicbox_off {
        return None;
    }
    match command {
        Epic1Command::Address(AccountArg { account }) => {
            get(format!("/v1/epic1/address?account={}", encode(account)))
        }
        Epic1Command::Link(Epic1LinkArgs {
            account: AccountArg { account },
            amount,
            message: MessageArg { message },
            printed,
            epicbox,
        }) => post_json(
            "/v1/epic1/links",
            json!({
                "account": account,
                "amount": amount,
                "message": message,
                "printed": printed,
                "relays": epicbox,
            }),
        ),
        Epic1Command::Retire(Epic1RetireArgs {
            account: AccountArg { account },
            n,
        }) => post_json(
            format!("/v1/epic1/links/{n}/retire"),
            json!({ "account": account }),
        ),
        Epic1Command::Links => get("/v1/epic1/links"),
        Epic1Command::Read(Epic1LinkArg { link }) => {
            post_json("/v1/epic1/read", json!({ "link": link }))
        }
        Epic1Command::Pay(Epic1PayArgs {
            link: Epic1LinkArg { link },
            amount,
            account: AccountArg { account },
            message: MessageArg { message },
            spend,
            proof,
            hosts_ok,
        }) => {
            let (min_confirmations, change_outputs, _) = plain_spend(spend, false)?;
            post_json(
                "/v1/epic1/pay",
                json!({
                    "link": link,
                    "amount": amount,
                    "account": account,
                    "message": message,
                    "min_confirmations": min_confirmations,
                    "change_outputs": change_outputs,
                    "proof": proof,
                    "hosts_ok": hosts_ok,
                }),
            )
        }
        Epic1Command::PostNext(Epic1PostNextArgs { slate_id, hosts_ok }) => post_json(
            format!("/v1/epic1/{}/post-next", encode(slate_id)),
            json!({ "hosts_ok": hosts_ok }),
        ),
        Epic1Command::Answers => get("/v1/epic1/answers"),
        Epic1Command::PostAnswer(Epic1PostAnswerArgs { slate_id, relay_ok }) => post_json(
            format!("/v1/epic1/{}/post-answer", encode(slate_id)),
            json!({ "relay_ok": relay_ok }),
        ),
        Epic1Command::Restore => post("/v1/epic1/restore"),
    }
}

/// `epictx open`, for a file or standard input; text given directly is the API's own.
pub(super) fn epictx(command: &EpictxCommand) -> Option<Call> {
    let EpictxCommand::Open(EpictxOpenArgs { input, text: None }) = command else {
        return None;
    };
    let input = input.clone();
    Some(
        Call::new(Method::POST, "/v1/epictx/open".to_owned())
            .read(move || Ok(json!({ "text": files::sealed_text(&input)? }))),
    )
}

pub(super) fn domain(command: &DomainCommand) -> Option<Call> {
    match command {
        DomainCommand::Show => get("/v1/profile/domain"),
        DomainCommand::Attach => post("/v1/profile/domain/attach"),
        DomainCommand::File(DomainFileArgs { path, relay, force }) => Some(
            Call::new(Method::POST, "/v1/profile/domain/file".to_owned())
                .json(json!({ "relays": relay }))
                .finish(Finish::DomainFile {
                    path: path.clone(),
                    force: *force,
                }),
        ),
    }
}
