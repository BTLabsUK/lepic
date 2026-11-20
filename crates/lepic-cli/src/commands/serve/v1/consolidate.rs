// SPDX-License-Identifier: Apache-2.0
//! `POST /outputs/consolidate`: the wallet's outputs spent to itself as fewer outputs.
//!
//! A consolidation is a payment to the wallet itself. One with an `id` takes the job path of a
//! payment create with an id: the id is recorded under the payment scope, becomes the slate id
//! of the self-send, and its repeat answers the payment it made.

use std::num::NonZeroU64;

use lepic_wallet::selection::SelectionError;
use lepic_wallet::send::SendError;
use serde::Deserialize;
use serde_json::Value;

use super::super::Service;
use super::Reply;
use super::events::{self, Change};
use super::payments::{self, Work, uuid};
use super::wallet::resolve;
use crate::amount::format_units;
use crate::api::model::Estimate;
use crate::api::{Category, Context, Listener, Problem, Request, created, ok};
use crate::api_clients::Role;
use crate::cli::{AccountArg, Command, ConsolidateArgs, SendSlateIdArg, WalletCommand};
use crate::commands::consolidate::selection;
use crate::exit::CliError;
use crate::host::Host;
use crate::output::Report;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    max_inputs: Option<NonZeroU64>,
    #[serde(default)]
    inputs: Vec<String>,
    outputs: Option<u64>,
    #[serde(default)]
    dry_run: bool,
    account: Option<String>,
    id: Option<String>,
    min_confirmations: Option<u64>,
}

/// A consolidation, checked: what [`make`] makes. Its id is the slate id of `args`.
pub(in crate::commands::serve) struct Consolidation(ConsolidateArgs);

impl Consolidation {
    pub(in crate::commands::serve) fn id(&self) -> Option<String> {
        self.0.slate_id.slate_id.clone()
    }
}

pub(super) async fn consolidate<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    context: &Context,
) -> Reply {
    request.require(Role::Full)?;
    let value: Value = request.json()?;
    let body: Body = serde_json::from_value(value.clone())
        .map_err(|error| Problem::bad_request("invalid_body", error.to_string()))?;
    if body.max_inputs.is_some() && !body.inputs.is_empty() {
        return Err(Problem::invalid(
            "/inputs",
            "inputs names the outputs to spend; leave out max_inputs with it",
        ));
    }
    let account = resolve(service, body.account.as_deref(), "/account")?;
    let id = match body.id.as_deref() {
        Some(id) if !body.dry_run => Some(uuid(id)?),
        None if !body.dry_run && request.listener() == Listener::Tls => {
            return Err(Problem::invalid(
                "/id",
                "id is required over the owner TLS listener, so a retry cannot spend twice",
            ));
        }
        _ => None,
    };
    let args = ConsolidateArgs {
        max_inputs: body
            .max_inputs
            .map_or(crate::cli::DEFAULT_MAX_INPUTS, NonZeroU64::get),
        inputs: body.inputs,
        outputs: body.outputs.unwrap_or(1),
        dry_run: body.dry_run,
        account: AccountArg {
            account: account.label.clone(),
        },
        min_confirmations: body
            .min_confirmations
            .unwrap_or(lepic_wallet::selection::SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS),
        slate_id: SendSlateIdArg {
            slate_id: id.clone(),
        },
    };
    let (options, request) = selection(&args, account.index).map_err(|(position, hex)| {
        Problem::invalid(
            &format!("/inputs/{position}"),
            format!("{hex} is not an output commitment in hex"),
        )
    })?;
    if args.dry_run {
        let selection = service
            .held
            .wallet
            .estimate_send_to_self(options, request)
            .await
            .map_err(|error| problem(error.into(), &args.inputs).unwrap_or_else(Into::into))?;
        let received = selection
            .total
            .value()
            .saturating_sub(selection.fee.value());
        let estimate = Estimate::new(format_units(selection.fee.value()), format_units(received));
        return payments::with_coins(service, estimate, &account.label, selection.inputs);
    }
    let consolidation = Consolidation(args);
    match id {
        Some(id) => {
            let work = Work::Consolidation(consolidation);
            payments::with_id(service, context, &id, &value, work).await
        }
        None => make(service, consolidation).await,
    }
}

/// Makes the consolidation and answers 201 with its payment, or 200 with the payment a
/// consolidation under the same id made before. When it fails once its payment is stored (the
/// push to the node failed), 201 with that payment, as for a payment create.
pub(in crate::commands::serve) async fn make<H: Host>(
    service: &Service<'_, H>,
    consolidation: Consolidation,
) -> Reply {
    let id = consolidation.id();
    let inputs = consolidation.0.inputs.clone();
    let command = Command::Wallet(WalletCommand::Consolidate(consolidation.0));
    let report = match Box::pin(service.command(command)).await {
        Ok(Report::Consolidate(report)) => report,
        Ok(_) => return Err(internal("the wallet reported no consolidation")),
        // The id was checked new, or its repeat answered, before: a payment under it now was
        // stored by this call.
        Err(error) => {
            return match problem(error, &inputs) {
                Ok(problem) => Err(problem),
                Err(error) => payments::failed(service, id.as_deref(), false, error).await,
            };
        }
    };
    let slate_id = report
        .slate_id
        .ok_or_else(|| internal("the wallet reported no slate id"))?;
    if !report.repeated {
        events::payment(service, &slate_id, Change::Created).await;
    }
    let payment = payments::object(service, &slate_id)
        .await?
        .ok_or_else(|| internal("the consolidation is not a payment of this wallet"))?;
    if report.repeated {
        ok(&payment)
    } else {
        created(&payment)
    }
}

/// The answer to a selection `error` that names a field of the body; any other error back.
fn problem(error: CliError, inputs: &[String]) -> Result<Problem, CliError> {
    match error {
        CliError::Send(SendError::Selection(SelectionError::NamedOutputUnavailable {
            position,
        })) => Ok(Problem::invalid(
            &format!("/inputs/{position}"),
            format!(
                "the output {} cannot be spent now, or is named twice",
                inputs.get(position).map_or("", |hex| hex.trim())
            ),
        )),
        CliError::Send(SendError::Selection(error @ SelectionError::SelfSendOutputs { .. })) => {
            Ok(Problem::invalid("/outputs", error.to_string()))
        }
        error => Err(error),
    }
}

fn internal(detail: &str) -> Problem {
    Problem::of(Category::Internal, "internal", detail.to_owned())
}
