// SPDX-License-Identifier: Apache-2.0
//! `lepic wallet consolidate`: the wallet's outputs spent to itself as fewer outputs.

use std::num::NonZeroUsize;

use lepic_node::Propagation;
use lepic_store::AccountIndex;
use lepic_wallet::selection::{
    Commitment, SelectionOptions, SelfInputs, SelfOutputs, SelfSendRequest,
};
use lepic_wallet::self_send::SELF;
use lepic_wallet::send::SendError;

use super::{Run, caller_slate_id};
use crate::cli::ConsolidateArgs;
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{ConsolidateReport, Report};

impl<H: Host> Run<'_, H> {
    pub(super) async fn consolidate(&mut self, args: ConsolidateArgs) -> Result<Report, CliError> {
        let slate_id = args
            .slate_id
            .slate_id
            .as_deref()
            .map(caller_slate_id)
            .transpose()?;
        let opened = self.open().await?;
        let account = opened.wallet.account(&args.account.account)?;
        let (options, request) = selection(&args, account.index).map_err(|(_, hex)| {
            CliError::Arguments(format!("--input {hex} is not an output commitment in hex"))
        })?;
        if args.dry_run {
            let selection = opened
                .wallet
                .estimate_send_to_self(options, request)
                .await?;
            return Ok(Report::Consolidate(ConsolidateReport::of(
                account.label,
                &selection,
                None,
                None,
            )));
        }
        let sent = opened
            .wallet
            .send_to_self_as(options, request, Propagation::Fluff, slate_id)
            .await;
        let sent = match sent.map_err(CliError::from) {
            // A consolidation of the account under the same slate id ran before, or at the
            // same time, and stored its transaction first: nothing is spent again.
            Err(CliError::Send(SendError::SlateIdTaken {
                sent: Some(tx_id), ..
            })) => {
                let entry = opened
                    .wallet
                    .transaction_details(tx_id)
                    .await?
                    .transaction
                    .entry;
                if entry.transport.as_deref() != Some(SELF.as_str())
                    || entry.account != account.index
                {
                    return Err(CliError::SlateIdReused { tx_id: tx_id.0 });
                }
                return Ok(Report::Consolidate(ConsolidateReport {
                    repeated: true,
                    account: account.label,
                    tx_id: Some(tx_id.0),
                    slate_id: entry.slate_id.map(|id| id.to_string()),
                    ..ConsolidateReport::default()
                }));
            }
            sent => sent?,
        };
        let details = opened.wallet.transaction_details(sent.tx_id).await?;
        let slate_id = details.transaction.entry.slate_id.map(|id| id.to_string());
        Ok(Report::Consolidate(ConsolidateReport::of(
            account.label,
            &sent.selection,
            Some(sent.tx_id.0),
            slate_id,
        )))
    }
}

/// The selection options and the request of the consolidation `args` asks of `account`. Fails
/// with the place in `args.inputs` of the first that is not an output commitment in hex, and
/// that input.
pub(crate) fn selection(
    args: &ConsolidateArgs,
    account: AccountIndex,
) -> Result<(SelectionOptions, SelfSendRequest), (usize, &str)> {
    let named = args
        .inputs
        .iter()
        .enumerate()
        .map(|(position, hex)| {
            Commitment::from_hex(hex.trim()).map_err(|_| (position, hex.as_str()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let options = SelectionOptions {
        minimum_confirmations: args.min_confirmations,
        // Zero is refused before, by the CLI and the API.
        max_outputs: NonZeroUsize::new(usize::try_from(args.max_inputs).unwrap_or(usize::MAX))
            .unwrap_or(NonZeroUsize::MIN),
        ..SelectionOptions::new(account)
    };
    let request = SelfSendRequest {
        inputs: if named.is_empty() {
            SelfInputs::All
        } else {
            SelfInputs::Named(named)
        },
        outputs: SelfOutputs::Count(usize::try_from(args.outputs).unwrap_or(usize::MAX)),
    };
    Ok((options, request))
}
