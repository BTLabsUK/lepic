// SPDX-License-Identifier: Apache-2.0
//! `lepic peer`: the seal keys pinned for the LEPIC wallets this wallet paid directly.

use std::fmt::Write as _;

use lepic_methods::http::Origin;

use super::Run;
use crate::cli::PeerCommand;
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{PeerForgetReport, PeerPinListReport, PeerPinReport, Report};

impl<H: Host> Run<'_, H> {
    pub(super) async fn peer(&mut self, command: PeerCommand) -> Result<Report, CliError> {
        match command {
            PeerCommand::Pins(args) => {
                let opened = self.open().await?;
                let account = opened.wallet.account(&args.account)?;
                let pins = opened
                    .wallet
                    .peer_pins(account.index)?
                    .into_iter()
                    .map(|pin| PeerPinReport {
                        origin: pin.origin,
                        seal_key: to_hex(&pin.seal_key),
                        first_seen: pin.first_seen.to_string(),
                        last_seen: pin.last_seen.to_string(),
                    })
                    .collect();
                Ok(Report::PeerPins(PeerPinListReport {
                    account: account.label,
                    pins,
                }))
            }
            PeerCommand::Forget(args) => {
                let origin = Origin::parse(&args.origin)
                    .map_err(CliError::PeerOrigin)?
                    .to_string();
                let opened = self.open().await?;
                let account = opened.wallet.account(&args.account.account)?;
                let forgotten = opened.wallet.forget_peer_pin(account.index, &origin)?;
                Ok(Report::PeerForget(PeerForgetReport { origin, forgotten }))
            }
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
