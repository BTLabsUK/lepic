// SPDX-License-Identifier: Apache-2.0
//! `lepic profile`: what the wallet tells its paired contacts about the host (ADR 0041).

use lepic_wallet_contacts::{ContactRelays, RelayMode, WalletContacts as _};

use super::Run;
use crate::cli::{ProfileCommand, ProfileSetArgs};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{ProfileSetReport, ProfileShowReport, Report};
use crate::profile::{describe, parse_bits, parse_names};
use crate::settings::{Origin, SettingsError};

impl<H: Host> Run<'_, H> {
    pub(super) async fn profile(&mut self, command: ProfileCommand) -> Result<Report, CliError> {
        let configured = self.settings.profile;
        match command {
            ProfileCommand::Show => {
                let (names, unnamed) = describe(u32::from(configured));
                Ok(Report::ProfileShow(ProfileShowReport {
                    profile: configured,
                    names,
                    unnamed,
                }))
            }
            ProfileCommand::Set(args) => {
                let profile = set_value(&args)?;
                let opened = self.open().await?;
                let relays = ContactRelays::new(opened.epicbox.clone(), RelayMode::Online)
                    .with_meeting(self.settings.servers.meeting_relays.clone());
                let queued = opened
                    .wallet
                    .contact_book()
                    .contacts_set_own_profile(&relays, profile)
                    .await?;
                let (names, unnamed) = describe(u32::from(profile));
                Ok(Report::ProfileSet(ProfileSetReport {
                    profile,
                    names,
                    unnamed,
                    queued,
                    configured,
                }))
            }
        }
    }
}

fn set_value(args: &ProfileSetArgs) -> Result<u16, CliError> {
    let invalid = || {
        CliError::from(SettingsError::InvalidValue {
            key: "profile",
            origin: Origin::Flag,
        })
    };
    match (&args.bits, &args.names) {
        (Some(bits), _) => parse_bits(bits).ok_or_else(invalid),
        (None, Some(names)) => parse_names(names).ok_or_else(invalid),
        (None, None) => Err(invalid()),
    }
}
