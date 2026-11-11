// SPDX-License-Identifier: Apache-2.0
//! `lepic profile`: what the wallet tells its paired contacts about the host (ADR 0041).

use lepic_wallet_contacts::{
    ContactRelays, DOMAIN_FILE_MAX, DomainFile, RelayMode, WalletContacts as _,
};

#[cfg(unix)]
use super::Opened;
use super::Run;
use crate::cli::{DomainCommand, DomainFileArgs, ProfileCommand, ProfileSetArgs};
use crate::exit::CliError;
use crate::host::Host;
#[cfg(unix)]
use crate::output::ProfileDomainDocumentReport;
use crate::output::{
    ProfileDomainAttachReport, ProfileDomainFileReport, ProfileDomainShowReport, ProfileSetReport,
    ProfileShowReport, Report,
};
use crate::profile::{describe, parse_bits, parse_names};
#[cfg(unix)]
use crate::settings::Settings;
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
                let relays = ContactRelays::new((*opened.epicbox).clone(), RelayMode::Online)
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
            ProfileCommand::Domain(args) => self.domain(args.command).await,
        }
    }

    async fn domain(&mut self, command: DomainCommand) -> Result<Report, CliError> {
        match command {
            DomainCommand::Show => {
                let opened = self.open().await?;
                let key = opened.wallet.contact_book().own_domain_key()?;
                Ok(Report::ProfileDomainShow(ProfileDomainShowReport {
                    domain: self.settings.domain.clone(),
                    network: self.settings.network.to_string(),
                    domain_key: key_hex(&key),
                }))
            }
            DomainCommand::File(args) => {
                let opened = self.open().await?;
                let key = opened.wallet.contact_book().own_domain_key()?;
                write_file(
                    &args,
                    self.settings.network,
                    &key,
                    self.settings.domain.as_deref(),
                )
            }
            DomainCommand::Attach => {
                let domain = self
                    .settings
                    .domain
                    .clone()
                    .ok_or(CliError::DomainNotConfigured)?;
                let opened = self.open().await?;
                let relays = ContactRelays::new((*opened.epicbox).clone(), RelayMode::Online)
                    .with_meeting(self.settings.servers.meeting_relays.clone());
                let queued = opened
                    .wallet
                    .contact_book()
                    .contacts_tell_domain(&relays)
                    .await?;
                Ok(Report::ProfileDomainAttach(ProfileDomainAttachReport {
                    domain,
                    queued,
                }))
            }
        }
    }
}

fn key_hex(key: &lepic_wallet_contacts::VerifyingKey) -> String {
    use std::fmt::Write as _;
    key.as_bytes().iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// The well-known file of this wallet's domain, as a report holding its text.
#[cfg(unix)]
pub(super) fn domain_document<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    settings: &Settings,
    relays: &[String],
) -> Result<Report, CliError> {
    let key = opened.wallet.contact_book().own_domain_key()?;
    let document = domain_file_text(settings.network, &key, relays)?;
    Ok(Report::ProfileDomainDocument(ProfileDomainDocumentReport {
        document,
        url: domain_url(settings.domain.as_deref()),
    }))
}

fn domain_file_text(
    network: lepic_primitives::params::Network,
    key: &lepic_wallet_contacts::VerifyingKey,
    relays: &[String],
) -> Result<String, CliError> {
    use lepic_wallet_contacts::ContactNetwork;
    let network = match network {
        lepic_primitives::params::Network::Mainnet => ContactNetwork::Mainnet,
        lepic_primitives::params::Network::Floonet => ContactNetwork::Floonet,
    };
    let text = DomainFile::render(network, std::slice::from_ref(key), relays);
    if text.len() > DOMAIN_FILE_MAX {
        return Err(CliError::DomainFileTooLarge);
    }
    Ok(text)
}

fn domain_url(domain: Option<&str>) -> Option<String> {
    domain.map(|domain| format!("https://{domain}/.well-known/epic-wallet.json"))
}

fn write_file(
    args: &DomainFileArgs,
    network: lepic_primitives::params::Network,
    key: &lepic_wallet_contacts::VerifyingKey,
    domain: Option<&str>,
) -> Result<Report, CliError> {
    let text = domain_file_text(network, key, &args.relay)?;
    write_text(args.path.as_deref(), args.force, &text, domain_url(domain))
}

/// Writes the domain file `text` to `path` (`./epic-wallet.json` when none), which must not exist
/// unless `force`, and reports it.
pub(super) fn write_text(
    path: Option<&std::path::Path>,
    force: bool,
    text: &str,
    url: Option<String>,
) -> Result<Report, CliError> {
    use std::io::Write as _;
    let path = path.map_or_else(
        || std::path::PathBuf::from("epic-wallet.json"),
        ToOwned::to_owned,
    );
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::FileExists { path: path.clone() }
        } else {
            CliError::Io {
                what: "write the domain file",
                source: error,
            }
        }
    })?;
    file.write_all(text.as_bytes())
        .map_err(CliError::io("write the domain file"))?;
    Ok(Report::ProfileDomainFile(ProfileDomainFileReport {
        path: path.display().to_string(),
        bytes: text.len(),
        url,
    }))
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
