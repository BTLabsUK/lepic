// SPDX-License-Identifier: Apache-2.0
//! `lepic api client`: edits the clients `serve --owner-tls` accepts. Needs no wallet.

use std::io::Read as _;
use std::path::Path;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;

use super::Run;
use crate::api_clients::{Client, Clients, Fingerprint, check_name};
use crate::cli::ApiClientCommand;
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{ApiClientListReport, ApiClientReport, Report};

/// Far above any certificate a client presents.
const MAX_CERTIFICATE_LEN: u64 = 64 * 1024;

impl<H: Host> Run<'_, H> {
    pub(super) fn api_client(&self, command: ApiClientCommand) -> Result<Report, CliError> {
        let mut clients = Clients::read(&self.settings.data_dir)?;
        match command {
            ApiClientCommand::Add(args) => {
                check_name(&args.name)?;
                let client = Client {
                    name: args.name,
                    fingerprint: certificate_fingerprint(&args.certificate)?,
                };
                let report = report(&client);
                clients.add(client)?;
                clients.write()?;
                Ok(Report::ApiClientAdd(report))
            }
            ApiClientCommand::List => Ok(Report::ApiClientList(ApiClientListReport {
                clients: clients.clients().map(report).collect(),
            })),
            ApiClientCommand::Remove(args) => {
                let removed = clients.remove(&args.name)?;
                clients.write()?;
                Ok(Report::ApiClientRemove(report(&removed)))
            }
        }
    }
}

fn report(client: &Client) -> ApiClientReport {
    ApiClientReport {
        name: client.name.clone(),
        fingerprint: client.fingerprint.to_string(),
    }
}

/// The fingerprint of the first certificate in the PEM file at `path`.
fn certificate_fingerprint(path: &Path) -> Result<Fingerprint, CliError> {
    let file = std::fs::File::open(path).map_err(CliError::io("read the certificate"))?;
    let mut pem = Vec::new();
    file.take(MAX_CERTIFICATE_LEN.saturating_add(1))
        .read_to_end(&mut pem)
        .map_err(CliError::io("read the certificate"))?;
    let not_a_certificate = || CliError::ApiClientCertificate {
        path: path.to_owned(),
    };
    if u64::try_from(pem.len()).unwrap_or(u64::MAX) > MAX_CERTIFICATE_LEN {
        return Err(not_a_certificate());
    }
    let certificate = CertificateDer::from_pem_slice(&pem).map_err(|_| not_a_certificate())?;
    Fingerprint::of_ed25519(&certificate).ok_or_else(not_a_certificate)
}
