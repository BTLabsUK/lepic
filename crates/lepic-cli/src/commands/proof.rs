// SPDX-License-Identifier: Apache-2.0
//! `lepic proof`: the payment proof of a payment to an epic1 address, exported from the paying
//! wallet and verified anywhere (`docs/protocols/epic1-receipt.md`).

use std::io::{Read as _, Write as _};
use std::path::Path;

use lepic_store::TxId;
use lepic_wallet::NodeEndpoint;
use lepic_wallet_contacts::{
    Epic1Receipt, MAX_RECEIPT_LEN, ReceiptOnChain, ReceiptVerdict, WalletContacts as _,
};

use super::{Run, relay_network};
use crate::cli::{ProofCommand, ProofExportArgs, ProofVerifyArgs};
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{ProofExportReport, ProofVerifyReport, Report};
use crate::settings::{Origin, SettingsError};

impl<H: Host> Run<'_, H> {
    pub(super) async fn proof(&mut self, command: ProofCommand) -> Result<Report, CliError> {
        match command {
            ProofCommand::Export(args) => self.proof_export(args).await,
            ProofCommand::Verify(args) => self.proof_verify(&args).await,
        }
    }

    async fn proof_export(&mut self, args: ProofExportArgs) -> Result<Report, CliError> {
        let tx_id = args.tx.tx_id;
        let opened = self.open().await?;
        let receipt = opened
            .wallet
            .contact_book()
            .epic1_receipt(TxId(tx_id))
            .await?
            .ok_or(CliError::NoPaymentProof { tx_id })?;
        match args.out {
            Some(path) => save_proof(&path, args.force, tx_id, &receipt),
            None => Ok(Report::ProofExport(ProofExportReport {
                tx_id,
                path: None,
                proof: receipt,
            })),
        }
    }

    async fn proof_verify(&mut self, args: &ProofVerifyArgs) -> Result<Report, CliError> {
        let text = read_proof(&args.input)?;
        let receipt = Epic1Receipt::parse(&text).ok_or_else(|| CliError::ProofRefused {
            reason: "the file is not a payment proof this release reads".to_owned(),
        })?;
        match receipt.check(Some(relay_network(self.settings.network))) {
            ReceiptVerdict::Valid => {}
            ReceiptVerdict::BadSignature => {
                return Err(CliError::ProofRefused {
                    reason: "its signature does not hold for what it says".to_owned(),
                });
            }
            ReceiptVerdict::Malformed => {
                return Err(CliError::ProofRefused {
                    reason: "a field does not decode, or the network is not the address's"
                        .to_owned(),
                });
            }
            ReceiptVerdict::WrongNetwork => {
                return Err(CliError::ProofRefused {
                    reason: format!(
                        "it is for {}; give --network {} to verify it",
                        receipt.network, receipt.network
                    ),
                });
            }
        }
        let height = if args.on_chain || args.node.is_some() {
            Some(self.kernel_height(&receipt, args.node.as_deref()).await?)
        } else {
            None
        };
        Ok(Report::ProofVerify(ProofVerifyReport {
            valid: true,
            network: receipt.network,
            address: receipt.address,
            amount: receipt.amount,
            kernel_excess: receipt.kernel_excess,
            slate_id: receipt.slate_id,
            on_chain: height.map(|_| true),
            height,
        }))
    }

    /// The height of the receipt's kernel on the chain of `node`, or of the configured node.
    async fn kernel_height(
        &self,
        receipt: &Epic1Receipt,
        node: Option<&str>,
    ) -> Result<u64, CliError> {
        let mut settings = self.settings.clone();
        if let Some(url) = node {
            settings.node = NodeEndpoint::parse(url).map_err(|_| SettingsError::InvalidValue {
                key: "node_url",
                origin: Origin::Flag,
            })?;
        }
        let client = self.host.node(&settings)?;
        match receipt.on_chain(&client).await? {
            Some(ReceiptOnChain::OnChain { height }) => Ok(height.value()),
            Some(ReceiptOnChain::NotOnChain) => Err(CliError::ProofRefused {
                reason: format!(
                    "the chain of {} holds no kernel {}",
                    settings.node.host(),
                    receipt.kernel_excess
                ),
            }),
            // `check` held, so the excess decodes.
            None => Err(CliError::ProofRefused {
                reason: "its kernel excess does not decode".to_owned(),
            }),
        }
    }
}

/// Reads the proof file `input`, or standard input for `-`, up to the longest proof read.
fn read_proof(input: &str) -> Result<String, CliError> {
    let limit = u64::try_from(MAX_RECEIPT_LEN + 1).unwrap_or(u64::MAX);
    let mut data = Vec::new();
    if input == "-" {
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut data)
            .map_err(CliError::io("read the payment proof from standard input"))?;
    } else {
        std::fs::File::open(input)
            .and_then(|file| file.take(limit).read_to_end(&mut data))
            .map_err(CliError::io("read the payment proof"))?;
    }
    String::from_utf8(data).map_err(|_| CliError::ProofRefused {
        reason: "the file is not a payment proof this release reads".to_owned(),
    })
}

/// Writes the proof of `tx_id` to `path`, which must not exist unless `force`, and reports it.
pub(crate) fn save_proof(
    path: &Path,
    force: bool,
    tx_id: u32,
    receipt: &Epic1Receipt,
) -> Result<Report, CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::FileExists {
                path: path.to_owned(),
            }
        } else {
            CliError::Io {
                what: "write the payment proof",
                source: error,
            }
        }
    })?;
    let mut text = receipt.to_text();
    text.push('\n');
    file.write_all(text.as_bytes())
        .map_err(CliError::io("write the payment proof"))?;
    Ok(Report::ProofExport(ProofExportReport {
        tx_id,
        path: Some(path.display().to_string()),
        proof: receipt.clone(),
    }))
}
