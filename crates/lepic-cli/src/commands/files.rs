// SPDX-License-Identifier: Apache-2.0
//! The files a command reads and writes on this side when `lepic serve` runs it (ADR 0053).
//!
//! A route takes the bytes of a file in its body and answers the text of one in its report, so
//! the command reads the file before the request and writes it after the answer, with the same
//! limits and errors as when it runs on its own.

use std::path::Path;

use crate::cli::{ContactPayloadPostArgs, InPersonCodeArg};
use crate::exit::CliError;
use crate::output::Report;

use super::contact::{payload_bytes, read_backup, read_sealed, to_hex, write_backup};
use super::in_person::{code_bytes, read_limited};
use super::profile::write_text;

/// The text of a sealed file, or of standard input for `-`.
pub(crate) fn sealed_text(input: &str) -> Result<String, CliError> {
    read_sealed(input)
}

/// A payload as hex: the bytes of the file, or the hex given.
pub(crate) fn payload_hex(args: &ContactPayloadPostArgs) -> Result<String, CliError> {
    match &args.file {
        Some(_) => Ok(to_hex(&payload_bytes(args)?)),
        None => Ok(args.hex.clone().unwrap_or_default()),
    }
}

/// A scanned code as hex: the bytes of the file, or the hex given.
pub(crate) fn code_hex(code: &InPersonCodeArg) -> Result<String, CliError> {
    match &code.file {
        Some(_) => Ok(to_hex(&code_bytes(code)?)),
        None => Ok(code.hex.clone().unwrap_or_default()),
    }
}

/// An answer file as hex.
pub(crate) fn answer_hex(path: &Path) -> Result<String, CliError> {
    Ok(to_hex(&read_limited(path)?))
}

/// The document of a contact backup file.
pub(crate) fn backup_text(file: &Path) -> Result<String, CliError> {
    read_backup(file)
}

/// Writes a contact backup document and reports the file.
pub(crate) fn save_backup(file: &Path, document: &str) -> Result<Report, CliError> {
    write_backup(file, document)
}

/// Writes the domain file and reports it.
pub(crate) fn save_domain_file(
    path: Option<&Path>,
    force: bool,
    text: &str,
    url: Option<String>,
) -> Result<Report, CliError> {
    write_text(path, force, text, url)
}
