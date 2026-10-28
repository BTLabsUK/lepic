// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TelemetryError {
    #[error("log filter is not valid")]
    InvalidFilter(#[source] tracing_subscriber::filter::ParseError),
    #[error("log filter environment variable is not unicode")]
    NonUnicodeFilter,
    #[error("log file in {directory} could not be opened")]
    LogFile {
        directory: PathBuf,
        #[source]
        source: tracing_appender::rolling::InitError,
    },
}
