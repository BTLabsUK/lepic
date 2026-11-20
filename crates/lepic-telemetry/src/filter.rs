// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::ffi::OsString;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::TelemetryError;

/// Environment variable read by [`LogFilter::from_env`].
pub const LOG_FILTER_ENV: &str = "LEPIC_LOG";

/// Which spans and events are recorded, in `tracing-subscriber` env-filter
/// syntax, for example `info,lepic_epicbox=debug`. Anything a directive does
/// not cover is recorded at `info` and above.
#[derive(Debug)]
pub struct LogFilter(EnvFilter);

impl LogFilter {
    /// # Errors
    ///
    /// [`TelemetryError::InvalidFilter`] when a directive does not parse.
    pub fn parse(directives: &str) -> Result<Self, TelemetryError> {
        EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .parse(directives)
            .map(Self)
            .map_err(TelemetryError::InvalidFilter)
    }

    /// Reads [`LOG_FILTER_ENV`]; unset or empty means `info`.
    ///
    /// # Errors
    ///
    /// [`TelemetryError::NonUnicodeFilter`] or [`TelemetryError::InvalidFilter`].
    pub fn from_env() -> Result<Self, TelemetryError> {
        Self::from_env_value(env::var_os(LOG_FILTER_ENV))
    }

    fn from_env_value(value: Option<OsString>) -> Result<Self, TelemetryError> {
        match value {
            None => Self::parse(""),
            Some(value) => value
                .to_str()
                .ok_or(TelemetryError::NonUnicodeFilter)
                .and_then(Self::parse),
        }
    }

    pub(crate) fn into_env_filter(self) -> EnvFilter {
        self.0
    }
}

impl Default for LogFilter {
    fn default() -> Self {
        Self(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .parse_lossy(""),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_directive() {
        let result = LogFilter::parse("lepic_wallet=loud");
        assert!(matches!(result, Err(TelemetryError::InvalidFilter(_))));
    }

    #[test]
    fn unset_variable_means_info() {
        let filter = LogFilter::from_env_value(None).unwrap();
        assert_eq!(
            filter.into_env_filter().max_level_hint(),
            Some(LevelFilter::INFO)
        );
    }

    #[test]
    fn variable_value_is_parsed() {
        let filter = LogFilter::from_env_value(Some("trace".into())).unwrap();
        assert_eq!(
            filter.into_env_filter().max_level_hint(),
            Some(LevelFilter::TRACE)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_unicode_variable() {
        use std::os::unix::ffi::OsStringExt;

        let value = OsString::from_vec(vec![0xff, 0xfe]);
        let result = LogFilter::from_env_value(Some(value));
        assert!(matches!(result, Err(TelemetryError::NonUnicodeFilter)));
    }
}
