// SPDX-License-Identifier: Apache-2.0
//! Error display with the source chain, for the `error` log field.

use core::error::Error;
use core::fmt;

/// Errors nested deeper than this are cut from a log line.
const MAX_ERROR_SOURCES: usize = 16;

/// Displays an error followed by its sources, separated by `": "`.
///
/// Log errors as `error = %ErrorChain(&error)`: the JSON and text formatters otherwise print
/// only the outermost error.
#[derive(Clone, Copy)]
pub struct ErrorChain<'a>(pub &'a (dyn Error + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let sources = core::iter::successors(self.0.source(), |&error| error.source());
        for source in sources.take(MAX_ERROR_SOURCES) {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Outer(std::io::Error);

    impl fmt::Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("could not connect")
        }
    }

    impl Error for Outer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn includes_sources() {
        let error = Outer(std::io::Error::other("refused by peer"));
        assert_eq!(
            ErrorChain(&error).to_string(),
            "could not connect: refused by peer"
        );
    }
}
