//! The lepic command-line wallet.

use std::io::{self, Write};

fn main() -> io::Result<()> {
    writeln!(io::stdout().lock(), "lepic {}", env!("CARGO_PKG_VERSION"))
}
