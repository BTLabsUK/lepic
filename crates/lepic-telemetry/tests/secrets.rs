use std::fmt;

use lepic_telemetry::{Encoding, LeakCheckError, assert_no_secrets, capture};

const SECRET: &[u8] = b"\x8c\x01\xfe\x42seed-material";
const OTHER_SECRET: &[u8] = b"correct horse battery staple";

/// A key type that forgot to redact its `Debug` output.
struct LeakyKey(&'static [u8]);

impl fmt::Debug for LeakyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LeakyKey({})", String::from_utf8_lossy(self.0))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn capture_returns_closure_output_and_all_levels() {
    let (output, captured) = capture(|| {
        let span = tracing::trace_span!("scan", account = "default");
        let _entered = span.enter();
        tracing::trace!("scan step");
        tracing::info!("scan finished");
        42
    });

    assert_eq!(output, 42);
    assert_eq!(captured.records.len(), 2);
    assert_eq!(captured.records[0].spans, ["scan"]);
    assert_eq!(captured.records[1].field("account"), Some("default"));
}

#[test]
fn clean_records_pass() {
    let (_, captured) = capture(|| {
        tracing::info!(slate_id = "0436430c", key = "[redacted]", "slate signed");
    });

    assert_eq!(
        assert_no_secrets(&captured.records, &[SECRET, OTHER_SECRET]),
        Ok(())
    );
}

#[test]
fn catches_secret_in_field_value() {
    let (_, captured) = capture(|| {
        tracing::info!("wallet opened");
        tracing::debug!(
            password = "correct horse battery staple",
            "unlock attempted"
        );
    });

    assert_eq!(
        assert_no_secrets(&captured.records, &[SECRET, OTHER_SECRET]),
        Err(LeakCheckError::Leaked {
            secret: 1,
            record: 1,
            encoding: Encoding::Raw,
        })
    );
}

#[test]
fn catches_secret_in_debug_output() {
    let (_, captured) = capture(|| {
        tracing::debug!(key = ?LeakyKey(OTHER_SECRET), "key derived");
    });

    let result = assert_no_secrets(&captured.records, &[OTHER_SECRET]);
    assert!(matches!(
        result,
        Err(LeakCheckError::Leaked { secret: 0, .. })
    ));
}

#[test]
fn catches_hex_encoded_secret_in_message() {
    let (_, captured) = capture(|| {
        tracing::trace!("blinding factor {}", hex(SECRET));
        tracing::trace!("blinding factor {}", hex(SECRET).to_uppercase());
    });

    assert_eq!(
        assert_no_secrets(&captured.records[..1], &[SECRET]),
        Err(LeakCheckError::Leaked {
            secret: 0,
            record: 0,
            encoding: Encoding::LowerHex,
        })
    );
    assert_eq!(
        assert_no_secrets(&captured.records[1..], &[SECRET]),
        Err(LeakCheckError::Leaked {
            secret: 0,
            record: 0,
            encoding: Encoding::UpperHex,
        })
    );
}

#[test]
fn catches_secret_in_span_field() {
    let (_, captured) = capture(|| {
        let span = tracing::info_span!("restore", mnemonic = "correct horse battery staple");
        let _entered = span.enter();
        tracing::info!("output restored");
    });

    let result = assert_no_secrets(&captured.records, &[OTHER_SECRET]);
    assert!(matches!(result, Err(LeakCheckError::Leaked { .. })));
}

#[test]
fn leak_report_does_not_contain_the_secret() {
    let (_, captured) = capture(|| tracing::info!(seed = %hex(SECRET), "seed loaded"));

    let report = assert_no_secrets(&captured.records, &[SECRET])
        .unwrap_err()
        .to_string();
    assert!(!report.contains(&hex(SECRET)));
    assert_eq!(report, "secret 0 appeared in record 0 as lowercase hex");
}

const KEY: [u8; 4] = [0x8c, 0x01, 0xfe, 0x42];

/// A key type with a derived, unredacted `Debug`.
#[derive(Debug)]
#[allow(dead_code)] // read only through Debug
struct DerivedKey {
    bytes: [u8; 4],
}

fn leak_encoding(f: impl FnOnce()) -> Option<Encoding> {
    let ((), captured) = capture(f);
    match assert_no_secrets(&captured.records, &[&KEY]) {
        Err(LeakCheckError::Leaked { encoding, .. }) => Some(encoding),
        _ => None,
    }
}

#[test]
fn catches_debug_formatted_byte_array() {
    let encoding = leak_encoding(|| tracing::debug!(key = ?KEY, "key derived"));
    assert_eq!(encoding, Some(Encoding::DebugDecimal));
}

#[test]
fn catches_secret_inside_derived_debug() {
    let encoding =
        leak_encoding(|| tracing::debug!(key = ?DerivedKey { bytes: KEY }, "key derived"));
    assert_eq!(encoding, Some(Encoding::DebugDecimal));
}

#[test]
fn catches_byte_slice_field() {
    let encoding = leak_encoding(|| tracing::debug!(key = &KEY[..], "key derived"));
    assert_eq!(encoding, Some(Encoding::SpacedHex));
}

#[test]
fn rejects_empty_secret() {
    assert_eq!(
        assert_no_secrets(&[], &[SECRET, b""]),
        Err(LeakCheckError::EmptySecret { secret: 1 })
    );
}
