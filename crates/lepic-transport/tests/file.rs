// SPDX-License-Identifier: Apache-2.0
//! The file transport: byte-exact export and import, the size limit, unreadable paths, and its
//! registration.

use std::path::Path;

use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::{MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use lepic_transport::error::{FileError, FileOperation, RegistryError, TransportError};
use lepic_transport::file::{FILE, FileTransport};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Exchange, Location, Transport};

fn location(path: &Path) -> Location {
    Location::File(path.to_path_buf())
}

async fn import(path: &Path) -> Result<WireSlate, TransportError> {
    FileTransport::new().import(&location(path)).await
}

#[tokio::test]
async fn export_writes_the_wire_bytes_unchanged_and_import_reads_them_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tx.slate");
    let text = r#"{"version_info":{"version":2},"id":"x"}"#;
    let wire = WireSlate::text(MediaType::JSON, text.to_owned());

    FileTransport::new()
        .export(&wire, &location(&path))
        .await
        .unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), text.as_bytes());
    let imported = import(&path).await.unwrap();
    assert_eq!(imported.as_bytes(), text.as_bytes());
    assert_eq!(imported.media_type(), MediaType::JSON);
}

#[tokio::test]
async fn export_replaces_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tx.slate");
    std::fs::write(&path, "an older and longer slate file").unwrap();
    let wire = WireSlate::text(MediaType::JSON, "{}".to_owned());

    FileTransport::new()
        .export(&wire, &location(&path))
        .await
        .unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
}

#[tokio::test]
async fn export_into_a_missing_directory_fails_to_create() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("tx.slate");
    let wire = WireSlate::text(MediaType::JSON, "{}".to_owned());

    let error = FileTransport::new()
        .export(&wire, &location(&path))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        TransportError::File(FileError::Io {
            operation: FileOperation::Create,
            ..
        })
    ));
}

#[tokio::test]
async fn imports_a_file_exactly_at_the_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large.slate");
    std::fs::write(&path, vec![b' '; MAX_WIRE_SLATE_LEN]).unwrap();

    assert_eq!(import(&path).await.unwrap().len(), MAX_WIRE_SLATE_LEN);
}

#[tokio::test]
async fn rejects_a_file_over_the_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversized.slate");
    std::fs::write(&path, vec![b' '; MAX_WIRE_SLATE_LEN + 1]).unwrap();

    let error = import(&path).await.unwrap_err();

    assert!(matches!(
        error,
        TransportError::File(FileError::TooLarge { len, max })
            if len == (MAX_WIRE_SLATE_LEN + 1) as u64 && max == MAX_WIRE_SLATE_LEN
    ));
}

#[tokio::test]
async fn rejects_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();

    let error = import(&dir.path().join("absent.slate")).await.unwrap_err();

    assert!(matches!(
        error,
        TransportError::File(FileError::Io {
            operation: FileOperation::Inspect,
            ..
        })
    ));
}

#[tokio::test]
async fn rejects_a_directory() {
    let dir = tempfile::tempdir().unwrap();

    let error = import(dir.path()).await.unwrap_err();

    assert!(matches!(error, TransportError::File(FileError::NotAFile)));
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_a_file_without_read_permission() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locked.slate");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&path).is_ok() {
        // Running as a user that bypasses permission checks; nothing to observe.
        return;
    }

    let error = import(&path).await.unwrap_err();

    assert!(matches!(
        error,
        TransportError::File(FileError::Io {
            operation: FileOperation::Open,
            ..
        })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_a_device_without_reading_it() {
    let error = import(Path::new("/dev/zero")).await.unwrap_err();

    assert!(matches!(error, TransportError::File(FileError::NotAFile)));
}

#[test]
fn file_transport_offers_exchange_only_and_accepts_both_legacy_codecs() {
    let transport = FileTransport::new();

    assert_eq!(transport.id(), FILE);
    assert_eq!(FILE.as_str(), "file");
    assert!(transport.exchange().is_some());
    assert!(transport.outbound().is_none());
    assert!(transport.inbound().is_none());
    assert_eq!(
        transport.policy().accepted(),
        &[LEGACY_V2_JSON, LEGACY_V3_JSON]
    );
}

#[test]
fn registry_finds_a_transport_by_id_and_refuses_a_second_with_the_same_id() {
    let mut registry = TransportRegistry::new();
    registry.register(Box::new(FileTransport::new())).unwrap();

    assert_eq!(registry.get(FILE).map(Transport::id), Some(FILE));
    assert_eq!(registry.ids().collect::<Vec<_>>(), [FILE]);
    assert_eq!(
        registry.register(Box::new(FileTransport::new())),
        Err(RegistryError::DuplicateTransport { transport: FILE })
    );
}
