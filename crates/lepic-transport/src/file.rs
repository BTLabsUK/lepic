// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/adapters/file.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! The file method: the user carries a slate file between wallets. Reads the files the file
//! method of `epic-wallet` writes (`docs/compat/legacy-slates.md`) and writes V3 (ADR 0015).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use lepic_legacy_slate::v2_json::{LEGACY_V2_JSON, V2JsonCodec};
use lepic_legacy_slate::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_primitives::params::Network;
pub use lepic_slate::codec::MAX_WIRE_SLATE_LEN;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::origin::{LegacyHeader, WireOrigin};
use lepic_slate::registry::CodecRegistry;
use lepic_slate::validate::check_size;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod probe;

use crate::codecs;
use crate::error::{FileError, FileOperation, FormatError, TransportError};
use crate::method::{Carries, Encoded, Method, Sending};
use crate::policy::{Encoding, FormatPolicy, encode_with};
use crate::transport::{BoxFuture, Exchange, Location, Transport, TransportId};
use lepic_legacy_slate::marker::v3::MarkedV3JsonCodec;

pub const FILE: TransportId = TransportId::new("file");

/// `version` and `orig_version` of every file LEPIC writes. A reader dispatches on `version`
/// (`Slate::deserialize_upgrade` upstream), so a V3-shaped file must say 3 or its TTL and payment
/// proof are dropped on read.
const V3_FILE_VERSION: u16 = 3;

/// The receiving wallet writes its reply next to the file it read, under this suffix.
const RESPONSE_SUFFIX: &str = ".response";

/// The file policy of ADR 0015: V2 and V3 accepted; new slates and replies are written in the V3
/// shape with header `3/3/<b>`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilePolicy;

impl FilePolicy {
    const ACCEPTED: [CodecId; 2] = [LEGACY_V2_JSON, LEGACY_V3_JSON];

    /// The file rule over the header the slate was received with, if any: `<b>` is that header's
    /// block header version, or the chain's for a slate this wallet starts.
    pub fn choose(received: Option<LegacyHeader>, context: &EncodeContext) -> Encoding {
        let block_header_version = received.map_or(context.block_header_version, |header| {
            header.block_header_version
        });
        Encoding {
            codec: LEGACY_V3_JSON,
            legacy_header: Some(LegacyHeader {
                version: V3_FILE_VERSION,
                orig_version: V3_FILE_VERSION,
                block_header_version,
            }),
        }
    }

    fn choose_for(slate: &Slate, context: &EncodeContext) -> Encoding {
        Self::choose(slate.origin().and_then(WireOrigin::legacy_header), context)
    }
}

impl FormatPolicy for FilePolicy {
    fn accepted(&self) -> &[CodecId] {
        &Self::ACCEPTED
    }

    fn for_new_slate(&self, slate: &Slate, context: &EncodeContext) -> Encoding {
        Self::choose_for(slate, context)
    }

    fn for_reply(&self, slate: &Slate, context: &EncodeContext) -> Encoding {
        Self::choose_for(slate, context)
    }

    /// Dispatches on `version_info.version`, as upstream's file method does
    /// (`Slate::deserialize_upgrade`), not on the JSON shape: version 2 is read as V2 with any V3
    /// keys ignored, so a V3-shaped file with a version 2 header loses its TTL and payment proof
    /// exactly as it does upstream, and version 3 is read as V3 only.
    fn decode(&self, codecs: &CodecRegistry, wire: &WireSlate) -> Result<Slate, DecodeError> {
        check_size(wire)?;
        let text = wire.as_text().ok_or(DecodeError::UnknownFormat)?;
        let header = probe::read_header(text)?;
        match header.version {
            V2_FILE_VERSION_NUMBER => {
                let codec = registered(codecs, LEGACY_V2_JSON)?;
                if header.has_v3_only_keys {
                    let stripped = probe::without_v3_only_keys(text)?;
                    codec.decode(&WireSlate::text(MediaType::JSON, stripped))
                } else {
                    codec.decode(wire)
                }
            }
            V3_FILE_VERSION_NUMBER => registered(codecs, LEGACY_V3_JSON)?.decode(wire),
            version => Err(DecodeError::UnsupportedVersion {
                codec: LEGACY_V3_JSON,
                version,
            }),
        }
    }
}

const V2_FILE_VERSION_NUMBER: u64 = 2;
const V3_FILE_VERSION_NUMBER: u64 = 3;

fn registered(codecs: &CodecRegistry, id: CodecId) -> Result<&dyn Codec, DecodeError> {
    codecs.get(id).ok_or(DecodeError::UnknownFormat)
}

/// The file method. Exports write the wire slate's bytes unchanged; imports read at most
/// [`MAX_WIRE_SLATE_LEN`] bytes from a regular file.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileTransport {
    policy: FilePolicy,
}

impl FileTransport {
    pub const fn new() -> Self {
        Self { policy: FilePolicy }
    }
}

impl Transport for FileTransport {
    fn id(&self) -> TransportId {
        FILE
    }

    fn policy(&self) -> &dyn FormatPolicy {
        &self.policy
    }

    fn exchange(&self) -> Option<&dyn Exchange> {
        Some(self)
    }
}

impl Method for FileTransport {
    fn carries(&self) -> Carries {
        Carries::new(true)
    }

    fn notice_lengths(&self) -> &'static [usize] {
        &[]
    }

    /// A slate file names no peer: whoever holds it may answer it.
    fn peer_key(&self, _network: Network, _address: &str) -> Result<String, TransportError> {
        Err(TransportError::UnknownDestination { transport: FILE })
    }

    fn encode_new(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
    ) -> Result<Encoded, FormatError> {
        let base_fee = sending.network.params().default_base_fee();
        // A slate that carries the reply key in the LEPIC marker lets a LEPIC receiver answer
        // sealed (RFC 0002 5); stock wallets ignore the extra key.
        let codecs = match sending.reply_key {
            Some(key) => codecs::legacy_with(
                Box::new(MarkedV3JsonCodec::new(V3JsonCodec::new(base_fee)).with_reply_key(key)),
                Box::new(V2JsonCodec::new(base_fee)),
            ),
            None => codecs::legacy(base_fee),
        };
        let encoding = self.policy.for_new_slate(slate, context);
        let wire = encode_with(&codecs, encoding, slate, context)?;
        Ok(Encoded {
            wire,
            codec: encoding.codec,
        })
    }
}

impl Exchange for FileTransport {
    fn export<'a>(
        &'a self,
        wire: &'a WireSlate,
        to: &'a Location,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            match to {
                Location::File(path) => Ok(write_slate_file(path, wire).await?),
            }
        })
    }

    fn import<'a>(
        &'a self,
        from: &'a Location,
    ) -> BoxFuture<'a, Result<WireSlate, TransportError>> {
        Box::pin(async move {
            match from {
                Location::File(path) => Ok(read_slate_file(path).await?),
            }
        })
    }
}

/// Where the reply to the slate file at `input` goes: `<input>.response`, as the `epic-wallet`
/// CLI names it.
pub fn response_path(input: &Path) -> PathBuf {
    let mut name = OsString::from(input.as_os_str());
    name.push(RESPONSE_SUFFIX);
    PathBuf::from(name)
}

fn io_error(operation: FileOperation) -> impl FnOnce(std::io::Error) -> FileError {
    move |source| FileError::Io { operation, source }
}

/// Creates or truncates the file, as upstream does, and syncs it before returning so that a
/// file the user is told is written survives a crash. A symbolic link at `path` is refused
/// rather than followed, so the slate lands in the file the user named and nowhere else.
async fn write_slate_file(path: &Path, wire: &WireSlate) -> Result<(), FileError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.custom_flags(lepic_primitives::open_flags::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .await
        .map_err(io_error(FileOperation::Create))?;
    file.write_all(wire.as_bytes())
        .await
        .map_err(io_error(FileOperation::Write))?;
    file.flush().await.map_err(io_error(FileOperation::Write))?;
    file.sync_all()
        .await
        .map_err(io_error(FileOperation::Sync))?;
    Ok(())
}

async fn read_slate_file(path: &Path) -> Result<WireSlate, FileError> {
    let max = MAX_WIRE_SLATE_LEN;
    let max_len = u64::try_from(max).unwrap_or(u64::MAX);
    // Checked before opening, because opening a FIFO or a device can block or have effects.
    check_slate_file(
        &tokio::fs::metadata(path)
            .await
            .map_err(io_error(FileOperation::Inspect))?,
        max_len,
    )?;
    let file = open_for_reading(path)
        .await
        .map_err(io_error(FileOperation::Open))?;
    // Checked again on the open file, which may not be the one inspected above.
    let len = check_slate_file(
        &file
            .metadata()
            .await
            .map_err(io_error(FileOperation::Inspect))?,
        max_len,
    )?;
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(max).min(max));
    // A file can grow after it was inspected, so the read itself is bounded as well.
    file.take(max_len.saturating_add(1))
        .read_to_end(&mut bytes)
        .await
        .map_err(io_error(FileOperation::Read))?;
    if bytes.len() > max {
        return Err(FileError::TooLarge {
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            max,
        });
    }
    // The file policy accepts only JSON codecs; a file in another format fails their decode.
    Ok(WireSlate::binary(MediaType::JSON, bytes))
}

fn check_slate_file(metadata: &std::fs::Metadata, max_len: u64) -> Result<u64, FileError> {
    if !metadata.is_file() {
        return Err(FileError::NotAFile);
    }
    let len = metadata.len();
    if len > max_len {
        return Err(FileError::TooLarge {
            len,
            max: MAX_WIRE_SLATE_LEN,
        });
    }
    Ok(len)
}

/// Opens for reading without blocking on a FIFO or device that replaced the regular file after
/// it was inspected; the open file is checked again before anything is read.
async fn open_for_reading(path: &Path) -> std::io::Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(lepic_primitives::open_flags::O_NONBLOCK);
    options.open(path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: EncodeContext = EncodeContext {
        block_header_version: 7,
    };

    const fn header(version: u16, block_header_version: u16) -> LegacyHeader {
        LegacyHeader {
            version,
            orig_version: version,
            block_header_version,
        }
    }

    /// Without `O_NONBLOCK` this open waits for a writer forever; the test then opens one to
    /// release it and fails.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[tokio::test]
    async fn opening_a_fifo_swapped_in_after_inspection_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("swapped.slate");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|status| status.success()) {
            // No mkfifo on this host; nothing to observe.
            return;
        }

        let opened =
            tokio::time::timeout(std::time::Duration::from_secs(5), open_for_reading(&fifo)).await;
        if opened.is_err() {
            let _writer = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("opening the fifo blocked");
        }

        let file = opened.unwrap().unwrap();
        assert!(matches!(
            check_slate_file(&file.metadata().await.unwrap(), 1),
            Err(FileError::NotAFile)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    #[tokio::test]
    async fn a_link_at_the_destination_is_refused_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"untouched").unwrap();
        let reply = dir.path().join("tx.slate.response");
        std::os::unix::fs::symlink(&outside, &reply).unwrap();

        let wire = WireSlate::text(MediaType::JSON, "{}".to_owned());
        assert!(matches!(
            write_slate_file(&reply, &wire).await,
            Err(FileError::Io {
                operation: FileOperation::Create,
                ..
            })
        ));
        assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");

        let plain = dir.path().join("plain.slate");
        std::fs::write(&plain, b"older and longer").unwrap();
        write_slate_file(&plain, &wire).await.unwrap();
        assert_eq!(std::fs::read(&plain).unwrap(), b"{}");
    }

    #[test]
    fn new_slate_is_v3_with_header_three_at_chain_version() {
        let encoding = FilePolicy::choose(None, &CONTEXT);
        assert_eq!(encoding.codec, LEGACY_V3_JSON);
        assert_eq!(encoding.legacy_header, Some(header(3, 7)));
    }

    #[test]
    fn reply_to_a_version_two_file_is_v3_with_header_three_at_the_received_version() {
        let encoding = FilePolicy::choose(Some(header(2, 6)), &CONTEXT);
        assert_eq!(encoding.codec, LEGACY_V3_JSON);
        assert_eq!(encoding.legacy_header, Some(header(3, 6)));
    }

    #[test]
    fn reply_to_a_version_three_file_keeps_its_header() {
        let encoding = FilePolicy::choose(Some(header(3, 6)), &CONTEXT);
        assert_eq!(encoding.codec, LEGACY_V3_JSON);
        assert_eq!(encoding.legacy_header, Some(header(3, 6)));
    }

    #[test]
    fn reply_forces_version_three_even_when_orig_version_differs() {
        let received = LegacyHeader {
            version: 2,
            orig_version: 3,
            block_header_version: 7,
        };
        let encoding = FilePolicy::choose(Some(received), &CONTEXT);
        assert_eq!(encoding.legacy_header, Some(header(3, 7)));
    }

    #[test]
    fn response_path_appends_the_suffix_to_the_whole_name() {
        assert_eq!(
            response_path(Path::new("dir/tx.slate")),
            PathBuf::from("dir/tx.slate.response")
        );
        assert_eq!(response_path(Path::new("tx")), PathBuf::from("tx.response"));
    }
}
