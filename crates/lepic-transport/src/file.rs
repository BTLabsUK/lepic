//! The file method: the user carries a slate file between wallets. Matches the file method of
//! `epic-wallet` `v4.0.2` (`docs/compat/legacy-slates.md`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, FieldProblem};
use lepic_slate::model::Slate;
use lepic_slate::origin::{LegacyHeader, WireOrigin};
use lepic_slate::registry::CodecRegistry;
use lepic_slate::validate::check_size;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{FileError, FileOperation, TransportError};
use crate::policy::{Encoding, FormatPolicy};
use crate::transport::{BoxFuture, Exchange, Location, Transport, TransportId};

pub const FILE: TransportId = TransportId::new("file");

/// Upstream's file method writes `version` and `orig_version` 2 whenever it writes the V2
/// shape, whatever the slate's header says.
const V2_FILE_VERSION: u16 = 2;

/// The receiving wallet writes its reply next to the file it read, under this suffix.
const RESPONSE_SUFFIX: &str = ".response";

/// The file policy of ADR 0003: V2 and V3 accepted; a slate is written in the V2 shape unless
/// it carries a TTL or a payment proof, which only V3 can hold. Replies follow the same rule.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilePolicy;

impl FilePolicy {
    const ACCEPTED: [CodecId; 2] = [LEGACY_V2_JSON, LEGACY_V3_JSON];

    /// The file rule over what it depends on: whether the slate needs V3, and the header the
    /// slate was received with, if any. V3 keeps that header; V2 keeps only its block header
    /// version.
    pub fn choose(
        needs_v3: bool,
        received: Option<LegacyHeader>,
        context: &EncodeContext,
    ) -> Encoding {
        if needs_v3 {
            return Encoding {
                codec: LEGACY_V3_JSON,
                legacy_header: received,
            };
        }
        let block_header_version = received.map_or(context.block_header_version, |header| {
            header.block_header_version
        });
        Encoding {
            codec: LEGACY_V2_JSON,
            legacy_header: Some(LegacyHeader {
                version: V2_FILE_VERSION,
                orig_version: V2_FILE_VERSION,
                block_header_version,
            }),
        }
    }

    fn choose_for(slate: &Slate, context: &EncodeContext) -> Encoding {
        let needs_v3 = slate.ttl_cutoff_height().is_some() || slate.payment_proof().is_some();
        let received = slate.origin().and_then(WireOrigin::legacy_header);
        Self::choose(needs_v3, received, context)
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
        let mut slate: Value =
            serde_json::from_str(text).map_err(|_| DecodeError::UnknownFormat)?;
        match header_version(&slate)? {
            V2_FILE_VERSION_NUMBER => {
                let codec = registered(codecs, LEGACY_V2_JSON)?;
                if remove_v3_keys(&mut slate) {
                    codec.decode(&WireSlate::text(MediaType::JSON, slate.to_string()))
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

/// The keys V3 has and V2 lacks.
const V3_ONLY_KEYS: [&str; 2] = ["ttl_cutoff_height", "payment_proof"];

/// The slate version as upstream's version probe reads it: `version_info.version`; a slate with
/// only a top-level `version` key is version 1, and one with neither is version 0.
fn header_version(slate: &Value) -> Result<u64, DecodeError> {
    let object = slate.as_object().ok_or(DecodeError::UnknownFormat)?;
    match object.get("version_info") {
        Some(info) => info
            .get("version")
            .ok_or(DecodeError::Field {
                field: "version_info.version",
                problem: FieldProblem::Missing,
            })?
            .as_u64()
            .ok_or(DecodeError::Field {
                field: "version_info.version",
                problem: FieldProblem::WrongType,
            }),
        None if object.contains_key("version") => Ok(1),
        None => Err(DecodeError::Field {
            field: "version_info",
            problem: FieldProblem::Missing,
        }),
    }
}

/// Removes the V3-only keys and says whether there were any.
fn remove_v3_keys(slate: &mut Value) -> bool {
    let Some(object) = slate.as_object_mut() else {
        return false;
    };
    let mut removed = false;
    for key in V3_ONLY_KEYS {
        removed |= object.remove(key).is_some();
    }
    removed
}

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
/// file the user is told is written survives a crash.
async fn write_slate_file(path: &Path, wire: &WireSlate) -> Result<(), FileError> {
    let mut file = tokio::fs::File::create(path)
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
    if let Some(flag) = O_NONBLOCK {
        options.custom_flags(flag);
    }
    options.open(path).await
}

// `O_NONBLOCK` from the platform headers, for the targets LEPIC builds for. The value differs
// between kernels and, on Linux, between a few architectures; where it is not known here, the
// inspection before opening is the only guard.
#[cfg(unix)]
const O_NONBLOCK: Option<i32> = if cfg!(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "s390x",
        target_arch = "loongarch64"
    )
)) {
    Some(0o4000)
} else if cfg!(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)) {
    Some(0x0004)
} else {
    None
};

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

    #[test]
    fn new_slate_without_v3_fields_is_v2_with_file_header_at_chain_version() {
        let encoding = FilePolicy::choose(false, None, &CONTEXT);
        assert_eq!(encoding.codec, LEGACY_V2_JSON);
        assert_eq!(encoding.legacy_header, Some(header(2, 7)));
    }

    #[test]
    fn v2_keeps_the_received_block_header_version_but_forces_version_two() {
        let encoding = FilePolicy::choose(false, Some(header(3, 6)), &CONTEXT);
        assert_eq!(encoding.codec, LEGACY_V2_JSON);
        assert_eq!(encoding.legacy_header, Some(header(2, 6)));
    }

    #[test]
    fn slate_needing_v3_is_v3_with_the_received_header_unchanged() {
        let encoding = FilePolicy::choose(true, Some(header(2, 6)), &CONTEXT);
        assert_eq!(encoding.codec, LEGACY_V3_JSON);
        assert_eq!(encoding.legacy_header, Some(header(2, 6)));
    }

    #[test]
    fn new_slate_needing_v3_leaves_the_header_to_the_codec() {
        let encoding = FilePolicy::choose(true, None, &CONTEXT);
        assert_eq!(encoding.codec, LEGACY_V3_JSON);
        assert_eq!(encoding.legacy_header, None);
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
