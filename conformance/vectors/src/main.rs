// SPDX-License-Identifier: Apache-2.0
//! Golden vector generator. Runs the pinned reference code and writes one JSON file per case to
//! `testdata/vectors/<area>/<name>.json`, in the format `testdata/vectors/README.md` defines.
//!
//! Usage: `vectors generate [--area <area>] [--out <dir>]`, `vectors list`.

mod app_data;
mod engine;
mod epicbox;
mod keys;
mod primitives;
mod slates;
mod smoke;
mod store;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::Serialize;

/// One entry per vector area. A new area is one module plus one line here.
const AREAS: &[Area] = &[
    Area {
        name: "smoke",
        generate: smoke::generate,
    },
    Area {
        name: "primitives",
        generate: primitives::generate,
    },
    Area {
        name: "aggsig",
        generate: primitives::generate_aggsig,
    },
    Area {
        name: "keys",
        generate: keys::generate,
    },
    Area {
        name: "epicbox",
        generate: epicbox::generate,
    },
    Area {
        name: "slates",
        generate: slates::generate,
    },
    Area {
        name: "engine",
        generate: engine::generate,
    },
    Area {
        name: "app_data",
        generate: app_data::generate,
    },
    Area {
        name: "store",
        generate: store::generate,
    },
];

const SCHEMA: u32 = 1;

const LOCKFILE: &str = include_str!("../../Cargo.lock");

const DEFAULT_OUT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors");

struct Area {
    name: &'static str,
    generate: fn(&Pins) -> Result<Vec<Rendered>, Error>,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("usage: vectors generate [--area <area>] [--out <dir>] | vectors list")]
    Usage,
    #[error("unknown vector area {0:?}")]
    UnknownArea(String),
    #[error("package {0} with a git source is missing from conformance/Cargo.lock")]
    MissingPin(&'static str),
    #[error("i/o error on {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("vector serialization failed")]
    Json(#[from] serde_json::Error),
    #[error("reference code failed while computing {step}")]
    Reference {
        step: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl Error {
    fn reference<E>(step: &'static str) -> impl FnOnce(E) -> Error
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        move |source| Error::Reference {
            step,
            source: Box::new(source),
        }
    }

    fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
        move |source| Error::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// An upstream repository and the commit the reference code was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Upstream {
    repo: String,
    commit: String,
}

/// The upstream commits this build of the generator links, read from `conformance/Cargo.lock` so a
/// vector can never claim a commit other than the one that produced it.
struct Pins {
    node: Upstream,
}

impl Pins {
    fn from_lockfile(lockfile: &str) -> Result<Pins, Error> {
        Ok(Pins {
            node: git_source(lockfile, "epic_core")?,
        })
    }
}

/// Finds `source = "git+<repo>?<ref>#<commit>"` of the named package in a Cargo.lock.
fn git_source(lockfile: &str, package: &'static str) -> Result<Upstream, Error> {
    let name_line = format!("name = \"{package}\"");
    lockfile
        .split("[[package]]")
        .filter(|block| block.lines().any(|line| line.trim() == name_line))
        .find_map(|block| {
            let source = block
                .lines()
                .find_map(|line| line.trim().strip_prefix("source = \"git+"))?
                .strip_suffix('"')?;
            let (url, commit) = source.split_once('#')?;
            let repo = url.split_once('?').map_or(url, |(repo, _)| repo);
            Some(Upstream {
                repo: repo.to_owned(),
                commit: commit.to_owned(),
            })
        })
        .ok_or(Error::MissingPin(package))
}

/// The envelope every vector file shares. Field order here is the key order in the file.
#[derive(Serialize)]
struct Vector<'a, I, E> {
    schema: u32,
    area: &'a str,
    name: &'a str,
    generator: String,
    upstream: &'a Upstream,
    inputs: I,
    expected: E,
}

/// A vector rendered to the exact bytes that go into `<area>/<name>.json`.
struct Rendered {
    name: String,
    bytes: Vec<u8>,
}

fn render<I: Serialize, E: Serialize>(
    area: &str,
    name: &str,
    upstream: &Upstream,
    inputs: I,
    expected: E,
) -> Result<Rendered, Error> {
    render_from(area, area, name, upstream, inputs, expected)
}

/// `module` is the generator module under `conformance/vectors/src`, for an area whose generator
/// is not named after it.
fn render_from<I: Serialize, E: Serialize>(
    module: &str,
    area: &str,
    name: &str,
    upstream: &Upstream,
    inputs: I,
    expected: E,
) -> Result<Rendered, Error> {
    let vector = Vector {
        schema: SCHEMA,
        area,
        name,
        generator: format!("conformance/vectors/{module}"),
        upstream,
        inputs,
        expected,
    };
    let mut text = serde_json::to_string_pretty(&vector)?;
    text.push('\n');
    Ok(Rendered {
        name: name.to_owned(),
        bytes: text.into_bytes(),
    })
}

/// Upstream keeps the chain type in a process-wide lock. A generator that sets or reads it holds
/// this guard for as long as its output depends on the chain type, so generators running on
/// parallel test threads cannot change it under each other.
fn chain_type_guard() -> MutexGuard<'static, ()> {
    static CHAIN_TYPE: Mutex<()> = Mutex::new(());
    CHAIN_TYPE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().fold(String::new(), |mut out, byte| {
        let _infallible = write!(out, "{byte:02x}");
        out
    })
}

/// Writes the area's vectors and removes JSON files in the area directory it no longer produces.
fn write_area(out: &Path, area: &str, vectors: &[Rendered]) -> Result<(), Error> {
    let dir = out.join(area);
    std::fs::create_dir_all(&dir).map_err(Error::io(&dir))?;
    for entry in std::fs::read_dir(&dir).map_err(Error::io(&dir))? {
        let path = entry.map_err(Error::io(&dir))?.path();
        let is_json = path.extension().is_some_and(|ext| ext == "json");
        let produced = path
            .file_stem()
            .is_some_and(|stem| vectors.iter().any(|v| stem == v.name.as_str()));
        if is_json && !produced {
            std::fs::remove_file(&path).map_err(Error::io(&path))?;
            println!("removed {}", path.display());
        }
    }
    for vector in vectors {
        let path = dir.join(format!("{}.json", vector.name));
        std::fs::write(&path, &vector.bytes).map_err(Error::io(&path))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

enum Command {
    Generate { area: Option<String>, out: PathBuf },
    List,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Command, Error> {
    match args.next().as_deref() {
        Some("list") => match args.next() {
            None => Ok(Command::List),
            Some(_) => Err(Error::Usage),
        },
        Some("generate") => {
            let mut area = None;
            let mut out = PathBuf::from(DEFAULT_OUT);
            while let Some(flag) = args.next() {
                let value = args.next().ok_or(Error::Usage)?;
                match flag.as_str() {
                    "--area" => area = Some(value),
                    "--out" => out = PathBuf::from(value),
                    _ => return Err(Error::Usage),
                }
            }
            Ok(Command::Generate { area, out })
        }
        _ => Err(Error::Usage),
    }
}

fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::List => {
            for area in AREAS {
                println!("{}", area.name);
            }
            Ok(())
        }
        Command::Generate { area, out } => {
            let selected: Vec<&Area> = match area {
                None => AREAS.iter().collect(),
                Some(name) => vec![
                    AREAS
                        .iter()
                        .find(|a| a.name == name)
                        .ok_or(Error::UnknownArea(name))?,
                ],
            };
            let pins = Pins::from_lockfile(LOCKFILE)?;
            for area in selected {
                let vectors = (area.generate)(&pins)?;
                write_area(&out, area.name, &vectors)?;
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut message = format!("error: {error}");
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                let _infallible = write!(message, ": {cause}");
                source = cause.source();
            }
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pins of ADR 0020. Changing one is a deliberate pin bump: update the ADR, the lockfile and
    // the regenerated vectors together.
    const NODE_COMMIT: &str = "82fa7e813dc3b9bf137b9dd523d847f4210f5ba4";
    const WALLET_COMMIT: &str = "845b3fcf4df12ed0139929c62157015447a9d063";
    const SECP_COMMIT: &str = "1131a20920576413cd949e012a160561080324c1";
    // The LEPIC crates the differential tests link bring the product workspace's vendored
    // secp256k1-zkp, a path package with no source in the lockfile, so every git copy of it is the
    // reference's.
    const SECP_REPO: &str = "https://github.com/EpicCash/rust-secp256k1-zkp";

    /// The source of the secp256k1-zkp copy that `epic_util`, the reference's crypto boundary,
    /// depends on.
    fn reference_secp_source() -> Option<&'static str> {
        LOCKFILE
            .split("[[package]]")
            .find(|block| {
                block
                    .lines()
                    .any(|line| line.trim() == "name = \"epic_util\"")
            })?
            .lines()
            .find_map(|line| line.trim().strip_prefix("\"grin_secp256k1zkp "))
    }

    #[test]
    fn lockfile_resolves_to_adr_0020_commits() -> Result<(), Error> {
        let expected = [
            ("epic_core", "https://github.com/EpicCash/epic", NODE_COMMIT),
            (
                "epic_wallet_libwallet",
                "https://github.com/EpicCash/epic-wallet",
                WALLET_COMMIT,
            ),
        ];
        for (package, repo, commit) in expected {
            let upstream = git_source(LOCKFILE, package)?;
            assert_eq!(upstream.repo, repo, "{package}");
            assert_eq!(upstream.commit, commit, "{package}");
        }
        assert_eq!(Pins::from_lockfile(LOCKFILE)?.node.commit, NODE_COMMIT);

        // The reference resolves its secp256k1-zkp to the commit its own lockfile records.
        let reference = reference_secp_source().ok_or(Error::MissingPin("grin_secp256k1zkp"))?;
        let resolved = LOCKFILE
            .split("[[package]]")
            .filter(|block| {
                block
                    .lines()
                    .any(|line| line.trim() == "name = \"grin_secp256k1zkp\"")
            })
            .filter_map(|block| {
                block
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("source = \"git+"))
            })
            .find(|source| {
                reference
                    .split_once('(')
                    .and_then(|(_, rest)| rest.strip_prefix("git+"))
                    .and_then(|rest| rest.strip_suffix(")\","))
                    .is_some_and(|url| source.starts_with(&format!("{url}#")))
            })
            .ok_or(Error::MissingPin("grin_secp256k1zkp"))?;
        assert!(
            resolved.starts_with(SECP_REPO) && resolved.ends_with(&format!("#{SECP_COMMIT}\"")),
            "{resolved}"
        );
        Ok(())
    }

    #[test]
    fn every_upstream_crate_resolves_to_a_single_pinned_commit() {
        let pinned: [(&str, &[&str]); 3] = [
            ("https://github.com/EpicCash/epic?", &[NODE_COMMIT]),
            ("https://github.com/EpicCash/epic-wallet?", &[WALLET_COMMIT]),
            (
                "https://github.com/EpicCash/rust-secp256k1-zkp?",
                &[SECP_COMMIT],
            ),
        ];
        let sources = LOCKFILE
            .lines()
            .filter_map(|line| line.trim().strip_prefix("source = \"git+"));
        for source in sources {
            for (repo, commits) in pinned {
                if source.starts_with(repo) {
                    assert!(
                        commits
                            .iter()
                            .any(|commit| source.ends_with(&format!("#{commit}\""))),
                        "{source}"
                    );
                }
            }
        }
    }

    #[test]
    fn missing_package_is_reported() {
        assert!(matches!(
            git_source(LOCKFILE, "no_such_package"),
            Err(Error::MissingPin("no_such_package"))
        ));
    }

    #[test]
    fn unknown_area_is_rejected() {
        let command = Command::Generate {
            area: Some("nope".to_owned()),
            out: PathBuf::from("unused"),
        };
        assert!(matches!(run(command), Err(Error::UnknownArea(name)) if name == "nope"));
    }

    #[test]
    fn generate_requires_a_value_for_each_flag() {
        let args = ["generate", "--area"].map(String::from).into_iter();
        assert!(matches!(parse_args(args), Err(Error::Usage)));
    }
}
