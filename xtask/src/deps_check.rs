use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::cargo;

const ARCHITECTURE_DOC: &str = "docs/architecture.md";
const EDGES_HEADING: &str = "## Allowed dependency edges";
const DEV_DEPENDENCY_ANYWHERE: &str = "lepic-telemetry";
/// Dev-dependency edges `docs/architecture.md` allows besides its block: the engine's tests
/// drive the contacts crate through the engine's own test harness (ADR 0029).
const DEV_ONLY_EDGES: &[(&str, &str)] = &[("lepic-wallet", "lepic-wallet-contacts")];
/// Members that are repository tooling rather than product crates. They may depend on no member.
const TOOLING_MEMBERS: &[&str] = &["xtask"];

/// Crates that do no I/O, read no clock and create no randomness (`docs/architecture.md`).
pub(crate) const PURE_CRATES: &[&str] = &[
    "lepic-crypto",
    "lepic-primitives",
    "lepic-keychain",
    "lepic-slate",
    "lepic-contact",
];

/// Runtime, network, storage, logging-output and OS-randomness crates a pure crate may not take
/// as a normal or build dependency.
const IMPURE_FOR_PURE_CRATES: &[&str] = &[
    "tokio",
    "tokio-tungstenite",
    "tokio-rustls",
    "futures-util",
    "hyper",
    "hyper-util",
    "hyper-rustls",
    "http-body-util",
    "rustls",
    "webpki-roots",
    "rusqlite",
    "tempfile",
    "getrandom",
    "tracing-appender",
    "tracing-subscriber",
    "clap",
    "flutter_rust_bridge",
];

/// Features through which a pure crate would draw OS randomness or read the clock itself.
const IMPURE_FEATURES: &[(&str, &[&str])] = &[
    ("rand", &["default", "sys_rng", "thread_rng"]),
    ("jiff", &["default", "std"]),
];

// Mirrors `[bans].deny` in deny.toml; `banned_list_matches_deny_toml` keeps them equal.
const BANNED: &[&str] = &[
    "randomx",
    "progpow",
    "progpow_cpu",
    "croaring",
    "croaring-sys",
    "lmdb",
    "lmdb-sys",
    "lmdb-zero",
    "liblmdb-sys",
    "lmdb-rkv",
    "lmdb-rkv-sys",
    "lmdb-master-sys",
    "openssl",
    "openssl-sys",
    "openssl-src",
    "native-tls",
    "tokio-native-tls",
    "hyper-tls",
    "aws-lc-rs",
    "aws-lc-sys",
    "cmake",
    "bindgen",
    "cxx",
    "cxx-build",
    "cxx-gen",
    "cxxbridge-cmd",
    "cxxbridge-flags",
    "cxxbridge-macro",
    "link-cplusplus",
    "autocxx",
    "autocxx-build",
    "cpp_build",
];

// ADR 0010 allows these deeper in the graph but not as direct dependencies of
// a workspace crate. cargo-deny cannot express that rule.
const NOT_DIRECT: &[&str] = &[
    "failure",
    "log4rs",
    "lazy_static",
    "once_cell",
    "chrono",
    "log",
];

pub(crate) fn run(root: &Path) -> Result<()> {
    let violations = check_workspace(&root.join(ARCHITECTURE_DOC), &root.join("Cargo.toml"))?;
    if violations.is_empty() {
        eprintln!("deps-check: ok");
        return Ok(());
    }
    for violation in &violations {
        eprintln!("deps-check: {violation}");
    }
    bail!("{} dependency policy violation(s)", violations.len())
}

fn check_workspace(architecture_doc: &Path, manifest: &Path) -> Result<Vec<Violation>> {
    let doc = fs::read_to_string(architecture_doc)
        .with_context(|| format!("could not read {}", architecture_doc.display()))?;
    let policy = EdgePolicy::parse(&doc)
        .with_context(|| format!("bad allowed edges in {}", architecture_doc.display()))?;
    let metadata = Metadata::load(manifest)?;
    Ok(find_violations(&policy, &metadata))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeKind {
    Normal,
    Build,
    Dev,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::Build => "build",
            Self::Dev => "dev",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Violation {
    ForbiddenEdge {
        from: String,
        to: String,
        kind: EdgeKind,
    },
    BannedCrate {
        name: String,
        version: String,
    },
    DirectDependency {
        from: String,
        to: String,
    },
    UndocumentedCrate {
        name: String,
    },
    ImpureDependency {
        from: String,
        to: String,
    },
    ImpureFeature {
        from: String,
        to: String,
        feature: String,
    },
    MissingCrate {
        name: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenEdge { from, to, kind } => write!(
                f,
                "{from} -> {to} ({kind} dependency) is not an allowed edge in {ARCHITECTURE_DOC}"
            ),
            Self::BannedCrate { name, version } => {
                write!(
                    f,
                    "banned crate {name} {version} is in the dependency graph"
                )
            }
            Self::DirectDependency { from, to } => {
                write!(
                    f,
                    "{from} depends directly on {to}, which ADR 0010 rules out"
                )
            }
            Self::UndocumentedCrate { name } => write!(
                f,
                "{name} is a workspace crate missing from the allowed edges in {ARCHITECTURE_DOC}"
            ),
            Self::ImpureDependency { from, to } => {
                write!(f, "{from} is a pure crate and may not depend on {to}")
            }
            Self::ImpureFeature { from, to, feature } => write!(
                f,
                "{from} is a pure crate and may not enable feature `{feature}` of {to}"
            ),
            Self::MissingCrate { name } => write!(
                f,
                "{name} is listed in {ARCHITECTURE_DOC} but is not a workspace crate"
            ),
        }
    }
}

struct EdgePolicy {
    allowed: BTreeMap<String, BTreeSet<String>>,
}

impl EdgePolicy {
    /// Reads the first code block after the edges heading. Each line is
    /// `crate -> a, b`, `crate -> (external only)` or `crate -> all crates above`.
    fn parse(doc: &str) -> Result<Self> {
        let mut lines = doc.lines().skip_while(|line| line.trim() != EDGES_HEADING);
        if lines.next().is_none() {
            bail!("heading `{EDGES_HEADING}` not found");
        }
        let mut lines = lines.skip_while(|line| !line.trim_start().starts_with("```"));
        if lines.next().is_none() {
            bail!("no code block after `{EDGES_HEADING}`");
        }

        let mut allowed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut closed = false;
        for line in lines {
            let line = line.trim();
            if line.starts_with("```") {
                closed = true;
                break;
            }
            if line.is_empty() {
                continue;
            }
            let (from, targets) = line
                .split_once("->")
                .with_context(|| format!("edge line `{line}` has no `->`"))?;
            let from = from.trim();
            let targets = match targets.trim() {
                "(external only)" => BTreeSet::new(),
                "all crates above" => allowed.keys().cloned().collect(),
                list => list.split(',').map(|name| name.trim().to_owned()).collect(),
            };
            if allowed.insert(from.to_owned(), targets).is_some() {
                bail!("crate `{from}` is listed twice");
            }
        }
        if !closed {
            bail!("code block after `{EDGES_HEADING}` is not closed");
        }
        for (from, targets) in &allowed {
            if let Some(unknown) = targets.iter().find(|target| !allowed.contains_key(*target)) {
                bail!("`{from}` lists `{unknown}`, which has no line of its own");
            }
        }
        Ok(Self { allowed })
    }

    fn allows(&self, from: &str, to: &str) -> bool {
        self.allowed
            .get(from)
            .is_some_and(|targets| targets.contains(to))
    }
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    version: String,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    name: String,
    kind: Option<RawKind>,
    features: Vec<String>,
    uses_default_features: bool,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum RawKind {
    Dev,
    Build,
}

impl Dependency {
    fn edge_kind(&self) -> EdgeKind {
        match self.kind {
            None => EdgeKind::Normal,
            Some(RawKind::Build) => EdgeKind::Build,
            Some(RawKind::Dev) => EdgeKind::Dev,
        }
    }
}

impl Metadata {
    fn load(manifest: &Path) -> Result<Self> {
        let output = cargo()
            .args([
                "metadata",
                "--format-version",
                "1",
                "--all-features",
                "--locked",
            ])
            .arg("--manifest-path")
            .arg(manifest)
            .output()
            .context("could not start `cargo metadata`")?;
        if !output.status.success() {
            bail!(
                "`cargo metadata` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        serde_json::from_slice(&output.stdout).context("could not parse `cargo metadata` output")
    }
}

fn find_violations(policy: &EdgePolicy, metadata: &Metadata) -> Vec<Violation> {
    let members: BTreeMap<&str, &Package> = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| (package.name.as_str(), package))
        .collect();
    let mut violations = Vec::new();

    for name in policy.allowed.keys() {
        if !members.contains_key(name.as_str()) {
            violations.push(Violation::MissingCrate { name: name.clone() });
        }
    }

    for (&from, package) in &members {
        if !TOOLING_MEMBERS.contains(&from) && !policy.allowed.contains_key(from) {
            violations.push(Violation::UndocumentedCrate {
                name: from.to_owned(),
            });
        }
        for dependency in &package.dependencies {
            let to = dependency.name.as_str();
            let kind = dependency.edge_kind();
            let is_member_edge = to != from && members.contains_key(to);
            let edge_allowed = policy.allows(from, to)
                || (kind == EdgeKind::Dev
                    && (to == DEV_DEPENDENCY_ANYWHERE || DEV_ONLY_EDGES.contains(&(from, to))));
            if is_member_edge && !edge_allowed {
                violations.push(Violation::ForbiddenEdge {
                    from: from.to_owned(),
                    to: to.to_owned(),
                    kind,
                });
            }
            if NOT_DIRECT.contains(&to) {
                violations.push(Violation::DirectDependency {
                    from: from.to_owned(),
                    to: to.to_owned(),
                });
            }
            if PURE_CRATES.contains(&from) && kind != EdgeKind::Dev {
                violations.extend(impurities(from, dependency));
            }
        }
    }

    for package in &metadata.packages {
        if BANNED.contains(&package.name.as_str()) {
            violations.push(Violation::BannedCrate {
                name: package.name.clone(),
                version: package.version.clone(),
            });
        }
    }
    violations
}

fn impurities(from: &str, dependency: &Dependency) -> Vec<Violation> {
    let to = dependency.name.as_str();
    if IMPURE_FOR_PURE_CRATES.contains(&to) {
        return vec![Violation::ImpureDependency {
            from: from.to_owned(),
            to: to.to_owned(),
        }];
    }
    let Some((_, forbidden)) = IMPURE_FEATURES.iter().find(|(name, _)| *name == to) else {
        return Vec::new();
    };
    let default = dependency
        .uses_default_features
        .then_some("default".to_owned());
    default
        .into_iter()
        .chain(dependency.features.iter().cloned())
        .filter(|feature| forbidden.contains(&feature.as_str()))
        .map(|feature| Violation::ImpureFeature {
            from: from.to_owned(),
            to: to.to_owned(),
            feature,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const FIXTURE_DOC: &str = "# Architecture

## Allowed dependency edges

```
lepic-crypto      -> (external only)
lepic-primitives  -> lepic-crypto
lepic-telemetry   -> (external only)
```
";

    /// A workspace in `ws/` that obeys `FIXTURE_DOC`, plus room for crates outside it.
    struct Fixture {
        dir: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let fixture = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            fixture.write(
                "ws/Cargo.toml",
                "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"3\"\n",
            );
            fixture.write("ws/docs/architecture.md", FIXTURE_DOC);
            fixture.member("lepic-crypto", "");
            fixture.member(
                "lepic-primitives",
                "[dependencies]\nlepic-crypto = { path = \"../lepic-crypto\" }\n",
            );
            fixture.member("lepic-telemetry", "");
            fixture
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.dir.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        fn package(&self, directory: &str, name: &str, sections: &str) {
            self.write(
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n{sections}"
                ),
            );
            self.write(&format!("{directory}/src/lib.rs"), "");
        }

        fn member(&self, name: &str, sections: &str) {
            self.package(&format!("ws/crates/{name}"), name, sections);
        }

        /// A crate outside the workspace, reachable from a member as `../../../external/<name>`.
        fn external(&self, name: &str) {
            self.package(&format!("external/{name}"), name, "");
        }

        fn violations(&self) -> Vec<Violation> {
            let ws = self.dir.path().join("ws");
            let manifest = ws.join("Cargo.toml");
            // deps-check runs `cargo metadata --locked`, so the fixture needs a lockfile.
            let status = cargo()
                .arg("generate-lockfile")
                .arg("--manifest-path")
                .arg(&manifest)
                .status()
                .unwrap();
            assert!(status.success());
            check_workspace(&ws.join("docs/architecture.md"), &manifest).unwrap()
        }
    }

    fn forbidden(from: &str, to: &str, kind: EdgeKind) -> Violation {
        Violation::ForbiddenEdge {
            from: from.to_owned(),
            to: to.to_owned(),
            kind,
        }
    }

    #[test]
    fn accepts_workspace_that_matches_the_doc() {
        assert_eq!(Fixture::new().violations(), []);
    }

    #[test]
    fn rejects_edge_missing_from_the_doc() {
        let fixture = Fixture::new();
        fixture.member(
            "lepic-telemetry",
            "[build-dependencies]\nlepic-crypto = { path = \"../lepic-crypto\" }\n",
        );
        assert_eq!(
            fixture.violations(),
            [forbidden(
                "lepic-telemetry",
                "lepic-crypto",
                EdgeKind::Build
            )]
        );
    }

    #[test]
    fn rejects_banned_crate_anywhere_in_the_graph() {
        let fixture = Fixture::new();
        fixture.external("openssl-sys");
        fixture.member(
            "lepic-telemetry",
            "[dependencies]\nopenssl-sys = { path = \"../../../external/openssl-sys\" }\n",
        );
        assert_eq!(
            fixture.violations(),
            [Violation::BannedCrate {
                name: "openssl-sys".to_owned(),
                version: "0.1.0".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_cxx_bridge_crates_anywhere_in_the_graph() {
        let fixture = Fixture::new();
        fixture.external("link-cplusplus");
        fixture.external("cxx");
        fixture.write(
            "external/cxx/Cargo.toml",
            "[package]\nname = \"cxx\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nlink-cplusplus = { path = \"../link-cplusplus\" }\n",
        );
        fixture.member(
            "lepic-crypto",
            "[build-dependencies]\ncxx = { path = \"../../../external/cxx\" }\n",
        );
        let banned: Vec<String> = fixture
            .violations()
            .into_iter()
            .filter_map(|violation| match violation {
                Violation::BannedCrate { name, .. } => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(banned, ["cxx", "link-cplusplus"]);
    }

    #[test]
    fn rejects_direct_dependency_on_a_replaced_crate() {
        let fixture = Fixture::new();
        fixture.external("once_cell");
        fixture.member(
            "lepic-crypto",
            "[dependencies]\nonce_cell = { path = \"../../../external/once_cell\" }\n",
        );
        assert_eq!(
            fixture.violations(),
            [Violation::DirectDependency {
                from: "lepic-crypto".to_owned(),
                to: "once_cell".to_owned(),
            }]
        );
    }

    #[test]
    fn allows_telemetry_only_as_a_dev_dependency() {
        let fixture = Fixture::new();
        let telemetry = "lepic-telemetry = { path = \"../lepic-telemetry\" }\n";
        fixture.member("lepic-crypto", &format!("[dev-dependencies]\n{telemetry}"));
        assert_eq!(fixture.violations(), []);

        fixture.member("lepic-crypto", &format!("[dependencies]\n{telemetry}"));
        assert_eq!(
            fixture.violations(),
            [forbidden(
                "lepic-crypto",
                "lepic-telemetry",
                EdgeKind::Normal
            )]
        );
    }

    #[test]
    fn allows_the_contacts_crate_only_as_a_dev_dependency_of_the_engine() {
        let fixture = Fixture::new();
        fixture.write(
            "ws/docs/architecture.md",
            "## Allowed dependency edges\n```\nlepic-crypto -> (external only)\n\
             lepic-primitives -> lepic-crypto\nlepic-telemetry -> (external only)\n\
             lepic-wallet -> (external only)\nlepic-wallet-contacts -> lepic-wallet\n```\n",
        );
        let contacts = "lepic-wallet-contacts = { path = \"../lepic-wallet-contacts\" }\n";
        fixture.member(
            "lepic-wallet-contacts",
            "[dependencies]\nlepic-wallet = { path = \"../lepic-wallet\" }\n",
        );
        fixture.member("lepic-wallet", &format!("[dev-dependencies]\n{contacts}"));
        assert_eq!(fixture.violations(), []);

        fixture.member(
            "lepic-primitives",
            &format!(
                "[dependencies]\nlepic-crypto = {{ path = \"../lepic-crypto\" }}\n\n\
                 [dev-dependencies]\n{contacts}"
            ),
        );
        assert_eq!(
            fixture.violations(),
            [forbidden(
                "lepic-primitives",
                "lepic-wallet-contacts",
                EdgeKind::Dev
            )]
        );
    }

    #[test]
    fn rejects_dev_dependency_outside_the_doc() {
        let fixture = Fixture::new();
        fixture.member(
            "lepic-telemetry",
            "[dev-dependencies]\nlepic-crypto = { path = \"../lepic-crypto\" }\n",
        );
        assert_eq!(
            fixture.violations(),
            [forbidden("lepic-telemetry", "lepic-crypto", EdgeKind::Dev)]
        );
    }

    #[test]
    fn rejects_product_crate_missing_from_the_doc() {
        let fixture = Fixture::new();
        fixture.member("lepic-extra", "");
        assert_eq!(
            fixture.violations(),
            [Violation::UndocumentedCrate {
                name: "lepic-extra".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_any_member_missing_from_the_doc_except_tooling() {
        let fixture = Fixture::new();
        fixture.member("tools", "");
        fixture.member("xtask", "");
        assert_eq!(
            fixture.violations(),
            [Violation::UndocumentedCrate {
                name: "tools".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_io_crates_in_pure_crates_outside_dev_dependencies() {
        let fixture = Fixture::new();
        fixture.external("tokio");
        fixture.external("getrandom");
        fixture.member(
            "lepic-crypto",
            "[dependencies]\ntokio = { path = \"../../../external/tokio\" }\n\n[dev-dependencies]\ngetrandom = { path = \"../../../external/getrandom\" }\n",
        );
        fixture.member(
            "lepic-telemetry",
            "[dependencies]\ntokio = { path = \"../../../external/tokio\" }\n",
        );
        assert_eq!(
            fixture.violations(),
            [Violation::ImpureDependency {
                from: "lepic-crypto".to_owned(),
                to: "tokio".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_os_randomness_and_clock_features_in_pure_crates() {
        let fixture = Fixture::new();
        fixture.write(
            "external/rand/Cargo.toml",
            "[package]\nname = \"rand\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[features]\ndefault = []\nstd_rng = []\nsys_rng = []\n",
        );
        fixture.write("external/rand/src/lib.rs", "");
        let rand = "rand = { path = \"../../../external/rand\", default-features = false, features = [\"std_rng\", \"sys_rng\"] }\n";
        fixture.member(
            "lepic-primitives",
            &format!("[dependencies]\nlepic-crypto = {{ path = \"../lepic-crypto\" }}\n{rand}"),
        );
        fixture.member(
            "lepic-crypto",
            "[build-dependencies]\nrand = { path = \"../../../external/rand\" }\n",
        );
        assert_eq!(
            fixture.violations(),
            [
                Violation::ImpureFeature {
                    from: "lepic-crypto".to_owned(),
                    to: "rand".to_owned(),
                    feature: "default".to_owned(),
                },
                Violation::ImpureFeature {
                    from: "lepic-primitives".to_owned(),
                    to: "rand".to_owned(),
                    feature: "sys_rng".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn pure_crates_match_the_architecture_doc() {
        let doc = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/architecture.md"),
        )
        .unwrap();
        let sentence = doc
            .lines()
            .find(|line| line.starts_with("Pure crates ("))
            .unwrap();
        let listed: BTreeSet<String> = sentence
            .split('`')
            .skip(1)
            .step_by(2)
            .map(|name| format!("lepic-{name}"))
            .collect();
        let pure: BTreeSet<String> = PURE_CRATES.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(listed, pure);
    }

    #[test]
    fn all_crates_above_means_every_earlier_line() {
        let doc = "## Allowed dependency edges\n```\na -> (external only)\nb -> a\nc -> all crates above\nd -> (external only)\n```\n";
        let policy = EdgePolicy::parse(doc).unwrap();
        assert!(policy.allows("c", "a"));
        assert!(policy.allows("c", "b"));
        assert!(!policy.allows("c", "d"));
        assert!(!policy.allows("a", "b"));
    }

    #[test]
    fn rejects_doc_naming_an_unlisted_crate() {
        let doc = "## Allowed dependency edges\n```\na -> b\n```\n";
        assert!(EdgePolicy::parse(doc).is_err());
    }

    #[test]
    fn banned_list_matches_deny_toml() {
        let deny_toml =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../deny.toml")).unwrap();
        let in_deny_toml: BTreeSet<&str> = deny_toml
            .lines()
            .skip_while(|line| !line.starts_with("deny = ["))
            .take_while(|line| *line != "]")
            .filter_map(|line| line.trim().strip_prefix("{ crate = \""))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        let in_xtask: BTreeSet<&str> = BANNED.iter().copied().collect();
        assert_eq!(in_xtask, in_deny_toml);
    }
}
