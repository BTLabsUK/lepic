// SPDX-License-Identifier: Apache-2.0
//! The interop stack runs third-party images and services next to test wallets. Base images are
//! pinned by digest so a moved tag cannot change what runs, containers do not run as root, and
//! services listen on loopback only.

use std::fmt;

use crate::sources::SourceFile;

const DIGEST_MARKER: &str = "@sha256:";
const DIGEST_LEN: usize = 64;
/// Images built locally by `interop/build.sh` or compose, never pulled.
const LOCAL_TAG: &str = ":local";
const WILDCARD_ADDRESS: &str = "0.0.0.0";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    UnpinnedImage {
        file: String,
        line: usize,
        image: String,
    },
    RootImage {
        file: String,
    },
    RootService {
        file: String,
        service: String,
    },
    WildcardBind {
        file: String,
        line: usize,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnpinnedImage { file, line, image } => write!(
                f,
                "{file}:{line}: image `{image}` is not pinned by its sha256 digest"
            ),
            Self::RootImage { file } => write!(
                f,
                "{file}: the final stage has no `USER` instruction naming a non-root user"
            ),
            Self::RootService { file, service } => write!(
                f,
                "{file}: service `{service}` runs a pulled image without a non-root `user:`"
            ),
            Self::WildcardBind { file, line } => write!(
                f,
                "{file}:{line}: binds {WILDCARD_ADDRESS}; interop services listen on loopback only"
            ),
        }
    }
}

pub(crate) fn check(files: &[SourceFile]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for file in files {
        let name = file.path.rsplit('/').next().unwrap_or(&file.path);
        if name.ends_with("Dockerfile") {
            violations.extend(dockerfile(file));
        }
        if (name.starts_with("compose") || name.starts_with("docker-compose"))
            && (name.ends_with(".yaml") || name.ends_with(".yml"))
        {
            violations.extend(compose(file));
        }
        // Documentation may name the address it rules out.
        if !name.ends_with(".md") {
            violations.extend(wildcard_binds(file));
        }
    }
    violations
}

fn is_pinned(image: &str) -> bool {
    image.split_once(DIGEST_MARKER).is_some_and(|(_, digest)| {
        digest.len() == DIGEST_LEN && digest.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    })
}

fn is_root(user: &str) -> bool {
    let user = user.trim().trim_matches(['"', '\'']);
    let name = user.split(':').next().unwrap_or(user);
    name.is_empty() || name == "root" || name == "0"
}

/// The code part of a `#`-commented line.
fn without_comment(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }
    line.find(" #")
        .and_then(|index| line.get(..index))
        .unwrap_or(line)
}

fn dockerfile(file: &SourceFile) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut stages: Vec<String> = Vec::new();
    let mut final_user: Option<String> = None;
    for (line_number, line) in (1..).zip(file.text.lines()) {
        let mut words = without_comment(line).split_whitespace();
        let Some(instruction) = words.next() else {
            continue;
        };
        if instruction.eq_ignore_ascii_case("FROM") {
            final_user = None;
            let mut words = words.skip_while(|word| word.starts_with("--"));
            let image = words.next().unwrap_or_default();
            let is_stage = stages.iter().any(|stage| stage == image);
            if !(is_stage || image == "scratch" || is_pinned(image)) {
                violations.push(Violation::UnpinnedImage {
                    file: file.path.clone(),
                    line: line_number,
                    image: image.to_owned(),
                });
            }
            if words
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("AS"))
                && let Some(stage) = words.next()
            {
                stages.push(stage.to_owned());
            }
        } else if instruction.eq_ignore_ascii_case("USER") {
            final_user = words.next().map(str::to_owned);
        }
    }
    if final_user.as_deref().is_none_or(is_root) {
        violations.push(Violation::RootImage {
            file: file.path.clone(),
        });
    }
    violations
}

fn yaml_value(line: &str, key: &str) -> Option<String> {
    let value = without_comment(line)
        .trim()
        .strip_prefix(key)?
        .strip_prefix(':')?;
    Some(value.trim().trim_matches(['"', '\'']).to_owned())
}

fn compose(file: &SourceFile) -> Vec<Violation> {
    let mut violations = Vec::new();
    for (line_number, line) in (1..).zip(file.text.lines()) {
        if let Some(image) = yaml_value(line, "image")
            && !(is_pinned(&image) || image.ends_with(LOCAL_TAG))
        {
            violations.push(Violation::UnpinnedImage {
                file: file.path.clone(),
                line: line_number,
                image,
            });
        }
    }
    for (service, block) in services(&file.text) {
        let pulled = block
            .iter()
            .any(|line| yaml_value(line, "image").is_some_and(|image| !image.ends_with(LOCAL_TAG)));
        let non_root = block
            .iter()
            .filter_map(|line| yaml_value(line, "user"))
            .any(|user| !is_root(&user));
        if pulled && !non_root {
            violations.push(Violation::RootService {
                file: file.path.clone(),
                service: service.to_owned(),
            });
        }
    }
    violations
}

/// Each service under the top-level `services:` key with the lines of its block.
fn services(text: &str) -> Vec<(&str, Vec<&str>)> {
    let mut services: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut in_services = false;
    let mut service_indent = None;
    for line in text.lines() {
        let code = without_comment(line);
        if code.trim().is_empty() {
            continue;
        }
        let indent = code.len().saturating_sub(code.trim_start().len());
        if indent == 0 {
            in_services = code.trim_end() == "services:";
            service_indent = None;
            continue;
        }
        if !in_services {
            continue;
        }
        let indent_of_services = *service_indent.get_or_insert(indent);
        if indent == indent_of_services {
            let name = code.trim().trim_end_matches(':');
            services.push((name, Vec::new()));
        } else if let Some((_, block)) = services.last_mut() {
            block.push(code);
        }
    }
    services
}

fn wildcard_binds(file: &SourceFile) -> Vec<Violation> {
    (1..)
        .zip(file.text.lines())
        .filter(|(_, line)| without_comment(line).contains(WILDCARD_ADDRESS))
        .map(|(line, _)| Violation::WildcardBind {
            file: file.path.clone(),
            line,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::sources::repository_files;

    const DIGEST: &str = "3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251";

    fn file(path: &str, text: &str) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn accepts_pinned_non_root_images_and_stages() {
        let text = format!(
            "# FROM debian:latest\nFROM --platform=linux/amd64 debian:bookworm-slim@sha256:{DIGEST} AS base\nUSER root\nRUN useradd app\nFROM base\nUSER app:app\n"
        );
        assert_eq!(check(&[file("interop/docker/a.Dockerfile", &text)]), []);
    }

    #[test]
    fn rejects_unpinned_base_images_and_root_final_stages() {
        let text = format!(
            "FROM rust:1.89.0-bookworm AS build\nUSER app\nFROM debian@sha256:{}\nFROM debian:bookworm-slim@sha256:{DIGEST}\nUSER 0:0\n",
            &DIGEST[..12]
        );
        let path = "interop/docker/Dockerfile";
        assert_eq!(
            check(&[file(path, &text)]),
            [
                Violation::UnpinnedImage {
                    file: path.to_owned(),
                    line: 1,
                    image: "rust:1.89.0-bookworm".to_owned()
                },
                Violation::UnpinnedImage {
                    file: path.to_owned(),
                    line: 3,
                    image: format!("debian@sha256:{}", &DIGEST[..12])
                },
                Violation::RootImage {
                    file: path.to_owned()
                },
            ]
        );
        let no_user = format!("FROM debian@sha256:{DIGEST}\nRUN true\n");
        assert_eq!(
            check(&[file(path, &no_user)]),
            [Violation::RootImage {
                file: path.to_owned()
            }]
        );
    }

    #[test]
    fn requires_pinned_images_and_a_user_for_pulled_compose_services() {
        let text = format!(
            "x-runtime: &runtime\n  image: lepic-interop-runtime:local\nservices:\n  db:\n    image: mongo:6.0\n  cache:\n    image: \"redis@sha256:{DIGEST}\"\n    user: \"0\"\n  store:\n    image: mongo@sha256:{DIGEST}\n    user: \"999:999\"\n  node:\n    <<: *runtime\n    command: [\"node.sh\"]\nvolumes:\n  data: {{}}\n"
        );
        let path = "interop/compose.yaml";
        assert_eq!(
            check(&[file(path, &text)]),
            [
                Violation::UnpinnedImage {
                    file: path.to_owned(),
                    line: 5,
                    image: "mongo:6.0".to_owned()
                },
                Violation::RootService {
                    file: path.to_owned(),
                    service: "db".to_owned()
                },
                Violation::RootService {
                    file: path.to_owned(),
                    service: "cache".to_owned()
                },
            ]
        );
    }

    #[test]
    fn rejects_wildcard_binds_outside_comments() {
        let text = "# the node used to listen on 0.0.0.0\nset_key api_http_addr '\"0.0.0.0:23413\"'\nset_key a '\"127.0.0.1:1\"' # not 0.0.0.0\n";
        assert_eq!(
            check(&[
                file("interop/docker/node.sh", text),
                file("interop/README.md", "Nothing binds 0.0.0.0.\n"),
            ]),
            [Violation::WildcardBind {
                file: "interop/docker/node.sh".to_owned(),
                line: 2
            }]
        );
    }

    #[test]
    fn repository_interop_files_follow_the_rules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let files = repository_files(root, &["interop"]).unwrap();
        assert!(files.iter().any(|file| file.path == "interop/compose.yaml"));
        assert_eq!(check(&files), []);
    }
}
