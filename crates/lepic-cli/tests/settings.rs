// SPDX-License-Identifier: Apache-2.0
//! Settings precedence: flag, then `LEPIC_*` variable, then config file, then default.

// Tests may unwrap (docs/rules.md).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use lepic_cli::cli::{GlobalArgs, NetworkArg, OutputArg};
use lepic_cli::settings::{Env, Origin, OutputFormat, Settings, SettingsError};
use lepic_primitives::params::Network;

fn env(home: &Path, vars: &[(&str, &str)]) -> Env {
    let mut all = vec![("HOME".to_owned(), home.display().to_string())];
    all.extend(vars.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())));
    Env::new(all)
}

fn write_config(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn defaults_apply_when_nothing_is_set() {
    let home = tempfile::tempdir().unwrap();
    let settings = Settings::resolve(&GlobalArgs::default(), &env(home.path(), &[])).unwrap();
    assert_eq!(settings.network, Network::Mainnet);
    assert_eq!(settings.data_dir, home.path().join(".lepic/mainnet"));
    assert_eq!(settings.output, OutputFormat::Human);
    assert_eq!(settings.log_filter, "warn");
    assert_eq!(settings.node.as_str(), "http://127.0.0.1:3413");
    assert_eq!(settings.relay.url(), "wss://epicbox.epiccash.com:443");
}

#[test]
fn the_default_data_directory_follows_the_network() {
    let home = tempfile::tempdir().unwrap();
    let args = GlobalArgs {
        network: Some(NetworkArg::Floonet),
        ..GlobalArgs::default()
    };
    let settings = Settings::resolve(&args, &env(home.path(), &[])).unwrap();
    assert_eq!(settings.data_dir, home.path().join(".lepic/floonet"));
    assert_eq!(settings.node.as_str(), "http://127.0.0.1:13413");
}

#[test]
fn a_flag_beats_its_variable_which_beats_the_config_file() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(
        home.path(),
        "network = floonet\noutput = \"json\"\nlog_level = debug\n",
    );
    let config_text = config.display().to_string();

    let only_config = env(home.path(), &[("LEPIC_CONFIG", &config_text)]);
    let settings = Settings::resolve(&GlobalArgs::default(), &only_config).unwrap();
    assert_eq!(
        (
            settings.network,
            settings.output,
            settings.log_filter.as_str()
        ),
        (Network::Floonet, OutputFormat::Json, "debug")
    );

    let with_env = env(
        home.path(),
        &[
            ("LEPIC_CONFIG", &config_text),
            ("LEPIC_NETWORK", "mainnet"),
            ("LEPIC_OUTPUT", "human"),
        ],
    );
    let settings = Settings::resolve(&GlobalArgs::default(), &with_env).unwrap();
    assert_eq!(
        (settings.network, settings.output),
        (Network::Mainnet, OutputFormat::Human)
    );

    let flags = GlobalArgs {
        network: Some(NetworkArg::Floonet),
        output: Some(OutputArg::Json),
        ..GlobalArgs::default()
    };
    let settings = Settings::resolve(&flags, &with_env).unwrap();
    assert_eq!(
        (settings.network, settings.output),
        (Network::Floonet, OutputFormat::Json)
    );
}

#[test]
fn the_default_config_file_is_read_when_it_exists() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join(".lepic")).unwrap();
    write_config(
        &home.path().join(".lepic"),
        "node_url = \"https://node.example.org\"\n",
    );
    let settings = Settings::resolve(&GlobalArgs::default(), &env(home.path(), &[])).unwrap();
    assert_eq!(settings.node.host(), "node.example.org");
}

#[test]
fn config_paths_are_relative_to_the_config_file() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(home.path(), "data_dir = wallets/main\n");
    let args = GlobalArgs {
        config: Some(config),
        ..GlobalArgs::default()
    };
    let settings = Settings::resolve(&args, &env(home.path(), &[])).unwrap();
    assert_eq!(settings.data_dir, home.path().join("wallets/main"));
}

#[test]
fn an_explicit_config_file_must_exist() {
    let home = tempfile::tempdir().unwrap();
    let args = GlobalArgs {
        config: Some(home.path().join("absent.toml")),
        ..GlobalArgs::default()
    };
    assert!(matches!(
        Settings::resolve(&args, &env(home.path(), &[])),
        Err(SettingsError::ConfigRead { .. })
    ));
}

#[test]
fn config_files_with_unknown_repeated_or_malformed_lines_are_refused() {
    let home = tempfile::tempdir().unwrap();
    let resolve = |text: &str| {
        let args = GlobalArgs {
            config: Some(write_config(home.path(), text)),
            ..GlobalArgs::default()
        };
        Settings::resolve(&args, &env(home.path(), &[]))
    };
    assert!(matches!(
        resolve("# comment\n\nnetwrok = floonet\n"),
        Err(SettingsError::UnknownKey { line: 3, .. })
    ));
    assert!(matches!(
        resolve("network = floonet\nnetwork = mainnet\n"),
        Err(SettingsError::DuplicateKey { line: 2, .. })
    ));
    assert!(matches!(
        resolve("network floonet\n"),
        Err(SettingsError::ConfigSyntax { line: 1, .. })
    ));
    assert!(matches!(
        resolve(&"#".repeat(70_000)),
        Err(SettingsError::ConfigTooLarge { .. })
    ));
}

#[test]
fn invalid_values_name_their_key_and_origin() {
    let home = tempfile::tempdir().unwrap();
    let config = write_config(home.path(), "epicbox_relay = \"ws://host:port\"\n");
    let result = Settings::resolve(
        &GlobalArgs {
            config: Some(config.clone()),
            ..GlobalArgs::default()
        },
        &env(home.path(), &[]),
    );
    assert!(matches!(
        result,
        Err(SettingsError::InvalidValue { key: "epicbox_relay", origin: Origin::Config(ref path) })
            if *path == config
    ));
    let result = Settings::resolve(
        &GlobalArgs::default(),
        &env(home.path(), &[("LEPIC_NODE_URL", "ftp://node")]),
    );
    assert!(matches!(
        result,
        Err(SettingsError::InvalidValue {
            key: "node_url",
            origin: Origin::Env("LEPIC_NODE_URL")
        })
    ));
}

#[test]
fn a_relative_data_directory_is_resolved_once_to_an_absolute_path() {
    let home = tempfile::tempdir().unwrap();
    let args = GlobalArgs {
        data_dir: Some(PathBuf::from("relative/dir")),
        ..GlobalArgs::default()
    };
    let settings = Settings::resolve(&args, &env(home.path(), &[])).unwrap();
    assert!(settings.data_dir.is_absolute());
    assert!(settings.data_dir.ends_with("relative/dir"));
}

#[test]
fn without_a_home_the_data_directory_must_be_given() {
    assert!(matches!(
        Settings::resolve(&GlobalArgs::default(), &Env::default()),
        Err(SettingsError::NoHome)
    ));
}
