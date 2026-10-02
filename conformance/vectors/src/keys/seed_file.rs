//! The `wallet.seed` file as `epic-wallet` writes it when a wallet is created from a mnemonic with
//! a password. Upstream draws the salt and nonce itself, so these are the randomized cases of the
//! area: the recorded file is kept as long as the pin and the case inputs are unchanged and
//! upstream still decrypts it, and is written afresh by upstream otherwise.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use epic_keychain::{ExtKeychain, mnemonic};
use epic_util::ZeroingString;
use epic_wallet_impls::{DefaultLCProvider, HTTPNodeClient};
use epic_wallet_libwallet::WalletLCProvider;
use serde::Serialize;

use super::{AREA, Inconsistent, KeysPins, SEED_16, SEED_32, ensure};
use crate::{DEFAULT_OUT, Error, Rendered, hex, render};

// Where `DefaultLCProvider` keeps the seed file under its top-level directory.
const DATA_DIR: &str = "wallet_data";
const SEED_FILE: &str = "wallet.seed";

// Fixed test-only passwords; the empty one is accepted by upstream and must be by LEPIC too.
const CASES: [(&str, &[u8], &str); 2] = [
    ("wallet_seed_seed32", &SEED_32, "lepic test password"),
    ("wallet_seed_seed16_empty_password", &SEED_16, ""),
];

const WRONG_PASSWORD: &str = "not the password";

/// Gives concurrent generator runs in one process (the tests) separate scratch directories.
static SCRATCH_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Serialize, PartialEq)]
struct Inputs {
    mnemonic: String,
    entropy: String,
    password: String,
    wrong_password: String,
}

/// `file` is the exact file text. `encrypted_seed` is the ChaCha20-Poly1305 ciphertext followed by
/// the tag, `salt` and `nonce` are the values upstream drew. Upstream decrypts `file` with
/// `password` to the mnemonic of `entropy` and rejects `wrong_password`.
#[derive(Serialize, serde::Deserialize)]
struct Expected {
    file: String,
    encrypted_seed: String,
    salt: String,
    nonce: String,
}

#[derive(serde::Deserialize)]
struct SeedFile {
    encrypted_seed: String,
    salt: String,
    nonce: String,
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    CASES
        .iter()
        .map(|(name, entropy, password)| case(pins, name, entropy, password))
        .collect()
}

fn case(
    pins: &KeysPins<'_>,
    name: &str,
    entropy: &[u8],
    password: &str,
) -> Result<Rendered, Error> {
    let phrase = mnemonic::from_entropy(&entropy.to_vec())
        .map_err(|_| Error::reference("mnemonic from entropy")(Inconsistent("seed file")))?;
    let inputs = Inputs {
        mnemonic: phrase.clone(),
        entropy: hex(entropy),
        password: password.to_owned(),
        wrong_password: WRONG_PASSWORD.to_owned(),
    };

    let file = match recorded_file(pins, name, &inputs) {
        Some(file) => file,
        None => create_seed_file(&phrase, password)?,
    };
    check_with_upstream(&file, &phrase, password)?;

    let fields: SeedFile = serde_json::from_str(&file)?;
    let expected = Expected {
        file,
        encrypted_seed: fields.encrypted_seed,
        salt: fields.salt,
        nonce: fields.nonce,
    };
    render(AREA, name, &pins.wallet, inputs, expected)
}

/// The committed file's `expected.file`, if the committed vector was produced by the current pin
/// from the same inputs. Upstream checks it afterwards like a fresh one.
fn recorded_file(pins: &KeysPins<'_>, name: &str, inputs: &Inputs) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Recorded {
        upstream: RecordedUpstream,
        inputs: serde_json::Value,
        expected: Expected,
    }
    #[derive(serde::Deserialize)]
    struct RecordedUpstream {
        repo: String,
        commit: String,
    }

    let path = Path::new(DEFAULT_OUT)
        .join(AREA)
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(path).ok()?;
    let recorded: Recorded = serde_json::from_str(&text).ok()?;
    let same_pin = recorded.upstream.repo == pins.wallet.repo
        && recorded.upstream.commit == pins.wallet.commit;
    let same_inputs = serde_json::to_value(inputs).ok()? == recorded.inputs;
    (same_pin && same_inputs).then_some(recorded.expected.file)
}

/// A scratch top-level wallet directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Scratch, Error> {
        let n = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lepic-vectors-keys-{}-{n}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(Error::io(&dir))?;
        }
        std::fs::create_dir_all(&dir).map_err(Error::io(&dir))?;
        Ok(Scratch(dir))
    }

    fn seed_path(&self) -> PathBuf {
        self.0.join(DATA_DIR).join(SEED_FILE)
    }

    fn provider(&self) -> Result<DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>, Error> {
        // Never contacted: creating a wallet and reading its seed make no node calls.
        let client = HTTPNodeClient::new("http://127.0.0.1:1", None)
            .map_err(Error::reference("node client"))?;
        let mut provider = DefaultLCProvider::new(client);
        let dir = self
            .0
            .to_str()
            .ok_or(Error::reference("scratch directory")(Inconsistent(
                "non-utf8 path",
            )))?;
        provider
            .set_top_level_directory(dir)
            .map_err(Error::reference("wallet directory"))?;
        Ok(provider)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _best_effort = std::fs::remove_dir_all(&self.0);
    }
}

fn create_seed_file(phrase: &str, password: &str) -> Result<String, Error> {
    let scratch = Scratch::new()?;
    let mut provider = scratch.provider()?;
    provider
        .create_wallet(
            None,
            Some(ZeroingString::from(phrase)),
            32,
            ZeroingString::from(password),
            false,
        )
        .map_err(Error::reference("wallet creation"))?;
    let path = scratch.seed_path();
    std::fs::read_to_string(&path).map_err(Error::io(&path))
}

/// Places `file` where upstream looks for it, then has upstream decrypt it with the right password
/// and fail with the wrong one.
fn check_with_upstream(file: &str, phrase: &str, password: &str) -> Result<(), Error> {
    let scratch = Scratch::new()?;
    let path = scratch.seed_path();
    let data_dir = scratch.0.join(DATA_DIR);
    std::fs::create_dir_all(&data_dir).map_err(Error::io(&data_dir))?;
    std::fs::write(&path, file).map_err(Error::io(&path))?;
    let provider = scratch.provider()?;
    let decrypted = provider
        .get_mnemonic(None, ZeroingString::from(password))
        .map_err(Error::reference("seed file decryption"))?;
    ensure(&*decrypted == phrase, "seed file decrypts to its mnemonic")?;
    ensure(
        provider
            .get_mnemonic(None, ZeroingString::from(WRONG_PASSWORD))
            .is_err(),
        "seed file rejects a wrong password",
    )
}
