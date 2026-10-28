//! Measures Argon2id unlock time for candidate vault parameters.
//!
//! `cargo bench -p lepic-keychain --bench argon2` on the host. On Android, build it with
//! `cargo ndk ... build --release --benches`, push the binary and run it; `LEPIC_BENCH_SAMPLES`
//! sets the runs per parameter set. Prints one row per set with the median and slowest run.

// Measurement tooling that never ships: plain arithmetic, indexing and panics on a broken host
// keep it short, as in tests.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::time::{Duration, Instant};

use lepic_keychain::{KdfParams, MemoryVaultStorage, SecretBytes, SecretName, SecretStore, Vault};
use rand::SeedableRng;
use rand::rngs::StdRng;

const MIB: u32 = 1024;
const MEMORY_MIB: [u32; 5] = [19, 32, 46, 64, 128];
const ITERATIONS: [u32; 4] = [1, 2, 3, 4];
const DEFAULT_SAMPLES: usize = 5;

fn main() {
    let samples = std::env::var("LEPIC_BENCH_SAMPLES")
        .ok()
        .map(|value| value.parse().expect("LEPIC_BENCH_SAMPLES is a count"))
        .unwrap_or(DEFAULT_SAMPLES)
        .max(1);
    println!("argon2id v0x13, p=1, 32-byte key, {samples} samples per set");
    println!(
        "{:>8} {:>3} {:>11} {:>11}",
        "m (MiB)", "t", "median ms", "max ms"
    );
    for memory in MEMORY_MIB {
        for iterations in ITERATIONS {
            let params = KdfParams::for_tests(memory * MIB, iterations, 1).unwrap();
            let times = measure(samples, || unlock(params));
            println!(
                "{memory:>8} {iterations:>3} {:>11} {:>11}",
                millis(times[times.len() / 2]),
                millis(times[times.len() - 1])
            );
        }
    }
    let default = KdfParams::DEFAULT;
    let times = measure(samples, || unlock(default));
    println!(
        "default m={} MiB t={} p={}: median {} ms, max {} ms",
        default.memory_kib() / MIB,
        default.iterations(),
        default.parallelism(),
        millis(times[times.len() / 2]),
        millis(times[times.len() - 1])
    );
}

/// Sorted wall-clock durations of `samples` runs, after one unmeasured warm-up run.
fn measure(samples: usize, mut run: impl FnMut() -> Duration) -> Vec<Duration> {
    run();
    let mut times: Vec<Duration> = (0..samples).map(|_| run()).collect();
    times.sort();
    times
}

/// Times `Vault::open` on a vault holding one seed, which is what an app unlock costs.
fn unlock(params: KdfParams) -> Duration {
    let password = b"benchmark password";
    let mut vault = Vault::create(
        MemoryVaultStorage::new(),
        StdRng::seed_from_u64(1),
        password,
        params,
    )
    .unwrap();
    vault
        .put(
            &SecretName::new("wallet/default/seed").unwrap(),
            &SecretBytes::from_slice(&[7; 32]),
        )
        .unwrap();
    let storage = vault.into_storage();
    let start = Instant::now();
    let opened = Vault::open(storage, StdRng::seed_from_u64(2), password).unwrap();
    let elapsed = start.elapsed();
    std::hint::black_box(opened);
    elapsed
}

fn millis(duration: Duration) -> u128 {
    duration.as_millis()
}
