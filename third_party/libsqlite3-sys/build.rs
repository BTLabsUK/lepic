//! Builds SQLite3 Multiple Ciphers (from `sqlite3mc-src`) with the options libsqlite3-sys 0.38.2
//! gives its bundled SQLite, plus the cipher options in PATCHES.md, and installs the bundled
//! bindings. Every other way libsqlite3-sys can build is refused.

use std::env;
use std::path::Path;

fn main() {
    let refused = [
        ("bundled-sqlcipher", cfg!(feature = "bundled-sqlcipher")),
        (
            "bundled-sqlcipher-vendored-openssl",
            cfg!(feature = "bundled-sqlcipher-vendored-openssl"),
        ),
        ("sqlcipher", cfg!(feature = "sqlcipher")),
        ("buildtime_bindgen", cfg!(feature = "buildtime_bindgen")),
        ("loadable_extension", cfg!(feature = "loadable_extension")),
        ("preupdate_hook", cfg!(feature = "preupdate_hook")),
        ("session", cfg!(feature = "session")),
        ("in_gecko", cfg!(feature = "in_gecko")),
        ("wasm32-wasi-vfs", cfg!(feature = "wasm32-wasi-vfs")),
    ];
    for (feature, on) in refused {
        assert!(!on, "this libsqlite3-sys builds only SQLite3 Multiple Ciphers; `{feature}` is not supported");
    }
    assert!(
        cfg!(feature = "bundled"),
        "this libsqlite3-sys must be built with the `bundled` feature"
    );
    assert!(
        env::var_os("LIBSQLITE3_SYS_USE_PKG_CONFIG").is_none_or(|v| v == "0"),
        "LIBSQLITE3_SYS_USE_PKG_CONFIG would link a system SQLite without encryption"
    );

    let out_dir = env::var("OUT_DIR").unwrap();
    std::fs::copy(
        "sqlite3/bindgen_bundled_version.rs",
        Path::new(&out_dir).join("bindgen.rs"),
    )
    .expect("copy the bundled bindings");
    #[cfg(feature = "bundled")]
    bundled::build();
}

#[cfg(feature = "bundled")]
mod bundled {
    use std::env;

    pub fn build() {
        let source_dir = sqlite3mc_src::source_dir();
        let source = source_dir.join(sqlite3mc_src::SOURCE_FILE);
        println!("cargo:include={}", source_dir.display());
        println!("cargo:rerun-if-changed={}", source.display());
        println!("cargo:rerun-if-changed=build.rs");

        let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
        let windows = env::var("CARGO_CFG_WINDOWS").is_ok();

        let mut cfg = cc::Build::new();
        cfg.file(&source)
            // libsqlite3-sys 0.38.2's options for its bundled SQLite.
            .flag("-DSQLITE_CORE")
            .flag("-DSQLITE_DEFAULT_FOREIGN_KEYS=1")
            .flag("-DSQLITE_ENABLE_API_ARMOR")
            .flag("-DSQLITE_ENABLE_COLUMN_METADATA")
            .flag("-DSQLITE_ENABLE_DBSTAT_VTAB")
            .flag("-DSQLITE_ENABLE_FTS3")
            .flag("-DSQLITE_ENABLE_FTS3_PARENTHESIS")
            .flag("-DSQLITE_ENABLE_FTS5")
            .flag("-DSQLITE_ENABLE_JSON1")
            .flag("-DSQLITE_ENABLE_LOAD_EXTENSION=1")
            .flag("-DSQLITE_ENABLE_MEMORY_MANAGEMENT")
            .flag("-DSQLITE_ENABLE_RTREE")
            .flag("-DSQLITE_ENABLE_STAT4")
            .flag("-DSQLITE_SOUNDEX")
            .flag("-DSQLITE_THREADSAFE=1")
            .flag("-DSQLITE_USE_URI")
            .flag("-DHAVE_USLEEP=1")
            .flag("-DHAVE_ISNAN")
            .flag("-D_POSIX_THREAD_SAFE_FUNCTIONS")
            // SQLite3 Multiple Ciphers: only the ChaCha20-Poly1305 scheme, as the default.
            .flag("-DHAVE_CIPHER_AES_128_CBC=0")
            .flag("-DHAVE_CIPHER_AES_256_CBC=0")
            .flag("-DHAVE_CIPHER_SQLCIPHER=0")
            .flag("-DHAVE_CIPHER_RC4=0")
            .flag("-DHAVE_CIPHER_ASCON128=0")
            .flag("-DHAVE_CIPHER_AEGIS=0")
            .flag("-DHAVE_CIPHER_CHACHA20=1")
            .flag("-DCODEC_TYPE=CODEC_TYPE_CHACHA20")
            // Temporary tables, indices and sorts never reach a file: SQLite3MC does not seal
            // the main database's pages there.
            .flag("-DSQLITE_TEMP_STORE=3")
            .warnings(false);
        // C23 makes the amalgamation call memset_explicit, which C libraries before glibc 2.43
        // lack; C17 takes its explicit_bzero path.
        cfg.flag_if_supported("-std=gnu17");

        if env::var("CARGO_CFG_TARGET_FEATURE").is_ok_and(|v| v.split(',').any(|tf| tf == "crt-static"))
            && target_env == "msvc"
        {
            cfg.static_crt(true);
        }
        if !windows {
            cfg.flag("-DHAVE_LOCALTIME_R");
        }
        if cfg!(feature = "with-asan") {
            cfg.flag("-fsanitize=address");
        }
        if cfg!(feature = "unlock_notify") {
            cfg.flag("-DSQLITE_ENABLE_UNLOCK_NOTIFY");
        }
        for (variable, define) in [
            ("SQLITE_MAX_VARIABLE_NUMBER", "SQLITE_MAX_VARIABLE_NUMBER"),
            ("SQLITE_MAX_EXPR_DEPTH", "SQLITE_MAX_EXPR_DEPTH"),
            ("SQLITE_MAX_COLUMN", "SQLITE_MAX_COLUMN"),
        ] {
            println!("cargo:rerun-if-env-changed={variable}");
            if let Ok(limit) = env::var(variable) {
                cfg.flag(format!("-D{define}={limit}"));
            }
        }
        cfg.compile("sqlite3");
        println!("cargo:lib_dir={}", env::var("OUT_DIR").unwrap());
    }
}
