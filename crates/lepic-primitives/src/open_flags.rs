// SPDX-License-Identifier: Apache-2.0
//! `O_NONBLOCK` and `O_NOFOLLOW` for the Unix targets LEPIC runs on, for hosts that open files
//! with `custom_flags`. The std library does not expose them, and a `libc` dependency is not
//! worth two constants.

// From the platform headers. Their values differ between kernels
// and, on Linux, between architectures. A Unix target not listed here fails to build rather than
// lose either guard.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "loongarch64"
    )
))]
mod table {
    pub(super) const O_NONBLOCK: i32 = 0o4000;
    pub(super) const O_NOFOLLOW: i32 = 0o400000;
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc64"
    )
))]
mod table {
    pub(super) const O_NONBLOCK: i32 = 0o4000;
    pub(super) const O_NOFOLLOW: i32 = 0o100000;
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod table {
    pub(super) const O_NONBLOCK: i32 = 0x0004;
    pub(super) const O_NOFOLLOW: i32 = 0x0100;
}

#[cfg(all(
    unix,
    not(any(
        all(
            any(target_os = "linux", target_os = "android"),
            any(
                target_arch = "x86",
                target_arch = "x86_64",
                target_arch = "riscv64",
                target_arch = "s390x",
                target_arch = "loongarch64",
                target_arch = "arm",
                target_arch = "aarch64",
                target_arch = "powerpc64"
            )
        ),
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!("LEPIC does not know O_NONBLOCK and O_NOFOLLOW for this Unix target");

/// This platform's `O_NONBLOCK`: opening a FIFO without it waits for a writer.
pub const O_NONBLOCK: i32 = table::O_NONBLOCK;

/// This platform's `O_NOFOLLOW`: opening a symbolic link fails instead of following it.
pub const O_NOFOLLOW: i32 = table::O_NOFOLLOW;
