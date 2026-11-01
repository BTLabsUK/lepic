#![expect(non_snake_case, non_camel_case_types)]
#![cfg_attr(not(test), no_std)]

pub use self::error::*;

use core::mem;

mod error;

#[must_use]
pub fn SQLITE_STATIC() -> sqlite3_destructor_type {
    None
}

#[must_use]
pub fn SQLITE_TRANSIENT() -> sqlite3_destructor_type {
    Some(unsafe { mem::transmute::<isize, unsafe extern "C" fn(*mut core::ffi::c_void)>(-1_isize) })
}

#[allow(dead_code, clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindgen.rs"));
}
pub use bindings::*;

// SQLite3 Multiple Ciphers' key calls, which SQLite's own bindings lack (PATCHES.md).
extern "C" {
    /// Sets the key of the database `zDbName` ("main" when null) on `db`. Call it before the
    /// first access to that database.
    pub fn sqlite3_key_v2(
        db: *mut sqlite3,
        zDbName: *const core::ffi::c_char,
        pKey: *const core::ffi::c_void,
        nKey: core::ffi::c_int,
    ) -> core::ffi::c_int;
    /// Re-encrypts the database `zDbName` on `db` under a new key; an empty key decrypts it.
    pub fn sqlite3_rekey_v2(
        db: *mut sqlite3,
        zDbName: *const core::ffi::c_char,
        pKey: *const core::ffi::c_void,
        nKey: core::ffi::c_int,
    ) -> core::ffi::c_int;
}

impl Default for sqlite3_vtab {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

impl Default for sqlite3_vtab_cursor {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}
