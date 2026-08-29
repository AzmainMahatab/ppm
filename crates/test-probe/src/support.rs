//! Shared Win32 marshalling helpers for the verification suites.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

/// Encodes a Rust string as a NUL-terminated UTF-16 sequence.
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Decodes a NUL-terminated UTF-16 sequence from a raw pointer.
///
/// # Safety
/// `ptr` must point to a valid, NUL-terminated UTF-16 buffer readable up to and
/// including its terminator.
pub(crate) unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    unsafe {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}
