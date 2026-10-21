//! Shared Win32 marshalling helpers for the verification suites.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

/// Encodes a Rust string as a NUL-terminated UTF-16 sequence.
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Encodes a Rust string as the NUL-terminated ANSI bytes an `...A` Win32 API expects - the
/// system ANSI code page, not UTF-8 - or `None` when a character has no exact form there.
pub(crate) fn to_ansi(s: &str) -> Option<Vec<u8>> {
    use windows_sys::Win32::Globalization::{CP_ACP, WC_NO_BEST_FIT_CHARS, WideCharToMultiByte};

    let wide = to_wide(s);
    let length = i32::try_from(wide.len()).ok()?;
    let mut used_default = 0;
    // SAFETY: sizing call - no output buffer; `wide` is live and NUL-terminated.
    let needed = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            &mut used_default,
        )
    };
    if needed <= 0 || used_default != 0 {
        return None;
    }
    let mut ansi = vec![0u8; needed as usize];
    // SAFETY: `ansi` holds exactly the size the sizing call reported, terminator included.
    let written = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            length,
            ansi.as_mut_ptr(),
            needed,
            std::ptr::null(),
            &mut used_default,
        )
    };
    (written == needed && used_default == 0).then_some(ansi)
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
