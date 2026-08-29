//! Win32 UTF-16 string helpers shared by the hook modules.

/// Decodes a NUL-terminated UTF-16 string from a raw Win32 pointer.
///
/// # Safety
/// `ptr` must point to a valid NUL-terminated UTF-16 sequence readable up to the
/// terminator, or be null (null decodes to the empty string).
pub(crate) fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

use std::path::Path;
use windows_sys::Win32::System::Com::CoTaskMemAlloc;

#[allow(clippy::upper_case_acronyms)]
pub(crate) type PWSTR = *mut u16;

/// Encodes `s` as NUL-terminated UTF-16 for Win32 wide-string APIs.
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Encodes a path as NUL-terminated UTF-16, losslessly through `OsStr` (Windows paths
/// may contain unpaired surrogates that `str::encode_utf16` cannot represent).
pub(crate) fn path_to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Copies `w_str` (including its NUL terminator) into a COM-task-allocated buffer.
///
/// # Safety contract
/// The returned PWSTR is a caller-owned CoTaskMem allocation of exactly `w_str.len() * 2`
/// bytes, or null when the allocator fails. Release with `CoTaskMemFree`.
pub(crate) fn alloc_cotask_wide_string(w_str: &[u16]) -> PWSTR {
    // SAFETY: `CoTaskMemAlloc` either returns null or a `byte_len`-sized buffer; the copy
    // below fully initializes it before it is published to the caller.
    unsafe {
        let mem = CoTaskMemAlloc(w_str.len() * 2);
        if !mem.is_null() {
            std::ptr::copy_nonoverlapping(w_str.as_ptr(), mem.cast(), w_str.len());
        }
        mem.cast()
    }
}
