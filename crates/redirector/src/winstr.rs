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

/// Decodes a NUL-terminated string an `...A` API received, in the system ANSI code page.
///
/// # Safety
/// `ptr` must be null (decoding to the empty string) or point to a NUL-terminated byte string.
pub(crate) fn ansi_to_string(ptr: *const u8) -> String {
    use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: `ptr` is NUL-terminated per the contract; -1 makes both calls stop at the
    // terminator, and the second writes into a buffer of the size the first reported.
    unsafe {
        let needed = MultiByteToWideChar(CP_ACP, 0, ptr, -1, std::ptr::null_mut(), 0);
        if needed <= 0 {
            return String::new();
        }
        let mut wide = vec![0u16; needed as usize];
        let written = MultiByteToWideChar(CP_ACP, 0, ptr, -1, wide.as_mut_ptr(), needed);
        wide.truncate(written.max(1) as usize - 1);
        String::from_utf16_lossy(&wide)
    }
}

/// Decodes the `bytes` an `...A` value call supplies, in the system ANSI code page.
///
/// # Why an explicit length
/// Value data is counted, not terminated: a `REG_MULTI_SZ` payload holds NULs between its
/// strings, and a `REG_SZ` payload may omit its terminator. Decoding the counted bytes keeps
/// every NUL where the caller put it.
pub(crate) fn ansi_bytes_to_wide(bytes: &[u8]) -> Vec<u16> {
    use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar};
    if bytes.is_empty() {
        return Vec::new();
    }
    let length = i32::try_from(bytes.len())
        .expect("invariant: callers bound ANSI text payloads to i32::MAX bytes before converting");
    // SAFETY: both calls read exactly `length` bytes of the live slice and write into a buffer
    // of the size the first call reported.
    unsafe {
        let needed = MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), length, std::ptr::null_mut(), 0);
        assert!(
            needed > 0,
            "invariant: the system ANSI code page decodes any byte sequence"
        );
        let mut wide = vec![0u16; needed as usize];
        let written = MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), length, wide.as_mut_ptr(), needed);
        wide.truncate(written as usize);
        wide
    }
}

/// Encodes stored UTF-16 payload bytes as ANSI, the inverse of `ansi_bytes_to_wide`. NULs are
/// kept, so a `REG_MULTI_SZ` payload keeps its separators.
pub(crate) fn wide_bytes_to_ansi(bytes: &[u8]) -> Vec<u8> {
    use windows_sys::Win32::Globalization::{CP_ACP, WideCharToMultiByte};
    let wide: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    if wide.is_empty() {
        return Vec::new();
    }
    // Why this holds: a stored payload is at most u32::MAX bytes (the API's cbData), which is
    // at most i32::MAX UTF-16 units.
    let length = i32::try_from(wide.len()).expect("invariant: a u32-sized payload is at most i32::MAX units");
    // SAFETY: both calls read exactly `length` units of the live buffer and write into a buffer
    // of the size the first call reported.
    unsafe {
        let needed = WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        assert!(
            needed > 0,
            "invariant: the system ANSI code page encodes any UTF-16 sequence"
        );
        let mut ansi = vec![0u8; needed as usize];
        let written = WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            length,
            ansi.as_mut_ptr(),
            needed,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        assert!(
            written > 0,
            "invariant: the system ANSI code page encodes any UTF-16 sequence"
        );
        ansi.truncate(written as usize);
        ansi
    }
}

/// Encodes `s` as the NUL-terminated ANSI string an `...A` API returns. A character the code
/// page lacks becomes its default character - the same conversion the system's own `...A`
/// functions apply to their wide results.
pub(crate) fn to_ansi(s: &str) -> Vec<u8> {
    use windows_sys::Win32::Globalization::{CP_ACP, WideCharToMultiByte};
    let wide = to_wide(s);
    // SAFETY: `wide` is NUL-terminated; -1 includes the terminator in both calls, and the second
    // writes into a buffer of the size the first reported.
    unsafe {
        let needed = WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            -1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        if needed <= 0 {
            return vec![0];
        }
        let mut ansi = vec![0u8; needed as usize];
        let written = WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            -1,
            ansi.as_mut_ptr(),
            needed,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        ansi.truncate(written.max(1) as usize);
        ansi
    }
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
