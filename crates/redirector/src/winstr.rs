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
