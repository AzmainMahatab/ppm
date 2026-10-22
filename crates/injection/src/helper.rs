//! Both sides of injecting a process of the other bitness through a Detours `rundll32` helper.
//!
//! # Why a handshake
//! Detours judges the helper by its exit code, and `rundll32` exits 0 even when it cannot load
//! the engine at all, so a failed helper looked like a successful one and the child ran outside
//! virtualization. The injector cannot always check the child itself: a 32-bit process cannot
//! read a 64-bit child's memory. The helper always can - it has the child's bitness - so it
//! verifies its own work and then sets a named event the injector created for this child. The
//! injector accepts the injection only when the event is set; a helper that never ran our code
//! cannot set it.

use std::ffi::{CStr, c_char};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, FALSE, GetLastError, HANDLE, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, EVENT_MODIFY_STATE, OpenEventW, OpenProcess, PROCESS_ALL_ACCESS, SetEvent,
    WaitForSingleObject,
};

use crate::detours;

/// Exit codes of the helper. The 990x values are the ones Detours' own helper uses for the same
/// failures, so a code reads the same whichever entry point produced it.
mod exit_code {
    pub const SUCCESS: u32 = 0;
    pub const OPEN_FAILED: u32 = 9901;
    pub const MALFORMED_PAYLOAD: u32 = 9902;
    pub const UPDATE_FAILED: u32 = 9903;
    /// Detours reported success but the child holds no restore payload.
    pub const NOT_APPLIED: u32 = 9904;
    pub const NO_PAYLOAD: u32 = 9905;
    /// The injector's event exists but could not be set.
    pub const SIGNAL_FAILED: u32 = 9906;
}

/// The name of the event that confirms injection of the child `child_pid`, NUL-terminated.
///
/// # Why the child's pid
/// It is unique among live processes and known to both sides: the injector holds the suspended
/// child, and Detours passes its pid to the helper. `Local\` keeps it in the session both share.
fn event_name(child_pid: u32) -> Vec<u16> {
    format!("Local\\ppm-helper-{child_pid}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// The injector's side: an unset event the helper sets once the child is verified injected.
pub struct Handshake(HANDLE);

impl Handshake {
    /// Creates the event for `child_pid`, before the helper starts.
    pub fn create(child_pid: u32) -> std::io::Result<Self> {
        let name = event_name(child_pid);
        // SAFETY: `name` is NUL-terminated and outlives the call; default security, manual reset
        // (the state stays set for the single query), initially unset.
        let event = unsafe { CreateEventW(ptr::null(), TRUE, FALSE, name.as_ptr()) };
        if event.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // Why refuse an existing event: someone else set up this name for a live pid, so its state
        // says nothing about this injection.
        // SAFETY: reads the calling thread's last error, set by CreateEventW above.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: `event` is a handle this call opened.
            unsafe { CloseHandle(event) };
            return Err(std::io::Error::from_raw_os_error(ERROR_ALREADY_EXISTS as i32));
        }
        Ok(Self(event))
    }

    /// Whether the helper confirmed the injection. Asked after the helper has exited, so the
    /// answer is final and nothing is waited for.
    pub fn confirmed(&self) -> bool {
        // SAFETY: `self.0` is the live event this value owns; a zero timeout only reads its state.
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_OBJECT_0 }
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// What the helper payload asks for.
#[derive(Debug, PartialEq, Eq)]
struct HelperRequest<'a> {
    child_pid: u32,
    dlls: Vec<&'a CStr>,
}

// Intention: The size of the payload's fixed header, `DETOUR_EXE_HELPER` without its names.
// Why: three DWORDs (`cb`, `pid`, `nDlls`), as detours.h declares the struct; the NUL-terminated
//      DLL names follow it, filling the payload up to `cb`.
const HELPER_HEADER_LEN: usize = 12;

/// Parses a `DETOUR_EXE_HELPER` payload of `bytes.len()` bytes.
fn parse_helper_payload(bytes: &[u8]) -> Option<HelperRequest<'_>> {
    let field = |index: usize| {
        let start = index * 4;
        bytes
            .get(start..start + 4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("invariant: a 4-byte slice")))
    };
    let declared_len = usize::try_from(field(0)?).ok()?;
    let child_pid = field(1)?;
    let dll_count = field(2)?;
    let mut names = bytes.get(HELPER_HEADER_LEN..declared_len)?;

    let mut dlls = Vec::new();
    for _ in 0..dll_count {
        let name = CStr::from_bytes_until_nul(names).ok()?;
        names = &names[name.to_bytes_with_nul().len()..];
        dlls.push(name);
    }
    Some(HelperRequest { child_pid, dlls })
}

/// The helper's side: patches the child the helper payload names, verifies the patch, and sets
/// the injector's event. Returns the helper's exit code.
///
/// # Safety
/// Must run in a Detours helper process, where `DetourIsHelperProcess` holds.
pub unsafe fn finish_helper_process() -> u32 {
    let mut size = 0u32;
    // SAFETY: the GUID is a static Detours defines; `size` receives the payload's length.
    let payload =
        unsafe { detours::DetourFindPayloadEx(&raw const detours::DETOUR_EXE_HELPER_GUID, &mut size) };
    if payload.is_null() {
        return exit_code::NO_PAYLOAD;
    }
    // SAFETY: Detours reports `size` readable bytes at `payload`, live until it is freed below.
    let bytes = unsafe { std::slice::from_raw_parts(payload.cast::<u8>(), size as usize) };
    let code = match parse_helper_payload(bytes) {
        // SAFETY: forwarded contract - this is a helper process.
        Some(request) => unsafe { inject_and_confirm(&request) },
        None => exit_code::MALFORMED_PAYLOAD,
    };
    // SAFETY: `payload` came from DetourFindPayloadEx and is not used after this.
    unsafe { detours::DetourFreePayload(payload) };
    code
}

/// # Safety
/// Must run in a Detours helper process.
unsafe fn inject_and_confirm(request: &HelperRequest<'_>) -> u32 {
    // SAFETY: plain open of the child Detours' injector named.
    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, request.child_pid) };
    if process.is_null() {
        return exit_code::OPEN_FAILED;
    }
    let dlls: Vec<*const c_char> = request.dlls.iter().map(|name| name.as_ptr()).collect();
    // SAFETY: `process` is open with full access; `dlls` points at NUL-terminated names inside the
    // payload, which outlives this call.
    let code = unsafe {
        if detours::DetourUpdateProcessWithDll(process, dlls.as_ptr(), dlls.len() as u32) == 0 {
            exit_code::UPDATE_FAILED
        } else if !crate::import_table_was_patched(process) {
            exit_code::NOT_APPLIED
        } else {
            signal_injector(request.child_pid)
        }
    };
    // SAFETY: `process` is a handle this function opened.
    unsafe { CloseHandle(process) };
    code
}

/// Sets the injector's event for `child_pid`. No event means an injector that checks the child
/// itself and asked for no confirmation, which is a success.
fn signal_injector(child_pid: u32) -> u32 {
    let name = event_name(child_pid);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, FALSE, name.as_ptr()) };
    if event.is_null() {
        // SAFETY: reads the calling thread's last error, set by OpenEventW above.
        return match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND => exit_code::SUCCESS,
            _ => exit_code::SIGNAL_FAILED,
        };
    }
    // SAFETY: `event` is open with EVENT_MODIFY_STATE and closed right after.
    let set = unsafe { SetEvent(event) };
    // SAFETY: `event` is a handle this function opened.
    unsafe { CloseHandle(event) };
    match set {
        0 => exit_code::SIGNAL_FAILED,
        _ => exit_code::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload as Detours lays it out: `cb`, `pid`, `nDlls`, then the NUL-terminated names.
    fn payload(declared_len: Option<u32>, pid: u32, names: &[&str]) -> Vec<u8> {
        let mut tail: Vec<u8> = Vec::new();
        for name in names {
            tail.extend_from_slice(name.as_bytes());
            tail.push(0);
        }
        let len = declared_len.unwrap_or((HELPER_HEADER_LEN + tail.len()) as u32);
        let mut bytes = Vec::new();
        for word in [len, pid, names.len() as u32] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&tail);
        bytes
    }

    #[test]
    fn a_well_formed_payload_names_the_child_and_its_dlls() {
        let bytes = payload(None, 4242, &[r"C:\root\.ppm\lib\x64\redirector64.dll"]);
        let request = parse_helper_payload(&bytes).expect("well-formed");
        assert_eq!(request.child_pid, 4242);
        assert_eq!(request.dlls, [c"C:\\root\\.ppm\\lib\\x64\\redirector64.dll"]);
    }

    #[test]
    fn a_payload_whose_names_overrun_its_declared_length_is_rejected() {
        // The declared length stops inside the name, so it has no terminator within bounds.
        let truncated = payload(Some(HELPER_HEADER_LEN as u32 + 4), 7, &["redirector64.dll"]);
        assert_eq!(parse_helper_payload(&truncated), None);
        // More names announced than present.
        let mut missing = payload(None, 7, &["a.dll"]);
        missing[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse_helper_payload(&missing), None);
        // Shorter than its own header.
        assert_eq!(parse_helper_payload(&[1, 2, 3]), None);
    }

    #[test]
    fn the_event_name_is_per_child_and_session_local() {
        let name = String::from_utf16(&event_name(31337)).expect("UTF-16");
        assert_eq!(name, "Local\\ppm-helper-31337\0");
    }
}
