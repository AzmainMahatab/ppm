//! The Microsoft Detours API, compiled from `vendor/detours` by this crate's build script.

use std::ffi::{c_char, c_void};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::core::BOOL;

// Why "system": Detours declares its API WINAPI (stdcall). On x64 and ARM64 that is the C
// convention, but on 32-bit x86 a "C" declaration links against the wrong symbol.
unsafe extern "system" {
    pub fn DetourTransactionBegin() -> i32;
    pub fn DetourUpdateThread(hThread: HANDLE) -> i32;
    pub fn DetourAttach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> i32;
    pub fn DetourDetach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> i32;
    pub fn DetourTransactionCommit() -> i32;

    /// Adds `rlpDlls` to the import table of a suspended process of the caller's bitness.
    pub fn DetourUpdateProcessWithDll(hProcess: HANDLE, rlpDlls: *const *const c_char, nDlls: u32) -> BOOL;

    /// Injects a process of the other bitness through a `rundll32` helper of that bitness, which
    /// loads the `32`/`64`-swapped name of `rlpDlls[0]` and calls its ordinal-1 export
    /// (`DetourFinishHelperProcess`). `pfCreateProcessW` starts the helper and must not be null.
    pub fn DetourProcessViaHelperDllsW(
        dwTargetPid: u32,
        nDlls: u32,
        rlpDlls: *const *const c_char,
        pfCreateProcessW: *const c_void,
    ) -> BOOL;

    /// Whether this process is a Detours helper, in which case the engine must stay inert.
    pub fn DetourIsHelperProcess() -> BOOL;

    /// Restores the import table Detours patched to inject this process.
    pub fn DetourRestoreAfterWith() -> BOOL;
}
