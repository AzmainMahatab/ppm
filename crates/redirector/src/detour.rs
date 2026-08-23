use std::ffi::c_void;
use windows_sys::Win32::System::Threading::GetCurrentThread;

extern "system" {
    pub fn DetourTransactionBegin() -> i32;
    pub fn DetourUpdateThread(hThread: windows_sys::Win32::Foundation::HANDLE) -> i32;
    pub fn DetourAttach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> i32;
    pub fn DetourDetach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> i32;
    pub fn DetourTransactionCommit() -> i32;
}

/// Atomically attaches a detour to a target function using Microsoft Detours.
/// `target_ptr` must point to the variable holding the original function address.
/// Upon success, Microsoft Detours updates `*target_ptr` to point to the trampoline.
pub unsafe fn attach_detour(target_ptr: *mut *mut c_void, detour_fn: *mut c_void) -> bool {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    let status = DetourAttach(target_ptr, detour_fn);
    if status != 0 {
        tracing::error!("DetourAttach failed with code {}", status);
    }
    let commit_status = DetourTransactionCommit();
    if commit_status != 0 {
        tracing::error!("DetourTransactionCommit failed with code {}", commit_status);
    }
    status == 0 && commit_status == 0
}
