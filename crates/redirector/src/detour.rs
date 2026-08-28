use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::Win32::System::Threading::GetCurrentThread;

unsafe extern "system" {
    pub fn DetourTransactionBegin() -> i32;
    pub fn DetourUpdateThread(hThread: windows_sys::Win32::Foundation::HANDLE) -> i32;
    pub fn DetourAttach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> i32;
    pub fn DetourDetach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> i32;
    pub fn DetourTransactionCommit() -> i32;
}

/// Atomically attaches a detour to a target function using Microsoft Detours.
/// `target_ptr` must point to the variable holding the original function address.
/// Upon success, Microsoft Detours updates `*target_ptr` to point to the trampoline.
///
/// # Safety
/// Caller must ensure `target_ptr` points to a valid function pointer in executable memory
/// and `detour_fn` has a signature matching the target ABI.
pub unsafe fn attach_detour(target_ptr: *mut *mut c_void, detour_fn: *mut c_void) -> bool {
    unsafe {
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
}

/// Attaches `hook` over the API whose original address is `original`, then publishes the
/// trampoline Detours left in the thread-confined local to `slot` with Release ordering.
///
/// # Why the store is unconditional
/// The published value is call-valid for a live hook in every outcome: the trampoline on
/// success, the unpatched original on failure (where the hook is never entered). Gating the
/// publication on the transaction result would instead risk an unbounded hook spin in the
/// pathological "patched but reported failure" case.
pub(crate) fn install_detour(slot: &AtomicPtr<c_void>, original: *mut c_void, hook: *mut c_void) -> bool {
    let mut real: *mut c_void = original;
    let ok = unsafe { attach_detour(&mut real, hook) };
    slot.store(real, Ordering::Release);
    ok
}

/// Loads the published trampoline for `slot`, yielding only once a non-null address is visible.
///
/// # Why an acquire spin
/// Detours' code patch becomes live inside `DetourTransactionCommit`, while the trampoline
/// pointer is published by the attaching thread right after the transaction returns. A hook
/// entered inside that microscopic window must not read null; the Acquire spin converts the
/// window into a bounded wait. Under this crate's deployment model (attach from `DllMain` while
/// the loader lock serializes process startup) the spin never executes; under a future
/// hot-attach path it stays correct instead of dispatching through null.
pub(crate) fn load_trampoline(slot: &AtomicPtr<c_void>) -> *mut c_void {
    loop {
        match slot.load(Ordering::Acquire) {
            trampoline if !trampoline.is_null() => return trampoline,
            _ => std::hint::spin_loop(),
        }
    }
}
