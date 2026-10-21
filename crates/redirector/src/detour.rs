use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::thread::LocalKey;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
use windows_sys::Win32::System::Threading::GetCurrentThread;

pub use injection::detours::{
    DetourAttach, DetourDetach, DetourTransactionBegin, DetourTransactionCommit, DetourUpdateThread,
};

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
            tracing::error!("DetourAttach failed with code {status}");
        }
        let commit_status = DetourTransactionCommit();
        if commit_status != 0 {
            tracing::error!("DetourTransactionCommit failed with code {commit_status}");
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
///
/// # Invariant
/// Attach runs from `DllMain`. The loader lock serializes `DllMain` calls but does NOT freeze
/// the process: any DLL in the load chain may spawn threads that reach hooked APIs while this
/// function runs. Publication therefore never relies on "no other threads exist" - hooks wait
/// for this store instead (see [`load_trampoline`]).
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
/// window into a bounded wait.
///
/// # Invariant
/// The loader lock serializes `DllMain` calls but does not freeze the process: DLLs in the
/// load chain may spawn threads that reach hooked APIs during attach. The spin is therefore
/// live protection for that case - not dead code - and it keeps a future hot-attach path
/// correct instead of dispatching through null.
pub(crate) fn load_trampoline(slot: &AtomicPtr<c_void>) -> *mut c_void {
    loop {
        match slot.load(Ordering::Acquire) {
            trampoline if !trampoline.is_null() => return trampoline,
            _ => std::hint::spin_loop(),
        }
    }
}

/// Loads the published trampoline for `slot` without waiting, yielding `None` when the API was
/// never hooked.
///
/// # Why a non-blocking variant exists
/// [`load_trampoline`] may spin because a hook body is entitled to assume its *own* API
/// attached: the hook is running, so the attach happened. That assumption does not carry to a
/// hook that needs a *different* API's trampoline. The registry enumerators read the host's
/// listing through `RegEnumKeyExW` and `RegEnumValueW`, and if either export could not be hooked
/// its slot stays null for the life of the process, so spinning there would hang the application
/// inside a registry call instead of degrading.
pub(crate) fn try_load_trampoline(slot: &AtomicPtr<c_void>) -> Option<*mut c_void> {
    match slot.load(Ordering::Acquire) {
        trampoline if trampoline.is_null() => None,
        trampoline => Some(trampoline),
    }
}

/// Re-entrancy guard for detour hook bodies.
///
/// # Why
/// A hook body may re-enter its own hooked API (directly or transitively); without a
/// guard each re-entry would re-apply the redirect instead of reaching the original
/// implementation. Each hook module owns one thread-local flag; while the flag is set
/// on the current thread, nested entry yields `None` and the caller must forward to
/// the trampoline - the documented unvirtualized fallback.
///
/// # Why `try_with` and a silent forward
/// Thread-local access can fail only after thread destruction has begun, when the flag
/// storage no longer exists. That path is unreachable while redirect logic is live, so
/// forwarding cannot mask a live-path bug; panicking would instead unwind across an
/// `extern "system"` frame and abort the virtualized host application during teardown.
pub(crate) struct ReenterGuard {
    key: &'static LocalKey<Cell<bool>>,
}

impl ReenterGuard {
    pub(crate) fn enter(key: &'static LocalKey<Cell<bool>>) -> Option<Self> {
        key.try_with(|flag| {
            if flag.get() {
                None
            } else {
                flag.set(true);
                Some(Self { key })
            }
        })
        .ok()
        .flatten()
    }
}

impl Drop for ReenterGuard {
    fn drop(&mut self) {
        let _ = self.key.try_with(|flag| flag.set(false));
    }
}

/// Evaluates `body` under the re-entrancy flag of `key`, or returns `fallback` when the
/// hook was re-entered (see [`ReenterGuard`]).
macro_rules! guard_detour {
    ($key:expr, $fallback:expr, $body:expr) => {{
        let _guard = match $crate::detour::ReenterGuard::enter($key) {
            Some(guard) => guard,
            None => return $fallback,
        };
        $body
    }};
}
pub(crate) use guard_detour;

/// Resolves `api` on `module` and attaches `hook` over it.
///
/// # Why a single seam
/// Every `init_hooks` call site resolved exports with hand-rolled `GetProcAddress`
/// blocks whose failure behavior had drifted (some silent, some logged). Centralizing
/// here makes a missing export or failed attach uniformly loud: a silently absent hook
/// would leave an isolation boundary unenforced while the process keeps running.
///
/// # Invariant
/// The slot is published by [`install_detour`] in every outcome, so a live hook never
/// dispatches through null.
pub(crate) fn hook_export(module: HMODULE, api: &str, slot: &AtomicPtr<c_void>, hook: *mut c_void) -> bool {
    if module.is_null() {
        tracing::warn!("Hook {api}: module handle is null");
        return false;
    }
    // SAFETY: `export_name` is a NUL-terminated ANSI export name; `module` is a live
    // module handle obtained by the caller; `hook` is a valid hook function pointer.
    let export_name: Vec<u8> = api.bytes().chain(std::iter::once(0)).collect();
    unsafe {
        let Some(target) = GetProcAddress(module, export_name.as_ptr()) else {
            tracing::warn!("Hook {api}: export not found");
            return false;
        };
        let ok = install_detour(slot, target as *mut c_void, hook);
        tracing::info!("Hook {api}: {ok}");
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// A real, non-null address with valid provenance - only ever loaded, never called.
    fn sentinel(byte: u8) -> *mut c_void {
        (Box::leak(Box::new(byte)) as *mut u8).cast::<c_void>()
    }

    #[test]
    fn load_trampoline_returns_the_preseeded_trampoline() {
        let trampoline = sentinel(7);
        let slot = AtomicPtr::new(trampoline);
        assert_eq!(load_trampoline(&slot), trampoline);
    }

    #[test]
    fn load_trampoline_observes_cross_thread_publication() {
        let slot = std::sync::Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        let publisher = std::sync::Arc::clone(&slot);

        thread::spawn(move || {
            let published = sentinel(9);
            publisher.store(published, Ordering::Release);
        });

        // The Acquire spin is the contract itself: whatever the interleaving, the load
        // must never observe null and must observe the publication.
        let loaded = load_trampoline(&slot);
        assert!(!loaded.is_null());
    }
}
