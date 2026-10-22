pub mod credentials;
pub mod detour;
pub(crate) mod host_modules;
pub mod paths;
pub(crate) mod persist;
pub mod process;
pub mod registry;
pub mod shell;
pub(crate) mod winstr;

pub type BOOL = i32;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

use std::sync::atomic::{AtomicIsize, Ordering};
use windows_sys::Win32::Foundation::{HMODULE, HWND};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::ExitProcess;

/// Ordinal 1 (exports.def): the entry point Detours' `rundll32` helper runs to inject a process of
/// this DLL's bitness. It patches the child, verifies the patch, and confirms it to the injector
/// (`injection::helper`); the exit code is what Detours reports to the injector.
///
/// # Safety
/// Only `rundll32` may call it, as ordinal 1 in a helper process Detours started: it ends the
/// process.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ppm_finish_helper(
    _window: HWND,
    _instance: HMODULE,
    _command_line: *const u8,
    _show: i32,
) {
    // SAFETY: `rundll32` calls ordinal 1 only in the helper process Detours started, where the
    // helper payload is present.
    let code = unsafe { injection::helper::finish_helper_process() };
    // SAFETY: the helper process exists only to run this export.
    unsafe { ExitProcess(code) }
}

pub static HMODULE_SELF: AtomicIsize = AtomicIsize::new(0);

/// DLL entry point invoked by the Windows PE Loader.
///
/// # Safety
/// Must only be invoked by Windows runtime loader in accordance with standard Win32 `DllMain` ABI contracts.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    h_inst_dll: HMODULE,
    fdw_reason: u32,
    _lp_reserved: *mut std::ffi::c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Why first: in a Detours helper (the `rundll32` that injects a process of the other
            // bitness) this DLL is loaded only to run its ordinal-1 export. The helper is not an
            // application, so no boundary may be installed in it. The call also locates the
            // helper's payload, which that export reads.
            // SAFETY: plain Detours query of the current process's own image.
            if unsafe { injection::detours::DetourIsHelperProcess() } != 0 {
                return TRUE;
            }
            // Detours patched this process's import table to load the engine; restore it so the
            // application sees its own image as built. Detours requires this in every DLL it
            // injects.
            // SAFETY: called once, at attach, as Detours documents.
            unsafe { injection::detours::DetourRestoreAfterWith() };

            HMODULE_SELF.store(h_inst_dll as isize, Ordering::SeqCst);
            paths::init_paths();
            paths::init_logger();

            tracing::info!("redirector.dll attached to process (PID: {})", std::process::id());

            // Initialize every isolation boundary: registry, process spawning, credentials, shell
            registry::init_hooks();
            process::init_hooks();
            credentials::init_hooks();
            shell::init_hooks();
        }
        DLL_PROCESS_DETACH => {
            // Note: Keep DllMain clean on process detach to avoid TLS teardown issues
        }
        _ => {}
    }

    TRUE
}
