pub mod credentials;
pub mod detour;
pub mod paths;
pub mod process;
pub mod registry;
pub mod shell;

use std::sync::atomic::{AtomicIsize, Ordering};
use windows_sys::Win32::Foundation::{BOOL, HMODULE, TRUE};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

pub static HMODULE_SELF: AtomicIsize = AtomicIsize::new(0);

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    h_inst_dll: HMODULE,
    fdw_reason: u32,
    _lp_reserved: *mut std::ffi::c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            HMODULE_SELF.store(h_inst_dll as isize, Ordering::SeqCst);
            paths::init_paths();
            paths::init_logger();

            tracing::info!("redirector.dll attached to process (PID: {})", std::process::id());

            // Initialize all 4 virtualization pillars
            registry::init_hooks();
            process::init_hooks();
            credentials::init_hooks();
            shell::init_hooks();
        }
        DLL_PROCESS_DETACH => {
            tracing::info!("redirector.dll detached from process (PID: {})", std::process::id());
        }
        _ => {}
    }

    TRUE
}
