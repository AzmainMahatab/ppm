mod cred_store;
mod hooks;
mod paths;
mod taskbar;

use std::ffi::c_void;
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, TRUE};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH,
};

/// Export required for Microsoft Detours withdll loader compatibility at Ordinal 1
#[no_mangle]
pub extern "system" fn DetourFinishHelperProcess() -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            paths::set_dll_handle(hinst_dll);
            let cfg = paths::init_paths();
            paths::log_always(&format!(
                "Redirector DLL attached! UserProfile: {:?}, LocalAppData: {:?}, RoamingAppData: {:?}",
                cfg.user_profile, cfg.local_appdata, cfg.roaming_appdata
            ));
            hooks::install_hooks();
            taskbar::init_taskbar_integration();
        }
        DLL_PROCESS_DETACH => {
            paths::log_always("Redirector DLL detaching from process.");
        }
        _ => {}
    }
    TRUE
}
