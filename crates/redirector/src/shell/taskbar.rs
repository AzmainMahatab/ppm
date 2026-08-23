use crate::detour::attach_detour;
use std::cell::Cell;
use std::ffi::c_void;
use windows_sys::core::HRESULT;

thread_local! {
    static IN_APP_ID_HOOK: Cell<bool> = const { Cell::new(false) };
}

type FnSetCurrentProcessExplicitAppUserModelID = unsafe extern "system" fn(*const u16) -> HRESULT;
static mut REAL_SET_APP_USER_MODEL_ID: *mut c_void = std::ptr::null_mut();

unsafe extern "system" fn hook_set_app_user_model_id(app_id: *const u16) -> HRESULT {
    let real_fn: FnSetCurrentProcessExplicitAppUserModelID = std::mem::transmute(REAL_SET_APP_USER_MODEL_ID);
    if IN_APP_ID_HOOK.with(|h| h.get()) {
        return real_fn(app_id);
    }

    IN_APP_ID_HOOK.with(|h| h.set(true));

    // Force canonical portable application ID
    let portable_id = windows_sys::core::w!("Google.Antigravity.Portable");
    let res = real_fn(portable_id);

    IN_APP_ID_HOOK.with(|h| h.set(false));
    res
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let shell32 = GetModuleHandleW(windows_sys::core::w!("shell32.dll"));
        if !shell32.is_null() {
            if let Some(proc) = GetProcAddress(shell32, b"SetCurrentProcessExplicitAppUserModelID\0".as_ptr()) {
                REAL_SET_APP_USER_MODEL_ID = proc as *mut c_void;
                attach_detour(&raw mut REAL_SET_APP_USER_MODEL_ID, hook_set_app_user_model_id as *mut c_void);
            }
        }
    }
}
