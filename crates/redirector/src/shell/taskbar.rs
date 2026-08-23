use retour::GenericDetour;
use std::cell::Cell;
use std::sync::OnceLock;
use windows_sys::core::HRESULT;

thread_local! {
    static IN_APP_ID_HOOK: Cell<bool> = const { Cell::new(false) };
}

type FnSetCurrentProcessExplicitAppUserModelID = unsafe extern "system" fn(*const u16) -> HRESULT;
static HOOK_SET_APP_USER_MODEL_ID: OnceLock<GenericDetour<FnSetCurrentProcessExplicitAppUserModelID>> = OnceLock::new();

unsafe extern "system" fn hook_set_app_user_model_id(app_id: *const u16) -> HRESULT {
    if IN_APP_ID_HOOK.with(|h| h.get()) {
        return HOOK_SET_APP_USER_MODEL_ID.get().unwrap().call(app_id);
    }

    IN_APP_ID_HOOK.with(|h| h.set(true));

    // Force canonical portable application ID
    let portable_id = windows_sys::core::w!("Google.Antigravity.Portable");
    let res = HOOK_SET_APP_USER_MODEL_ID.get().unwrap().call(portable_id);

    IN_APP_ID_HOOK.with(|h| h.set(false));
    res
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let shell32 = GetModuleHandleW(windows_sys::core::w!("shell32.dll"));
        if !shell32.is_null() {
            if let Some(proc) = GetProcAddress(shell32, b"SetCurrentProcessExplicitAppUserModelID\0".as_ptr()) {
                let target: FnSetCurrentProcessExplicitAppUserModelID = std::mem::transmute(proc);
                if let Ok(d) = GenericDetour::new(target, hook_set_app_user_model_id) {
                    if d.enable().is_ok() {
                        let _ = HOOK_SET_APP_USER_MODEL_ID.set(d);
                    }
                }
            }
        }
    }
}
