use crate::detour::{install_detour, load_trampoline};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::AtomicPtr;
use windows_sys::core::HRESULT;

thread_local! {
    static IN_APP_ID_HOOK: Cell<bool> = const { Cell::new(false) };
}

type FnSetCurrentProcessExplicitAppUserModelID = unsafe extern "system" fn(*const u16) -> HRESULT;
static REAL_SET_APP_USER_MODEL_ID: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

struct AppIdHookGuard;

impl AppIdHookGuard {
    fn enter() -> Option<Self> {
        if IN_APP_ID_HOOK.try_with(|h| h.get()).unwrap_or(false) {
            return None;
        }
        let _ = IN_APP_ID_HOOK.try_with(|h| h.set(true));
        Some(AppIdHookGuard)
    }
}

impl Drop for AppIdHookGuard {
    fn drop(&mut self) {
        let _ = IN_APP_ID_HOOK.try_with(|h| h.set(false));
    }
}

unsafe extern "system" fn hook_set_app_user_model_id(app_id: *const u16) -> HRESULT {
    let real_fn: FnSetCurrentProcessExplicitAppUserModelID =
        unsafe { std::mem::transmute(load_trampoline(&REAL_SET_APP_USER_MODEL_ID)) };

    let _guard = match AppIdHookGuard::enter() {
        Some(g) => g,
        // SAFETY: forwarding to the original API is the documented fallback for re-entrant
        // calls; `load_trampoline` guarantees the trampoline is published and call-valid.
        None => unsafe { return real_fn(app_id) },
    };

    let app_id_str = wide_to_string(app_id);
    let synthetic_id = format!("PPM.Isolated.{app_id_str}");
    let synthetic_wide: Vec<u16> = synthetic_id.encode_utf16().chain(std::iter::once(0)).collect();

    tracing::debug!("SetCurrentProcessExplicitAppUserModelID: mapped '{app_id_str}' -> '{synthetic_id}'");

    // SAFETY: forwarding the rewritten AppID to the original API.
    unsafe { real_fn(synthetic_wide.as_ptr()) }
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    unsafe {
        let shell32 = LoadLibraryW(windows_sys::core::w!("shell32.dll"));
        if !shell32.is_null()
            && let Some(proc) = GetProcAddress(
                shell32,
                c"SetCurrentProcessExplicitAppUserModelID".as_ptr().cast(),
            )
        {
            install_detour(
                &REAL_SET_APP_USER_MODEL_ID,
                proc as *mut c_void,
                hook_set_app_user_model_id as *mut c_void,
            );
        }
    }
}
