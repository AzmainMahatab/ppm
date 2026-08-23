use retour::GenericDetour;
use std::cell::Cell;
use std::ffi::{c_void, CString};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{BOOL, TRUE};
use windows_sys::Win32::System::Threading::{
    PROCESS_INFORMATION, STARTUPINFOW,
};

type LPSTARTUPINFOW = *mut STARTUPINFOW;
type LpprocessInformation = *mut PROCESS_INFORMATION;

thread_local! {
    static IN_PROC_HOOK: Cell<bool> = const { Cell::new(false) };
}

macro_rules! guard_proc_hook {
    ($fallback:expr, $body:expr) => {{
        if IN_PROC_HOOK.with(|h| h.get()) {
            return $fallback;
        }
        IN_PROC_HOOK.with(|h| h.set(true));
        let res = $body;
        IN_PROC_HOOK.with(|h| h.set(false));
        res
    }};
}

extern "C" {
    fn DetourCreateProcessWithDllExW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: u32,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
        lpDllName: *const std::ffi::c_char,
        pfCreateProcessW: *mut c_void,
    ) -> BOOL;
}

type FnCreateProcessW = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    *const u16,
    LPSTARTUPINFOW,
    LpprocessInformation,
) -> BOOL;

static HOOK_CREATE_PROCESS_W: OnceLock<GenericDetour<FnCreateProcessW>> = OnceLock::new();

unsafe extern "system" fn hook_create_process_w(
    app_name: *const u16,
    cmd_line: *mut u16,
    proc_attr: *const c_void,
    thread_attr: *const c_void,
    inherit: BOOL,
    flags: u32,
    env: *const c_void,
    curr_dir: *const u16,
    startup_info: LPSTARTUPINFOW,
    proc_info: LpprocessInformation,
) -> BOOL {
    guard_proc_hook!(
        HOOK_CREATE_PROCESS_W.get().unwrap().call(
            app_name, cmd_line, proc_attr, thread_attr, inherit, flags, env, curr_dir, startup_info, proc_info
        ),
        {
            let cfg = crate::paths::init_paths();
            let dll_path = cfg.ppm_dir.join("lib").join("redirector.dll");

            if dll_path.is_file() {
                if let Ok(dll_cstr) = CString::new(dll_path.to_string_lossy().as_bytes()) {
                    let res = DetourCreateProcessWithDllExW(
                        app_name,
                        cmd_line,
                        proc_attr as *mut _,
                        thread_attr as *mut _,
                        inherit,
                        flags,
                        env as *mut _,
                        curr_dir,
                        startup_info as *mut _,
                        proc_info as *mut _,
                        dll_cstr.as_ptr(),
                        std::ptr::null_mut(),
                    );
                    if res != 0 {
                        return TRUE;
                    }
                }
            }

            HOOK_CREATE_PROCESS_W.get().unwrap().call(
                app_name, cmd_line, proc_attr, thread_attr, inherit, flags, env, curr_dir, startup_info, proc_info
            )
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let kernelbase = GetModuleHandleW(windows_sys::core::w!("kernelbase.dll"));
        let kernel32 = GetModuleHandleW(windows_sys::core::w!("kernel32.dll"));

        let mut target_proc = None;

        // 1. Try kernelbase.dll!CreateProcessW
        if !kernelbase.is_null() {
            if let Some(proc) = GetProcAddress(kernelbase, b"CreateProcessW\0".as_ptr()) {
                target_proc = Some(proc);
            }
        }

        // 2. Fallback kernel32.dll!CreateProcessW
        if target_proc.is_none() && !kernel32.is_null() {
            if let Some(proc) = GetProcAddress(kernel32, b"CreateProcessW\0".as_ptr()) {
                target_proc = Some(proc);
            }
        }

        if let Some(proc) = target_proc {
            let target: FnCreateProcessW = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_create_process_w) {
                if d.enable().is_ok() {
                    let _ = HOOK_CREATE_PROCESS_W.set(d);
                }
            }
        }
    }
}
