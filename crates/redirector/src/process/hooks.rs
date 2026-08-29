use crate::detour::{guard_detour, install_detour, load_trampoline};
use crate::{BOOL, TRUE};
use std::cell::Cell;
use std::ffi::{CString, c_void};
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};

#[allow(clippy::upper_case_acronyms)]
type LPSTARTUPINFOW = *mut STARTUPINFOW;
#[allow(clippy::upper_case_acronyms)]
type LpprocessInformation = *mut PROCESS_INFORMATION;

thread_local! {
    static IN_PROC_HOOK: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "C" {
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

static REAL_CREATE_PROCESS_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

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

fn is_sandboxed_chromium_child(app_name: *const u16, cmd_line: *const u16) -> bool {
    let mut check = String::new();
    if !app_name.is_null() {
        check.push_str(&wide_to_string(app_name));
        check.push(' ');
    }
    if !cmd_line.is_null() {
        check.push_str(&wide_to_string(cmd_line));
    }
    let lower = check.to_lowercase();
    lower.contains("--type=")
        || lower.contains("msedgewebview2.exe")
        || lower.contains("msedge.exe")
        || lower.contains("crashpad_handler.exe")
}

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
    let real_fn: FnCreateProcessW = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_PROCESS_W)) };
    guard_detour!(
        &IN_PROC_HOOK,
        unsafe {
            real_fn(
                app_name,
                cmd_line,
                proc_attr,
                thread_attr,
                inherit,
                flags,
                env,
                curr_dir,
                startup_info,
                proc_info,
            )
        },
        {
            if !is_sandboxed_chromium_child(app_name, cmd_line) {
                let cfg = crate::paths::init_paths();
                let dll_path = cfg.ppm_dir.join("lib").join("redirector.dll");

                if dll_path.is_file()
                    && let Ok(dll_cstr) = CString::new(dll_path.to_string_lossy().as_bytes())
                {
                    // SAFETY: every pointer argument is forwarded verbatim from the hooked
                    // CreateProcessW frame; `dll_cstr` outlives the call; `proc_attr`,
                    // `thread_attr`, `env`, `startup_info`, and `proc_info` only need their
                    // const-to-mut qualifiers relaxed to match the Detours ABI.
                    let res = unsafe {
                        DetourCreateProcessWithDllExW(
                            app_name,
                            cmd_line,
                            proc_attr.cast_mut(),
                            thread_attr.cast_mut(),
                            inherit,
                            flags,
                            env.cast_mut(),
                            curr_dir,
                            startup_info.cast(),
                            proc_info.cast(),
                            dll_cstr.as_ptr(),
                            std::ptr::null_mut(),
                        )
                    };
                    if res != 0 {
                        tracing::info!(
                            "CreateProcess [Child Injected]: Injected redirector.dll into new child process"
                        );
                        return TRUE;
                    }
                }
            }

            unsafe {
                real_fn(
                    app_name,
                    cmd_line,
                    proc_attr,
                    thread_attr,
                    inherit,
                    flags,
                    env,
                    curr_dir,
                    startup_info,
                    proc_info,
                )
            }
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
        if !kernelbase.is_null()
            && let Some(proc) = GetProcAddress(kernelbase, c"CreateProcessW".as_ptr().cast())
        {
            target_proc = Some(proc);
        }

        // 2. Fallback kernel32.dll!CreateProcessW
        if target_proc.is_none()
            && !kernel32.is_null()
            && let Some(proc) = GetProcAddress(kernel32, c"CreateProcessW".as_ptr().cast())
        {
            target_proc = Some(proc);
        }

        if let Some(proc) = target_proc {
            install_detour(
                &REAL_CREATE_PROCESS_W,
                proc as *mut c_void,
                hook_create_process_w as *mut c_void,
            );
        }
    }
}
