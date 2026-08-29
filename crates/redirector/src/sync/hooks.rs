use crate::detour::{install_detour, load_trampoline};
use crate::{BOOL, FALSE, TRUE};
use std::cell::Cell;
use std::ffi::{CStr, CString, c_char, c_void};
use std::path::PathBuf;
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, HANDLE, HWND, LPARAM, LRESULT, SetLastError, WPARAM,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowThreadProcessId, WNDENUMPROC};

thread_local! {
    static IN_SYNC_HOOK: Cell<bool> = const { Cell::new(false) };
}

struct SyncHookGuard;

impl SyncHookGuard {
    fn enter() -> Option<Self> {
        if IN_SYNC_HOOK.try_with(|h| h.get()).unwrap_or(false) {
            return None;
        }
        let _ = IN_SYNC_HOOK.try_with(|h| h.set(true));
        Some(SyncHookGuard)
    }
}

impl Drop for SyncHookGuard {
    fn drop(&mut self) {
        let _ = IN_SYNC_HOOK.try_with(|h| h.set(false));
    }
}

thread_local! {
    /// Marks threads whose Win32 window lookups must reach OS shell classes.
    ///
    /// Why: `ITaskbarList3`'s in-process COM proxy resolves the taskbar via
    /// `FindWindowW("Shell_TrayWnd", NULL)` executed inside this process; the window
    /// discovery hooks must not blind it there or every `SetOverlayIcon` fails with
    /// `E_FAIL` (0x80004005). See ENGINEERING_CHRONICLES, Iteration 5.4.
    static SHELL_QUERY_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Scoped permit that re-enables OS-shell window visibility for the calling thread.
///
/// Held for the taskbar monitor thread's lifetime. On every other thread, shell-class
/// windows stay strictly outside the portable session and are filtered like any other
/// foreign window.
pub(crate) struct ShellQueryExemption;

impl ShellQueryExemption {
    pub(crate) fn enter() -> Self {
        let _ = SHELL_QUERY_THREAD.try_with(|f| f.set(true));
        ShellQueryExemption
    }
}

impl Drop for ShellQueryExemption {
    fn drop(&mut self) {
        let _ = SHELL_QUERY_THREAD.try_with(|f| f.set(false));
    }
}

macro_rules! guard_sync_hook {
    ($fallback:expr_2021, $body:expr_2021) => {{
        let _guard = match SyncHookGuard::enter() {
            Some(g) => g,
            None => return unsafe { $fallback },
        };
        unsafe { $body }
    }};
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

unsafe fn ansi_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

fn isolate_object_name_w(name_ptr: *const u16, session_id: &str) -> Option<Vec<u16>> {
    if name_ptr.is_null() {
        return None;
    }
    let name = unsafe { wide_to_string(name_ptr) };
    if name.is_empty() || name.contains("PPM_") || name.contains("ppm_") {
        return None;
    }

    let isolated = if let Some(stripped) = name.strip_prefix("Global\\") {
        format!("Global\\PPM_{}_{}", session_id, stripped)
    } else if let Some(stripped) = name.strip_prefix("global\\") {
        format!("global\\PPM_{}_{}", session_id, stripped)
    } else if let Some(stripped) = name.strip_prefix("Local\\") {
        format!("Local\\PPM_{}_{}", session_id, stripped)
    } else if let Some(stripped) = name.strip_prefix("local\\") {
        format!("local\\PPM_{}_{}", session_id, stripped)
    } else {
        format!("Local\\PPM_{}_{}", session_id, name)
    };

    Some(isolated.encode_utf16().chain(std::iter::once(0)).collect())
}

fn isolate_object_name_a(name_ptr: *const c_char, session_id: &str) -> Option<CString> {
    if name_ptr.is_null() {
        return None;
    }
    let name = unsafe { ansi_to_string(name_ptr) };
    if name.is_empty() || name.contains("PPM_") || name.contains("ppm_") {
        return None;
    }

    let isolated = if let Some(stripped) = name.strip_prefix("Global\\") {
        format!("Global\\PPM_{}_{}", session_id, stripped)
    } else if let Some(stripped) = name.strip_prefix("global\\") {
        format!("global\\PPM_{}_{}", session_id, stripped)
    } else if let Some(stripped) = name.strip_prefix("Local\\") {
        format!("Local\\PPM_{}_{}", session_id, stripped)
    } else if let Some(stripped) = name.strip_prefix("local\\") {
        format!("local\\PPM_{}_{}", session_id, stripped)
    } else {
        format!("Local\\PPM_{}_{}", session_id, name)
    };

    CString::new(isolated).ok()
}

fn is_internal_child_ipc_pipe(pipe_name: &str) -> bool {
    let lower = pipe_name.to_lowercase();
    let current_pid = std::process::id().to_string();
    lower.contains("mojo")
        || lower.contains("crashpad")
        || lower.starts_with(&format!("{}.", current_pid))
        || lower.starts_with(&format!("{}_", current_pid))
        || lower.starts_with(&format!("{}-", current_pid))
}

fn isolate_pipe_path_w(path_ptr: *const u16, session_id: &str) -> Option<Vec<u16>> {
    if path_ptr.is_null() {
        return None;
    }
    let path = unsafe { wide_to_string(path_ptr) };
    if path.is_empty() {
        return None;
    }

    if let Some(pipe_name) = path.strip_prefix(r"\\.\pipe\") {
        if pipe_name.starts_with("ppm_")
            || pipe_name.starts_with("PPM_")
            || is_internal_child_ipc_pipe(pipe_name)
        {
            return None;
        }
        let isolated = format!(r"\\.\pipe\ppm_{}_{}", session_id, pipe_name);
        Some(isolated.encode_utf16().chain(std::iter::once(0)).collect())
    } else if let Some(pipe_name) = path.strip_prefix(r"\\?\pipe\") {
        if pipe_name.starts_with("ppm_")
            || pipe_name.starts_with("PPM_")
            || is_internal_child_ipc_pipe(pipe_name)
        {
            return None;
        }
        let isolated = format!(r"\\?\pipe\ppm_{}_{}", session_id, pipe_name);
        Some(isolated.encode_utf16().chain(std::iter::once(0)).collect())
    } else {
        None
    }
}

fn isolate_pipe_path_a(path_ptr: *const c_char, session_id: &str) -> Option<CString> {
    if path_ptr.is_null() {
        return None;
    }
    let path = unsafe { ansi_to_string(path_ptr) };
    if path.is_empty() {
        return None;
    }

    if let Some(pipe_name) = path.strip_prefix(r"\\.\pipe\") {
        if pipe_name.starts_with("ppm_")
            || pipe_name.starts_with("PPM_")
            || is_internal_child_ipc_pipe(pipe_name)
        {
            return None;
        }
        let isolated = format!(r"\\.\pipe\ppm_{}_{}", session_id, pipe_name);
        CString::new(isolated).ok()
    } else if let Some(pipe_name) = path.strip_prefix(r"\\?\pipe\") {
        if pipe_name.starts_with("ppm_")
            || pipe_name.starts_with("PPM_")
            || is_internal_child_ipc_pipe(pipe_name)
        {
            return None;
        }
        let isolated = format!(r"\\?\pipe\ppm_{}_{}", session_id, pipe_name);
        CString::new(isolated).ok()
    } else {
        None
    }
}

unsafe fn is_system_shell_window(hwnd: HWND) -> bool {
    let mut class_buf = [0u16; 64];
    use windows_sys::Win32::UI::WindowsAndMessaging::GetClassNameW;
    let len = unsafe { GetClassNameW(hwnd, class_buf.as_mut_ptr(), 64) };
    if len > 0 {
        let class_name = String::from_utf16_lossy(&class_buf[..len as usize]);
        if class_name == "Shell_TrayWnd"
            || class_name == "Shell_SecondaryTrayWnd"
            || class_name == "Progman"
            || class_name == "WorkerW"
            || class_name == "TaskSwitcherWnd"
            || class_name == "Shell_CharmWindow"
            || class_name == "#32768"
            || class_name == "ComboLBox"
        {
            return true;
        }
    }
    false
}

unsafe fn is_window_in_portable_session(hwnd: HWND) -> bool {
    if hwnd.is_null() {
        return false;
    }
    let val = hwnd as isize;
    if val == -1 || val == 0 {
        return false; // HWND_BROADCAST / HWND_DESKTOP
    }
    if val == -3 {
        return true; // HWND_MESSAGE
    }

    let shell_exempt = SHELL_QUERY_THREAD.try_with(|f| f.get()).unwrap_or(false);
    let is_shell_window = shell_exempt && unsafe { is_system_shell_window(hwnd) };
    if is_shell_window {
        return true;
    }

    let mut window_pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, &mut window_pid) };

    if window_pid == std::process::id() {
        return true;
    }
    if window_pid == 0 {
        return false;
    }

    let h_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, window_pid) };
    if !h_proc.is_null() {
        let mut buf = [0u16; 1024];
        let mut size = 1024u32;
        let resolved = unsafe {
            if QueryFullProcessImageNameW(h_proc, 0, buf.as_mut_ptr(), &mut size) != 0 {
                CloseHandle(h_proc);
                Some(String::from_utf16_lossy(&buf[..size as usize]))
            } else {
                None
            }
        };
        if let Some(exe_str) = resolved {
            let exe_path = PathBuf::from(exe_str);
            let cfg = crate::paths::init_paths();
            return exe_path.starts_with(&cfg.root);
        }
        unsafe { CloseHandle(h_proc) };
    }

    false
}

// ---------------------------------------------------------------------------
// 1. Mutex Detours (Wide & ANSI)
// ---------------------------------------------------------------------------

type FnCreateMutexW = unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, BOOL, *const u16) -> HANDLE;
type FnCreateMutexA = unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, BOOL, *const c_char) -> HANDLE;
type FnCreateMutexExW = unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, *const u16, u32, u32) -> HANDLE;
type FnCreateMutexExA =
    unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, *const c_char, u32, u32) -> HANDLE;
type FnOpenMutexW = unsafe extern "system" fn(u32, BOOL, *const u16) -> HANDLE;
type FnOpenMutexA = unsafe extern "system" fn(u32, BOOL, *const c_char) -> HANDLE;

static REAL_CREATE_MUTEX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_MUTEX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_MUTEX_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_MUTEX_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_OPEN_MUTEX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_OPEN_MUTEX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "system" fn hook_create_mutex_w(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    b_initial_owner: BOOL,
    lp_name: *const u16,
) -> HANDLE {
    let real_fn: FnCreateMutexW = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_MUTEX_W)) };
    guard_sync_hook!(real_fn(lp_attributes, b_initial_owner, lp_name), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_w(lp_name, &cfg.session_id) {
            return real_fn(lp_attributes, b_initial_owner, isolated.as_ptr());
        }
        real_fn(lp_attributes, b_initial_owner, lp_name)
    })
}

unsafe extern "system" fn hook_create_mutex_a(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    b_initial_owner: BOOL,
    lp_name: *const c_char,
) -> HANDLE {
    let real_fn: FnCreateMutexA = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_MUTEX_A)) };
    guard_sync_hook!(real_fn(lp_attributes, b_initial_owner, lp_name), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_a(lp_name, &cfg.session_id) {
            return real_fn(lp_attributes, b_initial_owner, isolated.as_ptr());
        }
        real_fn(lp_attributes, b_initial_owner, lp_name)
    })
}

unsafe extern "system" fn hook_create_mutex_ex_w(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    lp_name: *const u16,
    dw_flags: u32,
    dw_desired_access: u32,
) -> HANDLE {
    let real_fn: FnCreateMutexExW = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_MUTEX_EX_W)) };
    guard_sync_hook!(real_fn(lp_attributes, lp_name, dw_flags, dw_desired_access), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_w(lp_name, &cfg.session_id) {
            return real_fn(lp_attributes, isolated.as_ptr(), dw_flags, dw_desired_access);
        }
        real_fn(lp_attributes, lp_name, dw_flags, dw_desired_access)
    })
}

unsafe extern "system" fn hook_create_mutex_ex_a(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    lp_name: *const c_char,
    dw_flags: u32,
    dw_desired_access: u32,
) -> HANDLE {
    let real_fn: FnCreateMutexExA = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_MUTEX_EX_A)) };
    guard_sync_hook!(real_fn(lp_attributes, lp_name, dw_flags, dw_desired_access), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_a(lp_name, &cfg.session_id) {
            return real_fn(lp_attributes, isolated.as_ptr(), dw_flags, dw_desired_access);
        }
        real_fn(lp_attributes, lp_name, dw_flags, dw_desired_access)
    })
}

unsafe extern "system" fn hook_open_mutex_w(
    dw_desired_access: u32,
    b_inherit_handle: BOOL,
    lp_name: *const u16,
) -> HANDLE {
    let real_fn: FnOpenMutexW = unsafe { std::mem::transmute(load_trampoline(&REAL_OPEN_MUTEX_W)) };
    guard_sync_hook!(real_fn(dw_desired_access, b_inherit_handle, lp_name), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_w(lp_name, &cfg.session_id) {
            return real_fn(dw_desired_access, b_inherit_handle, isolated.as_ptr());
        }
        real_fn(dw_desired_access, b_inherit_handle, lp_name)
    })
}

unsafe extern "system" fn hook_open_mutex_a(
    dw_desired_access: u32,
    b_inherit_handle: BOOL,
    lp_name: *const c_char,
) -> HANDLE {
    let real_fn: FnOpenMutexA = unsafe { std::mem::transmute(load_trampoline(&REAL_OPEN_MUTEX_A)) };
    guard_sync_hook!(real_fn(dw_desired_access, b_inherit_handle, lp_name), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_a(lp_name, &cfg.session_id) {
            return real_fn(dw_desired_access, b_inherit_handle, isolated.as_ptr());
        }
        real_fn(dw_desired_access, b_inherit_handle, lp_name)
    })
}

// ---------------------------------------------------------------------------
// 2. Event, Semaphore, FileMapping & WaitableTimer Detours
// ---------------------------------------------------------------------------

type FnCreateEventW = unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, BOOL, BOOL, *const u16) -> HANDLE;
type FnCreateEventA =
    unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, BOOL, BOOL, *const c_char) -> HANDLE;
type FnOpenEventW = unsafe extern "system" fn(u32, BOOL, *const u16) -> HANDLE;
type FnOpenEventA = unsafe extern "system" fn(u32, BOOL, *const c_char) -> HANDLE;
type FnCreateSemaphoreW =
    unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, i32, i32, *const u16) -> HANDLE;
type FnCreateSemaphoreA =
    unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, i32, i32, *const c_char) -> HANDLE;
type FnCreateFileMappingW =
    unsafe extern "system" fn(HANDLE, *const SECURITY_ATTRIBUTES, u32, u32, u32, *const u16) -> HANDLE;
type FnCreateFileMappingA =
    unsafe extern "system" fn(HANDLE, *const SECURITY_ATTRIBUTES, u32, u32, u32, *const c_char) -> HANDLE;

static REAL_CREATE_EVENT_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_EVENT_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_OPEN_EVENT_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_OPEN_EVENT_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_SEMAPHORE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_SEMAPHORE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_FILE_MAPPING_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_FILE_MAPPING_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "system" fn hook_create_event_w(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    b_manual_reset: BOOL,
    b_initial_state: BOOL,
    lp_name: *const u16,
) -> HANDLE {
    let real_fn: FnCreateEventW = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_EVENT_W)) };
    guard_sync_hook!(
        real_fn(lp_attributes, b_manual_reset, b_initial_state, lp_name),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_object_name_w(lp_name, &cfg.session_id) {
                return real_fn(lp_attributes, b_manual_reset, b_initial_state, isolated.as_ptr());
            }
            real_fn(lp_attributes, b_manual_reset, b_initial_state, lp_name)
        }
    )
}

unsafe extern "system" fn hook_create_event_a(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    b_manual_reset: BOOL,
    b_initial_state: BOOL,
    lp_name: *const c_char,
) -> HANDLE {
    let real_fn: FnCreateEventA = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_EVENT_A)) };
    guard_sync_hook!(
        real_fn(lp_attributes, b_manual_reset, b_initial_state, lp_name),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_object_name_a(lp_name, &cfg.session_id) {
                return real_fn(lp_attributes, b_manual_reset, b_initial_state, isolated.as_ptr());
            }
            real_fn(lp_attributes, b_manual_reset, b_initial_state, lp_name)
        }
    )
}

unsafe extern "system" fn hook_open_event_w(
    dw_desired_access: u32,
    b_inherit_handle: BOOL,
    lp_name: *const u16,
) -> HANDLE {
    let real_fn: FnOpenEventW = unsafe { std::mem::transmute(load_trampoline(&REAL_OPEN_EVENT_W)) };
    guard_sync_hook!(real_fn(dw_desired_access, b_inherit_handle, lp_name), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_w(lp_name, &cfg.session_id) {
            return real_fn(dw_desired_access, b_inherit_handle, isolated.as_ptr());
        }
        real_fn(dw_desired_access, b_inherit_handle, lp_name)
    })
}

unsafe extern "system" fn hook_open_event_a(
    dw_desired_access: u32,
    b_inherit_handle: BOOL,
    lp_name: *const c_char,
) -> HANDLE {
    let real_fn: FnOpenEventA = unsafe { std::mem::transmute(load_trampoline(&REAL_OPEN_EVENT_A)) };
    guard_sync_hook!(real_fn(dw_desired_access, b_inherit_handle, lp_name), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_object_name_a(lp_name, &cfg.session_id) {
            return real_fn(dw_desired_access, b_inherit_handle, isolated.as_ptr());
        }
        real_fn(dw_desired_access, b_inherit_handle, lp_name)
    })
}

unsafe extern "system" fn hook_create_semaphore_w(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    l_initial_count: i32,
    l_maximum_count: i32,
    lp_name: *const u16,
) -> HANDLE {
    let real_fn: FnCreateSemaphoreW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_SEMAPHORE_W)) };
    guard_sync_hook!(
        real_fn(lp_attributes, l_initial_count, l_maximum_count, lp_name),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_object_name_w(lp_name, &cfg.session_id) {
                return real_fn(lp_attributes, l_initial_count, l_maximum_count, isolated.as_ptr());
            }
            real_fn(lp_attributes, l_initial_count, l_maximum_count, lp_name)
        }
    )
}

unsafe extern "system" fn hook_create_semaphore_a(
    lp_attributes: *const SECURITY_ATTRIBUTES,
    l_initial_count: i32,
    l_maximum_count: i32,
    lp_name: *const c_char,
) -> HANDLE {
    let real_fn: FnCreateSemaphoreA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_SEMAPHORE_A)) };
    guard_sync_hook!(
        real_fn(lp_attributes, l_initial_count, l_maximum_count, lp_name),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_object_name_a(lp_name, &cfg.session_id) {
                return real_fn(lp_attributes, l_initial_count, l_maximum_count, isolated.as_ptr());
            }
            real_fn(lp_attributes, l_initial_count, l_maximum_count, lp_name)
        }
    )
}

unsafe extern "system" fn hook_create_file_mapping_w(
    h_file: HANDLE,
    lp_attributes: *const SECURITY_ATTRIBUTES,
    fl_protect: u32,
    dw_maximum_size_high: u32,
    dw_maximum_size_low: u32,
    lp_name: *const u16,
) -> HANDLE {
    let real_fn: FnCreateFileMappingW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_FILE_MAPPING_W)) };
    guard_sync_hook!(
        real_fn(
            h_file,
            lp_attributes,
            fl_protect,
            dw_maximum_size_high,
            dw_maximum_size_low,
            lp_name
        ),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_object_name_w(lp_name, &cfg.session_id) {
                return real_fn(
                    h_file,
                    lp_attributes,
                    fl_protect,
                    dw_maximum_size_high,
                    dw_maximum_size_low,
                    isolated.as_ptr(),
                );
            }
            real_fn(
                h_file,
                lp_attributes,
                fl_protect,
                dw_maximum_size_high,
                dw_maximum_size_low,
                lp_name,
            )
        }
    )
}

unsafe extern "system" fn hook_create_file_mapping_a(
    h_file: HANDLE,
    lp_attributes: *const SECURITY_ATTRIBUTES,
    fl_protect: u32,
    dw_maximum_size_high: u32,
    dw_maximum_size_low: u32,
    lp_name: *const c_char,
) -> HANDLE {
    let real_fn: FnCreateFileMappingA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_FILE_MAPPING_A)) };
    guard_sync_hook!(
        real_fn(
            h_file,
            lp_attributes,
            fl_protect,
            dw_maximum_size_high,
            dw_maximum_size_low,
            lp_name
        ),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_object_name_a(lp_name, &cfg.session_id) {
                return real_fn(
                    h_file,
                    lp_attributes,
                    fl_protect,
                    dw_maximum_size_high,
                    dw_maximum_size_low,
                    isolated.as_ptr(),
                );
            }
            real_fn(
                h_file,
                lp_attributes,
                fl_protect,
                dw_maximum_size_high,
                dw_maximum_size_low,
                lp_name,
            )
        }
    )
}

// ---------------------------------------------------------------------------
// 3. Window Discovery & Enumeration Isolation
// ---------------------------------------------------------------------------

type FnFindWindowW = unsafe extern "system" fn(*const u16, *const u16) -> HWND;
type FnFindWindowA = unsafe extern "system" fn(*const c_char, *const c_char) -> HWND;
type FnFindWindowExW = unsafe extern "system" fn(HWND, HWND, *const u16, *const u16) -> HWND;
type FnFindWindowExA = unsafe extern "system" fn(HWND, HWND, *const c_char, *const c_char) -> HWND;
type FnEnumWindows = unsafe extern "system" fn(WNDENUMPROC, LPARAM) -> BOOL;
type FnEnumDesktopWindows = unsafe extern "system" fn(*mut c_void, WNDENUMPROC, LPARAM) -> BOOL;

static REAL_FIND_WINDOW_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_FIND_WINDOW_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_FIND_WINDOW_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_FIND_WINDOW_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_ENUM_WINDOWS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_ENUM_DESKTOP_WINDOWS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "system" fn hook_find_window_w(lp_class_name: *const u16, lp_window_name: *const u16) -> HWND {
    let real_fn: FnFindWindowW = unsafe { std::mem::transmute(load_trampoline(&REAL_FIND_WINDOW_W)) };
    guard_sync_hook!(real_fn(lp_class_name, lp_window_name), {
        let hwnd = real_fn(lp_class_name, lp_window_name);
        if !hwnd.is_null() && !is_window_in_portable_session(hwnd) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return std::ptr::null_mut();
        }
        hwnd
    })
}

unsafe extern "system" fn hook_find_window_a(
    lp_class_name: *const c_char,
    lp_window_name: *const c_char,
) -> HWND {
    let real_fn: FnFindWindowA = unsafe { std::mem::transmute(load_trampoline(&REAL_FIND_WINDOW_A)) };
    guard_sync_hook!(real_fn(lp_class_name, lp_window_name), {
        let hwnd = real_fn(lp_class_name, lp_window_name);
        if !hwnd.is_null() && !is_window_in_portable_session(hwnd) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return std::ptr::null_mut();
        }
        hwnd
    })
}

unsafe extern "system" fn hook_find_window_ex_w(
    h_wnd_parent: HWND,
    h_wnd_child_after: HWND,
    lpsz_class: *const u16,
    lpsz_window: *const u16,
) -> HWND {
    let real_fn: FnFindWindowExW = unsafe { std::mem::transmute(load_trampoline(&REAL_FIND_WINDOW_EX_W)) };
    guard_sync_hook!(
        real_fn(h_wnd_parent, h_wnd_child_after, lpsz_class, lpsz_window),
        {
            let hwnd = real_fn(h_wnd_parent, h_wnd_child_after, lpsz_class, lpsz_window);
            if !hwnd.is_null() && !is_window_in_portable_session(hwnd) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return std::ptr::null_mut();
            }
            hwnd
        }
    )
}

unsafe extern "system" fn hook_find_window_ex_a(
    h_wnd_parent: HWND,
    h_wnd_child_after: HWND,
    lpsz_class: *const c_char,
    lpsz_window: *const c_char,
) -> HWND {
    let real_fn: FnFindWindowExA = unsafe { std::mem::transmute(load_trampoline(&REAL_FIND_WINDOW_EX_A)) };
    guard_sync_hook!(
        real_fn(h_wnd_parent, h_wnd_child_after, lpsz_class, lpsz_window),
        {
            let hwnd = real_fn(h_wnd_parent, h_wnd_child_after, lpsz_class, lpsz_window);
            if !hwnd.is_null() && !is_window_in_portable_session(hwnd) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                return std::ptr::null_mut();
            }
            hwnd
        }
    )
}

struct ProxyEnumContext {
    user_callback: unsafe extern "system" fn(HWND, LPARAM) -> BOOL,
    user_lparam: LPARAM,
}

unsafe extern "system" fn proxy_enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    unsafe {
        let ctx = &*(lparam as *const ProxyEnumContext);
        if !is_window_in_portable_session(hwnd) {
            return TRUE; // Transparently skip foreign host windows
        }
        (ctx.user_callback)(hwnd, ctx.user_lparam)
    }
}

unsafe extern "system" fn hook_enum_windows(lp_enum_func: WNDENUMPROC, l_param: LPARAM) -> BOOL {
    let real_fn: FnEnumWindows = unsafe { std::mem::transmute(load_trampoline(&REAL_ENUM_WINDOWS)) };
    guard_sync_hook!(real_fn(lp_enum_func, l_param), {
        if let Some(user_cb) = lp_enum_func {
            let ctx = ProxyEnumContext {
                user_callback: user_cb,
                user_lparam: l_param,
            };
            return real_fn(Some(proxy_enum_windows_proc), &ctx as *const _ as LPARAM);
        }
        real_fn(lp_enum_func, l_param)
    })
}

unsafe extern "system" fn hook_enum_desktop_windows(
    h_desktop: *mut c_void,
    lp_fn: WNDENUMPROC,
    l_param: LPARAM,
) -> BOOL {
    let real_fn: FnEnumDesktopWindows =
        unsafe { std::mem::transmute(load_trampoline(&REAL_ENUM_DESKTOP_WINDOWS)) };
    guard_sync_hook!(real_fn(h_desktop, lp_fn, l_param), {
        if let Some(user_cb) = lp_fn {
            let ctx = ProxyEnumContext {
                user_callback: user_cb,
                user_lparam: l_param,
            };
            return real_fn(
                h_desktop,
                Some(proxy_enum_windows_proc),
                &ctx as *const _ as LPARAM,
            );
        }
        real_fn(h_desktop, lp_fn, l_param)
    })
}

// ---------------------------------------------------------------------------
// 4. Focus Hijacking & Cross-Process Activation Prevention
// ---------------------------------------------------------------------------

type FnSetForegroundWindow = unsafe extern "system" fn(HWND) -> BOOL;
type FnBringWindowToTop = unsafe extern "system" fn(HWND) -> BOOL;
type FnSwitchToThisWindow = unsafe extern "system" fn(HWND, BOOL);
type FnSendMessageW = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;
type FnSendMessageA = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;
type FnPostMessageW = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> BOOL;
type FnPostMessageA = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> BOOL;

static REAL_SET_FOREGROUND_WINDOW: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_BRING_WINDOW_TO_TOP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_SWITCH_TO_THIS_WINDOW: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_SEND_MESSAGE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_SEND_MESSAGE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_POST_MESSAGE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_POST_MESSAGE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

const WM_COPYDATA: u32 = 0x004A;
const HWND_BROADCAST: HWND = 0xffff as HWND;

unsafe extern "system" fn hook_set_foreground_window(hwnd: HWND) -> BOOL {
    let real_fn: FnSetForegroundWindow =
        unsafe { std::mem::transmute(load_trampoline(&REAL_SET_FOREGROUND_WINDOW)) };
    guard_sync_hook!(real_fn(hwnd), {
        if !hwnd.is_null() && !is_window_in_portable_session(hwnd) {
            return FALSE; // Block bringing host window to foreground
        }
        real_fn(hwnd)
    })
}

unsafe extern "system" fn hook_bring_window_to_top(hwnd: HWND) -> BOOL {
    let real_fn: FnBringWindowToTop =
        unsafe { std::mem::transmute(load_trampoline(&REAL_BRING_WINDOW_TO_TOP)) };
    guard_sync_hook!(real_fn(hwnd), {
        if !hwnd.is_null() && !is_window_in_portable_session(hwnd) {
            return FALSE;
        }
        real_fn(hwnd)
    })
}

unsafe extern "system" fn hook_switch_to_this_window(hwnd: HWND, f_alt_tab: BOOL) {
    let real_fn: FnSwitchToThisWindow =
        unsafe { std::mem::transmute(load_trampoline(&REAL_SWITCH_TO_THIS_WINDOW)) };
    guard_sync_hook!(real_fn(hwnd, f_alt_tab), {
        if !hwnd.is_null() && !is_window_in_portable_session(hwnd) {
            return;
        }
        real_fn(hwnd, f_alt_tab)
    })
}

unsafe extern "system" fn hook_send_message_w(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let real_fn: FnSendMessageW = unsafe { std::mem::transmute(load_trampoline(&REAL_SEND_MESSAGE_W)) };
    guard_sync_hook!(real_fn(hwnd, msg, wparam, lparam), {
        let foreign_target =
            hwnd == HWND_BROADCAST || (!hwnd.is_null() && !is_window_in_portable_session(hwnd));
        if foreign_target && msg == WM_COPYDATA {
            return 0; // Drop cross-process activation payload to host
        }
        real_fn(hwnd, msg, wparam, lparam)
    })
}

unsafe extern "system" fn hook_send_message_a(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let real_fn: FnSendMessageA = unsafe { std::mem::transmute(load_trampoline(&REAL_SEND_MESSAGE_A)) };
    guard_sync_hook!(real_fn(hwnd, msg, wparam, lparam), {
        let foreign_target =
            hwnd == HWND_BROADCAST || (!hwnd.is_null() && !is_window_in_portable_session(hwnd));
        if foreign_target && msg == WM_COPYDATA {
            return 0;
        }
        real_fn(hwnd, msg, wparam, lparam)
    })
}

unsafe extern "system" fn hook_post_message_w(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> BOOL {
    let real_fn: FnPostMessageW = unsafe { std::mem::transmute(load_trampoline(&REAL_POST_MESSAGE_W)) };
    guard_sync_hook!(real_fn(hwnd, msg, wparam, lparam), {
        let foreign_target =
            hwnd == HWND_BROADCAST || (!hwnd.is_null() && !is_window_in_portable_session(hwnd));
        if foreign_target && msg == WM_COPYDATA {
            return TRUE; // Pretend delivered without reaching host
        }
        real_fn(hwnd, msg, wparam, lparam)
    })
}

unsafe extern "system" fn hook_post_message_a(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> BOOL {
    let real_fn: FnPostMessageA = unsafe { std::mem::transmute(load_trampoline(&REAL_POST_MESSAGE_A)) };
    guard_sync_hook!(real_fn(hwnd, msg, wparam, lparam), {
        let foreign_target =
            hwnd == HWND_BROADCAST || (!hwnd.is_null() && !is_window_in_portable_session(hwnd));
        if foreign_target && msg == WM_COPYDATA {
            return TRUE;
        }
        real_fn(hwnd, msg, wparam, lparam)
    })
}

// ---------------------------------------------------------------------------
// 5. Named Pipe Isolation
// ---------------------------------------------------------------------------

type FnCreateNamedPipeW =
    unsafe extern "system" fn(*const u16, u32, u32, u32, u32, u32, u32, *const SECURITY_ATTRIBUTES) -> HANDLE;
type FnCreateNamedPipeA = unsafe extern "system" fn(
    *const c_char,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    *const SECURITY_ATTRIBUTES,
) -> HANDLE;
type FnWaitNamedPipeW = unsafe extern "system" fn(*const u16, u32) -> BOOL;
type FnWaitNamedPipeA = unsafe extern "system" fn(*const c_char, u32) -> BOOL;
type FnCreateFileW =
    unsafe extern "system" fn(*const u16, u32, u32, *const SECURITY_ATTRIBUTES, u32, u32, HANDLE) -> HANDLE;
type FnCreateFileA = unsafe extern "system" fn(
    *const c_char,
    u32,
    u32,
    *const SECURITY_ATTRIBUTES,
    u32,
    u32,
    HANDLE,
) -> HANDLE;

static REAL_CREATE_NAMED_PIPE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_NAMED_PIPE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_WAIT_NAMED_PIPE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_WAIT_NAMED_PIPE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_FILE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_FILE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "system" fn hook_create_named_pipe_w(
    lp_name: *const u16,
    dw_open_mode: u32,
    dw_pipe_mode: u32,
    n_max_instances: u32,
    n_out_buffer_size: u32,
    n_in_buffer_size: u32,
    n_default_time_out: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
) -> HANDLE {
    let real_fn: FnCreateNamedPipeW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_NAMED_PIPE_W)) };
    guard_sync_hook!(
        real_fn(
            lp_name,
            dw_open_mode,
            dw_pipe_mode,
            n_max_instances,
            n_out_buffer_size,
            n_in_buffer_size,
            n_default_time_out,
            lp_security_attributes,
        ),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_pipe_path_w(lp_name, &cfg.session_id) {
                return real_fn(
                    isolated.as_ptr(),
                    dw_open_mode,
                    dw_pipe_mode,
                    n_max_instances,
                    n_out_buffer_size,
                    n_in_buffer_size,
                    n_default_time_out,
                    lp_security_attributes,
                );
            }
            real_fn(
                lp_name,
                dw_open_mode,
                dw_pipe_mode,
                n_max_instances,
                n_out_buffer_size,
                n_in_buffer_size,
                n_default_time_out,
                lp_security_attributes,
            )
        }
    )
}

unsafe extern "system" fn hook_create_named_pipe_a(
    lp_name: *const c_char,
    dw_open_mode: u32,
    dw_pipe_mode: u32,
    n_max_instances: u32,
    n_out_buffer_size: u32,
    n_in_buffer_size: u32,
    n_default_time_out: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
) -> HANDLE {
    let real_fn: FnCreateNamedPipeA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_NAMED_PIPE_A)) };
    guard_sync_hook!(
        real_fn(
            lp_name,
            dw_open_mode,
            dw_pipe_mode,
            n_max_instances,
            n_out_buffer_size,
            n_in_buffer_size,
            n_default_time_out,
            lp_security_attributes,
        ),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_pipe_path_a(lp_name, &cfg.session_id) {
                return real_fn(
                    isolated.as_ptr(),
                    dw_open_mode,
                    dw_pipe_mode,
                    n_max_instances,
                    n_out_buffer_size,
                    n_in_buffer_size,
                    n_default_time_out,
                    lp_security_attributes,
                );
            }
            real_fn(
                lp_name,
                dw_open_mode,
                dw_pipe_mode,
                n_max_instances,
                n_out_buffer_size,
                n_in_buffer_size,
                n_default_time_out,
                lp_security_attributes,
            )
        }
    )
}

unsafe extern "system" fn hook_wait_named_pipe_w(lp_named_pipe_name: *const u16, n_time_out: u32) -> BOOL {
    let real_fn: FnWaitNamedPipeW = unsafe { std::mem::transmute(load_trampoline(&REAL_WAIT_NAMED_PIPE_W)) };
    guard_sync_hook!(real_fn(lp_named_pipe_name, n_time_out), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_pipe_path_w(lp_named_pipe_name, &cfg.session_id) {
            return real_fn(isolated.as_ptr(), n_time_out);
        }
        real_fn(lp_named_pipe_name, n_time_out)
    })
}

unsafe extern "system" fn hook_wait_named_pipe_a(lp_named_pipe_name: *const c_char, n_time_out: u32) -> BOOL {
    let real_fn: FnWaitNamedPipeA = unsafe { std::mem::transmute(load_trampoline(&REAL_WAIT_NAMED_PIPE_A)) };
    guard_sync_hook!(real_fn(lp_named_pipe_name, n_time_out), {
        let cfg = crate::paths::init_paths();
        if let Some(isolated) = isolate_pipe_path_a(lp_named_pipe_name, &cfg.session_id) {
            return real_fn(isolated.as_ptr(), n_time_out);
        }
        real_fn(lp_named_pipe_name, n_time_out)
    })
}

unsafe extern "system" fn hook_create_file_w(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: HANDLE,
) -> HANDLE {
    let real_fn: FnCreateFileW = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_FILE_W)) };
    guard_sync_hook!(
        real_fn(
            lp_file_name,
            dw_desired_access,
            dw_share_mode,
            lp_security_attributes,
            dw_creation_disposition,
            dw_flags_and_attributes,
            h_template_file,
        ),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_pipe_path_w(lp_file_name, &cfg.session_id) {
                return real_fn(
                    isolated.as_ptr(),
                    dw_desired_access,
                    dw_share_mode,
                    lp_security_attributes,
                    dw_creation_disposition,
                    dw_flags_and_attributes,
                    h_template_file,
                );
            }
            real_fn(
                lp_file_name,
                dw_desired_access,
                dw_share_mode,
                lp_security_attributes,
                dw_creation_disposition,
                dw_flags_and_attributes,
                h_template_file,
            )
        }
    )
}

unsafe extern "system" fn hook_create_file_a(
    lp_file_name: *const c_char,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: HANDLE,
) -> HANDLE {
    let real_fn: FnCreateFileA = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_FILE_A)) };
    guard_sync_hook!(
        real_fn(
            lp_file_name,
            dw_desired_access,
            dw_share_mode,
            lp_security_attributes,
            dw_creation_disposition,
            dw_flags_and_attributes,
            h_template_file,
        ),
        {
            let cfg = crate::paths::init_paths();
            if let Some(isolated) = isolate_pipe_path_a(lp_file_name, &cfg.session_id) {
                return real_fn(
                    isolated.as_ptr(),
                    dw_desired_access,
                    dw_share_mode,
                    lp_security_attributes,
                    dw_creation_disposition,
                    dw_flags_and_attributes,
                    h_template_file,
                );
            }
            real_fn(
                lp_file_name,
                dw_desired_access,
                dw_share_mode,
                lp_security_attributes,
                dw_creation_disposition,
                dw_flags_and_attributes,
                h_template_file,
            )
        }
    )
}

// ---------------------------------------------------------------------------
// Hook Initialization
// ---------------------------------------------------------------------------

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};

    unsafe {
        let kernelbase = GetModuleHandleW(windows_sys::core::w!("kernelbase.dll"));
        let kernel32 = GetModuleHandleW(windows_sys::core::w!("kernel32.dll"));
        let user32 = LoadLibraryW(windows_sys::core::w!("user32.dll"));

        let hook_api = |name: &[u8], hook_fn: *mut c_void, real_slot: &AtomicPtr<c_void>| {
            let mut c_name = name.to_vec();
            c_name.push(0);

            let mut target_proc: *mut c_void = std::ptr::null_mut();
            if !kernelbase.is_null()
                && let Some(proc) = GetProcAddress(kernelbase, c_name.as_ptr())
            {
                target_proc = proc as *mut c_void;
            }
            if target_proc.is_null()
                && !kernel32.is_null()
                && let Some(proc) = GetProcAddress(kernel32, c_name.as_ptr())
            {
                target_proc = proc as *mut c_void;
            }

            if !target_proc.is_null() {
                install_detour(real_slot, target_proc, hook_fn);
            }
        };

        let hook_user32 = |name: &[u8], hook_fn: *mut c_void, real_slot: &AtomicPtr<c_void>| {
            if user32.is_null() {
                return;
            }
            let mut c_name = name.to_vec();
            c_name.push(0);
            if let Some(proc) = GetProcAddress(user32, c_name.as_ptr()) {
                install_detour(real_slot, proc as *mut c_void, hook_fn);
            }
        };

        // Mutex
        hook_api(
            b"CreateMutexW",
            hook_create_mutex_w as *mut c_void,
            &REAL_CREATE_MUTEX_W,
        );
        hook_api(
            b"CreateMutexA",
            hook_create_mutex_a as *mut c_void,
            &REAL_CREATE_MUTEX_A,
        );
        hook_api(
            b"CreateMutexExW",
            hook_create_mutex_ex_w as *mut c_void,
            &REAL_CREATE_MUTEX_EX_W,
        );
        hook_api(
            b"CreateMutexExA",
            hook_create_mutex_ex_a as *mut c_void,
            &REAL_CREATE_MUTEX_EX_A,
        );
        hook_api(
            b"OpenMutexW",
            hook_open_mutex_w as *mut c_void,
            &REAL_OPEN_MUTEX_W,
        );
        hook_api(
            b"OpenMutexA",
            hook_open_mutex_a as *mut c_void,
            &REAL_OPEN_MUTEX_A,
        );

        // Event, Semaphore, FileMapping
        hook_api(
            b"CreateEventW",
            hook_create_event_w as *mut c_void,
            &REAL_CREATE_EVENT_W,
        );
        hook_api(
            b"CreateEventA",
            hook_create_event_a as *mut c_void,
            &REAL_CREATE_EVENT_A,
        );
        hook_api(
            b"OpenEventW",
            hook_open_event_w as *mut c_void,
            &REAL_OPEN_EVENT_W,
        );
        hook_api(
            b"OpenEventA",
            hook_open_event_a as *mut c_void,
            &REAL_OPEN_EVENT_A,
        );
        hook_api(
            b"CreateSemaphoreW",
            hook_create_semaphore_w as *mut c_void,
            &REAL_CREATE_SEMAPHORE_W,
        );
        hook_api(
            b"CreateSemaphoreA",
            hook_create_semaphore_a as *mut c_void,
            &REAL_CREATE_SEMAPHORE_A,
        );
        hook_api(
            b"CreateFileMappingW",
            hook_create_file_mapping_w as *mut c_void,
            &REAL_CREATE_FILE_MAPPING_W,
        );
        hook_api(
            b"CreateFileMappingA",
            hook_create_file_mapping_a as *mut c_void,
            &REAL_CREATE_FILE_MAPPING_A,
        );

        // Pipes & CreateFile
        hook_api(
            b"CreateNamedPipeW",
            hook_create_named_pipe_w as *mut c_void,
            &REAL_CREATE_NAMED_PIPE_W,
        );
        hook_api(
            b"CreateNamedPipeA",
            hook_create_named_pipe_a as *mut c_void,
            &REAL_CREATE_NAMED_PIPE_A,
        );
        hook_api(
            b"WaitNamedPipeW",
            hook_wait_named_pipe_w as *mut c_void,
            &REAL_WAIT_NAMED_PIPE_W,
        );
        hook_api(
            b"WaitNamedPipeA",
            hook_wait_named_pipe_a as *mut c_void,
            &REAL_WAIT_NAMED_PIPE_A,
        );
        hook_api(
            b"CreateFileW",
            hook_create_file_w as *mut c_void,
            &REAL_CREATE_FILE_W,
        );
        hook_api(
            b"CreateFileA",
            hook_create_file_a as *mut c_void,
            &REAL_CREATE_FILE_A,
        );

        // Window Discovery & Enumeration
        hook_user32(
            b"FindWindowW",
            hook_find_window_w as *mut c_void,
            &REAL_FIND_WINDOW_W,
        );
        hook_user32(
            b"FindWindowA",
            hook_find_window_a as *mut c_void,
            &REAL_FIND_WINDOW_A,
        );
        hook_user32(
            b"FindWindowExW",
            hook_find_window_ex_w as *mut c_void,
            &REAL_FIND_WINDOW_EX_W,
        );
        hook_user32(
            b"FindWindowExA",
            hook_find_window_ex_a as *mut c_void,
            &REAL_FIND_WINDOW_EX_A,
        );
        hook_user32(
            b"EnumWindows",
            hook_enum_windows as *mut c_void,
            &REAL_ENUM_WINDOWS,
        );
        hook_user32(
            b"EnumDesktopWindows",
            hook_enum_desktop_windows as *mut c_void,
            &REAL_ENUM_DESKTOP_WINDOWS,
        );

        // Focus Hijacking & Messaging
        hook_user32(
            b"SetForegroundWindow",
            hook_set_foreground_window as *mut c_void,
            &REAL_SET_FOREGROUND_WINDOW,
        );
        hook_user32(
            b"BringWindowToTop",
            hook_bring_window_to_top as *mut c_void,
            &REAL_BRING_WINDOW_TO_TOP,
        );
        hook_user32(
            b"SwitchToThisWindow",
            hook_switch_to_this_window as *mut c_void,
            &REAL_SWITCH_TO_THIS_WINDOW,
        );
        hook_user32(
            b"SendMessageW",
            hook_send_message_w as *mut c_void,
            &REAL_SEND_MESSAGE_W,
        );
        hook_user32(
            b"SendMessageA",
            hook_send_message_a as *mut c_void,
            &REAL_SEND_MESSAGE_A,
        );
        hook_user32(
            b"PostMessageW",
            hook_post_message_w as *mut c_void,
            &REAL_POST_MESSAGE_W,
        );
        hook_user32(
            b"PostMessageA",
            hook_post_message_a as *mut c_void,
            &REAL_POST_MESSAGE_A,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolate_object_name_w() {
        let session = "abcd1234";

        let local_raw: Vec<u16> = "Local\\MyMutex\0".encode_utf16().collect();
        let isolated = isolate_object_name_w(local_raw.as_ptr(), session).unwrap();
        let s = String::from_utf16_lossy(&isolated);
        assert_eq!(s, "Local\\PPM_abcd1234_MyMutex\0");

        let global_raw: Vec<u16> = "Global\\MyLock\0".encode_utf16().collect();
        let isolated = isolate_object_name_w(global_raw.as_ptr(), session).unwrap();
        let s = String::from_utf16_lossy(&isolated);
        assert_eq!(s, "Global\\PPM_abcd1234_MyLock\0");

        let bare_raw: Vec<u16> = "MyBareMutex\0".encode_utf16().collect();
        let isolated = isolate_object_name_w(bare_raw.as_ptr(), session).unwrap();
        let s = String::from_utf16_lossy(&isolated);
        assert_eq!(s, "Local\\PPM_abcd1234_MyBareMutex\0");

        // Idempotency: already isolated
        let already_raw: Vec<u16> = "Local\\PPM_abcd1234_MyMutex\0".encode_utf16().collect();
        assert!(isolate_object_name_w(already_raw.as_ptr(), session).is_none());
    }

    #[test]
    fn test_isolate_object_name_a() {
        let session = "abcd1234";

        let local_c = CString::new("Local\\MyAnsiMutex").unwrap();
        let isolated = isolate_object_name_a(local_c.as_ptr(), session).unwrap();
        assert_eq!(isolated.to_str().unwrap(), "Local\\PPM_abcd1234_MyAnsiMutex");

        let global_c = CString::new("Global\\MyAnsiLock").unwrap();
        let isolated = isolate_object_name_a(global_c.as_ptr(), session).unwrap();
        assert_eq!(isolated.to_str().unwrap(), "Global\\PPM_abcd1234_MyAnsiLock");
    }

    #[test]
    fn test_isolate_pipe_path_w_and_a() {
        let session = "abcd1234";

        let pipe_raw: Vec<u16> = format!("{}\0", r"\\.\pipe\my_app_pipe").encode_utf16().collect();
        let isolated = isolate_pipe_path_w(pipe_raw.as_ptr(), session).unwrap();
        let s = String::from_utf16_lossy(&isolated);
        assert_eq!(s, format!("{}\0", r"\\.\pipe\ppm_abcd1234_my_app_pipe"));

        let pipe_c = CString::new(r"\\.\pipe\my_ansi_pipe").unwrap();
        let isolated_c = isolate_pipe_path_a(pipe_c.as_ptr(), session).unwrap();
        assert_eq!(
            isolated_c.to_str().unwrap(),
            r"\\.\pipe\ppm_abcd1234_my_ansi_pipe"
        );

        // Internal Mojo/child pipes must NOT be isolated
        let mojo_pipe: Vec<u16> = format!("{}\0", r"\\.\pipe\mojo.1234.5678.9999")
            .encode_utf16()
            .collect();
        assert!(isolate_pipe_path_w(mojo_pipe.as_ptr(), session).is_none());

        let crashpad_pipe = CString::new(r"\\.\pipe\crashpad_1234_abc").unwrap();
        assert!(isolate_pipe_path_a(crashpad_pipe.as_ptr(), session).is_none());
    }
}
