use crate::detour::attach_detour;
use std::cell::Cell;
use std::ffi::c_void;
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{BOOL, HANDLE, HWND, S_OK, TRUE};

type PWSTR = *mut u16;

thread_local! {
    static IN_SHELL_HOOK: Cell<bool> = const { Cell::new(false) };
}

macro_rules! guard_shell_hook {
    ($fallback:expr, $body:expr) => {{
        if IN_SHELL_HOOK.with(|h| h.get()) {
            return $fallback;
        }
        IN_SHELL_HOOK.with(|h| h.set(true));
        let res = $body;
        IN_SHELL_HOOK.with(|h| h.set(false));
        res
    }};
}

extern "system" {
    fn CoTaskMemAlloc(cb: usize) -> *mut c_void;
}

// GUID constants
const FOLDERID_PROFILE: GUID = GUID {
    data1: 0x5e6c858f,
    data2: 0x0e22,
    data3: 0x4760,
    data4: [0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73],
};

const FOLDERID_LOCAL_APP_DATA: GUID = GUID {
    data1: 0xf1b32785,
    data2: 0x6fba,
    data3: 0x4fcf,
    data4: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
};

const FOLDERID_ROAMING_APP_DATA: GUID = GUID {
    data1: 0x3eb68528,
    data2: 0x012f,
    data3: 0x4761,
    data4: [0xb2, 0xde, 0x46, 0x54, 0x79, 0xe0, 0x70, 0x23],
};

const FOLDERID_DOCUMENTS: GUID = GUID {
    data1: 0xfdd39ad0,
    data2: 0x238f,
    data3: 0x46af,
    data4: [0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7],
};

// CSIDL constants
const CSIDL_PERSONAL: i32 = 0x0005;
const CSIDL_APPDATA: i32 = 0x001a;
const CSIDL_LOCAL_APPDATA: i32 = 0x001c;
const CSIDL_PROFILE: i32 = 0x0028;

type FnSHGetKnownFolderPath = unsafe extern "system" fn(*const GUID, u32, HANDLE, *mut PWSTR) -> HRESULT;
type FnSHGetFolderPathW = unsafe extern "system" fn(HWND, i32, HANDLE, u32, PWSTR) -> HRESULT;
type FnGetUserProfileDirectoryW = unsafe extern "system" fn(HANDLE, PWSTR, *mut u32) -> BOOL;

static mut REAL_SH_GET_KNOWN_FOLDER_PATH: *mut c_void = std::ptr::null_mut();
static mut REAL_SH_GET_FOLDER_PATH_W: *mut c_void = std::ptr::null_mut();
static mut REAL_GET_USER_PROFILE_DIRECTORY_W: *mut c_void = std::ptr::null_mut();

fn guids_equal(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe fn alloc_cotask_wide_string(w_str: &[u16]) -> PWSTR {
    let byte_len = w_str.len() * 2;
    let mem = CoTaskMemAlloc(byte_len);
    if !mem.is_null() {
        std::ptr::copy_nonoverlapping(w_str.as_ptr(), mem as *mut u16, w_str.len());
    }
    mem as PWSTR
}

unsafe extern "system" fn hook_sh_get_known_folder_path(
    rfid: *const GUID,
    flags: u32,
    token: HANDLE,
    path_out: *mut PWSTR,
) -> HRESULT {
    let real_fn: FnSHGetKnownFolderPath = std::mem::transmute(REAL_SH_GET_KNOWN_FOLDER_PATH);
    guard_shell_hook!(
        real_fn(rfid, flags, token, path_out),
        {
            if !rfid.is_null() && !path_out.is_null() {
                let id = &*rfid;
                let cfg = crate::paths::init_paths();

                let target_w = if guids_equal(id, &FOLDERID_PROFILE) {
                    tracing::debug!("SHGetKnownFolderPath [PROFILE]: redirected to Home");
                    Some(&cfg.user_profile_w)
                } else if guids_equal(id, &FOLDERID_LOCAL_APP_DATA) {
                    tracing::debug!("SHGetKnownFolderPath [LOCAL_APP_DATA]: redirected to Home/AppData/Local");
                    Some(&cfg.local_appdata_w)
                } else if guids_equal(id, &FOLDERID_ROAMING_APP_DATA) {
                    tracing::debug!("SHGetKnownFolderPath [ROAMING_APP_DATA]: redirected to Home/AppData/Roaming");
                    Some(&cfg.roaming_appdata_w)
                } else if guids_equal(id, &FOLDERID_DOCUMENTS) {
                    tracing::debug!("SHGetKnownFolderPath [DOCUMENTS]: redirected to Home/Documents");
                    Some(&cfg.documents_w)
                } else {
                    None
                };

                if let Some(w) = target_w {
                    *path_out = alloc_cotask_wide_string(w);
                    return S_OK;
                }
            }

            real_fn(rfid, flags, token, path_out)
        }
    )
}

unsafe extern "system" fn hook_sh_get_folder_path_w(
    hwnd: HWND,
    csidl: i32,
    token: HANDLE,
    flags: u32,
    path_out: PWSTR,
) -> HRESULT {
    let real_fn: FnSHGetFolderPathW = std::mem::transmute(REAL_SH_GET_FOLDER_PATH_W);
    guard_shell_hook!(
        real_fn(hwnd, csidl, token, flags, path_out),
        {
            if !path_out.is_null() {
                let clean_csidl = csidl & 0x00FF;
                let cfg = crate::paths::init_paths();

                let target_w = match clean_csidl {
                    CSIDL_PROFILE => {
                        tracing::debug!("SHGetFolderPathW [CSIDL_PROFILE]: redirected to Home");
                        Some(&cfg.user_profile_w)
                    }
                    CSIDL_LOCAL_APPDATA => {
                        tracing::debug!("SHGetFolderPathW [CSIDL_LOCAL_APPDATA]: redirected to Home/AppData/Local");
                        Some(&cfg.local_appdata_w)
                    }
                    CSIDL_APPDATA => {
                        tracing::debug!("SHGetFolderPathW [CSIDL_APPDATA]: redirected to Home/AppData/Roaming");
                        Some(&cfg.roaming_appdata_w)
                    }
                    CSIDL_PERSONAL => {
                        tracing::debug!("SHGetFolderPathW [CSIDL_PERSONAL]: redirected to Home/Documents");
                        Some(&cfg.documents_w)
                    }
                    _ => None,
                };

                if let Some(w) = target_w {
                    std::ptr::copy_nonoverlapping(w.as_ptr(), path_out, w.len());
                    return S_OK;
                }
            }

            real_fn(hwnd, csidl, token, flags, path_out)
        }
    )
}

unsafe extern "system" fn hook_get_user_profile_directory_w(
    token: HANDLE,
    profile_dir: PWSTR,
    size: *mut u32,
) -> BOOL {
    let real_fn: FnGetUserProfileDirectoryW = std::mem::transmute(REAL_GET_USER_PROFILE_DIRECTORY_W);
    guard_shell_hook!(
        real_fn(token, profile_dir, size),
        {
            if !size.is_null() {
                let cfg = crate::paths::init_paths();
                let needed_len = cfg.user_profile_w.len() as u32;

                if profile_dir.is_null() || *size < needed_len {
                    *size = needed_len;
                    return windows_sys::Win32::Foundation::FALSE;
                }

                std::ptr::copy_nonoverlapping(
                    cfg.user_profile_w.as_ptr(),
                    profile_dir,
                    cfg.user_profile_w.len(),
                );
                *size = needed_len;
                tracing::debug!("GetUserProfileDirectoryW: redirected to Home");
                return TRUE;
            }

            real_fn(token, profile_dir, size)
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let shell32 = GetModuleHandleW(windows_sys::core::w!("shell32.dll"));
        let userenv = GetModuleHandleW(windows_sys::core::w!("userenv.dll"));

        if !shell32.is_null() {
            if let Some(proc) = GetProcAddress(shell32, b"SHGetKnownFolderPath\0".as_ptr()) {
                REAL_SH_GET_KNOWN_FOLDER_PATH = proc as *mut c_void;
                attach_detour(&raw mut REAL_SH_GET_KNOWN_FOLDER_PATH, hook_sh_get_known_folder_path as *mut c_void);
            }

            if let Some(proc) = GetProcAddress(shell32, b"SHGetFolderPathW\0".as_ptr()) {
                REAL_SH_GET_FOLDER_PATH_W = proc as *mut c_void;
                attach_detour(&raw mut REAL_SH_GET_FOLDER_PATH_W, hook_sh_get_folder_path_w as *mut c_void);
            }
        }

        if !userenv.is_null() {
            if let Some(proc) = GetProcAddress(userenv, b"GetUserProfileDirectoryW\0".as_ptr()) {
                REAL_GET_USER_PROFILE_DIRECTORY_W = proc as *mut c_void;
                attach_detour(&raw mut REAL_GET_USER_PROFILE_DIRECTORY_W, hook_get_user_profile_directory_w as *mut c_void);
            }
        }
    }
}
