use retour::GenericDetour;
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::OnceLock;
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{BOOL, FALSE, HANDLE, HWND, S_OK, TRUE};
use windows_sys::Win32::Security::Credentials::CREDENTIALW;
use windows_sys::Win32::System::Threading::{
    PROCESS_INFORMATION, STARTUPINFOW,
};

type PWSTR = *mut u16;
type PCREDENTIALW = *mut CREDENTIALW;
type LPSTARTUPINFOW = *mut STARTUPINFOW;
type LPPROCESS_INFORMATION = *mut PROCESS_INFORMATION;

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

// Win32 Credential Types
const CRED_TYPE_GENERIC: u32 = 1;

thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

macro_rules! guard_hook {
    ($fallback:expr, $body:expr) => {{
        if IN_HOOK.with(|h| h.get()) {
            return $fallback;
        }
        IN_HOOK.with(|h| h.set(true));
        let res = $body;
        IN_HOOK.with(|h| h.set(false));
        res
    }};
}

// Function pointer type definitions
type FnSHGetKnownFolderPath = unsafe extern "system" fn(*const GUID, u32, HANDLE, *mut PWSTR) -> HRESULT;
type FnSHGetFolderPathW = unsafe extern "system" fn(HWND, i32, HANDLE, u32, PWSTR) -> HRESULT;
type FnGetUserProfileDirectoryW = unsafe extern "system" fn(HANDLE, PWSTR, *mut u32) -> BOOL;
type FnCredReadW = unsafe extern "system" fn(*const u16, u32, u32, *mut PCREDENTIALW) -> BOOL;
type FnCredWriteW = unsafe extern "system" fn(PCREDENTIALW, u32) -> BOOL;
type FnCredDeleteW = unsafe extern "system" fn(*const u16, u32, u32) -> BOOL;
type FnCredFree = unsafe extern "system" fn(*const c_void);
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
    LPPROCESS_INFORMATION,
) -> BOOL;

static HOOK_SH_GET_KNOWN_FOLDER_PATH: OnceLock<GenericDetour<FnSHGetKnownFolderPath>> = OnceLock::new();
static HOOK_SH_GET_FOLDER_PATH_W: OnceLock<GenericDetour<FnSHGetFolderPathW>> = OnceLock::new();
static HOOK_GET_USER_PROFILE_DIRECTORY_W: OnceLock<GenericDetour<FnGetUserProfileDirectoryW>> = OnceLock::new();
static HOOK_CRED_READ_W: OnceLock<GenericDetour<FnCredReadW>> = OnceLock::new();
static HOOK_CRED_WRITE_W: OnceLock<GenericDetour<FnCredWriteW>> = OnceLock::new();
static HOOK_CRED_DELETE_W: OnceLock<GenericDetour<FnCredDeleteW>> = OnceLock::new();
static HOOK_CRED_FREE: OnceLock<GenericDetour<FnCredFree>> = OnceLock::new();
static HOOK_CREATE_PROCESS_W: OnceLock<GenericDetour<FnCreateProcessW>> = OnceLock::new();

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
    guard_hook!(
        HOOK_SH_GET_KNOWN_FOLDER_PATH.get().unwrap().call(rfid, flags, token, path_out),
        {
            if !rfid.is_null() && !path_out.is_null() {
                let id = &*rfid;
                let cfg = crate::paths::init_paths();

                let target_w = if guids_equal(id, &FOLDERID_PROFILE) {
                    Some(&cfg.user_profile_w)
                } else if guids_equal(id, &FOLDERID_LOCAL_APP_DATA) {
                    Some(&cfg.local_appdata_w)
                } else if guids_equal(id, &FOLDERID_ROAMING_APP_DATA) {
                    Some(&cfg.roaming_appdata_w)
                } else if guids_equal(id, &FOLDERID_DOCUMENTS) {
                    Some(&cfg.documents_w)
                } else {
                    None
                };

                if let Some(target) = target_w {
                    let ptr = alloc_cotask_wide_string(target);
                    if !ptr.is_null() {
                        *path_out = ptr;
                        crate::paths::log_always("SHGetKnownFolderPath intercepted and redirected to USB!");
                        return S_OK;
                    }
                }
            }
            HOOK_SH_GET_KNOWN_FOLDER_PATH.get().unwrap().call(rfid, flags, token, path_out)
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
    guard_hook!(
        HOOK_SH_GET_FOLDER_PATH_W.get().unwrap().call(hwnd, csidl, token, flags, path_out),
        {
            if !path_out.is_null() {
                let clean_csidl = csidl & 0x00ff;
                let cfg = crate::paths::init_paths();

                let target_w = match clean_csidl {
                    CSIDL_PROFILE => Some(&cfg.user_profile_w),
                    CSIDL_LOCAL_APPDATA => Some(&cfg.local_appdata_w),
                    CSIDL_APPDATA => Some(&cfg.roaming_appdata_w),
                    CSIDL_PERSONAL => Some(&cfg.documents_w),
                    _ => None,
                };

                if let Some(target) = target_w {
                    let len = target.len().min(260);
                    std::ptr::copy_nonoverlapping(target.as_ptr(), path_out, len);
                    crate::paths::log_always(&format!("SHGetFolderPathW intercepted for CSIDL 0x{:04x} -> redirected to USB!", csidl));
                    return S_OK;
                }
            }
            HOOK_SH_GET_FOLDER_PATH_W.get().unwrap().call(hwnd, csidl, token, flags, path_out)
        }
    )
}

unsafe extern "system" fn hook_get_user_profile_directory_w(
    token: HANDLE,
    profile_dir: PWSTR,
    size: *mut u32,
) -> BOOL {
    guard_hook!(
        HOOK_GET_USER_PROFILE_DIRECTORY_W.get().unwrap().call(token, profile_dir, size),
        {
            if !size.is_null() {
                let cfg = crate::paths::init_paths();
                let needed_len = cfg.user_profile_w.len() as u32;

                if profile_dir.is_null() || *size < needed_len {
                    *size = needed_len;
                    windows_sys::Win32::Foundation::SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
                    return FALSE;
                }

                std::ptr::copy_nonoverlapping(cfg.user_profile_w.as_ptr(), profile_dir, needed_len as usize);
                *size = needed_len;
                crate::paths::log_always("GetUserProfileDirectoryW intercepted -> redirected to USB!");
                return TRUE;
            }
            HOOK_GET_USER_PROFILE_DIRECTORY_W.get().unwrap().call(token, profile_dir, size)
        }
    )
}

unsafe fn wide_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    Some(String::from_utf16_lossy(slice))
}

unsafe extern "system" fn hook_cred_read_w(
    target_name: *const u16,
    cred_type: u32,
    flags: u32,
    credential: *mut PCREDENTIALW,
) -> BOOL {
    guard_hook!(
        HOOK_CRED_READ_W.get().unwrap().call(target_name, cred_type, flags, credential),
        {
            if let Some(target) = wide_to_string(target_name) {
                // 1. Check virtual overlay store on USB first
                if let Some(p_mem) = crate::cred_store::cred_read(&target) {
                    if !credential.is_null() {
                        *credential = p_mem as PCREDENTIALW;
                        crate::paths::log_always(&format!("CredReadW [USB Overlay Hit] target: {}", target));
                        return TRUE;
                    }
                }

                // 2. If it is an application generic secret (CRED_TYPE_GENERIC = 1),
                // enforce Clean-Room isolation: never ask the host.
                if cred_type == CRED_TYPE_GENERIC {
                    crate::paths::log_always(&format!("CredReadW [Clean-Room] generic secret '{}' not in USB overlay -> returning ERROR_NOT_FOUND", target));
                    windows_sys::Win32::Foundation::SetLastError(1168); // ERROR_NOT_FOUND
                    return FALSE;
                }

                // 3. For OS network handshake types (Domain / Proxy / Cert), pass to OS network stack.
                crate::paths::log_always(&format!("CredReadW [OS Network Passthrough] type {} for '{}'", cred_type, target));
            }
            HOOK_CRED_READ_W.get().unwrap().call(target_name, cred_type, flags, credential)
        }
    )
}

unsafe extern "system" fn hook_cred_write_w(credential: PCREDENTIALW, flags: u32) -> BOOL {
    guard_hook!(
        HOOK_CRED_WRITE_W.get().unwrap().call(credential, flags),
        {
            if !credential.is_null() {
                let p = &*credential;
                if let Some(target_name) = wide_to_string(p.TargetName) {
                    let user_name = wide_to_string(p.UserName).unwrap_or_default();
                    let blob = if !p.CredentialBlob.is_null() && p.CredentialBlobSize > 0 {
                        std::slice::from_raw_parts(p.CredentialBlob, p.CredentialBlobSize as usize).to_vec()
                    } else {
                        Vec::new()
                    };

                    let cred = crate::cred_store::StoredCredential {
                        target_name: target_name.clone(),
                        user_name,
                        credential_blob: blob,
                        cred_type: p.Type,
                        flags: p.Flags,
                        persist: p.Persist,
                    };

                    // Save all writes to USB credentials overlay (never touch host)
                    crate::cred_store::cred_write(cred);
                    crate::paths::log_always(&format!("CredWriteW [USB Overlay Saved] target: {} (type: {})", target_name, p.Type));
                    return TRUE;
                }
            }
            HOOK_CRED_WRITE_W.get().unwrap().call(credential, flags)
        }
    )
}

unsafe extern "system" fn hook_cred_delete_w(target_name: *const u16, cred_type: u32, flags: u32) -> BOOL {
    guard_hook!(
        HOOK_CRED_DELETE_W.get().unwrap().call(target_name, cred_type, flags),
        {
            if let Some(target) = wide_to_string(target_name) {
                // Delete from USB overlay
                if crate::cred_store::cred_delete(&target) {
                    crate::paths::log_always(&format!("CredDeleteW [USB Overlay Deleted] target: {}", target));
                    return TRUE;
                } else {
                    // Prevent deleting anything from the host OS
                    crate::paths::log_always(&format!("CredDeleteW [Host Protected] target '{}' not in USB overlay -> returning ERROR_NOT_FOUND", target));
                    windows_sys::Win32::Foundation::SetLastError(1168); // ERROR_NOT_FOUND
                    return FALSE;
                }
            }
            windows_sys::Win32::Foundation::SetLastError(1168);
            FALSE
        }
    )
}

unsafe extern "system" fn hook_cred_free(buffer: *const c_void) {
    guard_hook!(
        HOOK_CRED_FREE.get().unwrap().call(buffer),
        {
            if !buffer.is_null() && crate::cred_store::is_custom_allocation(buffer) {
                crate::cred_store::free_custom_allocation(buffer as *mut c_void);
                return;
            }
            HOOK_CRED_FREE.get().unwrap().call(buffer);
        }
    )
}

unsafe extern "system" fn hook_create_process_w(
    app_name: *const u16,
    cmd_line: *mut u16,
    proc_attr: *const c_void,
    thread_attr: *const c_void,
    inherit_handles: BOOL,
    creation_flags: u32,
    env: *const c_void,
    curr_dir: *const u16,
    startup_info: LPSTARTUPINFOW,
    process_info: LPPROCESS_INFORMATION,
) -> BOOL {
    guard_hook!(
        HOOK_CREATE_PROCESS_W.get().unwrap().call(
            app_name,
            cmd_line,
            proc_attr,
            thread_attr,
            inherit_handles,
            creation_flags,
            env,
            curr_dir,
            startup_info,
            process_info,
        ),
        {
            HOOK_CREATE_PROCESS_W.get().unwrap().call(
                app_name,
                cmd_line,
                proc_attr,
                thread_attr,
                inherit_handles,
                creation_flags,
                env,
                curr_dir,
                startup_info,
                process_info,
            )
        }
    )
}

pub unsafe fn install_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    crate::paths::log_always("Installing inline detours via retour...");

    // 1. shell32.dll
    let shell32 = LoadLibraryA(b"shell32.dll\0".as_ptr());
    if !shell32.is_null() {
        let p_sh_get_known = GetProcAddress(shell32, b"SHGetKnownFolderPath\0".as_ptr());
        if let Some(target) = p_sh_get_known {
            let func: FnSHGetKnownFolderPath = std::mem::transmute(target);
            match GenericDetour::new(func, hook_sh_get_known_folder_path) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_SH_GET_KNOWN_FOLDER_PATH.set(detour);
                    crate::paths::log_always("Hooked SHGetKnownFolderPath successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook SHGetKnownFolderPath: {:?}", e));
                }
            }
        }

        let p_sh_get_folder = GetProcAddress(shell32, b"SHGetFolderPathW\0".as_ptr());
        if let Some(target) = p_sh_get_folder {
            let func: FnSHGetFolderPathW = std::mem::transmute(target);
            match GenericDetour::new(func, hook_sh_get_folder_path_w) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_SH_GET_FOLDER_PATH_W.set(detour);
                    crate::paths::log_always("Hooked SHGetFolderPathW successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook SHGetFolderPathW: {:?}", e));
                }
            }
        }
    }

    // 2. userenv.dll
    let userenv = LoadLibraryA(b"userenv.dll\0".as_ptr());
    if !userenv.is_null() {
        let p_get_user_profile = GetProcAddress(userenv, b"GetUserProfileDirectoryW\0".as_ptr());
        if let Some(target) = p_get_user_profile {
            let func: FnGetUserProfileDirectoryW = std::mem::transmute(target);
            match GenericDetour::new(func, hook_get_user_profile_directory_w) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_GET_USER_PROFILE_DIRECTORY_W.set(detour);
                    crate::paths::log_always("Hooked GetUserProfileDirectoryW successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook GetUserProfileDirectoryW: {:?}", e));
                }
            }
        }
    }

    // 3. advapi32.dll
    let advapi32 = LoadLibraryA(b"advapi32.dll\0".as_ptr());
    if !advapi32.is_null() {
        let p_cred_read = GetProcAddress(advapi32, b"CredReadW\0".as_ptr());
        if let Some(target) = p_cred_read {
            let func: FnCredReadW = std::mem::transmute(target);
            match GenericDetour::new(func, hook_cred_read_w) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_CRED_READ_W.set(detour);
                    crate::paths::log_always("Hooked CredReadW successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook CredReadW: {:?}", e));
                }
            }
        }

        let p_cred_write = GetProcAddress(advapi32, b"CredWriteW\0".as_ptr());
        if let Some(target) = p_cred_write {
            let func: FnCredWriteW = std::mem::transmute(target);
            match GenericDetour::new(func, hook_cred_write_w) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_CRED_WRITE_W.set(detour);
                    crate::paths::log_always("Hooked CredWriteW successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook CredWriteW: {:?}", e));
                }
            }
        }

        let p_cred_delete = GetProcAddress(advapi32, b"CredDeleteW\0".as_ptr());
        if let Some(target) = p_cred_delete {
            let func: FnCredDeleteW = std::mem::transmute(target);
            match GenericDetour::new(func, hook_cred_delete_w) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_CRED_DELETE_W.set(detour);
                    crate::paths::log_always("Hooked CredDeleteW successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook CredDeleteW: {:?}", e));
                }
            }
        }

        let p_cred_free = GetProcAddress(advapi32, b"CredFree\0".as_ptr());
        if let Some(target) = p_cred_free {
            let func: FnCredFree = std::mem::transmute(target);
            match GenericDetour::new(func, hook_cred_free) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_CRED_FREE.set(detour);
                    crate::paths::log_always("Hooked CredFree successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook CredFree: {:?}", e));
                }
            }
        }
    }

    // 4. kernel32.dll
    let kernel32 = LoadLibraryA(b"kernel32.dll\0".as_ptr());
    if !kernel32.is_null() {
        let p_create_proc = GetProcAddress(kernel32, b"CreateProcessW\0".as_ptr());
        if let Some(target) = p_create_proc {
            let func: FnCreateProcessW = std::mem::transmute(target);
            match GenericDetour::new(func, hook_create_process_w) {
                Ok(detour) => {
                    let _ = detour.enable();
                    let _ = HOOK_CREATE_PROCESS_W.set(detour);
                    crate::paths::log_always("Hooked CreateProcessW successfully.");
                }
                Err(e) => {
                    crate::paths::log_always(&format!("Failed to hook CreateProcessW: {:?}", e));
                }
            }
        }
    }

    crate::paths::log_always("All hooks initialization complete.");
}
