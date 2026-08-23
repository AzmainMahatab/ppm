use crate::credentials::vault::get_vault;
use retour::GenericDetour;
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{BOOL, TRUE};
use windows_sys::Win32::Security::Credentials::CREDENTIALW;

type PWSTR = *mut u16;
type PCREDENTIALW = *mut CREDENTIALW;

thread_local! {
    static IN_CRED_HOOK: Cell<bool> = const { Cell::new(false) };
}

macro_rules! guard_cred_hook {
    ($fallback:expr, $body:expr) => {{
        if IN_CRED_HOOK.with(|h| h.get()) {
            return $fallback;
        }
        IN_CRED_HOOK.with(|h| h.set(true));
        let res = $body;
        IN_CRED_HOOK.with(|h| h.set(false));
        res
    }};
}

extern "system" {
    fn CoTaskMemAlloc(cb: usize) -> *mut c_void;
    fn CoTaskMemFree(pv: *mut c_void);
}

type FnCredReadW = unsafe extern "system" fn(*const u16, u32, u32, *mut PCREDENTIALW) -> BOOL;
type FnCredWriteW = unsafe extern "system" fn(PCREDENTIALW, u32) -> BOOL;
type FnCredDeleteW = unsafe extern "system" fn(*const u16, u32, u32) -> BOOL;
type FnCredFree = unsafe extern "system" fn(*const c_void);

static HOOK_CRED_READ_W: OnceLock<GenericDetour<FnCredReadW>> = OnceLock::new();
static HOOK_CRED_WRITE_W: OnceLock<GenericDetour<FnCredWriteW>> = OnceLock::new();
static HOOK_CRED_DELETE_W: OnceLock<GenericDetour<FnCredDeleteW>> = OnceLock::new();
static HOOK_CRED_FREE: OnceLock<GenericDetour<FnCredFree>> = OnceLock::new();

unsafe fn utf16_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

unsafe fn alloc_cotask_wide_string(w_str: &[u16]) -> PWSTR {
    let byte_len = w_str.len() * 2;
    let mem = CoTaskMemAlloc(byte_len);
    if !mem.is_null() {
        std::ptr::copy_nonoverlapping(w_str.as_ptr(), mem as *mut u16, w_str.len());
    }
    mem as PWSTR
}

unsafe extern "system" fn hook_cred_read_w(
    target_name: *const u16,
    cred_type: u32,
    flags: u32,
    credential_out: *mut PCREDENTIALW,
) -> BOOL {
    guard_cred_hook!(
        HOOK_CRED_READ_W.get().unwrap().call(target_name, cred_type, flags, credential_out),
        {
            if !target_name.is_null() && !credential_out.is_null() {
                let target_str = utf16_ptr_to_string(target_name);

                if let Some(cred) = get_vault().get(&target_str) {
                    let blob_bytes = hex::decode(&cred.credential_blob_hex).unwrap_or_default();

                    let cred_mem = CoTaskMemAlloc(std::mem::size_of::<CREDENTIALW>()) as PCREDENTIALW;
                    if !cred_mem.is_null() {
                        let cred_struct = &mut *cred_mem;
                        cred_struct.Flags = 0;
                        cred_struct.Type = cred.cred_type;

                        use std::os::windows::ffi::OsStrExt;
                        use std::ffi::OsStr;

                        let target_w: Vec<u16> = OsStr::new(&cred.target_name)
                            .encode_wide()
                            .chain(std::iter::once(0))
                            .collect();
                        cred_struct.TargetName = alloc_cotask_wide_string(&target_w);

                        let user_w: Vec<u16> = OsStr::new(&cred.user_name)
                            .encode_wide()
                            .chain(std::iter::once(0))
                            .collect();
                        cred_struct.UserName = alloc_cotask_wide_string(&user_w);

                        cred_struct.CredentialBlobSize = blob_bytes.len() as u32;
                        if !blob_bytes.is_empty() {
                            let blob_mem = CoTaskMemAlloc(blob_bytes.len()) as *mut u8;
                            if !blob_mem.is_null() {
                                std::ptr::copy_nonoverlapping(blob_bytes.as_ptr(), blob_mem, blob_bytes.len());
                                cred_struct.CredentialBlob = blob_mem;
                            } else {
                                cred_struct.CredentialBlob = std::ptr::null_mut();
                            }
                        } else {
                            cred_struct.CredentialBlob = std::ptr::null_mut();
                        }

                        cred_struct.Persist = cred.persist;
                        cred_struct.AttributeCount = 0;
                        cred_struct.Attributes = std::ptr::null_mut();
                        cred_struct.TargetAlias = std::ptr::null_mut();
                        cred_struct.Comment = std::ptr::null_mut();

                        *credential_out = cred_mem;
                        return TRUE;
                    }
                }
            }

            HOOK_CRED_READ_W.get().unwrap().call(target_name, cred_type, flags, credential_out)
        }
    )
}

unsafe extern "system" fn hook_cred_write_w(
    credential: PCREDENTIALW,
    flags: u32,
) -> BOOL {
    guard_cred_hook!(
        HOOK_CRED_WRITE_W.get().unwrap().call(credential, flags),
        {
            if !credential.is_null() {
                let cred = &*credential;
                let target_name = utf16_ptr_to_string(cred.TargetName);
                let user_name = utf16_ptr_to_string(cred.UserName);

                let blob = if !cred.CredentialBlob.is_null() && cred.CredentialBlobSize > 0 {
                    std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                } else {
                    &[]
                };

                get_vault().set(target_name, cred.Type, user_name, blob, cred.Persist);
                return TRUE;
            }

            HOOK_CRED_WRITE_W.get().unwrap().call(credential, flags)
        }
    )
}

unsafe extern "system" fn hook_cred_delete_w(
    target_name: *const u16,
    cred_type: u32,
    flags: u32,
) -> BOOL {
    guard_cred_hook!(
        HOOK_CRED_DELETE_W.get().unwrap().call(target_name, cred_type, flags),
        {
            if !target_name.is_null() {
                let target_str = utf16_ptr_to_string(target_name);
                if get_vault().delete(&target_str) {
                    return TRUE;
                }
            }

            HOOK_CRED_DELETE_W.get().unwrap().call(target_name, cred_type, flags)
        }
    )
}

unsafe extern "system" fn hook_cred_free(buffer: *const c_void) {
    guard_cred_hook!(
        HOOK_CRED_FREE.get().unwrap().call(buffer),
        {
            if !buffer.is_null() {
                let cred_ptr = buffer as *mut CREDENTIALW;
                let cred = &*cred_ptr;
                if !cred.TargetName.is_null() {
                    CoTaskMemFree(cred.TargetName as *mut c_void);
                }
                if !cred.UserName.is_null() {
                    CoTaskMemFree(cred.UserName as *mut c_void);
                }
                if !cred.CredentialBlob.is_null() {
                    CoTaskMemFree(cred.CredentialBlob as *mut c_void);
                }
                CoTaskMemFree(buffer as *mut c_void);
                return;
            }
            HOOK_CRED_FREE.get().unwrap().call(buffer);
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let advapi32 = GetModuleHandleW(windows_sys::core::w!("advapi32.dll"));
        if advapi32.is_null() {
            return;
        }

        if let Some(proc) = GetProcAddress(advapi32, b"CredReadW\0".as_ptr()) {
            let target: FnCredReadW = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_cred_read_w) {
                if d.enable().is_ok() {
                    let _ = HOOK_CRED_READ_W.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(advapi32, b"CredWriteW\0".as_ptr()) {
            let target: FnCredWriteW = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_cred_write_w) {
                if d.enable().is_ok() {
                    let _ = HOOK_CRED_WRITE_W.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(advapi32, b"CredDeleteW\0".as_ptr()) {
            let target: FnCredDeleteW = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_cred_delete_w) {
                if d.enable().is_ok() {
                    let _ = HOOK_CRED_DELETE_W.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(advapi32, b"CredFree\0".as_ptr()) {
            let target: FnCredFree = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_cred_free) {
                if d.enable().is_ok() {
                    let _ = HOOK_CRED_FREE.set(d);
                }
            }
        }
    }
}
