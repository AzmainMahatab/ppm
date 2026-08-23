use crate::credentials::vault::get_vault;
use crate::detour::attach_detour;
use crate::{BOOL, TRUE};
use std::cell::Cell;
use std::ffi::c_void;
use windows_sys::Win32::Security::Credentials::CREDENTIALW;

#[allow(clippy::upper_case_acronyms)]
type PWSTR = *mut u16;
#[allow(clippy::upper_case_acronyms)]
type PCREDENTIALW = *mut CREDENTIALW;

thread_local! {
    static IN_CRED_HOOK: Cell<bool> = const { Cell::new(false) };
}

struct CredHookGuard;

impl CredHookGuard {
    fn enter() -> Option<Self> {
        if IN_CRED_HOOK.try_with(|h| h.get()).unwrap_or(false) {
            return None;
        }
        let _ = IN_CRED_HOOK.try_with(|h| h.set(true));
        Some(CredHookGuard)
    }
}

impl Drop for CredHookGuard {
    fn drop(&mut self) {
        let _ = IN_CRED_HOOK.try_with(|h| h.set(false));
    }
}

macro_rules! guard_cred_hook {
    ($fallback:expr, $body:expr) => {{
        let _guard = match CredHookGuard::enter() {
            Some(g) => g,
            None => return $fallback,
        };
        $body
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

static mut REAL_CRED_READ_W: *mut c_void = std::ptr::null_mut();
static mut REAL_CRED_WRITE_W: *mut c_void = std::ptr::null_mut();
static mut REAL_CRED_DELETE_W: *mut c_void = std::ptr::null_mut();
static mut REAL_CRED_FREE: *mut c_void = std::ptr::null_mut();

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
    let real_fn: FnCredReadW = std::mem::transmute(REAL_CRED_READ_W);
    guard_cred_hook!(
        real_fn(target_name, cred_type, flags, credential_out),
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
                        tracing::trace!("CredReadW [Vault Hit]: target '{}' read from virtual store", target_str);
                        return TRUE;
                    }
                }
            }

            real_fn(target_name, cred_type, flags, credential_out)
        }
    )
}

unsafe extern "system" fn hook_cred_write_w(
    credential: PCREDENTIALW,
    flags: u32,
) -> BOOL {
    let real_fn: FnCredWriteW = std::mem::transmute(REAL_CRED_WRITE_W);
    guard_cred_hook!(
        real_fn(credential, flags),
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

                get_vault().set(target_name.clone(), cred.Type, user_name.clone(), blob, cred.Persist);
                tracing::debug!("CredWriteW [Vault Intercept]: target '{}' (user: '{}') saved to virtual store", target_name, user_name);
                return TRUE;
            }

            real_fn(credential, flags)
        }
    )
}

unsafe extern "system" fn hook_cred_delete_w(
    target_name: *const u16,
    cred_type: u32,
    flags: u32,
) -> BOOL {
    let real_fn: FnCredDeleteW = std::mem::transmute(REAL_CRED_DELETE_W);
    guard_cred_hook!(
        real_fn(target_name, cred_type, flags),
        {
            if !target_name.is_null() {
                let target_str = utf16_ptr_to_string(target_name);
                if get_vault().delete(&target_str) {
                    tracing::debug!("CredDeleteW [Vault Intercept]: target '{}' removed from virtual store", target_str);
                    return TRUE;
                }
            }

            real_fn(target_name, cred_type, flags)
        }
    )
}

unsafe extern "system" fn hook_cred_free(buffer: *const c_void) {
    let real_fn: FnCredFree = std::mem::transmute(REAL_CRED_FREE);
    guard_cred_hook!(
        real_fn(buffer),
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
            real_fn(buffer);
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    unsafe {
        let advapi32 = LoadLibraryW(windows_sys::core::w!("advapi32.dll"));
        if advapi32.is_null() {
            return;
        }

        if let Some(proc) = GetProcAddress(advapi32, c"CredReadW".as_ptr().cast()) {
            REAL_CRED_READ_W = proc as *mut c_void;
            attach_detour(&raw mut REAL_CRED_READ_W, hook_cred_read_w as *mut c_void);
        }

        if let Some(proc) = GetProcAddress(advapi32, c"CredWriteW".as_ptr().cast()) {
            REAL_CRED_WRITE_W = proc as *mut c_void;
            attach_detour(&raw mut REAL_CRED_WRITE_W, hook_cred_write_w as *mut c_void);
        }

        if let Some(proc) = GetProcAddress(advapi32, c"CredDeleteW".as_ptr().cast()) {
            REAL_CRED_DELETE_W = proc as *mut c_void;
            attach_detour(&raw mut REAL_CRED_DELETE_W, hook_cred_delete_w as *mut c_void);
        }

        if let Some(proc) = GetProcAddress(advapi32, c"CredFree".as_ptr().cast()) {
            REAL_CRED_FREE = proc as *mut c_void;
            attach_detour(&raw mut REAL_CRED_FREE, hook_cred_free as *mut c_void);
        }
    }
}
