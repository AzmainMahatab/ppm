use crate::credentials::vault::get_vault;
use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::{BOOL, TRUE};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Security::Credentials::CREDENTIALW;

#[allow(clippy::upper_case_acronyms)]
type PWSTR = *mut u16;
#[allow(clippy::upper_case_acronyms)]
type PCREDENTIALW = *mut CREDENTIALW;

thread_local! {
    static IN_CRED_HOOK: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "system" {
    fn CoTaskMemAlloc(cb: usize) -> *mut c_void;
    fn CoTaskMemFree(pv: *mut c_void);
}

type FnCredReadW = unsafe extern "system" fn(*const u16, u32, u32, *mut PCREDENTIALW) -> BOOL;
type FnCredWriteW = unsafe extern "system" fn(PCREDENTIALW, u32) -> BOOL;
type FnCredDeleteW = unsafe extern "system" fn(*const u16, u32, u32) -> BOOL;
type FnCredFree = unsafe extern "system" fn(*const c_void);

static REAL_CRED_READ_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_WRITE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_DELETE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_FREE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Decodes a NUL-terminated UTF-16 string from a raw Win32 pointer.
///
/// # Safety
/// `ptr` must point to a valid NUL-terminated UTF-16 sequence readable up to the terminator.
fn utf16_ptr_to_string(ptr: *const u16) -> String {
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

/// Allocates a NUL-terminated wide copy of `w_str` from the COM task allocator.
fn alloc_cotask_wide_string(w_str: &[u16]) -> PWSTR {
    unsafe {
        let byte_len = w_str.len() * 2;
        let mem = CoTaskMemAlloc(byte_len);
        if !mem.is_null() {
            std::ptr::copy_nonoverlapping(w_str.as_ptr(), mem.cast(), w_str.len());
        }
        mem.cast()
    }
}

unsafe extern "system" fn hook_cred_read_w(
    target_name: *const u16,
    cred_type: u32,
    flags: u32,
    credential_out: *mut PCREDENTIALW,
) -> BOOL {
    let real_fn: FnCredReadW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_READ_W)) };
    guard_detour!(
        &IN_CRED_HOOK,
        unsafe { real_fn(target_name, cred_type, flags, credential_out) },
        {
            if !target_name.is_null() && !credential_out.is_null() {
                let target_str = utf16_ptr_to_string(target_name);

                if let Some(cred) = get_vault().get(&target_str) {
                    let blob_bytes = hex::decode(&cred.credential_blob_hex).unwrap_or_default();

                    // SAFETY: `cred_mem` comes from CoTaskMemAlloc sized for exactly one
                    // CREDENTIALW (non-null via `as_mut`) and is fully initialized below before
                    // being published to the caller through `*credential_out`.
                    let cred_mem = unsafe { CoTaskMemAlloc(std::mem::size_of::<CREDENTIALW>()) };
                    let cred_struct = unsafe { cred_mem.cast::<CREDENTIALW>().as_mut() };
                    if let Some(cred_struct) = cred_struct {
                        cred_struct.Flags = 0;
                        cred_struct.Type = cred.cred_type;

                        use std::ffi::OsStr;
                        use std::os::windows::ffi::OsStrExt;

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
                            let blob_mem = unsafe { CoTaskMemAlloc(blob_bytes.len()) };
                            if !blob_mem.is_null() {
                                // SAFETY: `blob_mem` is non-null (checked above), freshly
                                // allocated with room for `blob_bytes`, and the source slice
                                // is a valid `blob_bytes`-long byte buffer.
                                unsafe {
                                    std::ptr::copy_nonoverlapping(
                                        blob_bytes.as_ptr(),
                                        blob_mem.cast(),
                                        blob_bytes.len(),
                                    );
                                }
                                cred_struct.CredentialBlob = blob_mem.cast();
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

                        // SAFETY: `credential_out` is non-null (checked at the top of the
                        // guard body) and is the caller-owned out-parameter.
                        unsafe {
                            *credential_out = cred_mem.cast();
                        }
                        tracing::trace!(
                            "CredReadW [Vault Hit]: target '{target_str}' read from virtual store"
                        );
                        return TRUE;
                    }
                }
            }

            unsafe { real_fn(target_name, cred_type, flags, credential_out) }
        }
    )
}

unsafe extern "system" fn hook_cred_write_w(credential: PCREDENTIALW, flags: u32) -> BOOL {
    let real_fn: FnCredWriteW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_WRITE_W)) };
    guard_detour!(&IN_CRED_HOOK, unsafe { real_fn(credential, flags) }, {
        if !credential.is_null() {
            // SAFETY: `credential` is non-null (checked above) and points to a CREDENTIALW
            // owned by the caller for the duration of this call.
            let cred = unsafe { &*credential };
            let target_name = utf16_ptr_to_string(cred.TargetName);
            let user_name = utf16_ptr_to_string(cred.UserName);

            let blob = if !cred.CredentialBlob.is_null() && cred.CredentialBlobSize > 0 {
                // SAFETY: `CredentialBlob` points to `CredentialBlobSize` bytes owned by the
                // caller's CREDENTIALW.
                unsafe { std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize) }
            } else {
                &[]
            };

            get_vault().set(
                target_name.clone(),
                cred.Type,
                user_name.clone(),
                blob,
                cred.Persist,
            );
            tracing::debug!(
                "CredWriteW [Vault Intercept]: target '{target_name}' (user: '{user_name}') saved to virtual store"
            );
            return TRUE;
        }

        unsafe { real_fn(credential, flags) }
    })
}

unsafe extern "system" fn hook_cred_delete_w(target_name: *const u16, cred_type: u32, flags: u32) -> BOOL {
    let real_fn: FnCredDeleteW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_DELETE_W)) };
    guard_detour!(
        &IN_CRED_HOOK,
        unsafe { real_fn(target_name, cred_type, flags) },
        {
            if !target_name.is_null() {
                let target_str = utf16_ptr_to_string(target_name);
                if get_vault().delete(&target_str) {
                    tracing::debug!(
                        "CredDeleteW [Vault Intercept]: target '{target_str}' removed from virtual store"
                    );
                    return TRUE;
                }
            }

            unsafe { real_fn(target_name, cred_type, flags) }
        }
    )
}

unsafe extern "system" fn hook_cred_free(buffer: *const c_void) {
    let real_fn: FnCredFree = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_FREE)) };
    guard_detour!(&IN_CRED_HOOK, unsafe { real_fn(buffer) }, {
        if !buffer.is_null() {
            // SAFETY: `buffer` is non-null (checked above) and points to a CREDENTIALW the
            // caller owns for the duration of this call; each `CoTaskMemFree` below releases
            // memory that was allocated through `CoTaskMemAlloc` on that structure's behalf.
            unsafe {
                let cred = &*buffer.cast::<CREDENTIALW>();
                if !cred.TargetName.is_null() {
                    CoTaskMemFree(cred.TargetName.cast());
                }
                if !cred.UserName.is_null() {
                    CoTaskMemFree(cred.UserName.cast());
                }
                if !cred.CredentialBlob.is_null() {
                    CoTaskMemFree(cred.CredentialBlob.cast());
                }
                CoTaskMemFree(buffer.cast_mut());
            }
            return;
        }
        unsafe { real_fn(buffer) }
    })
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

    unsafe {
        let advapi32 = LoadLibraryW(windows_sys::core::w!("advapi32.dll"));
        if advapi32.is_null() {
            return;
        }

        hook_export(
            advapi32,
            "CredReadW",
            &REAL_CRED_READ_W,
            hook_cred_read_w as *mut c_void,
        );

        hook_export(
            advapi32,
            "CredWriteW",
            &REAL_CRED_WRITE_W,
            hook_cred_write_w as *mut c_void,
        );

        hook_export(
            advapi32,
            "CredDeleteW",
            &REAL_CRED_DELETE_W,
            hook_cred_delete_w as *mut c_void,
        );

        hook_export(
            advapi32,
            "CredFree",
            &REAL_CRED_FREE,
            hook_cred_free as *mut c_void,
        );
    }
}
