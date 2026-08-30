use crate::credentials::vault::get_vault;
use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::winstr::{alloc_cotask_wide_string, to_wide};
use crate::{BOOL, FALSE, TRUE};
use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::LazyLock;
use std::sync::atomic::AtomicPtr;

use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, FILETIME, SetLastError};
use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW};
use windows_sys::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

#[allow(clippy::upper_case_acronyms)]
type PCREDENTIALW = *mut CREDENTIALW;

thread_local! {
    static IN_CRED_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Tracks the CREDENTIALW structs this hook fabricates via CoTaskMemAlloc.
///
/// # Why
/// `CredFree` is a single global API: a vault-fabricated buffer and an advapi32-allocated
/// one (network-credential passthrough) are indistinguishable by pointer value. Freeing a
/// host allocation with `CoTaskMemFree` is cross-allocator UB that surfaces as
/// STATUS_HEAP_CORRUPTION, so ownership must be tracked explicitly at creation.
struct OwnedAllocations(Mutex<HashSet<usize>>);

impl OwnedAllocations {
    fn mark_owned(&self, ptr: usize) {
        self.0.lock().insert(ptr);
    }

    /// Removes `ptr` if this hook fabricated it; returns whether it was ours.
    fn take(&self, ptr: usize) -> bool {
        self.0.lock().remove(&ptr)
    }
}

static OWNED_CRED_ALLOCATIONS: LazyLock<OwnedAllocations> =
    LazyLock::new(|| OwnedAllocations(Mutex::new(HashSet::new())));

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
                    // A corrupt blob means the stored secret is unrecoverable; delivering an
                    // empty credential would silently masquerade as success, so the read
                    // defers to the host store (which reports the credential as absent).
                    let Ok(blob_bytes) = hex::decode(&cred.credential_blob_hex) else {
                        tracing::error!(
                            "Credential '{}' has a corrupt blob in the vault; deferring to host store",
                            cred.target_name
                        );
                        return unsafe { real_fn(target_name, cred_type, flags, credential_out) };
                    };

                    // SAFETY: `cred_mem` comes from CoTaskMemAlloc sized for exactly one
                    // CREDENTIALW (non-null via `as_mut`) and is fully initialized below before
                    // being published to the caller through `*credential_out`.
                    let cred_mem = unsafe { CoTaskMemAlloc(std::mem::size_of::<CREDENTIALW>()) };
                    let cred_struct = unsafe { cred_mem.cast::<CREDENTIALW>().as_mut() };
                    if let Some(cred_struct) = cred_struct {
                        cred_struct.Flags = 0;
                        cred_struct.Type = cred.cred_type;

                        let target_w = to_wide(&cred.target_name);
                        cred_struct.TargetName = alloc_cotask_wide_string(&target_w);

                        let user_w = to_wide(&cred.user_name);
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

                        // Fabricated credentials carry a real creation timestamp; leaving the
                        // CoTaskMem garbage uninitialized would leak nondeterminism into any
                        // caller that persists LastWritten.
                        // SAFETY: `now` is a valid, zero-initialized FILETIME out-parameter
                        // for the system-time query.
                        let now = unsafe {
                            let mut now = std::mem::zeroed::<FILETIME>();
                            GetSystemTimeAsFileTime(&mut now);
                            now
                        };
                        cred_struct.LastWritten = now;

                        // Mark the struct ours BEFORE publishing: once the caller sees it, the
                        // next CredFree must route back through this hook's owned-free path.
                        OWNED_CRED_ALLOCATIONS.mark_owned(cred_mem as usize);

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

                // Clean-room isolation for application secrets: a generic credential absent
                // from the vault must never resolve from the host profile - neither as a
                // leak of the real user's secrets, nor as a host-allocated CREDENTIALW the
                // caller will hand back to this hook's CredFree. Only OS network handshake
                // credentials (Domain / Proxy / Cert) fall through to the host stack.
                if cred_type == CRED_TYPE_GENERIC {
                    tracing::debug!(
                        "CredReadW [Clean-Room]: generic secret '{target_str}' not in vault -> ERROR_NOT_FOUND"
                    );
                    // SAFETY: SetLastError has no preconditions beyond the error code.
                    unsafe { SetLastError(ERROR_NOT_FOUND) };
                    return FALSE;
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
        if !buffer.is_null() && OWNED_CRED_ALLOCATIONS.take(buffer as usize) {
            // Why ownership tracking: CredFree is a single global API with no way to tell a
            // vault-fabricated buffer from an advapi32-allocated one (network-credential
            // passthrough). Freeing a host allocation with CoTaskMemFree is cross-allocator
            // UB that surfaces as STATUS_HEAP_CORRUPTION (the language-server crash), so
            // vault-fabricated structs are marked at creation and freed here; everything
            // else belongs to the host allocator and must go through the real CredFree.
            //
            // SAFETY: `buffer` is non-null and was fabricated by `hook_cred_read_w`, so it
            // points at a fully initialized CREDENTIALW with CoTaskMem-owned subfields.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_tracking_routes_only_marked_buffers_to_the_owned_free() {
        let owned = OwnedAllocations(Mutex::new(HashSet::new()));

        // An unmarked buffer (host-allocated) must NOT be claimed by the owned path.
        assert!(!owned.take(0x1234));

        owned.mark_owned(0x1234);
        assert!(owned.take(0x1234));

        // A second CredFree of the same pointer falls through to the real CredFree,
        // mirroring the Windows double-free contract instead of silently absorbing it.
        assert!(!owned.take(0x1234));
    }
}
