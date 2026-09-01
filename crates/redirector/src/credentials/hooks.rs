use crate::credentials::vault::{VaultCredential, get_vault};
use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::winstr::wide_to_string;
use crate::{BOOL, FALSE, TRUE};
use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::LazyLock;
use std::sync::atomic::AtomicPtr;

use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_FOUND, FILETIME, SetLastError};
use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW};
use windows_sys::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

#[allow(clippy::upper_case_acronyms)]
type PCREDENTIALW = *mut CREDENTIALW;

thread_local! {
    static IN_CRED_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Tracks the credential blocks this hook fabricates via CoTaskMemAlloc.
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

/// A stored credential with its blob decoded, ready to be written into a block.
struct Fabricated {
    target_name: String,
    user_name: String,
    cred_type: u32,
    persist: u32,
    blob: Vec<u8>,
}

impl Fabricated {
    /// Decodes a stored credential, or `None` when its stored bytes are unreadable.
    fn from_vault(credential: VaultCredential) -> Option<Self> {
        match hex::decode(&credential.credential_blob_hex) {
            Ok(blob) => Some(Fabricated {
                target_name: credential.target_name,
                user_name: credential.user_name,
                cred_type: credential.cred_type,
                persist: credential.persist,
                blob,
            }),
            Err(e) => {
                tracing::error!(
                    "Credential '{}' has unreadable stored bytes in the vault ({e})",
                    credential.target_name
                );
                None
            }
        }
    }
}

/// Byte length of `s` encoded as a NUL-terminated UTF-16 string.
fn wide_byte_len(s: &str) -> usize {
    (s.encode_utf16().count() + 1) * std::mem::size_of::<u16>()
}

/// A single contiguous CoTaskMem allocation holding fabricated `CREDENTIALW` structs together
/// with every string and blob they point at.
///
/// # Why one allocation instead of one per field
/// `CredFree` receives only a base pointer - no size, no shape - so any buffer it may be handed
/// must be releasable from that pointer alone. Packing a fabrication into one block makes that
/// true by construction: ownership is one pointer, release is one `CoTaskMemFree`, and a
/// partially built credential cannot strand allocations on an early return. The previous shape
/// allocated the struct, both strings and the blob separately, which needed a drop guard to
/// unwind and left `CredentialBlobSize` describing a null pointer whenever the blob allocation
/// was the one that failed.
struct CredentialBlock {
    base: *mut c_void,
    headers: *mut CREDENTIALW,
}

/// Appends a NUL-terminated UTF-16 copy of `text` at `cursor` and advances it.
///
/// # Safety
/// `cursor` must address at least `wide_byte_len(text)` writable bytes inside a live block.
unsafe fn append_wide(cursor: &mut *mut u8, text: &str) -> *mut u16 {
    unsafe {
        let start = cursor.cast::<u16>();
        let mut unit = start;
        for code_unit in text.encode_utf16().chain(std::iter::once(0)) {
            unit.write(code_unit);
            unit = unit.add(1);
        }
        *cursor = cursor.add(wide_byte_len(text));
        start
    }
}

/// Appends `bytes` at `cursor` and advances it. An empty blob yields a null pointer, which is
/// the credential-store convention for "no blob" and keeps size and pointer consistent.
///
/// # Safety
/// `cursor` must address at least `bytes.len()` writable bytes inside a live block.
unsafe fn append_bytes(cursor: &mut *mut u8, bytes: &[u8]) -> *mut u8 {
    if bytes.is_empty() {
        return std::ptr::null_mut();
    }
    unsafe {
        let start = *cursor;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), start, bytes.len());
        *cursor = cursor.add(bytes.len());
        start
    }
}

fn system_time_now() -> FILETIME {
    // SAFETY: `now` is a valid, zero-initialized FILETIME out-parameter for the system-time
    // query, which has no other preconditions.
    unsafe {
        let mut now = std::mem::zeroed::<FILETIME>();
        GetSystemTimeAsFileTime(&mut now);
        now
    }
}

/// Writes `credentials` into one CoTaskMem block and marks it owned by this hook.
///
/// `with_pointer_array` prepends the `*mut CREDENTIALW` array that `CredEnumerateW` returns.
/// Returns `None` only when the allocator declines.
///
/// # Safety
/// The returned `base` is a caller-owned CoTaskMem allocation released by a single
/// `CoTaskMemFree`; every pointer field inside it addresses memory within the same block.
unsafe fn build_credential_block(
    credentials: &[Fabricated],
    with_pointer_array: bool,
) -> Option<CredentialBlock> {
    let pointer_array_bytes = match with_pointer_array {
        true => credentials.len() * std::mem::size_of::<PCREDENTIALW>(),
        false => 0,
    };
    let header_bytes = credentials.len() * std::mem::size_of::<CREDENTIALW>();

    // Intention: Group every wide string ahead of every blob inside the trailing region.
    // Why: Blobs are arbitrary-length byte strings, so a credential whose blob has odd length
    //      would leave the cursor on an odd address and the *next* credential's UTF-16 string
    //      would start misaligned. Keeping the strings contiguous makes their region
    //      permanently 2-aligned - it starts aligned and every entry is an even number of
    //      bytes - while blobs, being bytes, need no alignment at all.
    // Ex: [target(12) blob(1) target(12)] -> [target(12) target(12) blob(1)]
    let string_bytes: usize = credentials
        .iter()
        .map(|credential| wide_byte_len(&credential.target_name) + wide_byte_len(&credential.user_name))
        .sum();
    let blob_bytes: usize = credentials.iter().map(|credential| credential.blob.len()).sum();

    let total = pointer_array_bytes + header_bytes + string_bytes + blob_bytes;

    // SAFETY: CoTaskMemAlloc either returns null or a `total`-sized buffer; every byte of it is
    // initialized below before the block is published to the caller.
    unsafe {
        let base = CoTaskMemAlloc(total);
        if base.is_null() {
            return None;
        }

        let headers = base.byte_add(pointer_array_bytes).cast::<CREDENTIALW>();
        let mut string_cursor = base.byte_add(pointer_array_bytes + header_bytes).cast::<u8>();
        let mut blob_cursor = base
            .byte_add(pointer_array_bytes + header_bytes + string_bytes)
            .cast::<u8>();

        for (index, credential) in credentials.iter().enumerate() {
            let target_name = append_wide(&mut string_cursor, &credential.target_name);
            let user_name = append_wide(&mut string_cursor, &credential.user_name);
            let blob = append_bytes(&mut blob_cursor, &credential.blob);

            headers.add(index).write(CREDENTIALW {
                Flags: 0,
                Type: credential.cred_type,
                TargetName: target_name,
                Comment: std::ptr::null_mut(),
                // Fabricated credentials carry a real creation timestamp; leaving the
                // CoTaskMem bytes uninitialized would leak nondeterminism into any caller
                // that persists LastWritten.
                LastWritten: system_time_now(),
                CredentialBlobSize: credential.blob.len() as u32,
                CredentialBlob: blob,
                Persist: credential.persist,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut(),
                TargetAlias: std::ptr::null_mut(),
                UserName: user_name,
            });

            if with_pointer_array {
                base.cast::<PCREDENTIALW>().add(index).write(headers.add(index));
            }
        }

        // Mark the block ours BEFORE it is published: once the caller sees it, the next
        // CredFree must route back through this hook's owned-free path.
        OWNED_CRED_ALLOCATIONS.mark_owned(base as usize);

        Some(CredentialBlock { base, headers })
    }
}

type FnCredReadW = unsafe extern "system" fn(*const u16, u32, u32, *mut PCREDENTIALW) -> BOOL;
type FnCredWriteW = unsafe extern "system" fn(PCREDENTIALW, u32) -> BOOL;
type FnCredDeleteW = unsafe extern "system" fn(*const u16, u32, u32) -> BOOL;
type FnCredEnumerateW = unsafe extern "system" fn(*const u16, u32, *mut u32, *mut *mut PCREDENTIALW) -> BOOL;
type FnCredFree = unsafe extern "system" fn(*const c_void);

static REAL_CRED_READ_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_WRITE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_DELETE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_ENUMERATE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_FREE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

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
            if target_name.is_null() || credential_out.is_null() {
                return unsafe { real_fn(target_name, cred_type, flags, credential_out) };
            }

            let target_str = wide_to_string(target_name);

            if let Some(stored) = get_vault().get(&target_str, cred_type) {
                // A corrupt blob means the stored secret is unrecoverable; delivering an
                // empty credential would silently masquerade as success, so the read
                // defers to the host store (which reports the credential as absent).
                let Some(fabricated) = Fabricated::from_vault(stored) else {
                    return unsafe { real_fn(target_name, cred_type, flags, credential_out) };
                };

                // SAFETY: the fabricated block is fully initialized before publication and is
                // released by the owned-free path in `hook_cred_free`.
                let Some(block) = (unsafe { build_credential_block(&[fabricated], false) }) else {
                    // A vault hit that failed to materialize must not masquerade as
                    // "absent" (the clean-room path below) - report the real failure.
                    unsafe { SetLastError(ERROR_NOT_ENOUGH_MEMORY) };
                    return FALSE;
                };

                // SAFETY: `credential_out` is non-null (checked above) and is the caller-owned
                // out-parameter; ownership of the block transfers to the caller here.
                unsafe { *credential_out = block.headers };
                tracing::trace!("CredReadW [Vault Hit]: target '{target_str}' read from virtual store");
                return TRUE;
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
                unsafe { SetLastError(ERROR_NOT_FOUND) };
                return FALSE;
            }

            unsafe { real_fn(target_name, cred_type, flags, credential_out) }
        }
    )
}

unsafe extern "system" fn hook_cred_write_w(credential: PCREDENTIALW, flags: u32) -> BOOL {
    let real_fn: FnCredWriteW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_WRITE_W)) };
    guard_detour!(&IN_CRED_HOOK, unsafe { real_fn(credential, flags) }, {
        if credential.is_null() {
            return unsafe { real_fn(credential, flags) };
        }

        // SAFETY: `credential` is non-null (checked above) and points to a CREDENTIALW
        // owned by the caller for the duration of this call.
        let cred = unsafe { &*credential };
        let target_name = wide_to_string(cred.TargetName);
        let user_name = wide_to_string(cred.UserName);

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
        TRUE
    })
}

/// Deletes only from the vault, never from the host credential store.
///
/// # Why no host fallthrough
/// `CredReadW` lets OS network-handshake credential types fall through to the host because a
/// read is non-destructive. A delete is not: forwarding one let a virtualized application
/// erase the real user's saved domain, proxy or certificate credentials. A target the vault
/// does not hold therefore reports absent instead of reaching the host.
unsafe extern "system" fn hook_cred_delete_w(target_name: *const u16, cred_type: u32, flags: u32) -> BOOL {
    let real_fn: FnCredDeleteW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_DELETE_W)) };
    guard_detour!(
        &IN_CRED_HOOK,
        unsafe { real_fn(target_name, cred_type, flags) },
        {
            if target_name.is_null() {
                unsafe { SetLastError(ERROR_NOT_FOUND) };
                return FALSE;
            }

            let target_str = wide_to_string(target_name);
            if get_vault().delete(&target_str, cred_type) {
                tracing::debug!(
                    "CredDeleteW [Vault Intercept]: target '{target_str}' removed from virtual store"
                );
                return TRUE;
            }

            tracing::debug!(
                "CredDeleteW [Clean-Room]: target '{target_str}' not in vault -> ERROR_NOT_FOUND (the host credential store is never modified)"
            );
            unsafe { SetLastError(ERROR_NOT_FOUND) };
            FALSE
        }
    )
}

/// Enumerates the vault instead of the host credential store.
///
/// # Why this needs a hook
/// Unhooked, `CredEnumerateW` returned the *real user's* credential list - target names,
/// user names and blobs - straight into the virtualized application. That is the leak the
/// clean-room read policy exists to prevent, arriving through the one Cred API that was
/// still forwarding.
unsafe extern "system" fn hook_cred_enumerate_w(
    filter: *const u16,
    flags: u32,
    count: *mut u32,
    credentials_out: *mut *mut PCREDENTIALW,
) -> BOOL {
    let real_fn: FnCredEnumerateW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_ENUMERATE_W)) };
    guard_detour!(
        &IN_CRED_HOOK,
        unsafe { real_fn(filter, flags, count, credentials_out) },
        {
            if count.is_null() || credentials_out.is_null() {
                return unsafe { real_fn(filter, flags, count, credentials_out) };
            }

            let filter_str = (!filter.is_null()).then(|| wide_to_string(filter));
            let selected: Vec<Fabricated> = get_vault()
                .matching(filter_str.as_deref())
                .into_iter()
                .filter_map(Fabricated::from_vault)
                .collect();

            if selected.is_empty() {
                // The documented empty result: no credentials, not an allocated empty array.
                tracing::debug!("CredEnumerateW [Clean-Room]: no vault credential matches the filter");
                unsafe { SetLastError(ERROR_NOT_FOUND) };
                return FALSE;
            }

            // SAFETY: the block is fully initialized before publication and is released by the
            // owned-free path in `hook_cred_free`.
            let Some(block) = (unsafe { build_credential_block(&selected, true) }) else {
                unsafe { SetLastError(ERROR_NOT_ENOUGH_MEMORY) };
                return FALSE;
            };

            // SAFETY: both out-parameters are non-null (checked above) and caller-owned;
            // ownership of the block transfers to the caller here.
            unsafe {
                *count = selected.len() as u32;
                *credentials_out = block.base.cast::<PCREDENTIALW>();
            }
            tracing::debug!(
                "CredEnumerateW [Vault]: returned {} credential(s) from the virtual store",
                selected.len()
            );
            TRUE
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
            // vault-fabricated blocks are marked at creation and freed here; everything
            // else belongs to the host allocator and must go through the real CredFree.
            //
            // One block, one free: every string and blob the credentials point at lives
            // inside this same allocation, so there are no subfields to release.
            //
            // SAFETY: `buffer` is non-null and was fabricated by `build_credential_block`,
            // so it is the base of a single CoTaskMem allocation.
            unsafe { CoTaskMemFree(buffer.cast_mut()) };
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
            tracing::warn!("advapi32.dll unavailable; credential vault hooks skipped");
            return;
        }

        // Intention: One row per intercepted credential API.
        // Why: The vault boundary is only as good as its least-covered entry point -
        //      CredEnumerateW forwarded the real user's whole credential list while the read
        //      path was carefully clean-roomed. A table keeps the covered surface reviewable.
        let hooks: [(&str, &AtomicPtr<c_void>, *mut c_void); 5] = [
            ("CredReadW", &REAL_CRED_READ_W, hook_cred_read_w as *mut c_void),
            ("CredWriteW", &REAL_CRED_WRITE_W, hook_cred_write_w as *mut c_void),
            (
                "CredDeleteW",
                &REAL_CRED_DELETE_W,
                hook_cred_delete_w as *mut c_void,
            ),
            (
                "CredEnumerateW",
                &REAL_CRED_ENUMERATE_W,
                hook_cred_enumerate_w as *mut c_void,
            ),
            ("CredFree", &REAL_CRED_FREE, hook_cred_free as *mut c_void),
        ];

        for (api, slot, hook) in hooks {
            if !hook_export(advapi32, api, slot, hook) {
                tracing::warn!("Hook {api}: not attached; credential vault inactive for this API");
            }
        }
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

    #[test]
    fn wide_byte_length_counts_the_terminator_and_surrogate_pairs() {
        assert_eq!(wide_byte_len(""), 2);
        assert_eq!(wide_byte_len("ab"), 6);
        // A non-BMP character encodes as a surrogate pair: two UTF-16 code units.
        assert_eq!(wide_byte_len("\u{1F600}"), 6);
    }

    fn fabricated(target: &str, user: &str, blob: &[u8]) -> Fabricated {
        Fabricated {
            target_name: target.to_string(),
            user_name: user.to_string(),
            cred_type: CRED_TYPE_GENERIC,
            persist: 1,
            blob: blob.to_vec(),
        }
    }

    /// Every pointer a fabricated credential publishes must address memory inside the one
    /// block that `CredFree` will release, and the blob size must describe the blob pointer.
    #[test]
    fn a_fabricated_credential_is_self_contained_and_consistent() {
        let credentials = [fabricated("git:https://example", "user", b"secret")];
        let expected_bytes = std::mem::size_of::<CREDENTIALW>()
            + wide_byte_len("git:https://example")
            + wide_byte_len("user")
            + b"secret".len();

        unsafe {
            let block = build_credential_block(&credentials, false).expect("allocation");
            let cred = &*block.headers;

            assert_eq!(cred.Type, CRED_TYPE_GENERIC);
            assert_eq!(cred.Persist, 1);
            assert_eq!(wide_to_string(cred.TargetName), "git:https://example");
            assert_eq!(wide_to_string(cred.UserName), "user");
            assert_eq!(cred.CredentialBlobSize, 6);
            assert!(!cred.CredentialBlob.is_null());
            assert_eq!(std::slice::from_raw_parts(cred.CredentialBlob, 6), b"secret");

            // Every published pointer lies within the single owned block.
            let base = block.base as usize;
            for pointer in [
                cred.TargetName as usize,
                cred.UserName as usize,
                cred.CredentialBlob as usize,
            ] {
                assert!(
                    pointer >= base && pointer < base + expected_bytes,
                    "field pointer escaped the block that CredFree releases"
                );
            }

            assert!(OWNED_CRED_ALLOCATIONS.take(block.base as usize));
            CoTaskMemFree(block.base);
        }
    }

    /// Regression: when only the blob allocation failed, the old per-field shape published a
    /// null `CredentialBlob` while `CredentialBlobSize` still claimed the full length.
    #[test]
    fn an_empty_blob_publishes_a_null_pointer_and_a_zero_size() {
        let credentials = [fabricated("target", "user", b"")];

        unsafe {
            let block = build_credential_block(&credentials, false).expect("allocation");
            let cred = &*block.headers;

            assert_eq!(cred.CredentialBlobSize, 0);
            assert!(cred.CredentialBlob.is_null());

            assert!(OWNED_CRED_ALLOCATIONS.take(block.base as usize));
            CoTaskMemFree(block.base);
        }
    }

    /// Regression: the trailing region used to interleave strings and blobs, so the 1-byte
    /// blob below left the cursor on an odd address and the next credential's UTF-16 target
    /// name was written through a misaligned pointer.
    #[test]
    fn an_enumeration_block_publishes_one_pointer_per_credential() {
        let credentials = [fabricated("a:one", "u1", b"x"), fabricated("b:two", "u2", b"yy")];

        unsafe {
            let block = build_credential_block(&credentials, true).expect("allocation");
            let array = block.base.cast::<PCREDENTIALW>();

            for (index, expected) in ["a:one", "b:two"].iter().enumerate() {
                let entry = *array.add(index);
                assert_eq!(entry, block.headers.add(index));
                assert_eq!(wide_to_string((*entry).TargetName), *expected);
            }

            assert!(OWNED_CRED_ALLOCATIONS.take(block.base as usize));
            CoTaskMemFree(block.base);
        }
    }
}
