use crate::credentials::vault::{VaultCredential, get_vault};
use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::winstr::{ansi_to_string, to_ansi, wide_to_string};
use crate::{BOOL, FALSE, TRUE};
use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::LazyLock;
use std::sync::atomic::AtomicPtr;

use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_FOUND, FILETIME, SetLastError};
use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALA, CREDENTIALW};
use windows_sys::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

#[allow(clippy::upper_case_acronyms)]
type PCREDENTIALW = *mut CREDENTIALW;
#[allow(clippy::upper_case_acronyms)]
type PCREDENTIALA = *mut CREDENTIALA;

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

fn system_time_now() -> FILETIME {
    // SAFETY: `now` is a valid, zero-initialized FILETIME out-parameter for the system-time
    // query, which has no other preconditions.
    unsafe {
        let mut now = std::mem::zeroed::<FILETIME>();
        GetSystemTimeAsFileTime(&mut now);
        now
    }
}

/// The credential record an API family returns: `CREDENTIALW` with UTF-16 strings for the wide
/// functions, `CREDENTIALA` with ANSI strings for the `...A` ones. The two structs share one
/// layout and differ only in their string encoding, so one block builder serves both.
trait CredentialRecord: Sized {
    /// One code unit of the record's strings.
    type Unit: Copy;

    /// `text` in the record's encoding, terminator included.
    fn encode(text: &str) -> Vec<Self::Unit>;

    fn record(
        credential: &Fabricated,
        target_name: *mut Self::Unit,
        user_name: *mut Self::Unit,
        blob: *mut u8,
    ) -> Self;
}

impl CredentialRecord for CREDENTIALW {
    type Unit = u16;

    fn encode(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn record(credential: &Fabricated, target_name: *mut u16, user_name: *mut u16, blob: *mut u8) -> Self {
        CREDENTIALW {
            Flags: 0,
            Type: credential.cred_type,
            TargetName: target_name,
            Comment: std::ptr::null_mut(),
            // Fabricated credentials carry a real creation timestamp; leaving the CoTaskMem
            // bytes uninitialized would leak nondeterminism into any caller that persists
            // LastWritten.
            LastWritten: system_time_now(),
            CredentialBlobSize: credential.blob.len() as u32,
            CredentialBlob: blob,
            Persist: credential.persist,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: user_name,
        }
    }
}

impl CredentialRecord for CREDENTIALA {
    type Unit = u8;

    fn encode(text: &str) -> Vec<u8> {
        to_ansi(text)
    }

    fn record(credential: &Fabricated, target_name: *mut u8, user_name: *mut u8, blob: *mut u8) -> Self {
        CREDENTIALA {
            Flags: 0,
            Type: credential.cred_type,
            TargetName: target_name,
            Comment: std::ptr::null_mut(),
            LastWritten: system_time_now(),
            CredentialBlobSize: credential.blob.len() as u32,
            CredentialBlob: blob,
            Persist: credential.persist,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: user_name,
        }
    }
}

/// A single contiguous CoTaskMem allocation holding fabricated credential records together
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
struct CredentialBlock<R> {
    base: *mut c_void,
    headers: *mut R,
}

/// Copies `units` to `cursor`, advances it, and returns where they start.
///
/// # Safety
/// `cursor` must address at least `units.len()` writable units inside a live block.
unsafe fn append_units<U: Copy>(cursor: &mut *mut U, units: &[U]) -> *mut U {
    unsafe {
        let start = *cursor;
        std::ptr::copy_nonoverlapping(units.as_ptr(), start, units.len());
        *cursor = cursor.add(units.len());
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
    unsafe { append_units(cursor, bytes) }
}

/// A credential's two strings in a record's encoding, terminators included.
struct EncodedNames<U> {
    target: Vec<U>,
    user: Vec<U>,
}

/// Writes `credentials` into one CoTaskMem block and marks it owned by this hook.
///
/// `with_pointer_array` prepends the record-pointer array that `CredEnumerate*` returns.
/// Returns `None` only when the allocator declines.
///
/// # Safety
/// The returned `base` is a caller-owned CoTaskMem allocation released by a single
/// `CoTaskMemFree`; every pointer field inside it addresses memory within the same block.
unsafe fn build_credential_block<R: CredentialRecord>(
    credentials: &[Fabricated],
    with_pointer_array: bool,
) -> Option<CredentialBlock<R>> {
    let encoded: Vec<EncodedNames<R::Unit>> = credentials
        .iter()
        .map(|credential| EncodedNames {
            target: R::encode(&credential.target_name),
            user: R::encode(&credential.user_name),
        })
        .collect();

    let pointer_array_bytes = match with_pointer_array {
        true => credentials.len() * size_of::<*mut R>(),
        false => 0,
    };
    let header_bytes = credentials.len() * size_of::<R>();

    // Intention: Group every string ahead of every blob inside the trailing region.
    // Why: Blobs are arbitrary-length byte strings, so a credential whose blob has odd length
    //      would leave the cursor on an odd address and the *next* credential's UTF-16 string
    //      would start misaligned. Keeping the strings contiguous makes their region
    //      permanently aligned to the code unit - it starts aligned after the headers and every
    //      entry is a whole number of units - while blobs, being bytes, need no alignment.
    // Ex: [target(12) blob(1) target(12)] -> [target(12) target(12) blob(1)]
    let string_units: usize = encoded
        .iter()
        .map(|names| names.target.len() + names.user.len())
        .sum();
    let string_bytes = string_units * size_of::<R::Unit>();
    let blob_bytes: usize = credentials.iter().map(|credential| credential.blob.len()).sum();

    let total = pointer_array_bytes + header_bytes + string_bytes + blob_bytes;

    // SAFETY: CoTaskMemAlloc either returns null or a `total`-sized buffer; every byte of it is
    // initialized below before the block is published to the caller.
    unsafe {
        let base = CoTaskMemAlloc(total);
        if base.is_null() {
            return None;
        }

        let headers = base.byte_add(pointer_array_bytes).cast::<R>();
        let mut string_cursor = base
            .byte_add(pointer_array_bytes + header_bytes)
            .cast::<R::Unit>();
        let mut blob_cursor = base
            .byte_add(pointer_array_bytes + header_bytes + string_bytes)
            .cast::<u8>();

        for (index, (credential, names)) in credentials.iter().zip(&encoded).enumerate() {
            let target_name = append_units(&mut string_cursor, &names.target);
            let user_name = append_units(&mut string_cursor, &names.user);
            let blob = append_bytes(&mut blob_cursor, &credential.blob);

            headers
                .add(index)
                .write(R::record(credential, target_name, user_name, blob));

            if with_pointer_array {
                base.cast::<*mut R>().add(index).write(headers.add(index));
            }
        }

        // Mark the block ours BEFORE it is published: once the caller sees it, the next
        // CredFree must route back through this hook's owned-free path.
        OWNED_CRED_ALLOCATIONS.mark_owned(base as usize);

        Some(CredentialBlock { base, headers })
    }
}

/// What the vault makes of a `CredRead*` call.
enum VaultRead<R> {
    /// Served from the vault; the record block now belongs to the caller.
    Hit(*mut R),
    /// Refused with this Win32 error.
    Refused(u32),
    /// An OS network-handshake credential type the vault does not hold: the host answers.
    Host,
}

fn vault_read<R: CredentialRecord>(api: &str, target: &str, cred_type: u32) -> VaultRead<R> {
    if let Some(stored) = get_vault().get(target, cred_type) {
        // A corrupt blob means the stored secret is unrecoverable; delivering an empty
        // credential would silently masquerade as success, so the read defers to the host
        // store (which reports the credential as absent).
        let Some(fabricated) = Fabricated::from_vault(stored) else {
            return VaultRead::Host;
        };
        // SAFETY: the fabricated block is fully initialized before publication and is released
        // by the owned-free path in `hook_cred_free`.
        return match unsafe { build_credential_block::<R>(&[fabricated], false) } {
            Some(block) => {
                tracing::trace!("{api} [Vault Hit]: target '{target}' read from virtual store");
                VaultRead::Hit(block.headers)
            }
            // A vault hit that failed to materialize must not masquerade as "absent".
            None => VaultRead::Refused(ERROR_NOT_ENOUGH_MEMORY),
        };
    }

    // Clean-room isolation for application secrets: a generic credential absent from the vault
    // must never resolve from the host profile - neither as a leak of the real user's secrets,
    // nor as a host-allocated record the caller will hand back to this hook's CredFree. Only OS
    // network handshake credentials (Domain / Proxy / Cert) fall through to the host stack.
    if cred_type == CRED_TYPE_GENERIC {
        tracing::debug!("{api} [Clean-Room]: generic secret '{target}' not in vault -> ERROR_NOT_FOUND");
        return VaultRead::Refused(ERROR_NOT_FOUND);
    }
    VaultRead::Host
}

/// Stores a credential a `CredWrite*` call submitted.
fn vault_write(api: &str, target: String, user: String, cred_type: u32, blob: &[u8], persist: u32) {
    tracing::debug!("{api} [Vault Intercept]: target '{target}' (user: '{user}') saved to virtual store");
    get_vault().set(target, cred_type, user, blob, persist);
}

/// Deletes only from the vault, never from the host credential store.
///
/// # Why no host fallthrough
/// `CredRead*` lets OS network-handshake credential types fall through to the host because a
/// read is non-destructive. A delete is not: forwarding one let a virtualized application erase
/// the real user's saved domain, proxy or certificate credentials. A target the vault does not
/// hold therefore reports absent instead of reaching the host.
fn vault_delete(api: &str, target: &str, cred_type: u32) -> BOOL {
    if get_vault().delete(target, cred_type) {
        tracing::debug!("{api} [Vault Intercept]: target '{target}' removed from virtual store");
        return TRUE;
    }
    tracing::debug!(
        "{api} [Clean-Room]: target '{target}' not in vault -> ERROR_NOT_FOUND (the host credential store is never modified)"
    );
    unsafe { SetLastError(ERROR_NOT_FOUND) };
    FALSE
}

/// Lists the vault instead of the host credential store.
///
/// # Why this needs a hook
/// Unhooked, `CredEnumerate*` returned the *real user's* credential list - target names, user
/// names and blobs - straight into the virtualized application. That is the leak the clean-room
/// read policy exists to prevent, arriving through the one Cred API that was still forwarding.
///
/// # Safety
/// `count` and `credentials_out` must be valid, writable out-parameters.
unsafe fn vault_enumerate<R: CredentialRecord>(
    api: &str,
    filter: Option<&str>,
    count: *mut u32,
    credentials_out: *mut *mut *mut R,
) -> BOOL {
    let selected: Vec<Fabricated> = get_vault()
        .matching(filter)
        .into_iter()
        .filter_map(Fabricated::from_vault)
        .collect();

    if selected.is_empty() {
        // The documented empty result: no credentials, not an allocated empty array.
        tracing::debug!("{api} [Clean-Room]: no vault credential matches the filter");
        unsafe { SetLastError(ERROR_NOT_FOUND) };
        return FALSE;
    }

    // SAFETY: the block is fully initialized before publication and is released by the
    // owned-free path in `hook_cred_free`.
    let Some(block) = (unsafe { build_credential_block::<R>(&selected, true) }) else {
        unsafe { SetLastError(ERROR_NOT_ENOUGH_MEMORY) };
        return FALSE;
    };

    // SAFETY: both out-parameters are valid per the contract; ownership of the block transfers
    // to the caller here.
    unsafe {
        *count = selected.len() as u32;
        *credentials_out = block.base.cast::<*mut R>();
    }
    tracing::debug!(
        "{api} [Vault]: returned {} credential(s) from the virtual store",
        selected.len()
    );
    TRUE
}

/// The bytes a submitted credential carries as its blob.
///
/// # Safety
/// `blob` must be null or point to `size` readable bytes.
unsafe fn submitted_blob<'a>(blob: *const u8, size: u32) -> &'a [u8] {
    if blob.is_null() || size == 0 {
        return &[];
    }
    // SAFETY: per the contract.
    unsafe { std::slice::from_raw_parts(blob, size as usize) }
}

type FnCredReadW = unsafe extern "system" fn(*const u16, u32, u32, *mut PCREDENTIALW) -> BOOL;
type FnCredWriteW = unsafe extern "system" fn(PCREDENTIALW, u32) -> BOOL;
type FnCredDeleteW = unsafe extern "system" fn(*const u16, u32, u32) -> BOOL;
type FnCredEnumerateW = unsafe extern "system" fn(*const u16, u32, *mut u32, *mut *mut PCREDENTIALW) -> BOOL;
type FnCredReadA = unsafe extern "system" fn(*const u8, u32, u32, *mut PCREDENTIALA) -> BOOL;
type FnCredWriteA = unsafe extern "system" fn(PCREDENTIALA, u32) -> BOOL;
type FnCredDeleteA = unsafe extern "system" fn(*const u8, u32, u32) -> BOOL;
type FnCredEnumerateA = unsafe extern "system" fn(*const u8, u32, *mut u32, *mut *mut PCREDENTIALA) -> BOOL;
type FnCredFree = unsafe extern "system" fn(*const c_void);

static REAL_CRED_READ_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_WRITE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_DELETE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_ENUMERATE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_READ_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_WRITE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_DELETE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_ENUMERATE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CRED_FREE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "system" fn hook_cred_read_w(
    target_name: *const u16,
    cred_type: u32,
    flags: u32,
    credential_out: *mut PCREDENTIALW,
) -> BOOL {
    let real_fn: FnCredReadW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_READ_W)) };
    let host = || unsafe { real_fn(target_name, cred_type, flags, credential_out) };
    guard_detour!(&IN_CRED_HOOK, host(), {
        if target_name.is_null() || credential_out.is_null() {
            return host();
        }
        match vault_read::<CREDENTIALW>("CredReadW", &wide_to_string(target_name), cred_type) {
            // SAFETY: `credential_out` is non-null (checked above) and caller-owned.
            VaultRead::Hit(record) => unsafe {
                *credential_out = record;
                TRUE
            },
            VaultRead::Refused(code) => unsafe {
                SetLastError(code);
                FALSE
            },
            VaultRead::Host => host(),
        }
    })
}

/// The ANSI family does not route through the hooked wide functions - `CredWriteA` was verified
/// to reach the host store while `CredWriteW` was vaulted - so each `...A` entry point carries
/// its own hook over the same vault.
unsafe extern "system" fn hook_cred_read_a(
    target_name: *const u8,
    cred_type: u32,
    flags: u32,
    credential_out: *mut PCREDENTIALA,
) -> BOOL {
    let real_fn: FnCredReadA = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_READ_A)) };
    let host = || unsafe { real_fn(target_name, cred_type, flags, credential_out) };
    guard_detour!(&IN_CRED_HOOK, host(), {
        if target_name.is_null() || credential_out.is_null() {
            return host();
        }
        match vault_read::<CREDENTIALA>("CredReadA", &ansi_to_string(target_name), cred_type) {
            // SAFETY: `credential_out` is non-null (checked above) and caller-owned.
            VaultRead::Hit(record) => unsafe {
                *credential_out = record;
                TRUE
            },
            VaultRead::Refused(code) => unsafe {
                SetLastError(code);
                FALSE
            },
            VaultRead::Host => host(),
        }
    })
}

unsafe extern "system" fn hook_cred_write_w(credential: PCREDENTIALW, flags: u32) -> BOOL {
    let real_fn: FnCredWriteW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_WRITE_W)) };
    guard_detour!(&IN_CRED_HOOK, unsafe { real_fn(credential, flags) }, {
        if credential.is_null() {
            return unsafe { real_fn(credential, flags) };
        }
        // SAFETY: non-null (checked above) and owned by the caller for the duration of this call;
        // the blob pointer addresses `CredentialBlobSize` bytes of it.
        let cred = unsafe { &*credential };
        let blob = unsafe { submitted_blob(cred.CredentialBlob, cred.CredentialBlobSize) };
        vault_write(
            "CredWriteW",
            wide_to_string(cred.TargetName),
            wide_to_string(cred.UserName),
            cred.Type,
            blob,
            cred.Persist,
        );
        TRUE
    })
}

/// Regression: `CredWriteA` wrote straight into the real user's credential store - an
/// application secret escaping the root onto the host, verified live by the probe.
unsafe extern "system" fn hook_cred_write_a(credential: PCREDENTIALA, flags: u32) -> BOOL {
    let real_fn: FnCredWriteA = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_WRITE_A)) };
    guard_detour!(&IN_CRED_HOOK, unsafe { real_fn(credential, flags) }, {
        if credential.is_null() {
            return unsafe { real_fn(credential, flags) };
        }
        // SAFETY: as in the wide hook.
        let cred = unsafe { &*credential };
        let blob = unsafe { submitted_blob(cred.CredentialBlob, cred.CredentialBlobSize) };
        vault_write(
            "CredWriteA",
            ansi_to_string(cred.TargetName),
            ansi_to_string(cred.UserName),
            cred.Type,
            blob,
            cred.Persist,
        );
        TRUE
    })
}

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
            vault_delete("CredDeleteW", &wide_to_string(target_name), cred_type)
        }
    )
}

unsafe extern "system" fn hook_cred_delete_a(target_name: *const u8, cred_type: u32, flags: u32) -> BOOL {
    let real_fn: FnCredDeleteA = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_DELETE_A)) };
    guard_detour!(
        &IN_CRED_HOOK,
        unsafe { real_fn(target_name, cred_type, flags) },
        {
            if target_name.is_null() {
                unsafe { SetLastError(ERROR_NOT_FOUND) };
                return FALSE;
            }
            vault_delete("CredDeleteA", &ansi_to_string(target_name), cred_type)
        }
    )
}

unsafe extern "system" fn hook_cred_enumerate_w(
    filter: *const u16,
    flags: u32,
    count: *mut u32,
    credentials_out: *mut *mut PCREDENTIALW,
) -> BOOL {
    let real_fn: FnCredEnumerateW = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_ENUMERATE_W)) };
    let host = || unsafe { real_fn(filter, flags, count, credentials_out) };
    guard_detour!(&IN_CRED_HOOK, host(), {
        if count.is_null() || credentials_out.is_null() {
            return host();
        }
        let filter = (!filter.is_null()).then(|| wide_to_string(filter));
        // SAFETY: both out-parameters are non-null (checked above) and caller-owned.
        unsafe { vault_enumerate::<CREDENTIALW>("CredEnumerateW", filter.as_deref(), count, credentials_out) }
    })
}

unsafe extern "system" fn hook_cred_enumerate_a(
    filter: *const u8,
    flags: u32,
    count: *mut u32,
    credentials_out: *mut *mut PCREDENTIALA,
) -> BOOL {
    let real_fn: FnCredEnumerateA = unsafe { std::mem::transmute(load_trampoline(&REAL_CRED_ENUMERATE_A)) };
    let host = || unsafe { real_fn(filter, flags, count, credentials_out) };
    guard_detour!(&IN_CRED_HOOK, host(), {
        if count.is_null() || credentials_out.is_null() {
            return host();
        }
        let filter = (!filter.is_null()).then(|| ansi_to_string(filter));
        // SAFETY: both out-parameters are non-null (checked above) and caller-owned.
        unsafe { vault_enumerate::<CREDENTIALA>("CredEnumerateA", filter.as_deref(), count, credentials_out) }
    })
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
        //      path was carefully clean-roomed, and the ANSI family wrote to the host store
        //      while the wide one was vaulted. A table keeps the covered surface reviewable.
        let hooks: [(&str, &AtomicPtr<c_void>, *mut c_void); 9] = [
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
            ("CredReadA", &REAL_CRED_READ_A, hook_cred_read_a as *mut c_void),
            ("CredWriteA", &REAL_CRED_WRITE_A, hook_cred_write_a as *mut c_void),
            (
                "CredDeleteA",
                &REAL_CRED_DELETE_A,
                hook_cred_delete_a as *mut c_void,
            ),
            (
                "CredEnumerateA",
                &REAL_CRED_ENUMERATE_A,
                hook_cred_enumerate_a as *mut c_void,
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
    fn wide_records_encode_with_a_terminator_and_surrogate_pairs() {
        assert_eq!(CREDENTIALW::encode(""), vec![0]);
        assert_eq!(CREDENTIALW::encode("ab"), vec![0x61, 0x62, 0]);
        // A non-BMP character encodes as a surrogate pair: two UTF-16 code units.
        assert_eq!(CREDENTIALW::encode("\u{1F600}"), vec![0xD83D, 0xDE00, 0]);
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

    /// The NUL-terminated byte string at `ptr`, terminator excluded.
    unsafe fn c_bytes<'a>(ptr: *const u8) -> &'a [u8] {
        unsafe { std::ffi::CStr::from_ptr(ptr.cast()).to_bytes() }
    }

    /// Every pointer a fabricated credential publishes must address memory inside the one
    /// block that `CredFree` will release, and the blob size must describe the blob pointer.
    #[test]
    fn a_fabricated_credential_is_self_contained_and_consistent() {
        let credentials = [fabricated("git:https://example", "user", b"secret")];
        // CREDENTIALW + "git:https://example\0" (20 units) + "user\0" (5 units) + 6 blob bytes.
        let expected_bytes = size_of::<CREDENTIALW>() + 20 * 2 + 5 * 2 + 6;

        unsafe {
            let block = build_credential_block::<CREDENTIALW>(&credentials, false).expect("allocation");
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

    /// The ANSI family's records carry 8-bit strings; an ASCII credential reads back byte for
    /// byte, and the block is owned exactly like a wide one.
    #[test]
    fn an_ansi_record_carries_byte_strings_in_one_owned_block() {
        let credentials = [fabricated("ansi:target", "ansi-user", b"pw")];

        unsafe {
            let block = build_credential_block::<CREDENTIALA>(&credentials, false).expect("allocation");
            let cred = &*block.headers;

            assert_eq!(c_bytes(cred.TargetName), b"ansi:target");
            assert_eq!(c_bytes(cred.UserName), b"ansi-user");
            assert_eq!(std::slice::from_raw_parts(cred.CredentialBlob, 2), b"pw");

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
            let block = build_credential_block::<CREDENTIALW>(&credentials, false).expect("allocation");
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
            let block = build_credential_block::<CREDENTIALW>(&credentials, true).expect("allocation");
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
