use crate::detour::{guard_detour, hook_export, load_trampoline, try_load_trampoline};
use crate::registry::enumeration::{HostListing, KeyView, ValueOrigin, cached_view, merge};
use crate::registry::handle_table::{KeyScope, get_handle_table};
use crate::registry::store::{KeyResolution, ValueResolution, get_registry_store};
use crate::winstr::{
    ansi_bytes_to_wide, ansi_to_string, to_ansi, to_wide, wide_bytes_to_ansi, wide_to_string,
};
use std::borrow::Cow;
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_KEY_DELETED, ERROR_MORE_DATA,
    ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME, HMODULE,
};
use windows_sys::Win32::System::Registry::{
    HKEY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ, RRF_NOEXPAND, RRF_RT_ANY,
};

// Intention: Name the `RegGetValueW` flag that winreg.h defines but the windows-sys bindings
//            do not surface.
// Why: The flag participates in the documented failure contract - a caller that asked for it
//      expects its buffer zeroed when the read fails - so honoring it needs the literal, and
//      the literal needs a name.
const RRF_ZEROONFAILURE: u32 = 0x2000_0000;

// Intention: Bound the wide-character buffer a REG_EXPAND_SZ expansion may grow into.
// Why: ExpandEnvironmentStringsW documents 32*1024 wide characters as the maximum size of an
//      expanded string; a larger request is the API's own hard limit, not a chosen number.
const MAX_EXPANDED_WCHARS: u32 = 32 * 1024;

thread_local! {
    static IN_REG_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Joins an open-key base path with a subkey the way the Win32 registry APIs compose them,
/// tolerating the leading-backslash variants callers pass.
fn resolve_full_key(base_path: &str, subkey: &str) -> String {
    let sub = subkey.trim_start_matches('\\');
    if !base_path.is_empty() && !sub.is_empty() {
        format!("{base_path}\\{sub}")
    } else if !sub.is_empty() {
        sub.to_string()
    } else {
        base_path.to_string()
    }
}

/// The key an operation addresses, once its incoming handle has been resolved.
enum Target {
    /// The addressed key path, plus whether the base handle was fabricated by this engine
    /// (and therefore has no host counterpart to fall through to).
    Resolved { path: String, synthetic: bool },
    /// The base handle is unknown to the engine, so the addressed key cannot be named.
    Untracked,
}

/// Resolves the key an intercepted call addresses from its base handle and subkey.
fn resolve_target(hkey: HKEY, subkey: *const u16) -> Target {
    resolve_subkey(hkey, &wide_to_string(subkey))
}

/// Resolves the key addressed by `subkey` under the handle `hkey`, already decoded to text.
fn resolve_subkey(hkey: HKEY, subkey: &str) -> Target {
    match get_handle_table().resolve(hkey.cast()) {
        KeyScope::Tracked { path, synthetic } => Target::Resolved {
            path: resolve_full_key(&path, subkey),
            synthetic,
        },
        KeyScope::Untracked => Target::Untracked,
    }
}

/// Stores a typed value in the overlay under `subkey` of the key `hkey` names. The wide and
/// ANSI entry points both end here, so one store path serves every spelling of the call.
fn set_value_virtually(api: &str, hkey: HKEY, subkey: &str, name: &str, dw_type: u32, data: &[u8]) -> i32 {
    let Target::Resolved { path, .. } = resolve_subkey(hkey, subkey) else {
        return refuse_untracked_mutation(api);
    };
    tracing::debug!(
        "{api} [CoW Virtual Store]: {path} / {name} (type: {dw_type}, bytes: {})",
        data.len()
    );
    get_registry_store().set_value(&path, name, dw_type, data);
    ERROR_SUCCESS as i32
}

/// Masks a value in the overlay under `subkey` of the key `hkey` names.
fn delete_value_virtually(api: &str, hkey: HKEY, subkey: &str, name: &str) -> i32 {
    let Target::Resolved { path, .. } = resolve_subkey(hkey, subkey) else {
        return refuse_untracked_mutation(api);
    };

    if get_registry_store().resolve_value(&path, name) == ValueResolution::Masked {
        // Already masked: Win32 reports a second delete of the same value as absent.
        return ERROR_FILE_NOT_FOUND as i32;
    }

    get_registry_store().delete_value(&path, name);
    tracing::info!("{api} [CoW Mask]: {path} / {name}");
    ERROR_SUCCESS as i32
}

/// Borrows the `cb` bytes a value-setting call supplies, or nothing when the payload is absent.
///
/// # Safety
/// `data` must be readable for `cb` bytes whenever it is non-null and `cb` is non-zero.
unsafe fn value_bytes<'a>(data: *const u8, cb: u32) -> &'a [u8] {
    if data.is_null() || cb == 0 {
        return &[];
    }
    // SAFETY: the caller guarantees `cb` readable bytes at a non-null `data`.
    unsafe { std::slice::from_raw_parts(data, cb as usize) }
}

/// Converts an `...A` value payload to its stored form. Text types are decoded from the ANSI
/// code page into UTF-16, as the system does; other types are stored as the caller wrote them.
///
/// Returns `None` for a text payload longer than the code-page conversion can take (`i32::MAX`
/// bytes); the caller refuses the write with `ERROR_INVALID_PARAMETER`.
///
/// # Why
/// The overlay keeps the wide representation the `...W` entry points write, so an ANSI write
/// read back through a wide read must produce the same bytes. The length bound is checked here,
/// at the caller's input, so an oversized `cbData` is reported to the application instead of
/// failing an invariant inside its process.
fn ansi_value_bytes(dw_type: u32, data: &[u8]) -> Option<Vec<u8>> {
    if !matches!(dw_type, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) {
        return Some(data.to_vec());
    }
    if i32::try_from(data.len()).is_err() {
        return None;
    }
    Some(
        ansi_bytes_to_wide(data)
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect(),
    )
}

/// Refuses a mutating registry call whose target key the engine cannot name.
///
/// # Why refusal beats both alternatives
/// Forwarding the mutation to the trampoline would change the real host registry - the exact
/// breach copy-on-write exists to prevent. Accepting it under a placeholder key would store it
/// where no read can ever reach it, which is what resolving an unknown handle to the empty
/// path used to do, silently. Reporting the real Win32 error for an unusable handle keeps the
/// boundary intact and the cause visible: ADR-006's fail-fast rule applied to the registry.
fn refuse_untracked_mutation(api: &str) -> i32 {
    tracing::error!(
        "{api}: the key handle is unknown to this engine, so the target key cannot be named; refusing the mutation rather than writing through to the host registry"
    );
    ERROR_INVALID_HANDLE as i32
}

/// Copies an overlay value into a caller's `RegQueryValueExW`-shaped out-parameters.
///
/// # Safety
/// `lp_type`, `lp_data` and `lpcb_data` must be the caller-owned out-parameters of the
/// intercepted API. Each is null-checked before use, and `lp_data` is written only within the
/// bound the caller published through `*lpcb_data`.
unsafe fn serve_value(
    val_type: u32,
    data: &[u8],
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    unsafe {
        if !lp_type.is_null() {
            *lp_type = val_type;
        }

        let required = data.len() as u32;

        if lpcb_data.is_null() {
            // Win32 requires the size cell whenever a data buffer is supplied; without it the
            // buffer has no bound and cannot be written at all.
            return if lp_data.is_null() {
                ERROR_SUCCESS as i32
            } else {
                ERROR_INVALID_PARAMETER as i32
            };
        }

        let provided = *lpcb_data;
        *lpcb_data = required;

        if lp_data.is_null() {
            // Size probe: the caller only asked how much room the value needs.
            return ERROR_SUCCESS as i32;
        }
        if provided < required {
            return ERROR_MORE_DATA as i32;
        }

        std::ptr::copy_nonoverlapping(data.as_ptr(), lp_data, data.len());
        ERROR_SUCCESS as i32
    }
}

/// Maps a registry value type onto the `RRF_RT_*` bit that admits it.
fn rrf_bit_for_type(val_type: u32) -> u32 {
    use windows_sys::Win32::System::Registry::{
        REG_BINARY, REG_DWORD, REG_NONE, REG_QWORD, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD,
        RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_NONE, RRF_RT_REG_QWORD, RRF_RT_REG_SZ,
    };
    match val_type {
        REG_NONE => RRF_RT_REG_NONE,
        REG_SZ => RRF_RT_REG_SZ,
        REG_EXPAND_SZ => RRF_RT_REG_EXPAND_SZ,
        REG_BINARY => RRF_RT_REG_BINARY,
        REG_DWORD => RRF_RT_REG_DWORD,
        REG_MULTI_SZ => RRF_RT_REG_MULTI_SZ,
        REG_QWORD => RRF_RT_REG_QWORD,
        _ => 0,
    }
}

/// Decodes a registry string payload into wide characters, or `None` when the payload is not
/// a whole number of them.
fn payload_to_wide(data: &[u8]) -> Option<Vec<u16>> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    Some(
        data.as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect(),
    )
}

fn wide_to_payload(wide: &[u16]) -> Vec<u8> {
    wide.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// Expands the environment references in a REG_EXPAND_SZ payload, the way `RegGetValueW` does
/// when the caller did not pass `RRF_NOEXPAND`.
///
/// Returns `None` when the payload is not a well-formed wide string or the OS declines the
/// expansion; the caller then serves the stored bytes unchanged rather than fabricating a value.
fn expand_reg_expand_sz(data: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;

    let mut source = payload_to_wide(data)?;
    if source.last() != Some(&0) {
        source.push(0);
    }

    // SAFETY: `source` is a NUL-terminated wide string; the first call only measures (null
    // destination, zero size) and the second writes within the measured capacity.
    unsafe {
        let needed = ExpandEnvironmentStringsW(source.as_ptr(), std::ptr::null_mut(), 0);
        if needed == 0 || needed > MAX_EXPANDED_WCHARS {
            return None;
        }
        let mut expanded = vec![0u16; needed as usize];
        let written = ExpandEnvironmentStringsW(source.as_ptr(), expanded.as_mut_ptr(), needed);
        if written == 0 || written > needed {
            return None;
        }
        expanded.truncate(written as usize);
        Some(wide_to_payload(&expanded))
    }
}

/// Applies the `RegGetValueW` post-processing contract to an overlay value: the `RRF_RT_*`
/// type restriction, REG_EXPAND_SZ expansion, and the NUL-termination guarantee for strings.
///
/// Returns the Win32 error to propagate when the stored type is not one the caller admits.
fn apply_get_value_contract(val_type: u32, data: Vec<u8>, dw_flags: u32) -> Result<(u32, Vec<u8>), i32> {
    use windows_sys::Win32::Foundation::ERROR_UNSUPPORTED_TYPE;

    // A caller that passed no RRF_RT_* bit placed no restriction on the type: winreg.h has no
    // "unrestricted" bit, so an empty mask is the absence of a filter, not a filter that
    // rejects everything.
    let type_mask = dw_flags & RRF_RT_ANY;
    if type_mask != 0 && rrf_bit_for_type(val_type) & type_mask == 0 {
        return Err(ERROR_UNSUPPORTED_TYPE as i32);
    }

    let expand_requested = val_type == REG_EXPAND_SZ && dw_flags & RRF_NOEXPAND == 0;
    let (served_type, mut served_data) = match expand_requested {
        // RegGetValueW reports an expanded REG_EXPAND_SZ as a plain REG_SZ.
        true => match expand_reg_expand_sz(&data) {
            Some(expanded) => (REG_SZ, expanded),
            None => (val_type, data),
        },
        false => (val_type, data),
    };

    let is_string = matches!(served_type, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ);
    let terminated = served_data.len() >= 2 && served_data[served_data.len() - 2..] == [0, 0];
    if is_string && !terminated {
        // RegGetValueW guarantees string results are NUL-terminated even when the stored
        // payload is not, and counts the terminator in the returned size.
        served_data.extend_from_slice(&[0, 0]);
    }

    Ok((served_type, served_data))
}

// Function pointer type definitions for Win32 Registry APIs
type FnRegOpenKeyExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32, *mut HKEY) -> i32;
type FnRegCreateKeyExW = unsafe extern "system" fn(
    HKEY,
    *const u16,
    u32,
    *mut u16,
    u32,
    u32,
    *const c_void,
    *mut HKEY,
    *mut u32,
) -> i32;
type FnRegQueryValueExW =
    unsafe extern "system" fn(HKEY, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type FnRegGetValueW =
    unsafe extern "system" fn(HKEY, *const u16, *const u16, u32, *mut u32, *mut c_void, *mut u32) -> i32;
type FnRegOpenKeyExA = unsafe extern "system" fn(HKEY, *const u8, u32, u32, *mut HKEY) -> i32;
type FnRegCreateKeyExA = unsafe extern "system" fn(
    HKEY,
    *const u8,
    u32,
    *mut u8,
    u32,
    u32,
    *const c_void,
    *mut HKEY,
    *mut u32,
) -> i32;
type FnRegQueryValueExA =
    unsafe extern "system" fn(HKEY, *const u8, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type FnRegGetValueA =
    unsafe extern "system" fn(HKEY, *const u8, *const u8, u32, *mut u32, *mut c_void, *mut u32) -> i32;
type FnRegEnumKeyExA = unsafe extern "system" fn(
    HKEY,
    u32,
    *mut u8,
    *mut u32,
    *const u32,
    *mut u8,
    *mut u32,
    *mut FILETIME,
) -> i32;
type FnRegEnumValueA =
    unsafe extern "system" fn(HKEY, u32, *mut u8, *mut u32, *const u32, *mut u32, *mut u8, *mut u32) -> i32;
type FnRegQueryInfoKeyA = unsafe extern "system" fn(
    HKEY,
    *mut u8,
    *mut u32,
    *const u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut FILETIME,
) -> i32;
type FnRegSetValueExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32, *const u8, u32) -> i32;
type FnRegSetValueExA = unsafe extern "system" fn(HKEY, *const u8, u32, u32, *const u8, u32) -> i32;
type FnRegSetKeyValueW =
    unsafe extern "system" fn(HKEY, *const u16, *const u16, u32, *const c_void, u32) -> i32;
type FnRegSetKeyValueA =
    unsafe extern "system" fn(HKEY, *const u8, *const u8, u32, *const c_void, u32) -> i32;
type FnRegSetValueW = unsafe extern "system" fn(HKEY, *const u16, u32, *const u8, u32) -> i32;
type FnRegSetValueA = unsafe extern "system" fn(HKEY, *const u8, u32, *const u8, u32) -> i32;
type FnRegDeleteValueW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegDeleteValueA = unsafe extern "system" fn(HKEY, *const u8) -> i32;
type FnRegDeleteKeyValueW = unsafe extern "system" fn(HKEY, *const u16, *const u16) -> i32;
type FnRegDeleteKeyValueA = unsafe extern "system" fn(HKEY, *const u8, *const u8) -> i32;
type FnRegDeleteKeyW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegDeleteKeyExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32) -> i32;
type FnRegDeleteTreeW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegEnumKeyExW = unsafe extern "system" fn(
    HKEY,
    u32,
    *mut u16,
    *mut u32,
    *const u32,
    *mut u16,
    *mut u32,
    *mut FILETIME,
) -> i32;
type FnRegEnumValueW =
    unsafe extern "system" fn(HKEY, u32, *mut u16, *mut u32, *const u32, *mut u32, *mut u8, *mut u32) -> i32;
type FnRegQueryInfoKeyW = unsafe extern "system" fn(
    HKEY,
    *mut u16,
    *mut u32,
    *const u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut FILETIME,
) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(HKEY) -> i32;
type FnRegOpenCurrentUser = unsafe extern "system" fn(u32, *mut HKEY) -> i32;

static REAL_REG_OPEN_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_CREATE_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_QUERY_VALUE_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_GET_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_VALUE_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_QUERY_VALUE_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_GET_VALUE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_ENUM_KEY_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_ENUM_VALUE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_QUERY_INFO_KEY_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_OPEN_KEY_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_CREATE_KEY_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_VALUE_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_KEY_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_KEY_VALUE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_VALUE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_VALUE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_KEY_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_KEY_VALUE_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_KEY_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_TREE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_ENUM_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_ENUM_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_QUERY_INFO_KEY_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_CLOSE_KEY: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_OPEN_CURRENT_USER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// ---------------------- WIN32 API HOOKS ----------------------

unsafe extern "system" fn hook_reg_open_key_ex_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    ul_options: u32,
    sam_desired: u32,
    phk_result: *mut HKEY,
) -> i32 {
    let real_fn: FnRegOpenKeyExW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_OPEN_KEY_EX_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result) },
        open_key_virtually(hkey, &wide_to_string(lp_sub_key), phk_result, || unsafe {
            real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result)
        })
    )
}

/// Opens `subkey` under `hkey` through the overlay. `host_open` performs the caller's own call
/// and serves a key the host owns.
///
/// # Why a closure
/// The `...W` and `...A` entry points differ only in how they spell the arguments. Taking the
/// host call as a closure lets both share this logic and still fall through with the caller's
/// own pointers.
fn open_key_virtually(hkey: HKEY, subkey: &str, phk_result: *mut HKEY, host_open: impl Fn() -> i32) -> i32 {
    let Target::Resolved { path, synthetic } = resolve_subkey(hkey, subkey) else {
        // An unnameable base key cannot be virtualized; a read-side open falls through to the
        // host, which is the documented copy-on-write behavior for anything the overlay does
        // not shadow.
        return host_open();
    };

    let resolution = get_registry_store().resolve_key(&path);
    if resolution == KeyResolution::Masked {
        return ERROR_FILE_NOT_FOUND as i32;
    }

    if synthetic {
        if !phk_result.is_null() && resolution == KeyResolution::Virtual {
            // SAFETY: `phk_result` is non-null (checked above) and is the caller-owned
            // out-parameter for the opened key.
            unsafe {
                *phk_result = get_handle_table().register_virtual_handle(path).cast();
            }
            return ERROR_SUCCESS as i32;
        }
        return ERROR_FILE_NOT_FOUND as i32;
    }

    let status = host_open();
    if status == ERROR_SUCCESS as i32 && !phk_result.is_null() {
        // SAFETY: `phk_result` is non-null (checked above) and the host open wrote a valid key
        // handle into it on success.
        unsafe {
            get_handle_table().register_host_handle((*phk_result).cast(), path);
        }
        return status;
    }

    if !phk_result.is_null() && resolution == KeyResolution::Virtual {
        // SAFETY: `phk_result` is non-null (checked above), caller-owned out-parameter.
        unsafe {
            *phk_result = get_handle_table().register_virtual_handle(path).cast();
        }
        return ERROR_SUCCESS as i32;
    }

    status
}

unsafe extern "system" fn hook_reg_create_key_ex_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    reserved: u32,
    lp_class: *mut u16,
    dw_options: u32,
    sam_desired: u32,
    lp_security_attributes: *const c_void,
    phk_result: *mut HKEY,
    lpdw_disposition: *mut u32,
) -> i32 {
    let real_fn: FnRegCreateKeyExW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_CREATE_KEY_EX_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe {
            real_fn(
                hkey,
                lp_sub_key,
                reserved,
                lp_class,
                dw_options,
                sam_desired,
                lp_security_attributes,
                phk_result,
                lpdw_disposition,
            )
        },
        create_key_virtually(
            "RegCreateKeyExW",
            hkey,
            &wide_to_string(lp_sub_key),
            phk_result,
            lpdw_disposition,
            || unsafe {
                real_fn(
                    hkey,
                    lp_sub_key,
                    reserved,
                    lp_class,
                    dw_options,
                    sam_desired,
                    lp_security_attributes,
                    phk_result,
                    lpdw_disposition,
                )
            }
        )
    )
}

/// Creates `subkey` under `hkey` in the overlay, then runs `host_create` for the host side.
///
/// # Why the host create still runs
/// The overlay shadows values and deletions, but subkey *existence* still falls through to the
/// host so an app can open the keys its installer left behind. The host key this creates is
/// empty - every value written into it is virtualized - and the probe's disposition assertion
/// depends on it. Narrowing this to a pure overlay create is a separate decision, not an
/// oversight.
fn create_key_virtually(
    api: &str,
    hkey: HKEY,
    subkey: &str,
    phk_result: *mut HKEY,
    lpdw_disposition: *mut u32,
    host_create: impl Fn() -> i32,
) -> i32 {
    let Target::Resolved { path, synthetic } = resolve_subkey(hkey, subkey) else {
        return refuse_untracked_mutation(api);
    };

    get_registry_store().create_key(&path);
    tracing::info!("{api}: Virtual key created -> {path}");

    if synthetic && !phk_result.is_null() {
        // SAFETY: `phk_result` is non-null (checked above) and is the caller-owned out-parameter
        // for the created key; `lpdw_disposition` likewise for the disposition value.
        unsafe {
            *phk_result = get_handle_table().register_virtual_handle(path).cast();
            if !lpdw_disposition.is_null() {
                *lpdw_disposition = 1;
            }
        }
        return ERROR_SUCCESS as i32;
    }

    let status = host_create();
    if status == ERROR_SUCCESS as i32 && !phk_result.is_null() {
        // SAFETY: `phk_result` is non-null (checked above) and the host create wrote a valid key
        // handle into it on success.
        unsafe {
            get_handle_table().register_host_handle((*phk_result).cast(), path);
        }
        return status;
    }

    if !phk_result.is_null() {
        // SAFETY: as above - caller-owned out-parameters, null-checked immediately.
        unsafe {
            *phk_result = get_handle_table().register_virtual_handle(path).cast();
            if !lpdw_disposition.is_null() {
                *lpdw_disposition = 1;
            }
        }
        return ERROR_SUCCESS as i32;
    }

    status
}

unsafe extern "system" fn hook_reg_query_value_ex_w(
    hkey: HKEY,
    lp_value_name: *const u16,
    lp_reserved: *mut u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    let real_fn: FnRegQueryValueExW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_QUERY_VALUE_EX_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data) },
        query_value_virtually(
            "RegQueryValueExW",
            resolve_subkey(hkey, ""),
            &wide_to_string(lp_value_name),
            ValueOut {
                lp_type,
                lp_data,
                lpcb_data
            },
            stored_payload,
            || unsafe { real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data) },
        )
    )
}

/// The caller-owned out-parameters of a value read: the type, the data buffer and its size cell.
#[derive(Clone, Copy)]
struct ValueOut {
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
}

/// Serves a value read from the overlay under the key `hkey` names, or falls through to
/// `host_query` for a value the overlay does not shadow.
fn query_value_virtually(
    api: &str,
    target: Target,
    name: &str,
    out: ValueOut,
    payload: PayloadEncoding,
    host_query: impl Fn() -> i32,
) -> i32 {
    let Target::Resolved { path, synthetic } = target else {
        return host_query();
    };

    match get_registry_store().resolve_value(&path, name) {
        ValueResolution::Virtual { val_type, data } => {
            tracing::debug!("{api} [Virtual Hit]: {path} / {name}");
            // SAFETY: every pointer is a caller-owned out-parameter of the intercepted API;
            // `serve_value` null-checks them and bounds the copy by the caller's size cell.
            unsafe {
                serve_value(
                    val_type,
                    &payload(val_type, &data),
                    out.lp_type,
                    out.lp_data,
                    out.lpcb_data,
                )
            }
        }
        ValueResolution::Masked => {
            tracing::debug!("{api} [Tombstoned Value]: {path} / {name}");
            ERROR_FILE_NOT_FOUND as i32
        }
        ValueResolution::Corrupt => {
            // The store already logged the corruption. Reading as absent keeps the boundary:
            // falling through would answer with the real user's data.
            ERROR_FILE_NOT_FOUND as i32
        }
        ValueResolution::PassThrough if synthetic => ERROR_FILE_NOT_FOUND as i32,
        ValueResolution::PassThrough => host_query(),
    }
}

/// Serves `RegGetValueW` from the overlay.
///
/// # Why this needs its own hook
/// `RegGetValueW` opens its `lpSubKey` through `RegOpenKeyExInternalW`, an entry point this
/// engine does not intercept, so the handle it then passed to `RegQueryValueExW` was unknown
/// to the engine and the read escaped to the host registry. Resolving the composed path here
/// closes that path, and serving the value directly also implements the API's own contract -
/// the `RRF_RT_*` type filter, REG_EXPAND_SZ expansion, and the string NUL-termination
/// guarantee - which the inner query hook has no way to apply.
unsafe extern "system" fn hook_reg_get_value_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    lp_value: *const u16,
    dw_flags: u32,
    pdw_type: *mut u32,
    pv_data: *mut c_void,
    pcb_data: *mut u32,
) -> i32 {
    let real_fn: FnRegGetValueW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_GET_VALUE_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, lp_value, dw_flags, pdw_type, pv_data, pcb_data) },
        // Why the subkey-less form is resolved here too, rather than forwarded: the
        // re-entrancy guard is one flag for the whole registry module, so a forwarded call
        // would re-enter `hook_reg_query_value_ex_w` with the guard already held and take its
        // unvirtualized fallback. Forwarding would therefore *break* the form that works today.
        // Resolving both forms here keeps one path and no nesting.
        get_value_virtually(
            "RegGetValueW",
            resolve_subkey(hkey, &wide_to_string(lp_sub_key)),
            &wide_to_string(lp_value),
            dw_flags,
            ValueOut {
                lp_type: pdw_type,
                lp_data: pv_data.cast(),
                lpcb_data: pcb_data
            },
            stored_payload,
            || unsafe { real_fn(hkey, lp_sub_key, lp_value, dw_flags, pdw_type, pv_data, pcb_data) },
        )
    )
}

/// Serves a `RegGetValueW`-shaped read from the overlay, applying the `RRF_*` contract to the
/// stored value. A value the overlay does not shadow falls through to `host_get`.
fn get_value_virtually(
    api: &str,
    target: Target,
    name: &str,
    dw_flags: u32,
    out: ValueOut,
    payload: PayloadEncoding,
    host_get: impl Fn() -> i32,
) -> i32 {
    let Target::Resolved { path, synthetic } = target else {
        return host_get();
    };
    let ValueOut {
        lp_type: pdw_type,
        lp_data: pv_data,
        lpcb_data: pcb_data,
    } = out;

    let zero_on_failure = dw_flags & RRF_ZEROONFAILURE != 0;
    let fail = |status: i32| -> i32 {
        if zero_on_failure && !pv_data.is_null() && !pcb_data.is_null() {
            // SAFETY: both pointers are non-null (checked) caller-owned out-parameters; the fill
            // is bounded by the caller's own size cell.
            unsafe {
                std::ptr::write_bytes(pv_data.cast::<u8>(), 0, *pcb_data as usize);
            }
        }
        status
    };

    match get_registry_store().resolve_value(&path, name) {
        ValueResolution::Virtual { val_type, data } => {
            match apply_get_value_contract(val_type, data, dw_flags) {
                Ok((served_type, served_data)) => {
                    tracing::debug!("{api} [Virtual Hit]: {path} / {name}");
                    // SAFETY: caller-owned out-parameters, null-checked and bounded inside `serve_value`.
                    unsafe {
                        serve_value(
                            served_type,
                            &payload(served_type, &served_data),
                            pdw_type,
                            pv_data.cast::<u8>(),
                            pcb_data,
                        )
                    }
                }
                Err(status) => fail(status),
            }
        }
        ValueResolution::Masked | ValueResolution::Corrupt => {
            tracing::debug!("{api} [Masked]: {path} / {name}");
            fail(ERROR_FILE_NOT_FOUND as i32)
        }
        ValueResolution::PassThrough if synthetic => fail(ERROR_FILE_NOT_FOUND as i32),
        ValueResolution::PassThrough => host_get(),
    }
}

/// Encodes a served payload for the caller's entry point: the stored form for `...W`, the ANSI
/// code page for `...A`.
type PayloadEncoding = for<'a> fn(u32, &'a [u8]) -> Cow<'a, [u8]>;

/// Serves a wide read's payload exactly as the overlay stores it.
fn stored_payload(_val_type: u32, data: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(data)
}

/// Serves an `...A` read: text payloads are encoded to the ANSI code page, as the system does.
fn ansi_payload(val_type: u32, data: &[u8]) -> Cow<'_, [u8]> {
    if matches!(val_type, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) {
        Cow::Owned(wide_bytes_to_ansi(data))
    } else {
        Cow::Borrowed(data)
    }
}

unsafe extern "system" fn hook_reg_query_value_ex_a(
    hkey: HKEY,
    lp_value_name: *const u8,
    lp_reserved: *mut u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    let real_fn: FnRegQueryValueExA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_QUERY_VALUE_EX_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data) },
        query_value_virtually(
            "RegQueryValueExA",
            resolve_subkey(hkey, ""),
            &ansi_to_string(lp_value_name),
            ValueOut {
                lp_type,
                lp_data,
                lpcb_data
            },
            ansi_payload,
            || unsafe { real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data) },
        )
    )
}

unsafe extern "system" fn hook_reg_get_value_a(
    hkey: HKEY,
    lp_sub_key: *const u8,
    lp_value: *const u8,
    dw_flags: u32,
    pdw_type: *mut u32,
    pv_data: *mut c_void,
    pcb_data: *mut u32,
) -> i32 {
    let real_fn: FnRegGetValueA = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_GET_VALUE_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, lp_value, dw_flags, pdw_type, pv_data, pcb_data) },
        get_value_virtually(
            "RegGetValueA",
            resolve_subkey(hkey, &ansi_to_string(lp_sub_key)),
            &ansi_to_string(lp_value),
            dw_flags,
            ValueOut {
                lp_type: pdw_type,
                lp_data: pv_data.cast(),
                lpcb_data: pcb_data
            },
            ansi_payload,
            || unsafe { real_fn(hkey, lp_sub_key, lp_value, dw_flags, pdw_type, pv_data, pcb_data) },
        )
    )
}

/// A name spelling an enumerator writes: UTF-16 for the `...W` entry points, the ANSI code page
/// for `...A`. Lengths are measured in the caller's units, so buffer sizing matches the call.
trait NameUnit: Copy {
    /// The zero unit that terminates a name.
    const NUL: Self;
    /// Encodes `name` without its terminator.
    fn encode(name: &str) -> Vec<Self>;
}

impl NameUnit for u16 {
    const NUL: Self = 0;

    fn encode(name: &str) -> Vec<Self> {
        name.encode_utf16().collect()
    }
}

impl NameUnit for u8 {
    const NUL: Self = 0;

    fn encode(name: &str) -> Vec<Self> {
        // `to_ansi` appends the terminator; the enumerator writes its own.
        let mut ansi = to_ansi(name);
        ansi.pop();
        ansi
    }
}

/// Serves `RegEnumKeyExA`: the listing's subkey names in the ANSI code page. The class and
/// timestamp are reported empty, as the wide enumerator does.
unsafe extern "system" fn hook_reg_enum_key_ex_a(
    hkey: HKEY,
    dw_index: u32,
    lp_name: *mut u8,
    lpcch_name: *mut u32,
    lp_reserved: *const u32,
    lp_class: *mut u8,
    lpcch_class: *mut u32,
    lpft_last_write_time: *mut FILETIME,
) -> i32 {
    let real_fn: FnRegEnumKeyExA = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_ENUM_KEY_EX_A)) };
    let host_enum = || unsafe {
        real_fn(
            hkey,
            dw_index,
            lp_name,
            lpcch_name,
            lp_reserved,
            lp_class,
            lpcch_class,
            lpft_last_write_time,
        )
    };
    guard_detour!(&IN_REG_HOOK, host_enum(), {
        let out = SubkeyOut {
            name: lp_name,
            name_len: lpcch_name,
            class: lp_class,
            class_len: lpcch_class,
            last_write: lpft_last_write_time,
        };
        // SAFETY: `out` holds the caller-owned out-parameters of this RegEnumKeyExA call.
        unsafe { enum_key_virtually(hkey, dw_index, out, host_enum) }
    })
}

/// Serves `RegEnumValueA`: the merged value names in the ANSI code page, with data from the
/// side that holds it and text payloads encoded for the caller.
unsafe extern "system" fn hook_reg_enum_value_a(
    hkey: HKEY,
    dw_index: u32,
    lp_value_name: *mut u8,
    lpcch_value_name: *mut u32,
    lp_reserved: *const u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    let real_fn: FnRegEnumValueA = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_ENUM_VALUE_A)) };
    let host_enum = || unsafe {
        real_fn(
            hkey,
            dw_index,
            lp_value_name,
            lpcch_value_name,
            lp_reserved,
            lp_type,
            lp_data,
            lpcb_data,
        )
    };
    let host_read = |name: &str| {
        let Some(trampoline) = try_load_trampoline(&REAL_REG_QUERY_VALUE_EX_A) else {
            tracing::error!(
                "RegEnumValueA: RegQueryValueExA is not hooked, so the host value '{name}' cannot be read"
            );
            return ERROR_FILE_NOT_FOUND as i32;
        };
        let query: FnRegQueryValueExA = unsafe { std::mem::transmute(trampoline) };
        let name_ansi = to_ansi(name);
        // SAFETY: `hkey` is the caller's live host handle and `name_ansi` is a NUL-terminated
        // ANSI name; the remaining pointers are the caller's own.
        unsafe {
            query(
                hkey,
                name_ansi.as_ptr(),
                std::ptr::null_mut(),
                lp_type,
                lp_data,
                lpcb_data,
            )
        }
    };
    guard_detour!(&IN_REG_HOOK, host_enum(), {
        let out = EnumValueOut {
            name: lp_value_name,
            name_len: lpcch_value_name,
            value: ValueOut {
                lp_type,
                lp_data,
                lpcb_data,
            },
        };
        // SAFETY: `out` holds the caller-owned out-parameters of this RegEnumValueA call.
        unsafe { enum_value_virtually(hkey, dw_index, out, ansi_payload, host_enum, host_read) }
    })
}

/// Serves `RegQueryInfoKeyA`. The counts come from the merged listing; the longest names are
/// measured in ANSI bytes, the unit the caller sizes its buffers in. The host answers class,
/// security and timestamp, and its own longest value, as it does for the wide entry point.
unsafe extern "system" fn hook_reg_query_info_key_a(
    hkey: HKEY,
    lp_class: *mut u8,
    lpcch_class: *mut u32,
    lp_reserved: *const u32,
    lpc_sub_keys: *mut u32,
    lpcb_max_sub_key_len: *mut u32,
    lpcb_max_class_len: *mut u32,
    lpc_values: *mut u32,
    lpcb_max_value_name_len: *mut u32,
    lpcb_max_value_len: *mut u32,
    lpcb_security_descriptor: *mut u32,
    lpft_last_write_time: *mut FILETIME,
) -> i32 {
    let real_fn: FnRegQueryInfoKeyA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_QUERY_INFO_KEY_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe {
            real_fn(
                hkey,
                lp_class,
                lpcch_class,
                lp_reserved,
                lpc_sub_keys,
                lpcb_max_sub_key_len,
                lpcb_max_class_len,
                lpc_values,
                lpcb_max_value_name_len,
                lpcb_max_value_len,
                lpcb_security_descriptor,
                lpft_last_write_time,
            )
        },
        {
            let listing = match unsafe { listing_for(hkey) } {
                Ok(listing) => listing,
                Err(UNTRACKED_FORWARD) => {
                    return unsafe {
                        real_fn(
                            hkey,
                            lp_class,
                            lpcch_class,
                            lp_reserved,
                            lpc_sub_keys,
                            lpcb_max_sub_key_len,
                            lpcb_max_class_len,
                            lpc_values,
                            lpcb_max_value_name_len,
                            lpcb_max_value_len,
                            lpcb_security_descriptor,
                            lpft_last_write_time,
                        )
                    };
                }
                Err(status) => return status,
            };

            let mut host_max_value_len = 0u32;
            let host_answered = unsafe {
                real_fn(
                    hkey,
                    lp_class,
                    lpcch_class,
                    lp_reserved,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    lpcb_max_class_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut host_max_value_len,
                    lpcb_security_descriptor,
                    lpft_last_write_time,
                )
            } == ERROR_SUCCESS as i32;
            if !host_answered {
                host_max_value_len = 0;
            }

            // Stored overlay values are UTF-16, so their byte length over-estimates the ANSI form.
            // Over-estimating is safe: the caller allocates more than it needs.
            let overlay_max_value_len = listing
                .view
                .values
                .iter()
                .filter_map(|entry| get_registry_store().overlay_value_len(&listing.path, &entry.name))
                .max()
                .unwrap_or(0) as u32;

            let max_subkey_len = listing
                .view
                .subkeys
                .iter()
                .map(|name| <u8 as NameUnit>::encode(name).len() as u32)
                .max()
                .unwrap_or(0);
            let max_value_name_len = listing
                .view
                .values
                .iter()
                .map(|entry| <u8 as NameUnit>::encode(&entry.name).len() as u32)
                .max()
                .unwrap_or(0);

            // SAFETY: every cell below is a caller-owned out-parameter, null-checked first.
            unsafe {
                if !lpc_sub_keys.is_null() {
                    *lpc_sub_keys = listing.view.subkeys.len() as u32;
                }
                if !lpcb_max_sub_key_len.is_null() {
                    *lpcb_max_sub_key_len = max_subkey_len;
                }
                if !lpc_values.is_null() {
                    *lpc_values = listing.view.values.len() as u32;
                }
                if !lpcb_max_value_name_len.is_null() {
                    *lpcb_max_value_name_len = max_value_name_len;
                }
                if !lpcb_max_value_len.is_null() {
                    *lpcb_max_value_len = host_max_value_len.max(overlay_max_value_len);
                }
            }

            ERROR_SUCCESS as i32
        }
    )
}

unsafe extern "system" fn hook_reg_set_value_ex_w(
    hkey: HKEY,
    lp_value_name: *const u16,
    reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    let real_fn: FnRegSetValueExW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_SET_VALUE_EX_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_value_name, reserved, dw_type, lp_data, cb_data) },
        {
            // SAFETY: RegSetValueExW supplies `cb_data` bytes at `lp_data`.
            let data = unsafe { value_bytes(lp_data, cb_data) };
            set_value_virtually(
                "RegSetValueExW",
                hkey,
                "",
                &wide_to_string(lp_value_name),
                dw_type,
                data,
            )
        }
    )
}

unsafe extern "system" fn hook_reg_open_key_ex_a(
    hkey: HKEY,
    lp_sub_key: *const u8,
    ul_options: u32,
    sam_desired: u32,
    phk_result: *mut HKEY,
) -> i32 {
    let real_fn: FnRegOpenKeyExA = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_OPEN_KEY_EX_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result) },
        open_key_virtually(hkey, &ansi_to_string(lp_sub_key), phk_result, || unsafe {
            real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result)
        })
    )
}

unsafe extern "system" fn hook_reg_create_key_ex_a(
    hkey: HKEY,
    lp_sub_key: *const u8,
    reserved: u32,
    lp_class: *mut u8,
    dw_options: u32,
    sam_desired: u32,
    lp_security_attributes: *const c_void,
    phk_result: *mut HKEY,
    lpdw_disposition: *mut u32,
) -> i32 {
    let real_fn: FnRegCreateKeyExA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_CREATE_KEY_EX_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe {
            real_fn(
                hkey,
                lp_sub_key,
                reserved,
                lp_class,
                dw_options,
                sam_desired,
                lp_security_attributes,
                phk_result,
                lpdw_disposition,
            )
        },
        create_key_virtually(
            "RegCreateKeyExA",
            hkey,
            &ansi_to_string(lp_sub_key),
            phk_result,
            lpdw_disposition,
            || unsafe {
                real_fn(
                    hkey,
                    lp_sub_key,
                    reserved,
                    lp_class,
                    dw_options,
                    sam_desired,
                    lp_security_attributes,
                    phk_result,
                    lpdw_disposition,
                )
            }
        )
    )
}

/// Serves the ANSI `RegSetValueExA` from the overlay. The system converts the name and text
/// data from the ANSI code page; this engine's overlay stores the wide form, so it converts the
/// same way before storing.
unsafe extern "system" fn hook_reg_set_value_ex_a(
    hkey: HKEY,
    lp_value_name: *const u8,
    reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    let real_fn: FnRegSetValueExA = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_SET_VALUE_EX_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_value_name, reserved, dw_type, lp_data, cb_data) },
        {
            // SAFETY: RegSetValueExA supplies `cb_data` bytes at `lp_data`.
            let data = unsafe { value_bytes(lp_data, cb_data) };
            let Some(stored) = ansi_value_bytes(dw_type, data) else {
                return ERROR_INVALID_PARAMETER as i32;
            };
            set_value_virtually(
                "RegSetValueExA",
                hkey,
                "",
                &ansi_to_string(lp_value_name),
                dw_type,
                &stored,
            )
        }
    )
}

unsafe extern "system" fn hook_reg_set_key_value_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    lp_value_name: *const u16,
    dw_type: u32,
    lp_data: *const c_void,
    cb_data: u32,
) -> i32 {
    let real_fn: FnRegSetKeyValueW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_SET_KEY_VALUE_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, lp_value_name, dw_type, lp_data, cb_data) },
        {
            // SAFETY: RegSetKeyValueW supplies `cb_data` bytes at `lp_data`.
            let data = unsafe { value_bytes(lp_data.cast(), cb_data) };
            set_value_virtually(
                "RegSetKeyValueW",
                hkey,
                &wide_to_string(lp_sub_key),
                &wide_to_string(lp_value_name),
                dw_type,
                data,
            )
        }
    )
}

unsafe extern "system" fn hook_reg_set_key_value_a(
    hkey: HKEY,
    lp_sub_key: *const u8,
    lp_value_name: *const u8,
    dw_type: u32,
    lp_data: *const c_void,
    cb_data: u32,
) -> i32 {
    let real_fn: FnRegSetKeyValueA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_SET_KEY_VALUE_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, lp_value_name, dw_type, lp_data, cb_data) },
        {
            // SAFETY: RegSetKeyValueA supplies `cb_data` bytes at `lp_data`.
            let data = unsafe { value_bytes(lp_data.cast(), cb_data) };
            let Some(stored) = ansi_value_bytes(dw_type, data) else {
                return ERROR_INVALID_PARAMETER as i32;
            };
            set_value_virtually(
                "RegSetKeyValueA",
                hkey,
                &ansi_to_string(lp_sub_key),
                &ansi_to_string(lp_value_name),
                dw_type,
                &stored,
            )
        }
    )
}

/// The legacy `RegSetValueW` writes the default value of `lpSubKey` and takes no name.
unsafe extern "system" fn hook_reg_set_value_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    let real_fn: FnRegSetValueW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_SET_VALUE_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, dw_type, lp_data, cb_data) },
        {
            // SAFETY: RegSetValueW supplies `cb_data` bytes at `lp_data`.
            let data = unsafe { value_bytes(lp_data, cb_data) };
            set_value_virtually(
                "RegSetValueW",
                hkey,
                &wide_to_string(lp_sub_key),
                "",
                dw_type,
                data,
            )
        }
    )
}

/// The legacy `RegSetValueA` writes the default value of `lpSubKey` and takes no name.
unsafe extern "system" fn hook_reg_set_value_a(
    hkey: HKEY,
    lp_sub_key: *const u8,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    let real_fn: FnRegSetValueA = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_SET_VALUE_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, dw_type, lp_data, cb_data) },
        {
            // SAFETY: RegSetValueA supplies `cb_data` bytes at `lp_data`.
            let data = unsafe { value_bytes(lp_data, cb_data) };
            let Some(stored) = ansi_value_bytes(dw_type, data) else {
                return ERROR_INVALID_PARAMETER as i32;
            };
            set_value_virtually(
                "RegSetValueA",
                hkey,
                &ansi_to_string(lp_sub_key),
                "",
                dw_type,
                &stored,
            )
        }
    )
}

unsafe extern "system" fn hook_reg_delete_value_w(hkey: HKEY, lp_value_name: *const u16) -> i32 {
    let real_fn: FnRegDeleteValueW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_VALUE_W)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey, lp_value_name) }, {
        delete_value_virtually("RegDeleteValueW", hkey, "", &wide_to_string(lp_value_name))
    })
}

unsafe extern "system" fn hook_reg_delete_value_a(hkey: HKEY, lp_value_name: *const u8) -> i32 {
    let real_fn: FnRegDeleteValueA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_VALUE_A)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey, lp_value_name) }, {
        delete_value_virtually("RegDeleteValueA", hkey, "", &ansi_to_string(lp_value_name))
    })
}

unsafe extern "system" fn hook_reg_delete_key_value_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    lp_value_name: *const u16,
) -> i32 {
    let real_fn: FnRegDeleteKeyValueW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_KEY_VALUE_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, lp_value_name) },
        {
            delete_value_virtually(
                "RegDeleteKeyValueW",
                hkey,
                &wide_to_string(lp_sub_key),
                &wide_to_string(lp_value_name),
            )
        }
    )
}

unsafe extern "system" fn hook_reg_delete_key_value_a(
    hkey: HKEY,
    lp_sub_key: *const u8,
    lp_value_name: *const u8,
) -> i32 {
    let real_fn: FnRegDeleteKeyValueA =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_KEY_VALUE_A)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, lp_value_name) },
        {
            delete_value_virtually(
                "RegDeleteKeyValueA",
                hkey,
                &ansi_to_string(lp_sub_key),
                &ansi_to_string(lp_value_name),
            )
        }
    )
}

/// Masks a key and its subtree in the overlay instead of deleting it on the host.
fn delete_key_virtually(api: &str, hkey: HKEY, lp_sub_key: *const u16) -> i32 {
    let Target::Resolved { path, .. } = resolve_target(hkey, lp_sub_key) else {
        return refuse_untracked_mutation(api);
    };

    if get_registry_store().resolve_key(&path) == KeyResolution::Masked {
        return ERROR_FILE_NOT_FOUND as i32;
    }

    get_registry_store().delete_key(&path);
    tracing::info!("{api} [CoW Tombstone]: {path}");
    ERROR_SUCCESS as i32
}

unsafe extern "system" fn hook_reg_delete_key_w(hkey: HKEY, lp_sub_key: *const u16) -> i32 {
    let real_fn: FnRegDeleteKeyW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_KEY_W)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey, lp_sub_key) }, {
        delete_key_virtually("RegDeleteKeyW", hkey, lp_sub_key)
    })
}

/// `RegDeleteKeyExW` reaches `RegDeleteKeyExInternalW` without passing through
/// `RegDeleteKeyW`, so leaving it unhooked let a virtualized application delete keys in the
/// real host registry.
///
/// `samDesired` carries only the `KEY_WOW64_*` view selector here; the overlay keeps a single
/// key space, so both views resolve to the same overlay key.
unsafe extern "system" fn hook_reg_delete_key_ex_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    sam_desired: u32,
    reserved: u32,
) -> i32 {
    let real_fn: FnRegDeleteKeyExW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_KEY_EX_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe { real_fn(hkey, lp_sub_key, sam_desired, reserved) },
        delete_key_virtually("RegDeleteKeyExW", hkey, lp_sub_key)
    )
}

/// `RegDeleteTreeW` walks the subtree through internal entry points and deletes it with
/// `RegDeleteKeyExInternalW`, so leaving it unhooked let a virtualized application erase whole
/// host registry subtrees.
unsafe extern "system" fn hook_reg_delete_tree_w(hkey: HKEY, lp_sub_key: *const u16) -> i32 {
    let real_fn: FnRegDeleteTreeW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_TREE_W)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey, lp_sub_key) }, {
        let Target::Resolved { path, .. } = resolve_target(hkey, lp_sub_key) else {
            return refuse_untracked_mutation("RegDeleteTreeW");
        };

        if get_registry_store().resolve_key(&path) == KeyResolution::Masked {
            return ERROR_FILE_NOT_FOUND as i32;
        }

        get_registry_store().delete_tree(&path);
        tracing::info!("RegDeleteTreeW [CoW Subtree Mask]: {path}");
        ERROR_SUCCESS as i32
    })
}

unsafe extern "system" fn hook_reg_close_key(hkey: HKEY) -> i32 {
    let real_fn: FnRegCloseKey = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_CLOSE_KEY)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey) }, {
        // The cached listing is keyed by handle value, and handle values are reused: a stale
        // entry would answer the next key opened at this address.
        crate::registry::enumeration::forget(hkey as usize);

        if let Some(entry) = get_handle_table().close_handle(hkey.cast())
            && entry.is_synthetic
        {
            return ERROR_SUCCESS as i32;
        }
        unsafe { real_fn(hkey) }
    })
}

/// Tracks the handle `RegOpenCurrentUser` returns as the `HKCU` hive.
///
/// # Why
/// Frameworks that reach HKCU through this API used to hand the engine an unknown handle, and
/// an unknown handle now refuses mutations. Registering it keeps those writes virtualized
/// instead of turning a silent misfiling into a visible failure.
unsafe extern "system" fn hook_reg_open_current_user(sam_desired: u32, phk_result: *mut HKEY) -> i32 {
    let real_fn: FnRegOpenCurrentUser =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_OPEN_CURRENT_USER)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(sam_desired, phk_result) }, {
        let status = unsafe { real_fn(sam_desired, phk_result) };
        if status == ERROR_SUCCESS as i32 && !phk_result.is_null() {
            // SAFETY: `phk_result` is non-null (checked) and `real_fn` wrote a valid key
            // handle into it on success.
            unsafe {
                get_handle_table().register_host_handle((*phk_result).cast(), "HKCU".to_string());
            }
        }
        status
    })
}

// ---------------------- ENUMERATION ----------------------

/// Copies `name` into a caller name buffer that counts characters.
///
/// # Why this is not `serve_value`
/// The value-data parameters count *bytes* and the caller's cell carries the buffer size on
/// input; the name parameters of `RegEnumKeyExW` and `RegEnumValueW` count *characters*, with
/// the input size including the terminator and the output size excluding it. Two conventions,
/// two helpers - sharing one would have to branch on which meaning the cell currently holds.
///
/// # Safety
/// `buffer` and `size` must be the caller-owned name out-parameters of the intercepted API.
unsafe fn serve_name<C: NameUnit>(name: &str, buffer: *mut C, size: *mut u32) -> i32 {
    if size.is_null() {
        // The size cell is mandatory: without it the name buffer has no bound.
        return ERROR_INVALID_PARAMETER as i32;
    }

    let encoded = C::encode(name);
    let required = encoded.len() as u32;

    unsafe {
        let capacity = *size;
        if buffer.is_null() {
            *size = required;
            return ERROR_SUCCESS as i32;
        }
        // The caller's capacity includes room for the terminator; the reported length does not.
        if capacity <= required {
            *size = required;
            return ERROR_MORE_DATA as i32;
        }

        std::ptr::copy_nonoverlapping(encoded.as_ptr(), buffer, encoded.len());
        *buffer.add(encoded.len()) = C::NUL;
        *size = required;
    }
    ERROR_SUCCESS as i32
}

/// Walks an index-based Win32 name enumerator until it stops yielding entries.
///
/// Stopping at the first non-success is correct for this use: the enumerator reports
/// `ERROR_NO_MORE_ITEMS` when the key is exhausted, and any other failure means the host has no
/// further entries this engine can offer.
///
/// # Safety
/// `step` must invoke a live registry enumerator with the index, name buffer and size cell it
/// is given, and must not retain them.
unsafe fn collect_host_names(mut step: impl FnMut(u32, *mut u16, *mut u32) -> i32) -> Vec<String> {
    // A registry key name is bounded at 255 characters and a value name at 16383 (winreg.h), so
    // one buffer at the larger bound serves both walks without a resize loop.
    const MAX_REGISTRY_NAME_CHARS: usize = 16_384;

    let mut names = Vec::new();
    let mut buffer = vec![0u16; MAX_REGISTRY_NAME_CHARS];

    for index in 0.. {
        // The APIs overwrite the size cell, so the capacity is republished every iteration.
        let mut size = MAX_REGISTRY_NAME_CHARS as u32;
        if step(index, buffer.as_mut_ptr(), &mut size) != ERROR_SUCCESS as i32 {
            break;
        }
        names.push(String::from_utf16_lossy(&buffer[..size as usize]));
    }

    names
}

/// Collects what the host registry itself lists under `hkey`.
///
/// Returns an empty listing for a synthetic key, which has no host counterpart to enumerate.
///
/// # Safety
/// `hkey` must be a live host key handle, or the caller must pass `synthetic` for a handle this
/// engine fabricated.
unsafe fn host_listing(hkey: HKEY, synthetic: bool) -> HostListing {
    if synthetic {
        return HostListing::default();
    }

    // A trampoline this hook does not own may never have been published: the export could be
    // absent on every module, in which case its slot stays null for the life of the process.
    // Waiting for it - which is what `load_trampoline` does - would hang the application inside
    // a registry call. The host's contribution to that axis is dropped instead, loudly: the
    // overlay's own entries still enumerate correctly, and the omission reaches the log rather
    // than silently changing what an application sees.
    let enum_key: Option<FnRegEnumKeyExW> = try_load_trampoline(&REAL_REG_ENUM_KEY_EX_W)
        .map(|trampoline| unsafe { std::mem::transmute(trampoline) });
    let enum_value: Option<FnRegEnumValueW> = try_load_trampoline(&REAL_REG_ENUM_VALUE_W)
        .map(|trampoline| unsafe { std::mem::transmute(trampoline) });
    if enum_key.is_none() || enum_value.is_none() {
        tracing::error!(
            "Registry enumeration: a host enumerator is not hooked (RegEnumKeyExW: {}, RegEnumValueW: {}); host entries are omitted from the merged listing",
            enum_key.is_some(),
            enum_value.is_some()
        );
    }

    let mut listing = HostListing::default();

    // SAFETY: `hkey` is the caller's live host handle, and each closure forwards the buffer and
    // size cell `collect_host_names` owns for the duration of the call.
    unsafe {
        if let Some(enum_key) = enum_key {
            listing.subkeys = collect_host_names(|index, buffer, size| {
                enum_key(
                    hkey,
                    index,
                    buffer,
                    size,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            });
        }
        if let Some(enum_value) = enum_value {
            listing.values = collect_host_names(|index, buffer, size| {
                enum_value(
                    hkey,
                    index,
                    buffer,
                    size,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            });
        }
    }

    listing
}

/// The key an enumeration addresses, together with its merged listing.
struct Listing {
    path: String,
    view: Arc<KeyView>,
}

/// The merged listing for an intercepted enumeration call, or the status to return instead.
///
/// # Safety
/// `hkey` must be the handle the intercepted call was made on.
unsafe fn listing_for(hkey: HKEY) -> Result<Listing, i32> {
    let Target::Resolved { path, synthetic } = resolve_target(hkey, std::ptr::null()) else {
        return Err(UNTRACKED_FORWARD);
    };

    let store = get_registry_store();
    let Some(overlay) = store.overlay_key_view(&path) else {
        // The key was deleted through the boundary while this handle was open.
        return Err(ERROR_KEY_DELETED as i32);
    };

    let generation = store.generation();
    let view = cached_view(hkey as usize, generation, || {
        // SAFETY: `hkey` is the caller's live handle; `synthetic` tells the collector there is
        // no host key behind it.
        let host = unsafe { host_listing(hkey, synthetic) };
        merge(&overlay, &host)
    });

    Ok(Listing { path, view })
}

/// Sentinel telling an enumeration hook to forward to the trampoline: the handle is unknown to
/// the engine, so - as with every other read - the host answer stands.
const UNTRACKED_FORWARD: i32 = -1;

unsafe extern "system" fn hook_reg_enum_key_ex_w(
    hkey: HKEY,
    dw_index: u32,
    lp_name: *mut u16,
    lpcch_name: *mut u32,
    lp_reserved: *const u32,
    lp_class: *mut u16,
    lpcch_class: *mut u32,
    lpft_last_write_time: *mut FILETIME,
) -> i32 {
    let real_fn: FnRegEnumKeyExW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_ENUM_KEY_EX_W)) };
    let host_enum = || unsafe {
        real_fn(
            hkey,
            dw_index,
            lp_name,
            lpcch_name,
            lp_reserved,
            lp_class,
            lpcch_class,
            lpft_last_write_time,
        )
    };
    guard_detour!(&IN_REG_HOOK, host_enum(), {
        let out = SubkeyOut {
            name: lp_name,
            name_len: lpcch_name,
            class: lp_class,
            class_len: lpcch_class,
            last_write: lpft_last_write_time,
        };
        // SAFETY: `out` holds the caller-owned out-parameters of this RegEnumKeyExW call.
        unsafe { enum_key_virtually(hkey, dw_index, out, host_enum) }
    })
}

/// The caller-owned out-parameters of a `RegEnumKeyEx*` call, in the caller's name spelling.
struct SubkeyOut<C> {
    name: *mut C,
    name_len: *mut u32,
    class: *mut C,
    class_len: *mut u32,
    last_write: *mut FILETIME,
}

/// Serves one index of a subkey enumeration from the merged listing. `host_enum` is the caller's
/// own call, used for a handle the engine does not track.
///
/// # Safety
/// Every pointer in `out` must be a caller-owned out-parameter of the intercepted enumerator.
unsafe fn enum_key_virtually<C: NameUnit>(
    hkey: HKEY,
    dw_index: u32,
    out: SubkeyOut<C>,
    host_enum: impl Fn() -> i32,
) -> i32 {
    let listing = match unsafe { listing_for(hkey) } {
        Ok(listing) => listing,
        Err(UNTRACKED_FORWARD) => return host_enum(),
        Err(status) => return status,
    };

    let Some(name) = listing.view.subkeys.get(dw_index as usize) else {
        return ERROR_NO_MORE_ITEMS as i32;
    };

    // SAFETY: the class and timestamp cells are caller-owned out-parameters, each null-checked
    // before use.
    unsafe {
        // The overlay records no class for a key, and the merged index does not map to a host
        // index, so neither the class nor the last-write time can be answered truthfully. They
        // are reported empty and zeroed - the documented "unknown" - rather than filled with a
        // plausible-looking value.
        if !out.class_len.is_null() {
            *out.class_len = 0;
        }
        if !out.class.is_null() {
            *out.class = C::NUL;
        }
        if !out.last_write.is_null() {
            *out.last_write = std::mem::zeroed::<FILETIME>();
        }

        serve_name(name, out.name, out.name_len)
    }
}

unsafe extern "system" fn hook_reg_enum_value_w(
    hkey: HKEY,
    dw_index: u32,
    lp_value_name: *mut u16,
    lpcch_value_name: *mut u32,
    lp_reserved: *const u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    let real_fn: FnRegEnumValueW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_ENUM_VALUE_W)) };
    let host_enum = || unsafe {
        real_fn(
            hkey,
            dw_index,
            lp_value_name,
            lpcch_value_name,
            lp_reserved,
            lp_type,
            lp_data,
            lpcb_data,
        )
    };
    let host_read = |name: &str| {
        let Some(trampoline) = try_load_trampoline(&REAL_REG_QUERY_VALUE_EX_W) else {
            tracing::error!(
                "RegEnumValueW: RegQueryValueExW is not hooked, so the host value '{name}' cannot be read"
            );
            return ERROR_FILE_NOT_FOUND as i32;
        };
        let query: FnRegQueryValueExW = unsafe { std::mem::transmute(trampoline) };
        let name_wide = to_wide(name);
        // SAFETY: `hkey` is the caller's live host handle and `name_wide` is a NUL-terminated
        // name; the remaining pointers are the caller's own.
        unsafe {
            query(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null_mut(),
                lp_type,
                lp_data,
                lpcb_data,
            )
        }
    };
    guard_detour!(&IN_REG_HOOK, host_enum(), {
        let out = EnumValueOut {
            name: lp_value_name,
            name_len: lpcch_value_name,
            value: ValueOut {
                lp_type,
                lp_data,
                lpcb_data,
            },
        };
        // SAFETY: `out` holds the caller-owned out-parameters of this RegEnumValueW call.
        unsafe { enum_value_virtually(hkey, dw_index, out, stored_payload, host_enum, host_read) }
    })
}

/// The caller-owned out-parameters of a `RegEnumValue*` call, in the caller's name spelling.
struct EnumValueOut<C> {
    name: *mut C,
    name_len: *mut u32,
    value: ValueOut,
}

/// Serves one index of a value enumeration from the merged listing: the name in the caller's
/// spelling, the data from whichever side of the boundary holds it. `host_enum` is the caller's
/// own call for an untracked handle; `host_read` reads a host-held value by name into the
/// caller's data cells.
///
/// # Safety
/// Every pointer in `out` must be a caller-owned out-parameter of the intercepted enumerator.
unsafe fn enum_value_virtually<C: NameUnit>(
    hkey: HKEY,
    dw_index: u32,
    out: EnumValueOut<C>,
    payload: PayloadEncoding,
    host_enum: impl Fn() -> i32,
    host_read: impl Fn(&str) -> i32,
) -> i32 {
    let listing = match unsafe { listing_for(hkey) } {
        Ok(listing) => listing,
        Err(UNTRACKED_FORWARD) => return host_enum(),
        Err(status) => return status,
    };

    let Some(entry) = listing.view.values.get(dw_index as usize) else {
        return ERROR_NO_MORE_ITEMS as i32;
    };

    let name_status = unsafe { serve_name(&entry.name, out.name, out.name_len) };
    if name_status != ERROR_SUCCESS as i32 {
        return name_status;
    }

    // The name is the caller's index into the listing; the data comes from whichever side of the
    // boundary actually holds it.
    match entry.origin {
        ValueOrigin::Host => host_read(&entry.name),
        ValueOrigin::Overlay => match get_registry_store().resolve_value(&listing.path, &entry.name) {
            ValueResolution::Virtual { val_type, data } => {
                let ValueOut {
                    lp_type,
                    lp_data,
                    lpcb_data,
                } = out.value;
                // SAFETY: caller-owned out-parameters, bounded inside `serve_value`.
                unsafe { serve_value(val_type, &payload(val_type, &data), lp_type, lp_data, lpcb_data) }
            }
            // The listing named this value a moment ago, so its disappearance means the overlay
            // changed underneath; report it the way a deleted value reads.
            _ => ERROR_FILE_NOT_FOUND as i32,
        },
    }
}

/// Reports the key's shape from the same merged listing the enumerators walk.
///
/// # Why the counts must come from that listing
/// Applications call this to size the buffers and bound the loop they then enumerate with. A
/// count larger than the listing makes a caller stop early on `ERROR_NO_MORE_ITEMS`; a count
/// smaller makes it miss entries entirely. The maximum lengths may only ever over-estimate.
unsafe extern "system" fn hook_reg_query_info_key_w(
    hkey: HKEY,
    lp_class: *mut u16,
    lpcch_class: *mut u32,
    lp_reserved: *const u32,
    lpc_sub_keys: *mut u32,
    lpcb_max_sub_key_len: *mut u32,
    lpcb_max_class_len: *mut u32,
    lpc_values: *mut u32,
    lpcb_max_value_name_len: *mut u32,
    lpcb_max_value_len: *mut u32,
    lpcb_security_descriptor: *mut u32,
    lpft_last_write_time: *mut FILETIME,
) -> i32 {
    let real_fn: FnRegQueryInfoKeyW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_QUERY_INFO_KEY_W)) };
    guard_detour!(
        &IN_REG_HOOK,
        unsafe {
            real_fn(
                hkey,
                lp_class,
                lpcch_class,
                lp_reserved,
                lpc_sub_keys,
                lpcb_max_sub_key_len,
                lpcb_max_class_len,
                lpc_values,
                lpcb_max_value_name_len,
                lpcb_max_value_len,
                lpcb_security_descriptor,
                lpft_last_write_time,
            )
        },
        {
            let listing = match unsafe { listing_for(hkey) } {
                Ok(listing) => listing,
                Err(UNTRACKED_FORWARD) => {
                    return unsafe {
                        real_fn(
                            hkey,
                            lp_class,
                            lpcch_class,
                            lp_reserved,
                            lpc_sub_keys,
                            lpcb_max_sub_key_len,
                            lpcb_max_class_len,
                            lpc_values,
                            lpcb_max_value_name_len,
                            lpcb_max_value_len,
                            lpcb_security_descriptor,
                            lpft_last_write_time,
                        )
                    };
                }
                Err(status) => return status,
            };

            // Let the host fill everything this engine does not model - class, security
            // descriptor, timestamp - and report its own longest value. A synthetic key has no
            // host counterpart, so those cells stay as the caller left them.
            let mut host_max_value_len = 0u32;
            let host_answered = unsafe {
                real_fn(
                    hkey,
                    lp_class,
                    lpcch_class,
                    lp_reserved,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    lpcb_max_class_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut host_max_value_len,
                    lpcb_security_descriptor,
                    lpft_last_write_time,
                )
            } == ERROR_SUCCESS as i32;
            if !host_answered {
                host_max_value_len = 0;
            }

            let overlay_max_value_len = listing
                .view
                .values
                .iter()
                .filter_map(|entry| get_registry_store().overlay_value_len(&listing.path, &entry.name))
                .max()
                .unwrap_or(0) as u32;

            // SAFETY: every cell below is a caller-owned out-parameter, null-checked first.
            unsafe {
                if !lpc_sub_keys.is_null() {
                    *lpc_sub_keys = listing.view.subkeys.len() as u32;
                }
                if !lpcb_max_sub_key_len.is_null() {
                    *lpcb_max_sub_key_len = listing.view.max_subkey_chars();
                }
                if !lpc_values.is_null() {
                    *lpc_values = listing.view.values.len() as u32;
                }
                if !lpcb_max_value_name_len.is_null() {
                    *lpcb_max_value_name_len = listing.view.max_value_name_chars();
                }
                if !lpcb_max_value_len.is_null() {
                    // Over-estimating is safe - the caller allocates more than it needs - while
                    // under-estimating truncates a value it is about to read.
                    *lpcb_max_value_len = host_max_value_len.max(overlay_max_value_len);
                }
            }

            ERROR_SUCCESS as i32
        }
    )
}

/// Hooks `api` on the first module of `modules` that exports it.
///
/// # Why per-export resolution
/// kernelbase and advapi32 export overlapping but incomplete registry API sets - this
/// build of kernelbase, for example, does not export RegDeleteKeyW at all. Choosing one
/// module up front left that API unhooked, so a virtualized app's RegDeleteKeyW deleted
/// keys in the real host registry: a Copy-on-Write boundary hole that surfaced only as
/// a per-attach warning. Resolving each export independently keeps every API hooked on
/// whichever module actually carries it.
///
/// # SAFETY
/// Module handles stay valid for the process lifetime, and each hook function matches
/// the ABI of the export it detours.
unsafe fn hook_on_first_export(
    modules: [HMODULE; 2],
    api: &str,
    slot: &AtomicPtr<c_void>,
    hook: *mut c_void,
) {
    for module in modules {
        if !module.is_null() && hook_export(module, api, slot, hook) {
            return;
        }
    }
    tracing::warn!("Hook {api}: not attached on any module; CoW inactive for this API");
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    unsafe {
        let kernelbase = GetModuleHandleW(windows_sys::core::w!("kernelbase.dll"));
        let advapi32 = crate::host_modules::loaded(windows_sys::core::w!("advapi32.dll"));
        let modules = [kernelbase, advapi32];

        // Intention: One table entry per intercepted registry API.
        // Why: The hook set is the boundary's surface area. A table makes an omission visible
        //      as a missing row instead of hiding it among a dozen near-identical call blocks -
        //      which is how RegDeleteKeyExW and RegDeleteTreeW stayed unhooked while their
        //      sibling RegDeleteKeyW was fixed.
        let hooks: [(&str, &AtomicPtr<c_void>, *mut c_void); 29] = [
            (
                "RegOpenKeyExW",
                &REAL_REG_OPEN_KEY_EX_W,
                hook_reg_open_key_ex_w as *mut c_void,
            ),
            (
                "RegCreateKeyExW",
                &REAL_REG_CREATE_KEY_EX_W,
                hook_reg_create_key_ex_w as *mut c_void,
            ),
            (
                "RegQueryValueExW",
                &REAL_REG_QUERY_VALUE_EX_W,
                hook_reg_query_value_ex_w as *mut c_void,
            ),
            (
                "RegGetValueW",
                &REAL_REG_GET_VALUE_W,
                hook_reg_get_value_w as *mut c_void,
            ),
            (
                "RegSetValueExW",
                &REAL_REG_SET_VALUE_EX_W,
                hook_reg_set_value_ex_w as *mut c_void,
            ),
            (
                "RegDeleteValueW",
                &REAL_REG_DELETE_VALUE_W,
                hook_reg_delete_value_w as *mut c_void,
            ),
            (
                "RegDeleteKeyW",
                &REAL_REG_DELETE_KEY_W,
                hook_reg_delete_key_w as *mut c_void,
            ),
            (
                "RegDeleteKeyExW",
                &REAL_REG_DELETE_KEY_EX_W,
                hook_reg_delete_key_ex_w as *mut c_void,
            ),
            (
                "RegDeleteTreeW",
                &REAL_REG_DELETE_TREE_W,
                hook_reg_delete_tree_w as *mut c_void,
            ),
            (
                "RegEnumKeyExW",
                &REAL_REG_ENUM_KEY_EX_W,
                hook_reg_enum_key_ex_w as *mut c_void,
            ),
            (
                "RegEnumValueW",
                &REAL_REG_ENUM_VALUE_W,
                hook_reg_enum_value_w as *mut c_void,
            ),
            (
                "RegQueryInfoKeyW",
                &REAL_REG_QUERY_INFO_KEY_W,
                hook_reg_query_info_key_w as *mut c_void,
            ),
            (
                "RegCloseKey",
                &REAL_REG_CLOSE_KEY,
                hook_reg_close_key as *mut c_void,
            ),
            (
                "RegOpenCurrentUser",
                &REAL_REG_OPEN_CURRENT_USER,
                hook_reg_open_current_user as *mut c_void,
            ),
            (
                "RegOpenKeyExA",
                &REAL_REG_OPEN_KEY_EX_A,
                hook_reg_open_key_ex_a as *mut c_void,
            ),
            (
                "RegCreateKeyExA",
                &REAL_REG_CREATE_KEY_EX_A,
                hook_reg_create_key_ex_a as *mut c_void,
            ),
            (
                "RegSetValueExA",
                &REAL_REG_SET_VALUE_EX_A,
                hook_reg_set_value_ex_a as *mut c_void,
            ),
            (
                "RegSetKeyValueW",
                &REAL_REG_SET_KEY_VALUE_W,
                hook_reg_set_key_value_w as *mut c_void,
            ),
            (
                "RegSetKeyValueA",
                &REAL_REG_SET_KEY_VALUE_A,
                hook_reg_set_key_value_a as *mut c_void,
            ),
            (
                "RegSetValueW",
                &REAL_REG_SET_VALUE_W,
                hook_reg_set_value_w as *mut c_void,
            ),
            (
                "RegSetValueA",
                &REAL_REG_SET_VALUE_A,
                hook_reg_set_value_a as *mut c_void,
            ),
            (
                "RegDeleteValueA",
                &REAL_REG_DELETE_VALUE_A,
                hook_reg_delete_value_a as *mut c_void,
            ),
            (
                "RegDeleteKeyValueW",
                &REAL_REG_DELETE_KEY_VALUE_W,
                hook_reg_delete_key_value_w as *mut c_void,
            ),
            (
                "RegDeleteKeyValueA",
                &REAL_REG_DELETE_KEY_VALUE_A,
                hook_reg_delete_key_value_a as *mut c_void,
            ),
            (
                "RegQueryValueExA",
                &REAL_REG_QUERY_VALUE_EX_A,
                hook_reg_query_value_ex_a as *mut c_void,
            ),
            (
                "RegGetValueA",
                &REAL_REG_GET_VALUE_A,
                hook_reg_get_value_a as *mut c_void,
            ),
            (
                "RegEnumKeyExA",
                &REAL_REG_ENUM_KEY_EX_A,
                hook_reg_enum_key_ex_a as *mut c_void,
            ),
            (
                "RegEnumValueA",
                &REAL_REG_ENUM_VALUE_A,
                hook_reg_enum_value_a as *mut c_void,
            ),
            (
                "RegQueryInfoKeyA",
                &REAL_REG_QUERY_INFO_KEY_A,
                hook_reg_query_info_key_a as *mut c_void,
            ),
        ];

        for (api, slot, hook) in hooks {
            hook_on_first_export(modules, api, slot, hook);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_key_composition_tolerates_the_separator_spellings_callers_pass() {
        assert_eq!(resolve_full_key("HKCU", "Software\\App"), "HKCU\\Software\\App");
        assert_eq!(resolve_full_key("HKCU", "\\Software"), "HKCU\\Software");
        assert_eq!(resolve_full_key("HKCU", ""), "HKCU");
        assert_eq!(resolve_full_key("", "Software"), "Software");
    }

    #[test]
    fn an_admitted_type_passes_the_rrf_filter_and_a_rejected_one_reports_it() {
        use windows_sys::Win32::Foundation::ERROR_UNSUPPORTED_TYPE;
        use windows_sys::Win32::System::Registry::{RRF_RT_REG_DWORD, RRF_RT_REG_SZ};

        let (val_type, data) = apply_get_value_contract(REG_SZ, vec![b'a', 0, 0, 0], RRF_RT_REG_SZ)
            .expect("REG_SZ must satisfy an RRF_RT_REG_SZ request");
        assert_eq!(val_type, REG_SZ);
        assert_eq!(data, vec![b'a', 0, 0, 0]);

        assert_eq!(
            apply_get_value_contract(REG_SZ, vec![0, 0], RRF_RT_REG_DWORD),
            Err(ERROR_UNSUPPORTED_TYPE as i32)
        );
    }

    #[test]
    fn an_empty_rrf_mask_places_no_type_restriction() {
        let (val_type, _) = apply_get_value_contract(REG_MULTI_SZ, vec![0, 0], 0)
            .expect("no RRF_RT_* bit means the caller accepts the stored type");
        assert_eq!(val_type, REG_MULTI_SZ);
    }

    #[test]
    fn string_results_gain_the_terminator_reg_get_value_guarantees() {
        // "ab" with no trailing NUL: RegGetValueW must still hand back a terminated string.
        let (_, data) = apply_get_value_contract(REG_SZ, vec![b'a', 0, b'b', 0], RRF_RT_ANY)
            .expect("REG_SZ is admitted by RRF_RT_ANY");
        assert_eq!(data, vec![b'a', 0, b'b', 0, 0, 0]);

        // An already-terminated payload is handed back untouched.
        let (_, terminated) = apply_get_value_contract(REG_SZ, vec![b'a', 0, 0, 0], RRF_RT_ANY)
            .expect("REG_SZ is admitted by RRF_RT_ANY");
        assert_eq!(terminated, vec![b'a', 0, 0, 0]);
    }

    #[test]
    fn binary_results_are_never_padded_with_a_terminator() {
        use windows_sys::Win32::System::Registry::REG_BINARY;

        let (_, data) = apply_get_value_contract(REG_BINARY, vec![1, 2, 3], RRF_RT_ANY)
            .expect("REG_BINARY is admitted by RRF_RT_ANY");
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[test]
    fn noexpand_keeps_an_expandable_payload_verbatim_and_typed_as_stored() {
        let stored = wide_to_payload(&[b'%' as u16, b'X' as u16, b'%' as u16, 0]);

        let (val_type, data) =
            apply_get_value_contract(REG_EXPAND_SZ, stored.clone(), RRF_RT_ANY | RRF_NOEXPAND)
                .expect("REG_EXPAND_SZ is admitted by RRF_RT_ANY");

        assert_eq!(val_type, REG_EXPAND_SZ);
        assert_eq!(data, stored);
    }

    #[test]
    fn odd_length_string_payloads_are_not_decoded_as_wide_characters() {
        assert!(payload_to_wide(&[1, 2, 3]).is_none());
        assert_eq!(payload_to_wide(&[b'a', 0]), Some(vec![b'a' as u16]));
    }
}
