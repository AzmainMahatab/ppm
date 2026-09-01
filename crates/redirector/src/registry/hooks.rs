use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::registry::handle_table::{KeyScope, get_handle_table};
use crate::registry::store::{KeyResolution, ValueResolution, get_registry_store};
use crate::winstr::wide_to_string;
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, ERROR_SUCCESS,
    HMODULE,
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
    match get_handle_table().resolve(hkey.cast()) {
        KeyScope::Tracked { path, synthetic } => Target::Resolved {
            path: resolve_full_key(&path, &wide_to_string(subkey)),
            synthetic,
        },
        KeyScope::Untracked => Target::Untracked,
    }
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
type FnRegSetValueExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32, *const u8, u32) -> i32;
type FnRegDeleteValueW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegDeleteKeyW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegDeleteKeyExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32) -> i32;
type FnRegDeleteTreeW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(HKEY) -> i32;
type FnRegOpenCurrentUser = unsafe extern "system" fn(u32, *mut HKEY) -> i32;

static REAL_REG_OPEN_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_CREATE_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_QUERY_VALUE_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_GET_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_VALUE_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_KEY_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_TREE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
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
        {
            let Target::Resolved { path, synthetic } = resolve_target(hkey, lp_sub_key) else {
                // An unnameable base key cannot be virtualized; a read-side open falls
                // through to the host, which is the documented copy-on-write behavior for
                // anything the overlay does not shadow.
                return unsafe { real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result) };
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

            let status = unsafe { real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result) };
            if status == ERROR_SUCCESS as i32 && !phk_result.is_null() {
                // SAFETY: `phk_result` is non-null (checked above) and `real_fn` wrote a valid
                // key handle into it on success.
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
    )
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
        {
            let Target::Resolved { path, synthetic } = resolve_target(hkey, lp_sub_key) else {
                return refuse_untracked_mutation("RegCreateKeyExW");
            };

            get_registry_store().create_key(&path);
            tracing::info!("RegCreateKeyExW: Virtual key created -> {path}");

            if synthetic && !phk_result.is_null() {
                // SAFETY: `phk_result` is non-null (checked above) and is the caller-owned
                // out-parameter for the created key; `lpdw_disposition` likewise for the
                // disposition value.
                unsafe {
                    *phk_result = get_handle_table().register_virtual_handle(path).cast();
                    if !lpdw_disposition.is_null() {
                        *lpdw_disposition = 1;
                    }
                }
                return ERROR_SUCCESS as i32;
            }

            // Why the real create still runs for a host-backed parent: the overlay shadows
            // values and deletions, but subkey *existence* still falls through to the host so
            // an app can open the keys its installer left behind. The host key this creates is
            // empty - every value written into it is virtualized - and the probe's disposition
            // assertion depends on it. Narrowing this to a pure overlay create is a separate
            // decision, not an oversight.
            let status = unsafe {
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
            };

            if status == ERROR_SUCCESS as i32 && !phk_result.is_null() {
                // SAFETY: `phk_result` is non-null (checked above) and `real_fn` wrote a valid
                // key handle into it on success.
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
    )
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
        {
            let Target::Resolved { path, synthetic } = resolve_target(hkey, std::ptr::null()) else {
                return unsafe { real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data) };
            };
            let val_name = wide_to_string(lp_value_name);

            match get_registry_store().resolve_value(&path, &val_name) {
                ValueResolution::Virtual { val_type, data } => {
                    tracing::debug!("RegQueryValueExW [Virtual Hit]: {path} / {val_name}");
                    // SAFETY: every pointer below is a caller-owned RegQueryValueExW
                    // out-parameter, null-checked inside `serve_value` and bounded by the
                    // caller's own size cell.
                    unsafe { serve_value(val_type, &data, lp_type, lp_data, lpcb_data) }
                }
                ValueResolution::Masked => {
                    tracing::debug!("RegQueryValueExW [Tombstoned Value]: {path} / {val_name}");
                    ERROR_FILE_NOT_FOUND as i32
                }
                ValueResolution::Corrupt => {
                    // The store already logged the corruption. Reading as absent keeps the
                    // boundary: falling through would answer with the real user's data.
                    ERROR_FILE_NOT_FOUND as i32
                }
                ValueResolution::PassThrough if synthetic => ERROR_FILE_NOT_FOUND as i32,
                ValueResolution::PassThrough => unsafe {
                    real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data)
                },
            }
        }
    )
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
        unsafe { real_fn(hkey, lp_sub_key, lp_value, dw_flags, pdw_type, pv_data, pcb_data,) },
        {
            let forward =
                || unsafe { real_fn(hkey, lp_sub_key, lp_value, dw_flags, pdw_type, pv_data, pcb_data) };

            // Why the subkey-less form is resolved here too, rather than forwarded: the
            // re-entrancy guard is one flag for the whole registry module, so a forwarded
            // call would re-enter `hook_reg_query_value_ex_w` with the guard already held and
            // take its unvirtualized fallback. Forwarding would therefore *break* the form
            // that works today. Resolving both forms here keeps one path and no nesting.
            let Target::Resolved { path, synthetic } = resolve_target(hkey, lp_sub_key) else {
                return forward();
            };
            let val_name = wide_to_string(lp_value);

            let zero_on_failure = dw_flags & RRF_ZEROONFAILURE != 0;
            let fail = |status: i32| -> i32 {
                if zero_on_failure && !pv_data.is_null() && !pcb_data.is_null() {
                    // SAFETY: both pointers are non-null (checked) caller-owned
                    // out-parameters; the fill is bounded by the caller's own size cell.
                    unsafe {
                        std::ptr::write_bytes(pv_data.cast::<u8>(), 0, *pcb_data as usize);
                    }
                }
                status
            };

            match get_registry_store().resolve_value(&path, &val_name) {
                ValueResolution::Virtual { val_type, data } => {
                    match apply_get_value_contract(val_type, data, dw_flags) {
                        Ok((served_type, served_data)) => {
                            tracing::debug!("RegGetValueW [Virtual Hit]: {path} / {val_name}");
                            // SAFETY: caller-owned out-parameters, null-checked and bounded
                            // inside `serve_value`.
                            unsafe {
                                serve_value(
                                    served_type,
                                    &served_data,
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
                    tracing::debug!("RegGetValueW [Masked]: {path} / {val_name}");
                    fail(ERROR_FILE_NOT_FOUND as i32)
                }
                ValueResolution::PassThrough if synthetic => fail(ERROR_FILE_NOT_FOUND as i32),
                ValueResolution::PassThrough => forward(),
            }
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
            let Target::Resolved { path, .. } = resolve_target(hkey, std::ptr::null()) else {
                return refuse_untracked_mutation("RegSetValueExW");
            };
            let val_name = wide_to_string(lp_value_name);

            let data_slice = if !lp_data.is_null() && cb_data > 0 {
                // SAFETY: `lp_data` points to `cb_data` bytes supplied by the caller.
                unsafe { std::slice::from_raw_parts(lp_data, cb_data as usize) }
            } else {
                &[]
            };

            tracing::debug!(
                "RegSetValueExW [CoW Virtual Store]: {path} / {val_name} (type: {dw_type}, bytes: {cb_data})"
            );
            get_registry_store().set_value(&path, &val_name, dw_type, data_slice);
            ERROR_SUCCESS as i32
        }
    )
}

unsafe extern "system" fn hook_reg_delete_value_w(hkey: HKEY, lp_value_name: *const u16) -> i32 {
    let real_fn: FnRegDeleteValueW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_VALUE_W)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey, lp_value_name) }, {
        let Target::Resolved { path, .. } = resolve_target(hkey, std::ptr::null()) else {
            return refuse_untracked_mutation("RegDeleteValueW");
        };
        let val_name = wide_to_string(lp_value_name);

        if get_registry_store().resolve_value(&path, &val_name) == ValueResolution::Masked {
            // Already masked: Win32 reports a second delete of the same value as absent.
            return ERROR_FILE_NOT_FOUND as i32;
        }

        get_registry_store().delete_value(&path, &val_name);
        tracing::info!("RegDeleteValueW [CoW Mask]: {path} / {val_name}");
        ERROR_SUCCESS as i32
    })
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
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};

    unsafe {
        let kernelbase = GetModuleHandleW(windows_sys::core::w!("kernelbase.dll"));
        let advapi32 = LoadLibraryW(windows_sys::core::w!("advapi32.dll"));
        let modules = [kernelbase, advapi32];

        // Intention: One table entry per intercepted registry API.
        // Why: The hook set is the boundary's surface area. A table makes an omission visible
        //      as a missing row instead of hiding it among a dozen near-identical call blocks -
        //      which is how RegDeleteKeyExW and RegDeleteTreeW stayed unhooked while their
        //      sibling RegDeleteKeyW was fixed.
        let hooks: [(&str, &AtomicPtr<c_void>, *mut c_void); 11] = [
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
                "RegCloseKey",
                &REAL_REG_CLOSE_KEY,
                hook_reg_close_key as *mut c_void,
            ),
            (
                "RegOpenCurrentUser",
                &REAL_REG_OPEN_CURRENT_USER,
                hook_reg_open_current_user as *mut c_void,
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
