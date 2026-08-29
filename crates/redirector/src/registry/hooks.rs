use crate::detour::{guard_detour, install_detour, load_trampoline};
use crate::registry::handle_table::get_handle_table;
use crate::registry::store::get_registry_store;
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::HKEY;

const ERROR_FILE_NOT_FOUND: u32 = 2;

thread_local! {
    static IN_REG_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Decodes a NUL-terminated UTF-16 string from a raw Win32 pointer.
///
/// # Safety
/// `ptr` must point to a valid NUL-terminated UTF-16 sequence readable up to the terminator.
fn wide_to_string(ptr: *const u16) -> String {
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
type FnRegSetValueExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32, *const u8, u32) -> i32;
type FnRegDeleteValueW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegDeleteKeyW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(HKEY) -> i32;

static REAL_REG_OPEN_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_CREATE_KEY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_QUERY_VALUE_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_SET_VALUE_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_VALUE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_DELETE_KEY_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_REG_CLOSE_KEY: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

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
            let base_path = get_handle_table().get_path(hkey.cast()).unwrap_or_default();
            let full_path = resolve_full_key(&base_path, &wide_to_string(lp_sub_key));

            if get_registry_store().is_key_tombstoned(&full_path) {
                return ERROR_FILE_NOT_FOUND as i32;
            }

            if get_handle_table().is_synthetic(hkey.cast()) {
                if !phk_result.is_null() && get_registry_store().key_exists(&full_path) {
                    // SAFETY: `phk_result` is non-null (checked above) and is the caller-owned
                    // out-parameter for the opened key.
                    unsafe {
                        *phk_result = get_handle_table().register_virtual_handle(full_path).cast();
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
                    get_handle_table().register_host_handle((*phk_result).cast(), full_path);
                }
                return status;
            }

            if !phk_result.is_null() && get_registry_store().key_exists(&full_path) {
                // SAFETY: `phk_result` is non-null (checked above), caller-owned out-parameter.
                unsafe {
                    *phk_result = get_handle_table().register_virtual_handle(full_path).cast();
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
            let base_path = get_handle_table().get_path(hkey.cast()).unwrap_or_default();
            let full_path = resolve_full_key(&base_path, &wide_to_string(lp_sub_key));

            get_registry_store().create_key(&full_path);
            tracing::info!("RegCreateKeyExW: Virtual key created -> {full_path}");

            if get_handle_table().is_synthetic(hkey.cast()) && !phk_result.is_null() {
                // SAFETY: `phk_result` is non-null (checked above) and is the caller-owned
                // out-parameter for the created key; `lpdw_disposition` likewise for the
                // disposition value.
                unsafe {
                    *phk_result = get_handle_table().register_virtual_handle(full_path).cast();
                    if !lpdw_disposition.is_null() {
                        *lpdw_disposition = 1;
                    }
                }
                return ERROR_SUCCESS as i32;
            }

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
                    get_handle_table().register_host_handle((*phk_result).cast(), full_path);
                }
                return status;
            }

            if !phk_result.is_null() {
                // SAFETY: as above - caller-owned out-parameters, null-checked immediately.
                unsafe {
                    *phk_result = get_handle_table().register_virtual_handle(full_path).cast();
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
            let key_path = get_handle_table().get_path(hkey.cast()).unwrap_or_default();
            let val_name = wide_to_string(lp_value_name);

            if let Some(query_res) = get_registry_store().get_value(&key_path, &val_name) {
                match query_res {
                    Err(()) => {
                        tracing::debug!("RegQueryValueExW [Tombstoned Value]: {key_path}\\{val_name}");
                        return ERROR_FILE_NOT_FOUND as i32;
                    }
                    Ok((val_type, data)) => {
                        // SAFETY: every dereferenced pointer below is a caller-owned
                        // REG_QUERY_VALUE_EXW out-parameter, null-checked immediately before
                        // use, with the buffer bound taken from the caller's own size cell.
                        unsafe {
                            if !lp_type.is_null() {
                                *lp_type = val_type;
                            }

                            let req_size = data.len() as u32;
                            if !lpcb_data.is_null() {
                                let provided_size = *lpcb_data;
                                *lpcb_data = req_size;

                                if lp_data.is_null() {
                                    return ERROR_SUCCESS as i32;
                                }

                                if provided_size < req_size {
                                    return ERROR_MORE_DATA as i32;
                                }

                                std::ptr::copy_nonoverlapping(data.as_ptr(), lp_data, data.len());
                            }

                            tracing::debug!("RegQueryValueExW [Virtual Hit]: {key_path}\\{val_name}");
                            return ERROR_SUCCESS as i32;
                        }
                    }
                }
            }

            if get_handle_table().is_synthetic(hkey.cast()) {
                return ERROR_FILE_NOT_FOUND as i32;
            }

            unsafe { real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data) }
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
            let key_path = get_handle_table().get_path(hkey.cast()).unwrap_or_default();
            let val_name = wide_to_string(lp_value_name);

            let data_slice = if !lp_data.is_null() && cb_data > 0 {
                // SAFETY: `lp_data` points to `cb_data` bytes supplied by the caller.
                unsafe { std::slice::from_raw_parts(lp_data, cb_data as usize) }
            } else {
                &[]
            };

            tracing::debug!(
                "RegSetValueExW [CoW Virtual Store]: {key_path}\\{val_name} (type: {dw_type}, bytes: {cb_data})"
            );
            get_registry_store().set_value(&key_path, &val_name, dw_type, data_slice);
            ERROR_SUCCESS as i32
        }
    )
}

unsafe extern "system" fn hook_reg_delete_value_w(hkey: HKEY, lp_value_name: *const u16) -> i32 {
    let real_fn: FnRegDeleteValueW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_VALUE_W)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey, lp_value_name) }, {
        let key_path = get_handle_table().get_path(hkey.cast()).unwrap_or_default();
        let val_name = wide_to_string(lp_value_name);
        get_registry_store().delete_value(&key_path, &val_name);
        tracing::info!("RegDeleteValueW [CoW Mask]: {key_path}\\{val_name}");
        ERROR_SUCCESS as i32
    })
}

unsafe extern "system" fn hook_reg_delete_key_w(hkey: HKEY, lp_sub_key: *const u16) -> i32 {
    let real_fn: FnRegDeleteKeyW = unsafe { std::mem::transmute(load_trampoline(&REAL_REG_DELETE_KEY_W)) };
    guard_detour!(&IN_REG_HOOK, unsafe { real_fn(hkey, lp_sub_key) }, {
        let base_path = get_handle_table().get_path(hkey.cast()).unwrap_or_default();
        let full_path = resolve_full_key(&base_path, &wide_to_string(lp_sub_key));

        get_registry_store().delete_key(&full_path);
        tracing::info!("RegDeleteKeyW [CoW Tombstone]: {full_path}");
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

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};

    unsafe {
        // Hook Win32 Registry APIs in KernelBase.dll (modern Windows) or advapi32.dll
        let reg_mod = {
            let kb = GetModuleHandleW(windows_sys::core::w!("kernelbase.dll"));
            if !kb.is_null() {
                kb
            } else {
                LoadLibraryW(windows_sys::core::w!("advapi32.dll"))
            }
        };

        if !reg_mod.is_null() {
            if let Some(proc) = GetProcAddress(reg_mod, c"RegOpenKeyExW".as_ptr().cast()) {
                let ok = install_detour(
                    &REAL_REG_OPEN_KEY_EX_W,
                    proc as *mut c_void,
                    hook_reg_open_key_ex_w as *mut c_void,
                );
                tracing::info!("Hook RegOpenKeyExW: {ok}");
            }

            if let Some(proc) = GetProcAddress(reg_mod, c"RegCreateKeyExW".as_ptr().cast()) {
                let ok = install_detour(
                    &REAL_REG_CREATE_KEY_EX_W,
                    proc as *mut c_void,
                    hook_reg_create_key_ex_w as *mut c_void,
                );
                tracing::info!("Hook RegCreateKeyExW: {ok}");
            }

            if let Some(proc) = GetProcAddress(reg_mod, c"RegQueryValueExW".as_ptr().cast()) {
                let ok = install_detour(
                    &REAL_REG_QUERY_VALUE_EX_W,
                    proc as *mut c_void,
                    hook_reg_query_value_ex_w as *mut c_void,
                );
                tracing::info!("Hook RegQueryValueExW: {ok}");
            }

            if let Some(proc) = GetProcAddress(reg_mod, c"RegSetValueExW".as_ptr().cast()) {
                let ok = install_detour(
                    &REAL_REG_SET_VALUE_EX_W,
                    proc as *mut c_void,
                    hook_reg_set_value_ex_w as *mut c_void,
                );
                tracing::info!("Hook RegSetValueExW: {ok}");
            }

            if let Some(proc) = GetProcAddress(reg_mod, c"RegDeleteValueW".as_ptr().cast()) {
                let ok = install_detour(
                    &REAL_REG_DELETE_VALUE_W,
                    proc as *mut c_void,
                    hook_reg_delete_value_w as *mut c_void,
                );
                tracing::info!("Hook RegDeleteValueW: {ok}");
            }

            if let Some(proc) = GetProcAddress(reg_mod, c"RegDeleteKeyW".as_ptr().cast()) {
                let ok = install_detour(
                    &REAL_REG_DELETE_KEY_W,
                    proc as *mut c_void,
                    hook_reg_delete_key_w as *mut c_void,
                );
                tracing::info!("Hook RegDeleteKeyW: {ok}");
            }

            if let Some(proc) = GetProcAddress(reg_mod, c"RegCloseKey".as_ptr().cast()) {
                let ok = install_detour(
                    &REAL_REG_CLOSE_KEY,
                    proc as *mut c_void,
                    hook_reg_close_key as *mut c_void,
                );
                tracing::info!("Hook RegCloseKey: {ok}");
            }
        }
    }
}
