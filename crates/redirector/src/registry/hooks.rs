use crate::detour::attach_detour;
use crate::registry::handle_table::get_handle_table;
use crate::registry::nt_types::*;
use crate::registry::store::get_registry_store;
use std::cell::Cell;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::System::Registry::HKEY;

const ERROR_FILE_NOT_FOUND: u32 = 2;

thread_local! {
    static IN_REG_HOOK: Cell<bool> = const { Cell::new(false) };
}

struct RegHookGuard;

impl RegHookGuard {
    fn enter() -> Option<Self> {
        if IN_REG_HOOK.try_with(|h| h.get()).unwrap_or(false) {
            return None;
        }
        let _ = IN_REG_HOOK.try_with(|h| h.set(true));
        Some(RegHookGuard)
    }
}

impl Drop for RegHookGuard {
    fn drop(&mut self) {
        let _ = IN_REG_HOOK.try_with(|h| h.set(false));
    }
}

macro_rules! guard_reg_hook {
    ($fallback:expr, $body:expr) => {{
        let _guard = match RegHookGuard::enter() {
            Some(g) => g,
            None => return $fallback,
        };
        $body
    }};
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
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

// Function pointer type definitions for NT syscalls
type FnNtOpenKey = unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES) -> NTSTATUS;
type FnNtOpenKeyEx = unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES, u32) -> NTSTATUS;
type FnNtCreateKey = unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES, u32, *const UNICODE_STRING, u32, *mut u32) -> NTSTATUS;
type FnNtQueryValueKey = unsafe extern "system" fn(HANDLE, *const UNICODE_STRING, u32, *mut c_void, u32, *mut u32) -> NTSTATUS;
#[allow(dead_code)]
type FnNtSetValueKey = unsafe extern "system" fn(HANDLE, *const UNICODE_STRING, u32, u32, *const c_void, u32) -> NTSTATUS;
#[allow(dead_code)]
type FnNtDeleteValueKey = unsafe extern "system" fn(HANDLE, *const UNICODE_STRING) -> NTSTATUS;
#[allow(dead_code)]
type FnNtDeleteKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
type FnNtClose = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

static mut REAL_NT_OPEN_KEY: *mut c_void = std::ptr::null_mut();
static mut REAL_NT_OPEN_KEY_EX: *mut c_void = std::ptr::null_mut();
static mut REAL_NT_CREATE_KEY: *mut c_void = std::ptr::null_mut();
static mut REAL_NT_QUERY_VALUE_KEY: *mut c_void = std::ptr::null_mut();
static mut REAL_NT_SET_VALUE_KEY: *mut c_void = std::ptr::null_mut();
static mut REAL_NT_DELETE_VALUE_KEY: *mut c_void = std::ptr::null_mut();
static mut REAL_NT_DELETE_KEY: *mut c_void = std::ptr::null_mut();
static mut REAL_NT_CLOSE: *mut c_void = std::ptr::null_mut();

// Function pointer type definitions for Win32 Registry APIs
type FnRegOpenKeyExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32, *mut HKEY) -> i32;
type FnRegCreateKeyExW = unsafe extern "system" fn(HKEY, *const u16, u32, *mut u16, u32, u32, *const c_void, *mut HKEY, *mut u32) -> i32;
type FnRegQueryValueExW = unsafe extern "system" fn(HKEY, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
#[allow(dead_code)]
type FnRegSetValueExW = unsafe extern "system" fn(HKEY, *const u16, u32, u32, *const u8, u32) -> i32;
#[allow(dead_code)]
type FnRegDeleteValueW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
#[allow(dead_code)]
type FnRegDeleteKeyW = unsafe extern "system" fn(HKEY, *const u16) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(HKEY) -> i32;

static mut REAL_REG_OPEN_KEY_EX_W: *mut c_void = std::ptr::null_mut();
static mut REAL_REG_CREATE_KEY_EX_W: *mut c_void = std::ptr::null_mut();
static mut REAL_REG_QUERY_VALUE_EX_W: *mut c_void = std::ptr::null_mut();
static mut REAL_REG_SET_VALUE_EX_W: *mut c_void = std::ptr::null_mut();
static mut REAL_REG_DELETE_VALUE_W: *mut c_void = std::ptr::null_mut();
static mut REAL_REG_DELETE_KEY_W: *mut c_void = std::ptr::null_mut();
static mut REAL_REG_CLOSE_KEY: *mut c_void = std::ptr::null_mut();

/// Normalizes an NT object path to a portable canonical root path (e.g. `HKCU\Software\Vendor\App`).
unsafe fn resolve_full_key_path(obj_attr: *const OBJECT_ATTRIBUTES) -> String {
    if obj_attr.is_null() {
        return String::new();
    }

    let attr = &*obj_attr;
    let raw_name = if !attr.ObjectName.is_null() {
        (&*attr.ObjectName).to_string_lossy()
    } else {
        String::new()
    };

    let base_path = if !attr.RootDirectory.is_null() {
        get_handle_table()
            .get_path(attr.RootDirectory)
            .unwrap_or_default()
    } else {
        String::new()
    };

    let full_raw = if !base_path.is_empty() && !raw_name.is_empty() {
        format!("{}\\{}", base_path, raw_name.trim_start_matches('\\'))
    } else if !raw_name.is_empty() {
        raw_name
    } else {
        base_path
    };

    // Normalize NT Registry paths case-insensitively
    let trimmed = full_raw.trim_start_matches('\\');
    let trimmed_upper = trimmed.to_uppercase();

    if trimmed_upper.starts_with("REGISTRY\\MACHINE") {
        let rest = &trimmed[16..];
        format!("HKLM\\{}", rest.trim_start_matches('\\'))
    } else if trimmed_upper.starts_with("REGISTRY\\USER") {
        if trimmed_upper.contains("_CLASSES") {
            let parts: Vec<&str> = trimmed.splitn(4, '\\').collect();
            if parts.len() >= 4 {
                format!("HKCR\\{}", parts[3])
            } else {
                "HKCR".to_string()
            }
        } else {
            let parts: Vec<&str> = trimmed.splitn(4, '\\').collect();
            if parts.len() >= 4 {
                format!("HKCU\\{}", parts[3])
            } else {
                "HKCU".to_string()
            }
        }
    } else {
        full_raw
    }
}

// ---------------------- WIN32 API HOOKS ----------------------

unsafe extern "system" fn hook_reg_open_key_ex_w(
    hkey: HKEY,
    lp_sub_key: *const u16,
    ul_options: u32,
    sam_desired: u32,
    phk_result: *mut HKEY,
) -> i32 {
    let real_fn: FnRegOpenKeyExW = std::mem::transmute(REAL_REG_OPEN_KEY_EX_W);
    guard_reg_hook!(
        real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result),
        {
            let base_path = get_handle_table().get_path(hkey as HANDLE).unwrap_or_default();
            let subkey_str = wide_to_string(lp_sub_key);
            let full_path = if !base_path.is_empty() && !subkey_str.is_empty() {
                format!("{}\\{}", base_path, subkey_str.trim_start_matches('\\'))
            } else if !subkey_str.is_empty() {
                subkey_str
            } else {
                base_path
            };

            if get_registry_store().is_key_tombstoned(&full_path) {
                return ERROR_FILE_NOT_FOUND as i32;
            }

            let status = real_fn(hkey, lp_sub_key, ul_options, sam_desired, phk_result);
            if status == ERROR_SUCCESS as i32 && !phk_result.is_null() {
                get_handle_table().register_host_handle(*phk_result as HANDLE, full_path);
                return status;
            }

            if !phk_result.is_null() && get_registry_store().key_exists(&full_path) {
                let vhandle = get_handle_table().register_virtual_handle(full_path);
                *phk_result = vhandle as HKEY;
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
    let real_fn: FnRegCreateKeyExW = std::mem::transmute(REAL_REG_CREATE_KEY_EX_W);
    guard_reg_hook!(
        real_fn(hkey, lp_sub_key, reserved, lp_class, dw_options, sam_desired, lp_security_attributes, phk_result, lpdw_disposition),
        {
            let base_path = get_handle_table().get_path(hkey as HANDLE).unwrap_or_default();
            let subkey_str = wide_to_string(lp_sub_key);
            let full_path = if !base_path.is_empty() && !subkey_str.is_empty() {
                format!("{}\\{}", base_path, subkey_str.trim_start_matches('\\'))
            } else if !subkey_str.is_empty() {
                subkey_str
            } else {
                base_path
            };

            get_registry_store().create_key(&full_path);
            tracing::info!("RegCreateKeyExW: Virtual key created -> {}", full_path);

            let status = real_fn(
                hkey,
                lp_sub_key,
                reserved,
                lp_class,
                dw_options,
                sam_desired,
                lp_security_attributes,
                phk_result,
                lpdw_disposition,
            );

            if status == ERROR_SUCCESS as i32 && !phk_result.is_null() {
                get_handle_table().register_host_handle(*phk_result as HANDLE, full_path);
                return status;
            }

            if !phk_result.is_null() {
                let vhandle = get_handle_table().register_virtual_handle(full_path);
                *phk_result = vhandle as HKEY;
                if !lpdw_disposition.is_null() {
                    *lpdw_disposition = 1;
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
    let real_fn: FnRegQueryValueExW = std::mem::transmute(REAL_REG_QUERY_VALUE_EX_W);
    guard_reg_hook!(
        real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data),
        {
            let key_path = get_handle_table().get_path(hkey as HANDLE).unwrap_or_default();
            let val_name = wide_to_string(lp_value_name);

            if let Some(query_res) = get_registry_store().get_value(&key_path, &val_name) {
                match query_res {
                    Err(()) => {
                        tracing::debug!("RegQueryValueExW [Tombstoned Value]: {}\\{}", key_path, val_name);
                        return ERROR_FILE_NOT_FOUND as i32;
                    }
                    Ok((val_type, data)) => {
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

                        tracing::debug!("RegQueryValueExW [Virtual Hit]: {}\\{}", key_path, val_name);
                        return ERROR_SUCCESS as i32;
                    }
                }
            }

            if get_handle_table().is_synthetic(hkey as HANDLE) {
                return ERROR_FILE_NOT_FOUND as i32;
            }

            real_fn(hkey, lp_value_name, lp_reserved, lp_type, lp_data, lpcb_data)
        }
    )
}

unsafe extern "system" fn hook_reg_set_value_ex_w(
    hkey: HKEY,
    lp_value_name: *const u16,
    _reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    guard_reg_hook!(
        ERROR_SUCCESS as i32,
        {
            let key_path = get_handle_table().get_path(hkey as HANDLE).unwrap_or_default();
            let val_name = wide_to_string(lp_value_name);

            let data_slice = if !lp_data.is_null() && cb_data > 0 {
                std::slice::from_raw_parts(lp_data, cb_data as usize)
            } else {
                &[]
            };

            tracing::debug!("RegSetValueExW [CoW Virtual Store]: {}\\{} (type: {}, bytes: {})", key_path, val_name, dw_type, cb_data);
            get_registry_store().set_value(&key_path, &val_name, dw_type, data_slice);
            ERROR_SUCCESS as i32
        }
    )
}

unsafe extern "system" fn hook_reg_delete_value_w(hkey: HKEY, lp_value_name: *const u16) -> i32 {
    guard_reg_hook!(
        ERROR_SUCCESS as i32,
        {
            let key_path = get_handle_table().get_path(hkey as HANDLE).unwrap_or_default();
            let val_name = wide_to_string(lp_value_name);
            get_registry_store().delete_value(&key_path, &val_name);
            tracing::info!("RegDeleteValueW [CoW Mask]: {}\\{}", key_path, val_name);
            ERROR_SUCCESS as i32
        }
    )
}

unsafe extern "system" fn hook_reg_delete_key_w(hkey: HKEY, lp_sub_key: *const u16) -> i32 {
    guard_reg_hook!(
        ERROR_SUCCESS as i32,
        {
            let base_path = get_handle_table().get_path(hkey as HANDLE).unwrap_or_default();
            let subkey_str = wide_to_string(lp_sub_key);
            let full_path = if !base_path.is_empty() && !subkey_str.is_empty() {
                format!("{}\\{}", base_path, subkey_str.trim_start_matches('\\'))
            } else if !subkey_str.is_empty() {
                subkey_str
            } else {
                base_path
            };

            get_registry_store().delete_key(&full_path);
            tracing::info!("RegDeleteKeyW [CoW Tombstone]: {}", full_path);
            ERROR_SUCCESS as i32
        }
    )
}

unsafe extern "system" fn hook_reg_close_key(hkey: HKEY) -> i32 {
    let real_fn: FnRegCloseKey = std::mem::transmute(REAL_REG_CLOSE_KEY);
    guard_reg_hook!(
        real_fn(hkey),
        {
            if let Some(entry) = get_handle_table().close_handle(hkey as HANDLE) {
                if entry.is_synthetic {
                    return ERROR_SUCCESS as i32;
                }
            }
            real_fn(hkey)
        }
    )
}

// ---------------------- NT SYSCALL HOOKS ----------------------

unsafe extern "system" fn hook_nt_open_key(
    key_handle: *mut HANDLE,
    desired_access: u32,
    obj_attr: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let real_fn: FnNtOpenKey = std::mem::transmute(REAL_NT_OPEN_KEY);
    guard_reg_hook!(
        real_fn(key_handle, desired_access, obj_attr),
        {
            let path = resolve_full_key_path(obj_attr);

            if get_registry_store().is_key_tombstoned(&path) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            let status = real_fn(key_handle, desired_access, obj_attr);
            if status == STATUS_SUCCESS && !key_handle.is_null() {
                get_handle_table().register_host_handle(*key_handle, path);
            }
            status
        }
    )
}

unsafe extern "system" fn hook_nt_open_key_ex(
    key_handle: *mut HANDLE,
    desired_access: u32,
    obj_attr: *const OBJECT_ATTRIBUTES,
    open_options: u32,
) -> NTSTATUS {
    let real_fn: FnNtOpenKeyEx = std::mem::transmute(REAL_NT_OPEN_KEY_EX);
    guard_reg_hook!(
        real_fn(key_handle, desired_access, obj_attr, open_options),
        {
            let path = resolve_full_key_path(obj_attr);

            if get_registry_store().is_key_tombstoned(&path) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            let status = real_fn(key_handle, desired_access, obj_attr, open_options);
            if status == STATUS_SUCCESS && !key_handle.is_null() {
                get_handle_table().register_host_handle(*key_handle, path);
            }
            status
        }
    )
}

unsafe extern "system" fn hook_nt_create_key(
    key_handle: *mut HANDLE,
    desired_access: u32,
    obj_attr: *const OBJECT_ATTRIBUTES,
    title_index: u32,
    class: *const UNICODE_STRING,
    create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    let real_fn: FnNtCreateKey = std::mem::transmute(REAL_NT_CREATE_KEY);
    guard_reg_hook!(
        real_fn(key_handle, desired_access, obj_attr, title_index, class, create_options, disposition),
        {
            let path = resolve_full_key_path(obj_attr);
            get_registry_store().create_key(&path);

            let status = real_fn(key_handle, desired_access, obj_attr, title_index, class, create_options, disposition);
            if status == STATUS_SUCCESS && !key_handle.is_null() {
                get_handle_table().register_host_handle(*key_handle, path);
                return status;
            }

            if !key_handle.is_null() {
                let virtual_handle = get_handle_table().register_virtual_handle(path);
                *key_handle = virtual_handle;
                if !disposition.is_null() {
                    *disposition = 1;
                }
                return STATUS_SUCCESS;
            }

            status
        }
    )
}

unsafe extern "system" fn hook_nt_query_value_key(
    key_handle: HANDLE,
    value_name: *const UNICODE_STRING,
    key_val_class: u32,
    key_val_info: *mut c_void,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    let real_fn: FnNtQueryValueKey = std::mem::transmute(REAL_NT_QUERY_VALUE_KEY);
    guard_reg_hook!(
        real_fn(key_handle, value_name, key_val_class, key_val_info, length, result_length),
        {
            let key_path = get_handle_table().get_path(key_handle).unwrap_or_default();
            let val_name_str = if !value_name.is_null() {
                (&*value_name).to_string_lossy()
            } else {
                String::new()
            };

            if let Some(query_res) = get_registry_store().get_value(&key_path, &val_name_str) {
                match query_res {
                    Err(()) => {
                        return STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                    Ok((val_type, data)) => {
                        match key_val_class {
                            KEY_VALUE_PARTIAL_INFORMATION_CLASS => {
                                let header_size = std::mem::offset_of!(KEY_VALUE_PARTIAL_INFORMATION, Data) as u32;
                                let required_size = header_size + data.len() as u32;

                                if !result_length.is_null() {
                                    *result_length = required_size;
                                }

                                if length < header_size {
                                    return STATUS_BUFFER_TOO_SMALL;
                                }

                                if !key_val_info.is_null() {
                                    let info = &mut *(key_val_info as *mut KEY_VALUE_PARTIAL_INFORMATION);
                                    info.TitleIndex = 0;
                                    info.Type = val_type;
                                    info.DataLength = data.len() as u32;

                                    let copy_len = std::cmp::min(data.len(), (length - header_size) as usize);
                                    if copy_len > 0 {
                                        std::ptr::copy_nonoverlapping(data.as_ptr(), info.Data.as_mut_ptr(), copy_len);
                                    }
                                }

                                if length < required_size {
                                    return STATUS_BUFFER_OVERFLOW;
                                }

                                return STATUS_SUCCESS;
                            }
                            KEY_VALUE_FULL_INFORMATION_CLASS => {
                                let name_utf16: Vec<u16> = val_name_str.encode_utf16().collect();
                                let name_bytes = (name_utf16.len() * 2) as u32;
                                let header_size = std::mem::offset_of!(KEY_VALUE_FULL_INFORMATION, Name) as u32;
                                let data_offset = (header_size + name_bytes + 3) & !3;
                                let required_size = data_offset + data.len() as u32;

                                if !result_length.is_null() {
                                    *result_length = required_size;
                                }

                                if length < header_size {
                                    return STATUS_BUFFER_TOO_SMALL;
                                }

                                if !key_val_info.is_null() {
                                    let info = &mut *(key_val_info as *mut KEY_VALUE_FULL_INFORMATION);
                                    info.TitleIndex = 0;
                                    info.Type = val_type;
                                    info.DataOffset = data_offset;
                                    info.DataLength = data.len() as u32;
                                    info.NameLength = name_bytes;

                                    if name_bytes > 0 && length >= header_size + name_bytes {
                                        std::ptr::copy_nonoverlapping(
                                            name_utf16.as_ptr(),
                                            info.Name.as_mut_ptr(),
                                            name_utf16.len(),
                                        );
                                    }

                                    if length >= required_size {
                                        let data_dest = (key_val_info as *mut u8).add(data_offset as usize);
                                        std::ptr::copy_nonoverlapping(data.as_ptr(), data_dest, data.len());
                                    }
                                }

                                if length < required_size {
                                    return STATUS_BUFFER_OVERFLOW;
                                }

                                return STATUS_SUCCESS;
                            }
                            KEY_VALUE_BASIC_INFORMATION_CLASS => {
                                let name_utf16: Vec<u16> = val_name_str.encode_utf16().collect();
                                let name_bytes = (name_utf16.len() * 2) as u32;
                                let header_size = std::mem::offset_of!(KEY_VALUE_BASIC_INFORMATION, Name) as u32;
                                let required_size = header_size + name_bytes;

                                if !result_length.is_null() {
                                    *result_length = required_size;
                                }

                                if length < header_size {
                                    return STATUS_BUFFER_TOO_SMALL;
                                }

                                if !key_val_info.is_null() {
                                    let info = &mut *(key_val_info as *mut KEY_VALUE_BASIC_INFORMATION);
                                    info.TitleIndex = 0;
                                    info.Type = val_type;
                                    info.NameLength = name_bytes;

                                    if name_bytes > 0 && length >= required_size {
                                        std::ptr::copy_nonoverlapping(
                                            name_utf16.as_ptr(),
                                            info.Name.as_mut_ptr(),
                                            name_utf16.len(),
                                        );
                                    }
                                }

                                if length < required_size {
                                    return STATUS_BUFFER_OVERFLOW;
                                }

                                return STATUS_SUCCESS;
                            }
                            _ => {}
                        }
                    }
                }
            }

            if get_handle_table().is_synthetic(key_handle) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            real_fn(key_handle, value_name, key_val_class, key_val_info, length, result_length)
        }
    )
}

unsafe extern "system" fn hook_nt_set_value_key(
    key_handle: HANDLE,
    value_name: *const UNICODE_STRING,
    _title_index: u32,
    val_type: u32,
    data: *const c_void,
    data_size: u32,
) -> NTSTATUS {
    guard_reg_hook!(
        STATUS_SUCCESS,
        {
            let key_path = get_handle_table().get_path(key_handle).unwrap_or_default();
            let val_name_str = if !value_name.is_null() {
                (&*value_name).to_string_lossy()
            } else {
                String::new()
            };

            let byte_slice = if !data.is_null() && data_size > 0 {
                std::slice::from_raw_parts(data as *const u8, data_size as usize)
            } else {
                &[]
            };

            get_registry_store().set_value(&key_path, &val_name_str, val_type, byte_slice);
            STATUS_SUCCESS
        }
    )
}

unsafe extern "system" fn hook_nt_delete_value_key(
    key_handle: HANDLE,
    value_name: *const UNICODE_STRING,
) -> NTSTATUS {
    guard_reg_hook!(
        STATUS_SUCCESS,
        {
            let key_path = get_handle_table().get_path(key_handle).unwrap_or_default();
            let val_name_str = if !value_name.is_null() {
                (&*value_name).to_string_lossy()
            } else {
                String::new()
            };

            get_registry_store().delete_value(&key_path, &val_name_str);
            STATUS_SUCCESS
        }
    )
}

unsafe extern "system" fn hook_nt_delete_key(key_handle: HANDLE) -> NTSTATUS {
    guard_reg_hook!(
        STATUS_SUCCESS,
        {
            let key_path = get_handle_table().get_path(key_handle).unwrap_or_default();
            get_registry_store().delete_key(&key_path);
            STATUS_SUCCESS
        }
    )
}

unsafe extern "system" fn hook_nt_close(handle: HANDLE) -> NTSTATUS {
    let real_fn: FnNtClose = std::mem::transmute(REAL_NT_CLOSE);
    guard_reg_hook!(
        real_fn(handle),
        {
            if let Some(entry) = get_handle_table().close_handle(handle) {
                if entry.is_synthetic {
                    return STATUS_SUCCESS;
                }
            }
            real_fn(handle)
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};

    unsafe {
        // 1. Hook NT Syscalls in ntdll.dll
        let ntdll = GetModuleHandleW(windows_sys::core::w!("ntdll.dll"));
        if !ntdll.is_null() {
            if let Some(proc) = GetProcAddress(ntdll, c"NtOpenKey".as_ptr().cast()) {
                REAL_NT_OPEN_KEY = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_OPEN_KEY, hook_nt_open_key as *mut c_void);
                tracing::info!("Hook NtOpenKey: {}", ok);
            }

            if let Some(proc) = GetProcAddress(ntdll, c"NtOpenKeyEx".as_ptr().cast()) {
                REAL_NT_OPEN_KEY_EX = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_OPEN_KEY_EX, hook_nt_open_key_ex as *mut c_void);
                tracing::info!("Hook NtOpenKeyEx: {}", ok);
            }

            if let Some(proc) = GetProcAddress(ntdll, c"NtCreateKey".as_ptr().cast()) {
                REAL_NT_CREATE_KEY = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_CREATE_KEY, hook_nt_create_key as *mut c_void);
                tracing::info!("Hook NtCreateKey: {}", ok);
            }

            if let Some(proc) = GetProcAddress(ntdll, c"NtQueryValueKey".as_ptr().cast()) {
                REAL_NT_QUERY_VALUE_KEY = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_QUERY_VALUE_KEY, hook_nt_query_value_key as *mut c_void);
                tracing::info!("Hook NtQueryValueKey: {}", ok);
            }

            if let Some(proc) = GetProcAddress(ntdll, c"NtSetValueKey".as_ptr().cast()) {
                REAL_NT_SET_VALUE_KEY = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_SET_VALUE_KEY, hook_nt_set_value_key as *mut c_void);
                tracing::info!("Hook NtSetValueKey: {}", ok);
            }

            if let Some(proc) = GetProcAddress(ntdll, c"NtDeleteValueKey".as_ptr().cast()) {
                REAL_NT_DELETE_VALUE_KEY = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_DELETE_VALUE_KEY, hook_nt_delete_value_key as *mut c_void);
                tracing::info!("Hook NtDeleteValueKey: {}", ok);
            }

            if let Some(proc) = GetProcAddress(ntdll, c"NtDeleteKey".as_ptr().cast()) {
                REAL_NT_DELETE_KEY = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_DELETE_KEY, hook_nt_delete_key as *mut c_void);
                tracing::info!("Hook NtDeleteKey: {}", ok);
            }

            if let Some(proc) = GetProcAddress(ntdll, c"NtClose".as_ptr().cast()) {
                REAL_NT_CLOSE = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_NT_CLOSE, hook_nt_close as *mut c_void);
                tracing::info!("Hook NtClose: {}", ok);
            }
        }

        // 2. Hook Win32 Registry APIs in advapi32.dll
        let advapi32 = LoadLibraryW(windows_sys::core::w!("advapi32.dll"));
        if !advapi32.is_null() {
            if let Some(proc) = GetProcAddress(advapi32, c"RegOpenKeyExW".as_ptr().cast()) {
                REAL_REG_OPEN_KEY_EX_W = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_REG_OPEN_KEY_EX_W, hook_reg_open_key_ex_w as *mut c_void);
                tracing::info!("Hook RegOpenKeyExW: {}", ok);
            }

            if let Some(proc) = GetProcAddress(advapi32, c"RegCreateKeyExW".as_ptr().cast()) {
                REAL_REG_CREATE_KEY_EX_W = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_REG_CREATE_KEY_EX_W, hook_reg_create_key_ex_w as *mut c_void);
                tracing::info!("Hook RegCreateKeyExW: {}", ok);
            }

            if let Some(proc) = GetProcAddress(advapi32, c"RegQueryValueExW".as_ptr().cast()) {
                REAL_REG_QUERY_VALUE_EX_W = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_REG_QUERY_VALUE_EX_W, hook_reg_query_value_ex_w as *mut c_void);
                tracing::info!("Hook RegQueryValueExW: {}", ok);
            }

            if let Some(proc) = GetProcAddress(advapi32, c"RegSetValueExW".as_ptr().cast()) {
                REAL_REG_SET_VALUE_EX_W = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_REG_SET_VALUE_EX_W, hook_reg_set_value_ex_w as *mut c_void);
                tracing::info!("Hook RegSetValueExW: {}", ok);
            }

            if let Some(proc) = GetProcAddress(advapi32, c"RegDeleteValueW".as_ptr().cast()) {
                REAL_REG_DELETE_VALUE_W = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_REG_DELETE_VALUE_W, hook_reg_delete_value_w as *mut c_void);
                tracing::info!("Hook RegDeleteValueW: {}", ok);
            }

            if let Some(proc) = GetProcAddress(advapi32, c"RegDeleteKeyW".as_ptr().cast()) {
                REAL_REG_DELETE_KEY_W = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_REG_DELETE_KEY_W, hook_reg_delete_key_w as *mut c_void);
                tracing::info!("Hook RegDeleteKeyW: {}", ok);
            }

            if let Some(proc) = GetProcAddress(advapi32, c"RegCloseKey".as_ptr().cast()) {
                REAL_REG_CLOSE_KEY = proc as *mut c_void;
                let ok = attach_detour(&raw mut REAL_REG_CLOSE_KEY, hook_reg_close_key as *mut c_void);
                tracing::info!("Hook RegCloseKey: {}", ok);
            }
        }
    }
}
