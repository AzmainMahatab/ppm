use crate::registry::handle_table::get_handle_table;
use crate::registry::nt_types::*;
use crate::registry::store::get_registry_store;
use retour::GenericDetour;
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HANDLE;

thread_local! {
    static IN_REG_HOOK: Cell<bool> = const { Cell::new(false) };
}

macro_rules! guard_reg_hook {
    ($fallback:expr, $body:expr) => {{
        if IN_REG_HOOK.with(|h| h.get()) {
            return $fallback;
        }
        IN_REG_HOOK.with(|h| h.set(true));
        let res = $body;
        IN_REG_HOOK.with(|h| h.set(false));
        res
    }};
}

// Function pointer type definitions for ntdll syscalls
type FnNtOpenKey = unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES) -> NTSTATUS;
type FnNtOpenKeyEx = unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES, u32) -> NTSTATUS;
type FnNtCreateKey = unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES, u32, *const UNICODE_STRING, u32, *mut u32) -> NTSTATUS;
type FnNtQueryValueKey = unsafe extern "system" fn(HANDLE, *const UNICODE_STRING, u32, *mut c_void, u32, *mut u32) -> NTSTATUS;
type FnNtSetValueKey = unsafe extern "system" fn(HANDLE, *const UNICODE_STRING, u32, u32, *const c_void, u32) -> NTSTATUS;
type FnNtDeleteValueKey = unsafe extern "system" fn(HANDLE, *const UNICODE_STRING) -> NTSTATUS;
type FnNtDeleteKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
type FnNtClose = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

static HOOK_NT_OPEN_KEY: OnceLock<GenericDetour<FnNtOpenKey>> = OnceLock::new();
static HOOK_NT_OPEN_KEY_EX: OnceLock<GenericDetour<FnNtOpenKeyEx>> = OnceLock::new();
static HOOK_NT_CREATE_KEY: OnceLock<GenericDetour<FnNtCreateKey>> = OnceLock::new();
static HOOK_NT_QUERY_VALUE_KEY: OnceLock<GenericDetour<FnNtQueryValueKey>> = OnceLock::new();
static HOOK_NT_SET_VALUE_KEY: OnceLock<GenericDetour<FnNtSetValueKey>> = OnceLock::new();
static HOOK_NT_DELETE_VALUE_KEY: OnceLock<GenericDetour<FnNtDeleteValueKey>> = OnceLock::new();
static HOOK_NT_DELETE_KEY: OnceLock<GenericDetour<FnNtDeleteKey>> = OnceLock::new();
static HOOK_NT_CLOSE: OnceLock<GenericDetour<FnNtClose>> = OnceLock::new();

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

    // Normalize NT Registry paths
    let trimmed = full_raw.trim_start_matches('\\');
    if let Some(rest) = trimmed.strip_prefix("Registry\\Machine") {
        format!("HKLM\\{}", rest.trim_start_matches('\\'))
    } else if trimmed.starts_with("Registry\\User") {
        if trimmed.contains("_Classes") {
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

// 1. NtOpenKey Detour
unsafe extern "system" fn hook_nt_open_key(
    key_handle: *mut HANDLE,
    desired_access: u32,
    obj_attr: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_OPEN_KEY.get().unwrap().call(key_handle, desired_access, obj_attr),
        {
            let path = resolve_full_key_path(obj_attr);

            if get_registry_store().is_key_tombstoned(&path) {
                tracing::trace!("NtOpenKey: Key is tombstoned -> {}", path);
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            let status = HOOK_NT_OPEN_KEY.get().unwrap().call(key_handle, desired_access, obj_attr);
            if status == STATUS_SUCCESS && !key_handle.is_null() {
                get_handle_table().register_host_handle(*key_handle, path);
            }
            status
        }
    )
}

// 2. NtOpenKeyEx Detour
unsafe extern "system" fn hook_nt_open_key_ex(
    key_handle: *mut HANDLE,
    desired_access: u32,
    obj_attr: *const OBJECT_ATTRIBUTES,
    open_options: u32,
) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_OPEN_KEY_EX.get().unwrap().call(key_handle, desired_access, obj_attr, open_options),
        {
            let path = resolve_full_key_path(obj_attr);

            if get_registry_store().is_key_tombstoned(&path) {
                tracing::trace!("NtOpenKeyEx: Key is tombstoned -> {}", path);
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            let status = HOOK_NT_OPEN_KEY_EX.get().unwrap().call(key_handle, desired_access, obj_attr, open_options);
            if status == STATUS_SUCCESS && !key_handle.is_null() {
                get_handle_table().register_host_handle(*key_handle, path);
            }
            status
        }
    )
}

// 3. NtCreateKey Detour
unsafe extern "system" fn hook_nt_create_key(
    key_handle: *mut HANDLE,
    desired_access: u32,
    obj_attr: *const OBJECT_ATTRIBUTES,
    title_index: u32,
    class: *const UNICODE_STRING,
    create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_CREATE_KEY.get().unwrap().call(key_handle, desired_access, obj_attr, title_index, class, create_options, disposition),
        {
            let path = resolve_full_key_path(obj_attr);
            get_registry_store().create_key(&path);
            tracing::debug!("NtCreateKey: Virtual key created -> {}", path);

            let status = HOOK_NT_CREATE_KEY.get().unwrap().call(key_handle, desired_access, obj_attr, title_index, class, create_options, disposition);
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

// 4. NtQueryValueKey Detour
unsafe extern "system" fn hook_nt_query_value_key(
    key_handle: HANDLE,
    value_name: *const UNICODE_STRING,
    key_val_class: u32,
    key_val_info: *mut c_void,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_QUERY_VALUE_KEY.get().unwrap().call(key_handle, value_name, key_val_class, key_val_info, length, result_length),
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
                        tracing::trace!("NtQueryValueKey [Tombstoned Value]: {}\\{}", key_path, val_name_str);
                        return STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                    Ok((val_type, data)) => {
                        if key_val_class == KeyValuePartialInformation {
                            let header_size = std::mem::size_of::<KEY_VALUE_PARTIAL_INFORMATION>() - 1;
                            let required_size = (header_size + data.len()) as u32;

                            if !result_length.is_null() {
                                *result_length = required_size;
                            }

                            if length < required_size {
                                return STATUS_BUFFER_TOO_SMALL;
                            }

                            if !key_val_info.is_null() {
                                let info = &mut *(key_val_info as *mut KEY_VALUE_PARTIAL_INFORMATION);
                                info.TitleIndex = 0;
                                info.Type = val_type;
                                info.DataLength = data.len() as u32;
                                std::ptr::copy_nonoverlapping(data.as_ptr(), info.Data.as_mut_ptr(), data.len());
                            }

                            tracing::trace!("NtQueryValueKey [Virtual Overlay Hit]: {}\\{}", key_path, val_name_str);
                            return STATUS_SUCCESS;
                        }
                    }
                }
            }

            if get_handle_table().is_synthetic(key_handle) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            HOOK_NT_QUERY_VALUE_KEY.get().unwrap().call(key_handle, value_name, key_val_class, key_val_info, length, result_length)
        }
    )
}

// 5. NtSetValueKey Detour (Copy-on-Write Core)
unsafe extern "system" fn hook_nt_set_value_key(
    key_handle: HANDLE,
    value_name: *const UNICODE_STRING,
    title_index: u32,
    val_type: u32,
    data: *const c_void,
    data_size: u32,
) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_SET_VALUE_KEY.get().unwrap().call(key_handle, value_name, title_index, val_type, data, data_size),
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

            // Copy-on-Write: Store exclusively in portable overlay!
            get_registry_store().set_value(&key_path, &val_name_str, val_type, byte_slice);
            tracing::debug!("NtSetValueKey [CoW Intercept]: {}\\{} (type: {}, bytes: {})", key_path, val_name_str, val_type, byte_slice.len());

            STATUS_SUCCESS
        }
    )
}

// 6. NtDeleteValueKey Detour
unsafe extern "system" fn hook_nt_delete_value_key(
    key_handle: HANDLE,
    value_name: *const UNICODE_STRING,
) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_DELETE_VALUE_KEY.get().unwrap().call(key_handle, value_name),
        {
            let key_path = get_handle_table().get_path(key_handle).unwrap_or_default();
            let val_name_str = if !value_name.is_null() {
                (&*value_name).to_string_lossy()
            } else {
                String::new()
            };

            get_registry_store().delete_value(&key_path, &val_name_str);
            tracing::debug!("NtDeleteValueKey [CoW Mask]: {}\\{}", key_path, val_name_str);
            STATUS_SUCCESS
        }
    )
}

// 7. NtDeleteKey Detour
unsafe extern "system" fn hook_nt_delete_key(key_handle: HANDLE) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_DELETE_KEY.get().unwrap().call(key_handle),
        {
            let key_path = get_handle_table().get_path(key_handle).unwrap_or_default();
            get_registry_store().delete_key(&key_path);
            tracing::debug!("NtDeleteKey [CoW Tombstone]: {}", key_path);
            STATUS_SUCCESS
        }
    )
}

// 8. NtClose Detour
unsafe extern "system" fn hook_nt_close(handle: HANDLE) -> NTSTATUS {
    guard_reg_hook!(
        HOOK_NT_CLOSE.get().unwrap().call(handle),
        {
            if let Some(entry) = get_handle_table().close_handle(handle) {
                if entry.is_synthetic {
                    return STATUS_SUCCESS;
                }
            }
            HOOK_NT_CLOSE.get().unwrap().call(handle)
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let ntdll = GetModuleHandleW(windows_sys::core::w!("ntdll.dll"));
        if ntdll.is_null() {
            return;
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtOpenKey\0".as_ptr()) {
            let target: FnNtOpenKey = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_open_key) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_OPEN_KEY.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtOpenKeyEx\0".as_ptr()) {
            let target: FnNtOpenKeyEx = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_open_key_ex) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_OPEN_KEY_EX.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtCreateKey\0".as_ptr()) {
            let target: FnNtCreateKey = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_create_key) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_CREATE_KEY.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtQueryValueKey\0".as_ptr()) {
            let target: FnNtQueryValueKey = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_query_value_key) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_QUERY_VALUE_KEY.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtSetValueKey\0".as_ptr()) {
            let target: FnNtSetValueKey = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_set_value_key) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_SET_VALUE_KEY.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtDeleteValueKey\0".as_ptr()) {
            let target: FnNtDeleteValueKey = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_delete_value_key) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_DELETE_VALUE_KEY.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtDeleteKey\0".as_ptr()) {
            let target: FnNtDeleteKey = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_delete_key) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_DELETE_KEY.set(d);
                }
            }
        }

        if let Some(proc) = GetProcAddress(ntdll, b"NtClose\0".as_ptr()) {
            let target: FnNtClose = std::mem::transmute(proc);
            if let Ok(d) = GenericDetour::new(target, hook_nt_close) {
                if d.enable().is_ok() {
                    let _ = HOOK_NT_CLOSE.set(d);
                }
            }
        }
    }
}
