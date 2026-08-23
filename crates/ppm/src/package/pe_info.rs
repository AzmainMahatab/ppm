use std::path::Path;

/// Dynamically extracts the binary product version directly from Windows PE header resources (VS_FIXEDFILEINFO).
pub fn get_pe_product_version(exe_path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        get_windows_pe_version(exe_path)
    }
    #[cfg(not(windows))]
    {
        let _ = exe_path;
        None
    }
}

/// Fallback: checks if Electron package.json exists in resources/app/package.json or app/package.json.
pub fn get_electron_package_version(exe_path: &Path) -> Option<String> {
    let parent = exe_path.parent()?;
    let candidate_paths = [
        parent.join("resources").join("app.asar"),
        parent.join("resources").join("app").join("package.json"),
        parent.join("package.json"),
    ];

    for path in &candidate_paths {
        if path.file_name()? == "package.json" && path.is_file() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(ver) = json.get("version").and_then(|v| v.as_str()) {
                        return Some(ver.to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(windows)]
fn get_windows_pe_version(exe_path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    if !exe_path.is_file() {
        return None;
    }

    let path_wide: Vec<u16> = exe_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Dynamically load version.dll
        let version_lib = windows_sys::Win32::System::LibraryLoader::LoadLibraryW(
            windows_sys::core::w!("version.dll"),
        );
        if version_lib.is_null() {
            return None;
        }

        type FnGetFileVersionInfoSizeW = unsafe extern "system" fn(*const u16, *mut u32) -> u32;
        type FnGetFileVersionInfoW = unsafe extern "system" fn(
            *const u16,
            u32,
            u32,
            *mut std::ffi::c_void,
        ) -> i32;
        type FnVerQueryValueW = unsafe extern "system" fn(
            *const std::ffi::c_void,
            *const u16,
            *mut *mut std::ffi::c_void,
            *mut u32,
        ) -> i32;

        let get_size_proc = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            version_lib,
            c"GetFileVersionInfoSizeW".as_ptr().cast(),
        );
        let get_info_proc = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            version_lib,
            c"GetFileVersionInfoW".as_ptr().cast(),
        );
        let query_val_proc = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            version_lib,
            c"VerQueryValueW".as_ptr().cast(),
        );

        if get_size_proc.is_none() || get_info_proc.is_none() || query_val_proc.is_none() {
            windows_sys::Win32::Foundation::FreeLibrary(version_lib);
            return None;
        }

        let get_size: FnGetFileVersionInfoSizeW = std::mem::transmute(get_size_proc.unwrap());
        let get_info: FnGetFileVersionInfoW = std::mem::transmute(get_info_proc.unwrap());
        let query_val: FnVerQueryValueW = std::mem::transmute(query_val_proc.unwrap());

        let mut _handle = 0u32;
        let size = get_size(path_wide.as_ptr(), &mut _handle);
        if size == 0 {
            windows_sys::Win32::Foundation::FreeLibrary(version_lib);
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        if get_info(
            path_wide.as_ptr(),
            0,
            size,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
        ) == 0
        {
            windows_sys::Win32::Foundation::FreeLibrary(version_lib);
            return None;
        }

        // Query root fixed file info: \
        let sub_block = windows_sys::core::w!("\\");
        let mut lp_buffer: *mut std::ffi::c_void = null_mut();
        let mut len: u32 = 0;

        if query_val(
            buffer.as_ptr() as *const std::ffi::c_void,
            sub_block,
            &mut lp_buffer,
            &mut len,
        ) != 0
            && !lp_buffer.is_null()
            && len >= 52
        {
            #[repr(C)]
            struct VsFixedFileInfo {
                dw_signature: u32,
                dw_struc_version: u32,
                dw_file_version_ms: u32,
                dw_file_version_ls: u32,
                dw_product_version_ms: u32,
                dw_product_version_ls: u32,
                dw_file_flags_mask: u32,
                dw_file_flags: u32,
                dw_file_os: u32,
                dw_file_type: u32,
                dw_file_subtype: u32,
                dw_file_date_ms: u32,
                dw_file_date_ls: u32,
            }

            let info = &*(lp_buffer as *const VsFixedFileInfo);
            if info.dw_signature == 0xFEEF04BD {
                let major = (info.dw_product_version_ms >> 16) & 0xFFFF;
                let minor = info.dw_product_version_ms & 0xFFFF;
                let patch = (info.dw_product_version_ls >> 16) & 0xFFFF;
                let build = info.dw_product_version_ls & 0xFFFF;

                windows_sys::Win32::Foundation::FreeLibrary(version_lib);
                if build > 0 {
                    return Some(format!("{}.{}.{}.{}", major, minor, patch, build));
                } else {
                    return Some(format!("{}.{}.{}", major, minor, patch));
                }
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(version_lib);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_extract_pe_version_from_system_binary() {
        let kernel32_path = Path::new("C:\\Windows\\System32\\kernel32.dll");
        if kernel32_path.is_file() {
            let version = get_pe_product_version(kernel32_path);
            assert!(version.is_some(), "Should extract version from kernel32.dll");
            let ver_str = version.unwrap();
            assert!(ver_str.starts_with("10.0") || ver_str.starts_with("6."), "Expected Windows version format, got: {}", ver_str);
        }
    }
}
