use crate::assets::EMBEDDED_REDIRECTOR_DLL;
use crate::config::load_manifest;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, GetLastError};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, WaitForSingleObject, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
};

extern "system" {
    fn DetourCreateProcessWithDllExW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *const std::ffi::c_void,
        lpThreadAttributes: *const std::ffi::c_void,
        bInheritHandles: i32,
        dwCreationFlags: u32,
        lpEnvironment: *const std::ffi::c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
        lpDllName: *const u8,
        pfCreateProcessW: *const std::ffi::c_void,
    ) -> i32;
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn set_win32_env(name: &str, value: &str) {
    let name_w = to_wide_null(name);
    let val_w = to_wide_null(value);
    windows_sys::Win32::System::Environment::SetEnvironmentVariableW(
        name_w.as_ptr(),
        val_w.as_ptr(),
    );
}

pub fn ensure_redirector_dll(root: &Path) -> Result<PathBuf, String> {
    let ppm_dir = root.join(".ppm");
    let dll_path = ppm_dir.join("redirector.dll");

    if !dll_path.exists() {
        if EMBEDDED_REDIRECTOR_DLL.is_empty() {
            // Check fallback locations in dev workspace
            let fallback_paths = [
                root.join("target").join("release").join("redirector.dll"),
                root.join("target").join("debug").join("redirector.dll"),
            ];
            let mut found = false;
            for fb in &fallback_paths {
                if fb.exists() {
                    let _ = fs::create_dir_all(&ppm_dir);
                    let _ = fs::copy(fb, &dll_path);
                    found = true;
                    break;
                }
            }
            if !found {
                return Err("redirector.dll not found and embedded asset is empty. Build redirector first.".to_string());
            }
        } else {
            let _ = fs::create_dir_all(&ppm_dir);
            fs::write(&dll_path, EMBEDDED_REDIRECTOR_DLL)
                .map_err(|e| format!("Failed to extract redirector.dll: {}", e))?;
        }
    }

    Ok(dll_path)
}

pub fn run_app(root: &Path, app_name_or_path: &str, extra_args: &[String]) -> Result<i32, String> {
    let mut target_exe_path: Option<PathBuf> = None;
    let mut combined_args: Vec<String> = Vec::new();

    // 1. Check if input matches configured app in .ppm/apps.json
    if let Ok(manifests) = load_manifest(root) {
        if let Some(app_def) = manifests.apps.get(app_name_or_path) {
            // Validate dependencies first
            if let Some(deps) = &app_def.dependencies {
                for dep_id in deps {
                    if let Some(dep_def) = manifests.apps.get(dep_id) {
                        let dep_exe = root.join(&dep_def.target_dir).join(&dep_def.executable);
                        if !dep_exe.exists() {
                            return Err(format!(
                                "Application '{}' requires missing dependency '{}'. Run 'ppm install {}' first.",
                                app_name_or_path, dep_id, app_name_or_path
                            ));
                        }
                    }
                }
            }

            let full_exe = root.join(&app_def.target_dir).join(&app_def.executable);
            if !full_exe.exists() {
                return Err(format!(
                    "Application '{}' is not installed at '{}'. Run 'ppm install {}' first.",
                    app_name_or_path,
                    full_exe.display(),
                    app_name_or_path
                ));
            }

            target_exe_path = Some(full_exe);

            // Apply default args
            if let Some(defaults) = &app_def.default_args {
                combined_args.extend(defaults.clone());
            }

            // Apply custom environment variables if declared
            if let Some(env_vars) = &app_def.env {
                for (k, v) in env_vars {
                    unsafe {
                        set_win32_env(k, v);
                    }
                }
            }
        }
    }

    let target_exe = match target_exe_path {
        Some(p) => p,
        None => {
            let direct_path = root.join(app_name_or_path);
            if direct_path.exists() {
                direct_path
            } else {
                PathBuf::from(app_name_or_path)
            }
        }
    };

    if !target_exe.exists() {
        return Err(format!(
            "Target executable not found: '{}'",
            target_exe.display()
        ));
    }

    combined_args.extend_from_slice(extra_args);

    // 2. Ensure .ppm/redirector.dll exists
    let redirector_dll = ensure_redirector_dll(root)?;
    let abs_dll = fs::canonicalize(&redirector_dll).unwrap_or(redirector_dll);
    let dll_str = abs_dll.to_string_lossy().replace(r"\\?\", "");

    let dll_cstr = CString::new(dll_str.as_bytes())
        .map_err(|e| format!("Invalid DLL path for Detours: {}", e))?;

    // 3. Set canonical Windows NT User Profile environment
    let home_dir = root.join("Home");
    let local_appdata = home_dir.join("AppData").join("Local");
    let roaming_appdata = home_dir.join("AppData").join("Roaming");
    let webview_runtime = root.join("Apps").join("WebView2");
    let webview_data = home_dir.join("AppData").join("WebViewData");

    let _ = fs::create_dir_all(&home_dir);
    let _ = fs::create_dir_all(&local_appdata);
    let _ = fs::create_dir_all(&roaming_appdata);
    let _ = fs::create_dir_all(&webview_data);

    let root_str = root.to_string_lossy().to_string();
    let target_exe_str = target_exe.to_string_lossy().to_string();
    let home_str = home_dir.to_string_lossy().to_string();
    let la_str = local_appdata.to_string_lossy().to_string();
    let ra_str = roaming_appdata.to_string_lossy().to_string();
    let wv_data_str = webview_data.to_string_lossy().to_string();

    unsafe {
        // Standard portable environment protocol
        set_win32_env("ELECTRON_NO_UPDATER", "1");
        set_win32_env("PORTABLE_EXECUTABLE_DIR", &root_str);
        set_win32_env("PORTABLE_EXECUTABLE_FILE", &target_exe_str);
        set_win32_env("PORTABLE_APP", "1");
        set_win32_env("PORTABLE_ROOT", &root_str);
        set_win32_env("PORTABLE_DEBUG", "1");

        // Canonical Profile Mappings
        set_win32_env("USERPROFILE", &home_str);
        set_win32_env("HOME", &home_str);
        set_win32_env("LOCALAPPDATA", &la_str);
        set_win32_env("APPDATA", &ra_str);

        if webview_runtime.exists() {
            let wv_rt_str = webview_runtime.to_string_lossy().to_string();
            set_win32_env("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", &wv_rt_str);
        }
        set_win32_env("WEBVIEW2_USER_DATA_FOLDER", &wv_data_str);
    }

    // 4. Build command line
    let mut cmd_line_str = format!("\"{}\"", target_exe_str);
    for arg in &combined_args {
        if arg.contains(' ') {
            cmd_line_str.push_str(&format!(" \"{}\"", arg));
        } else {
            cmd_line_str.push_str(&format!(" {}", arg));
        }
    }

    let app_name_w = to_wide_null(&target_exe_str);
    let mut cmd_line_w = to_wide_null(&cmd_line_str);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let success = unsafe {
        DetourCreateProcessWithDllExW(
            app_name_w.as_ptr(),
            cmd_line_w.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            FALSE,
            0,
            std::ptr::null(),
            std::ptr::null(),
            &mut si,
            &mut pi,
            dll_cstr.as_ptr() as *const u8,
            std::ptr::null(),
        )
    };

    if success == FALSE {
        let err = unsafe { GetLastError() };
        return Err(format!(
            "Failed to launch process with Detours injection! Error code: {}",
            err
        ));
    }

    let mut exit_code: u32 = 0;
    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Ok(exit_code as i32)
}
