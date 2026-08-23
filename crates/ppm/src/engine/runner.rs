use crate::core::arch::CpuArch;
use crate::core::config::AppManifests;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
extern "C" {
    fn DetourCreateProcessWithDllExW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut std::ffi::c_void,
        lpThreadAttributes: *mut std::ffi::c_void,
        bInheritHandles: i32,
        dwCreationFlags: u32,
        lpEnvironment: *mut std::ffi::c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut std::ffi::c_void,
        lpProcessInformation: *mut std::ffi::c_void,
        lpDllName: *const std::ffi::c_char,
        pfCreateProcessW: *mut std::ffi::c_void,
    ) -> i32;
}

pub fn run_app(root: &Path, app_name_or_path: &str, user_args: &[String]) -> Result<i32, String> {
    let host_arch = CpuArch::current();

    // 1. Resolve executable and target directory
    let (exe_path, app_dir, extra_env, default_args, run_arch) = if app_name_or_path.ends_with(".exe")
        || app_name_or_path.contains('\\')
        || app_name_or_path.contains('/')
    {
        let raw_path = Path::new(app_name_or_path);
        let resolved = if raw_path.is_absolute() {
            raw_path.to_path_buf()
        } else {
            root.join(raw_path)
        };
        let dir = resolved.parent().unwrap_or(root).to_path_buf();
        (resolved, dir, None, None, host_arch)
    } else {
        let manifest_path = root.join(".ppm").join("apps.json");
        let dev_manifest_path = root.join("manifests").join("apps.json");
        let path_to_load = if manifest_path.exists() {
            manifest_path
        } else {
            dev_manifest_path
        };

        let manifests = AppManifests::load_from_file(&path_to_load)?;
        let app_def = manifests
            .apps
            .get(app_name_or_path)
            .ok_or_else(|| format!("Application '{}' not found in apps.json", app_name_or_path))?;

        // Determine effective architecture: prefer native host arch, fallback to x64 on ARM64 if available
        let effective_arch = if app_def.is_installed_for_arch(root, host_arch) {
            host_arch
        } else if host_arch == CpuArch::Arm64 && app_def.is_installed_for_arch(root, CpuArch::X64) {
            println!(
                "[INFO] Native ARM64 binary not found for '{}'. Launching x64 version via Windows ARM64 emulation...",
                app_def.name
            );
            CpuArch::X64
        } else {
            host_arch
        };

        // Verify dependencies
        if let Some(deps) = &app_def.dependencies {
            for dep in deps {
                if let Some(dep_def) = manifests.apps.get(dep) {
                    if !dep_def.is_installed_for_arch(root, effective_arch) {
                        return Err(format!(
                            "Required dependency '{}' is not installed for [{}]. Run 'ppm install {}' first.",
                            dep_def.name,
                            effective_arch.as_str(),
                            dep
                        ));
                    }
                }
            }
        }

        let exe = app_def.executable_for_arch(root, effective_arch);
        let dir = app_def.app_dir_for_arch(root, effective_arch);
        (
            exe,
            dir,
            app_def.env.clone(),
            app_def.default_args.clone(),
            effective_arch,
        )
    };

    if !exe_path.exists() {
        return Err(format!(
            "Target binary does not exist at '{}' for architecture [{}]. Run 'ppm install {}' first.",
            exe_path.display(),
            run_arch.as_str(),
            app_name_or_path
        ));
    }

    // 2. Setup Canonical Portable User Profile (%USERPROFILE%, %HOME%, %LOCALAPPDATA%, %APPDATA%)
    let home_dir = root.join("Home");
    let local_appdata = home_dir.join("AppData").join("Local");
    let roaming_appdata = home_dir.join("AppData").join("Roaming");
    let webview_data = home_dir.join("AppData").join("WebViewData");
    let documents_dir = home_dir.join("Documents");

    let _ = fs::create_dir_all(&local_appdata);
    let _ = fs::create_dir_all(&roaming_appdata);
    let _ = fs::create_dir_all(&webview_data);
    let _ = fs::create_dir_all(&documents_dir);

    env::set_var("USERPROFILE", &home_dir);
    env::set_var("HOME", &home_dir);
    env::set_var("LOCALAPPDATA", &local_appdata);
    env::set_var("APPDATA", &roaming_appdata);
    env::set_var("WEBVIEW2_USER_DATA_FOLDER", &webview_data);

    // Auto-detect WebView2 engine if present under Apps/<run_arch>/WebView2
    let webview2_exe = root
        .join("Apps")
        .join(run_arch.as_str())
        .join("WebView2")
        .join("msedge.exe");
    if webview2_exe.is_file() {
        let webview2_dir = webview2_exe.parent().unwrap();
        env::set_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", webview2_dir);
    }

    env::set_var("PORTABLE_APP", "1");
    env::set_var("ELECTRON_ENABLE_LOGGING", "true");
    env::set_var("PPM_ROOT", root);

    if let Some(extra) = extra_env {
        for (k, v) in extra {
            let expanded = v
                .replace("{root}", &root.to_string_lossy())
                .replace("{home}", &home_dir.to_string_lossy())
                .replace("{arch}", run_arch.as_str());
            env::set_var(k, expanded);
        }
    }

    // 3. Prepare arguments
    let mut final_args = Vec::new();
    if let Some(def_args) = default_args {
        final_args.extend(def_args);
    }
    final_args.extend(user_args.to_vec());

    // 4. Check for redirector DLL at .ppm/lib/redirector.dll
    let redirector_dll = root.join(".ppm").join("lib").join("redirector.dll");

    #[cfg(windows)]
    {
        if redirector_dll.exists() {
            return launch_with_detours(&exe_path, &app_dir, &final_args, &redirector_dll);
        }
    }

    // Fallback standard launch
    let mut cmd = Command::new(&exe_path);
    cmd.current_dir(&app_dir);
    cmd.args(&final_args);

    let status = cmd
        .status()
        .map_err(|e| format!("Failed to spawn process '{}': {}", exe_path.display(), e))?;

    Ok(status.code().unwrap_or(0))
}

#[cfg(windows)]
fn launch_with_detours(
    exe_path: &Path,
    work_dir: &Path,
    args: &[String],
    dll_path: &Path,
) -> Result<i32, String> {
    use std::ffi::CString;
    use std::mem::zeroed;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let mut cmd_line_str = format!("\"{}\"", exe_path.display());
    for arg in args {
        cmd_line_str.push(' ');
        cmd_line_str.push_str(&quote_win32_arg(arg));
    }

    let mut cmd_line_wide: Vec<u16> = OsStr::new(&cmd_line_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let work_dir_wide: Vec<u16> = OsStr::new(work_dir)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let dll_path_cstr = CString::new(dll_path.to_string_lossy().as_bytes())
        .map_err(|e| format!("Invalid DLL path encoding: {}", e))?;

    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();

        let success = DetourCreateProcessWithDllExW(
            std::ptr::null(),
            cmd_line_wide.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null_mut(),
            work_dir_wide.as_ptr(),
            &mut si as *mut _ as *mut std::ffi::c_void,
            &mut pi as *mut _ as *mut std::ffi::c_void,
            dll_path_cstr.as_ptr(),
            std::ptr::null_mut(),
        );

        if success == 0 {
            return Err(format!(
                "DetourCreateProcessWithDllExW failed to launch '{}' with DLL '{}'",
                exe_path.display(),
                dll_path.display()
            ));
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        let mut exit_code = 0u32;
        GetExitCodeProcess(pi.hProcess, &mut exit_code);

        windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
        windows_sys::Win32::Foundation::CloseHandle(pi.hThread);

        Ok(exit_code as i32)
    }
}

#[cfg(windows)]
fn quote_win32_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..backslashes * 2 + 1 {
                    quoted.push('\\');
                }
                backslashes = 0;
                quoted.push('"');
            }
            _ => {
                for _ in 0..backslashes {
                    quoted.push('\\');
                }
                backslashes = 0;
                quoted.push(c);
            }
        }
    }
    for _ in 0..backslashes * 2 {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}
