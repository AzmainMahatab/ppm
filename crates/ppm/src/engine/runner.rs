use crate::core::arch::CpuArch;
use crate::core::config::AppManifests;
use anyhow::{Result, bail};
use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
unsafe extern "C" {
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

type EnvironmentOverrides = [(String, String)];

// Intention: Merge app-specific overrides into an explicit child environment.
// Why: Edition 2024 makes mutating the parent process environment unsafe and racy; handing the
//      child a dedicated block keeps ppm's own process pristine and the launch reproducible.
fn build_child_environment(overrides: &EnvironmentOverrides) -> Vec<(String, String)> {
    let override_keys: HashSet<String> = overrides.iter().map(|(key, _)| key.to_uppercase()).collect();

    // Ex: A variable that cannot be represented as UTF-8 is excluded rather than aborting the
    //     launch; Windows environment blocks are UTF-16 and such names are pathological.
    let inherited = env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(key, _)| !override_keys.contains(&key.to_uppercase()));

    let mut merged: Vec<(String, String)> = inherited.collect();
    merged.extend(overrides.iter().cloned());
    merged.sort_by_key(|(key, _)| key.to_uppercase());

    merged
}

fn to_utf16_environment_block(entries: &[(String, String)]) -> Vec<u16> {
    let mut block = Vec::new();
    for (key, value) in entries {
        let entry = format!("{key}={value}");
        let entry_wide = OsStr::new(&entry).encode_wide().chain(std::iter::once(0));
        block.extend(entry_wide);
    }

    block.push(0);

    block
}

pub fn run_app(root: &Path, app_name_or_path: &str, user_args: &[String]) -> Result<i32> {
    let host_arch = CpuArch::current();

    // 1. Resolve executable and target directory
    let resolved = if is_direct_executable_path(app_name_or_path) {
        let raw_path = Path::new(app_name_or_path);
        let exe = resolve_executable_path(root, raw_path);
        let dir = exe.parent().unwrap_or(root).to_path_buf();
        ResolvedApp {
            exe_path: exe,
            app_dir: dir,
            env: None,
            default_args: None,
            arch: host_arch,
        }
    } else {
        resolve_managed_app(root, app_name_or_path, host_arch)?
    };

    let ResolvedApp {
        exe_path,
        app_dir,
        env: extra_env,
        default_args,
        arch: run_arch,
    } = resolved;

    if !exe_path.exists() {
        bail!(
            "Target binary does not exist at '{}' for architecture [{}]. Run 'ppm install {}' first.",
            exe_path.display(),
            run_arch.as_str(),
            app_name_or_path
        );
    }

    // 2. Setup Canonical Portable User Profile (%USERPROFILE%, %HOME%, %LOCALAPPDATA%, %APPDATA%)
    let home_dir = root.join("Home");
    let local_appdata = home_dir.join("AppData").join("Local");
    let roaming_appdata = home_dir.join("AppData").join("Roaming");
    let webview_data = home_dir.join("AppData").join("WebViewData");
    let documents_dir = home_dir.join("Documents");

    fs::create_dir_all(&local_appdata)?;
    fs::create_dir_all(&roaming_appdata)?;
    fs::create_dir_all(&webview_data)?;
    fs::create_dir_all(&documents_dir)?;

    let mut overrides: Vec<(String, String)> = vec![
        ("USERPROFILE".into(), path_to_env_value(&home_dir)),
        ("HOME".into(), path_to_env_value(&home_dir)),
        ("LOCALAPPDATA".into(), path_to_env_value(&local_appdata)),
        ("APPDATA".into(), path_to_env_value(&roaming_appdata)),
        (
            "WEBVIEW2_USER_DATA_FOLDER".into(),
            path_to_env_value(&webview_data),
        ),
        ("PORTABLE_APP".into(), "1".into()),
        ("ELECTRON_ENABLE_LOGGING".into(), "true".into()),
        ("PPM_ROOT".into(), path_to_env_value(root)),
    ];

    // Auto-detect WebView2 engine if present under Apps/<run_arch>/WebView2
    let webview2_dir = root.join("Apps").join(run_arch.as_str()).join("WebView2");
    let webview2_engine_present =
        webview2_dir.join("msedgewebview2.exe").is_file() || webview2_dir.join("msedge.exe").is_file();
    if webview2_engine_present {
        overrides.push((
            "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER".into(),
            path_to_env_value(&webview2_dir),
        ));
    }

    if let Some(extra) = extra_env {
        for (key, value) in extra {
            let expanded = value
                .replace("{root}", &root.to_string_lossy())
                .replace("{home}", &home_dir.to_string_lossy())
                .replace("{arch}", run_arch.as_str());
            overrides.push((key, expanded));
        }
    }

    let child_environment = build_child_environment(&overrides);

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
            return launch_with_detours(
                &exe_path,
                &app_dir,
                &final_args,
                &redirector_dll,
                &child_environment,
            );
        }
    }

    // Fallback standard launch
    let mut cmd = Command::new(&exe_path);
    cmd.current_dir(&app_dir);
    cmd.args(&final_args);
    cmd.envs(
        child_environment
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(0))
}

fn path_to_env_value(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

struct ResolvedApp {
    exe_path: std::path::PathBuf,
    app_dir: std::path::PathBuf,
    env: Option<std::collections::HashMap<String, String>>,
    default_args: Option<Vec<String>>,
    arch: CpuArch,
}

fn is_direct_executable_path(app_name_or_path: &str) -> bool {
    app_name_or_path.ends_with(".exe") || app_name_or_path.contains("\\") || app_name_or_path.contains('/')
}

fn resolve_executable_path(root: &Path, raw_path: &Path) -> std::path::PathBuf {
    if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        root.join(raw_path)
    }
}

fn resolve_managed_app(root: &Path, app_id: &str, host_arch: CpuArch) -> Result<ResolvedApp> {
    let manifest_path = root.join(".ppm").join("apps.json");
    let dev_manifest_path = root.join("manifests").join("apps.json");
    let path_to_load = if manifest_path.exists() {
        manifest_path
    } else {
        dev_manifest_path
    };

    let manifests = AppManifests::load_from_file(&path_to_load)?;
    let Some(app_def) = manifests.apps.get(app_id) else {
        bail!("Application '{app_id}' not found in apps.json");
    };

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

    verify_dependencies(&manifests, app_def, root, effective_arch)?;

    let exe = app_def.executable_for_arch(root, effective_arch);
    let dir = app_def.app_dir_for_arch(root, effective_arch);

    Ok(ResolvedApp {
        exe_path: exe,
        app_dir: dir,
        env: app_def.env.clone(),
        default_args: app_def.default_args.clone(),
        arch: effective_arch,
    })
}

fn verify_dependencies(
    manifests: &AppManifests,
    app_def: &crate::core::config::AppDefinition,
    root: &Path,
    arch: CpuArch,
) -> Result<()> {
    let Some(deps) = &app_def.dependencies else {
        return Ok(());
    };

    for dep in deps {
        let Some(dep_def) = manifests.apps.get(dep) else {
            continue;
        };
        if !dep_def.is_installed_for_arch(root, arch) {
            bail!(
                "Required dependency '{}' is not installed for [{}]. Run 'ppm install {}' first.",
                dep_def.name,
                arch.as_str(),
                dep
            );
        }
    }

    Ok(())
}

#[cfg(windows)]
fn launch_with_detours(
    exe_path: &Path,
    work_dir: &Path,
    args: &[String],
    dll_path: &Path,
    environment: &[(String, String)],
) -> Result<i32> {
    use std::ffi::CString;
    use std::mem::zeroed;
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, GetExitCodeProcess, GetStartupInfoW, INFINITE, PROCESS_INFORMATION,
        STARTUPINFOW, WaitForSingleObject,
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

    let mut environment_block = to_utf16_environment_block(environment);

    let dll_path_cstr = CString::new(dll_path.to_string_lossy().as_bytes())?;

    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        GetStartupInfoW(&mut si);
        let mut pi: PROCESS_INFORMATION = zeroed();

        let success = DetourCreateProcessWithDllExW(
            std::ptr::null(),
            cmd_line_wide.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            environment_block.as_mut_ptr().cast::<std::ffi::c_void>(),
            work_dir_wide.as_ptr(),
            std::ptr::from_mut(&mut si).cast::<std::ffi::c_void>(),
            std::ptr::from_mut(&mut pi).cast::<std::ffi::c_void>(),
            dll_path_cstr.as_ptr(),
            std::ptr::null_mut(),
        );

        if success == 0 {
            bail!(
                "DetourCreateProcessWithDllExW failed to launch '{}' with DLL '{}': {}",
                exe_path.display(),
                dll_path.display(),
                std::io::Error::last_os_error()
            );
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
