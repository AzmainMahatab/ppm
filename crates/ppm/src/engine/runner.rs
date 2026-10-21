use crate::core::arch::CpuArch;
use crate::core::config::AppManifests;
use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

type EnvironmentOverrides = [(String, String)];

// Intention: Merge app-specific overrides into an explicit child environment.
// Why: Edition 2024 makes mutating the parent process environment unsafe and racy; handing the
//      child a dedicated block keeps ppm's own process pristine and the launch reproducible.
fn build_child_environment(overrides: &EnvironmentOverrides) -> Vec<(String, String)> {
    // Ex: A variable that cannot be represented as UTF-8 is excluded rather than aborting the
    //     launch; Windows environment blocks are UTF-16 and such names are pathological.
    let inherited =
        env::vars_os().filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)));
    merge_child_environment(inherited, overrides)
}

/// Keeps, for each case-insensitive key, the LAST occurrence - the precedence rule that
/// shields core vars and lets app env beat `global_env` - preserving final order.
fn dedup_env_last_wins(entries: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut winners: HashMap<String, usize> = HashMap::new();
    for (index, (key, _)) in entries.iter().enumerate() {
        winners.insert(key.to_uppercase(), index);
    }
    entries
        .into_iter()
        .enumerate()
        .filter(|(index, (key, _))| winners.get(&key.to_uppercase()) == Some(index))
        .map(|(_, entry)| entry)
        .collect()
}

fn merge_child_environment(
    inherited: impl Iterator<Item = (String, String)>,
    overrides: &EnvironmentOverrides,
) -> Vec<(String, String)> {
    let override_keys: HashSet<String> = overrides.iter().map(|(key, _)| key.to_uppercase()).collect();

    let inherited = inherited.filter(|(key, _)| !override_keys.contains(&key.to_uppercase()));

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
            manifests: None,
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
        manifests,
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

    // Env precedence (highest wins):
    //   1. Portable core vars (USERPROFILE, HOME, LOCALAPPDATA, APPDATA, PPM_ROOT,
    //      PPM_APP_NAME) - these *are* the isolation boundary; a manifest redefinition
    //      would silently break virtualization, so they shield against all config.
    //   2. The launching app's `env` - specific beats general.
    //   3. `global_env` from every manifest entry - injected on any launch so an engine
    //      entry (e.g. webview2) can provision its SDK vars from its own block.
    // Order below is lowest to highest; `dedup_env_last_wins` makes later entries win
    // key conflicts case-insensitively, which also removes duplicate env-block keys.
    let mut overrides: Vec<(String, String)> = Vec::new();

    let expand = expand_templates(root, &home_dir, run_arch);
    overrides.extend(collect_global_env(manifests.as_deref(), &expand));

    if let Some(extra) = extra_env {
        for (key, value) in extra {
            overrides.push((key, expand(&value)));
        }
    }

    overrides.extend([
        ("USERPROFILE".to_string(), path_to_env_value(&home_dir)),
        ("HOME".to_string(), path_to_env_value(&home_dir)),
        ("LOCALAPPDATA".to_string(), path_to_env_value(&local_appdata)),
        ("APPDATA".to_string(), path_to_env_value(&roaming_appdata)),
        ("PPM_ROOT".to_string(), path_to_env_value(root)),
        // Intention: Identify the virtualized app to the redirector so the child's process
        // identity (AUMID) is derived dynamically - see redirector shell::init_hooks.
        ("PPM_APP_NAME".to_string(), app_name_or_path.to_string()),
    ]);

    let overrides = dedup_env_last_wins(overrides);
    let child_environment = build_child_environment(&overrides);

    // 3. Prepare arguments
    let mut final_args = Vec::new();
    if let Some(def_args) = default_args {
        final_args.extend(def_args);
    }
    final_args.extend(user_args.to_vec());

    // 4. Launch with the engine for the application's machine injected
    let engine_lib_dir = crate::core::layout::PortableLayout::new(root).engine_lib_dir();
    launch_injected(
        &exe_path,
        &app_dir,
        &final_args,
        &engine_lib_dir,
        &child_environment,
    )
    .with_context(|| format!("Refusing to launch '{app_name_or_path}' unvirtualized"))
}

fn path_to_env_value(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

struct ResolvedApp {
    /// The full manifest the app resolved from; `None` for direct exe paths, which carry
    /// no manifest and therefore contribute no `global_env`. Boxed: read once per launch.
    manifests: Option<Box<AppManifests>>,
    exe_path: std::path::PathBuf,
    app_dir: std::path::PathBuf,
    env: Option<std::collections::BTreeMap<String, String>>,
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

/// Produces the value-expander for manifest env templates: `{root}`, `{home}`, `{arch}`.
fn expand_templates<'a>(root: &Path, home_dir: &Path, arch: CpuArch) -> impl Fn(&str) -> String + 'a {
    let root_s = root.to_string_lossy().into_owned();
    let home_s = home_dir.to_string_lossy().into_owned();
    let arch_s = arch.as_str().to_owned();
    move |value: &str| {
        value
            .replace("{root}", &root_s)
            .replace("{home}", &home_s)
            .replace("{arch}", &arch_s)
    }
}

/// Gathers `global_env` from every manifest entry. Returns pairs in manifest order;
/// later entries win key conflicts case-insensitively (deduplicated downstream).
fn collect_global_env(
    manifests: Option<&AppManifests>,
    expand: &impl Fn(&str) -> String,
) -> Vec<(String, String)> {
    let Some(manifests) = manifests else {
        return Vec::new();
    };
    manifests
        .apps
        .values()
        .filter_map(|def| def.global_env.as_ref())
        .flat_map(|global| {
            global
                .iter()
                .map(move |(key, value)| (key.clone(), expand(value)))
        })
        .collect()
}

fn resolve_managed_app(root: &Path, app_id: &str, host_arch: CpuArch) -> Result<ResolvedApp> {
    let layout = crate::core::layout::PortableLayout::new(root);
    let Some(manifest_path) = layout.manifest_source() else {
        bail!(
            "Manifest file not found at '{}'. Run 'ppm init' to generate default configuration.",
            layout.deployed_manifest().display()
        );
    };

    let manifests = AppManifests::load_from_file(&manifest_path)?;
    let Some(app_def) = manifests.apps.get(app_id) else {
        bail!("Application '{app_id}' not found in apps.json");
    };

    // Determine effective architecture: prefer native host arch, fallback to x64 on ARM64 if available
    let effective_arch = if app_def.is_installed_for_arch(root, host_arch) {
        host_arch
    } else if host_arch == CpuArch::Arm64 && app_def.is_installed_for_arch(root, CpuArch::X64) {
        tracing::info!(
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

    // Detach the app's own fields before moving `manifests` into the box: `app_def`
    // borrows the manifest, so a move while borrowed would not compile.
    let app_env = app_def.env.clone();
    let app_default_args = app_def.default_args.clone();

    Ok(ResolvedApp {
        manifests: Some(Box::new(manifests)),
        exe_path: exe,
        app_dir: dir,
        env: app_env,
        default_args: app_default_args,
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
        let dep_def = manifests
            .apps
            .get(dep)
            .expect("invariant: AppManifests::load_from_file rejects undefined dependencies");
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

/// Starts `exe_path` with the engine for its machine injected, waits for it, and returns its
/// exit code.
///
/// # Why the process is created suspended and injected afterwards
/// Which engine build an application needs depends on the machine it runs as - an x86 tool, or
/// an x64 application emulated on an ARM64 host - and only the created process can say which.
/// Nothing of the application runs before the engine is in place, and a process that cannot be
/// injected is terminated before its first instruction: an unvirtualized launch would write to
/// the real registry and profile while `ppm run` reported success (ADR-006).
fn launch_injected(
    exe_path: &Path,
    work_dir: &Path,
    args: &[String],
    engine_lib_dir: &Path,
    environment: &[(String, String)],
) -> Result<i32> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess, GetStartupInfoW,
        INFINITE, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
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
    let work_dir_wide: Vec<u16> = work_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut environment_block = to_utf16_environment_block(environment);

    // SAFETY: zeroed STARTUPINFOW/PROCESS_INFORMATION are valid initial states; every buffer
    // passed below is NUL-terminated and outlives the call.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    unsafe { GetStartupInfoW(&mut startup) };
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_line_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            environment_block.as_mut_ptr().cast(),
            work_dir_wide.as_ptr(),
            &startup,
            &mut info,
        )
    };
    if created == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to create '{}'", exe_path.display()));
    }
    // SAFETY: a successful create hands over ownership of both handles.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };

    // SAFETY: the process is suspended and `process` is a full-access handle to `info.dwProcessId`;
    // CreateProcessW is the helper launcher Detours expects.
    let injected = unsafe {
        injection::inject_suspended(
            process.as_raw_handle(),
            info.dwProcessId,
            engine_lib_dir,
            CreateProcessW as *const std::ffi::c_void,
        )
    };
    let machine = match injected {
        Ok(machine) => machine,
        Err(error) => {
            // SAFETY: terminating the suspended process this function created; it never ran.
            unsafe { TerminateProcess(process.as_raw_handle(), 1) };
            return Err(error)
                .with_context(|| format!("Cannot inject the engine into '{}'", exe_path.display()));
        }
    };
    tracing::debug!("Injected the {machine} engine into '{}'", exe_path.display());

    // ResumeThread reports failure as (DWORD)-1; zero is the valid previous suspend count.
    // SAFETY: resuming the thread this function created suspended.
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        let cause = std::io::Error::last_os_error();
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        return Err(cause).with_context(|| format!("Failed to start '{}'", exe_path.display()));
    }
    drop(thread);

    // A failed wait or exit-code query must not surface as a fabricated success exit code; both
    // are environmental failures and report with full context.
    // SAFETY: waiting on and querying the live process handle this function owns.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to wait for '{}'", exe_path.display()));
    }
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit_code) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to read the exit code of '{}'", exe_path.display()));
    }
    // Why the reinterpreting cast: Windows exit codes are 32-bit values that `std::process::exit`
    // takes as i32; NTSTATUS-style codes keep their bit pattern.
    Ok(exit_code as i32)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::{AppDefinition, PackageConfig, PackageKind, VersionCheckConfig};

    #[test]
    fn collect_global_env_gathers_all_entries_and_expands_templates() {
        let manifests = AppManifests {
            schema: None,
            apps: [
                (
                    "webview2".to_string(),
                    AppDefinition {
                        name: "WebView2".to_string(),
                        description: None,
                        homepage: None,
                        target_dir: "WebView2".to_string(),
                        executable: "msedgewebview2.exe".to_string(),
                        supported_arch: None,
                        default_args: None,
                        dependencies: None,
                        env: None,
                        global_env: Some(std::collections::BTreeMap::from([(
                            "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER".to_string(),
                            "{root}/Apps/{arch}/WebView2".to_string(),
                        )])),
                        version_check: VersionCheckConfig::GitHubRelease {
                            repo: "a/b".to_string(),
                            asset_pattern: None,
                        },
                        package: PackageConfig {
                            kind: PackageKind::Zip,
                            extract_subpath: None,
                        },
                        post_install: None,
                    },
                ),
                (
                    "plain-app".to_string(),
                    AppDefinition {
                        name: "Plain".to_string(),
                        description: None,
                        homepage: None,
                        target_dir: "Plain".to_string(),
                        executable: "plain.exe".to_string(),
                        supported_arch: None,
                        default_args: None,
                        dependencies: None,
                        env: None,
                        global_env: None,
                        version_check: VersionCheckConfig::GitHubRelease {
                            repo: "a/b".to_string(),
                            asset_pattern: None,
                        },
                        package: PackageConfig {
                            kind: PackageKind::Zip,
                            extract_subpath: None,
                        },
                        post_install: None,
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        let expand = |v: &str| v.replace("{root}", "C:/Portable").replace("{arch}", "x64");
        let collected = collect_global_env(Some(&manifests), &expand);

        // Entries without global_env contribute nothing; webview2's block expands.
        assert_eq!(
            collected,
            vec![(
                "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER".to_string(),
                "C:/Portable/Apps/x64/WebView2".to_string()
            )]
        );
    }

    #[test]
    fn last_wins_dedup_shields_core_vars_and_prefers_app_env() {
        let entries = vec![
            (
                "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER".to_string(),
                "global".to_string(),
            ),
            ("userprofile".to_string(), "C:/Evil".to_string()),
            ("CUSTOM".to_string(), "global-value".to_string()),
            ("custom".to_string(), "app-value".to_string()),
        ];

        let deduped = dedup_env_last_wins(entries);

        let get = |k: &str| {
            deduped
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
                .expect("key must survive dedup")
        };

        // Core vars shield (last entry wins over earlier redefinitions) ...
        assert_eq!(get("USERPROFILE"), "C:/Evil");
        // ... and the launching app's env beats global_env for the same key.
        assert_eq!(get("CUSTOM"), "app-value");
        // One entry per case-insensitive key survives.
        assert_eq!(deduped.len(), 3);
    }

    #[test]
    fn overrides_replace_inherited_keys_case_insensitively() {
        let inherited = [
            ("PATH".to_string(), "host".to_string()),
            ("KEEP".to_string(), "1".to_string()),
        ];
        let overrides = [("path".to_string(), "portable".to_string())];

        let merged = merge_child_environment(inherited.into_iter(), &overrides);

        assert_eq!(
            merged,
            vec![
                ("KEEP".to_string(), "1".to_string()),
                ("path".to_string(), "portable".to_string())
            ]
        );
    }

    #[test]
    fn merged_output_is_case_insensitively_sorted() {
        let inherited = [
            ("b".to_string(), "1".to_string()),
            ("A".to_string(), "2".to_string()),
        ];

        let merged = merge_child_environment(inherited.into_iter(), &[]);

        assert_eq!(
            merged,
            vec![
                ("A".to_string(), "2".to_string()),
                ("b".to_string(), "1".to_string())
            ]
        );
    }

    #[test]
    fn environment_block_is_nul_terminated_per_entry_and_overall() {
        let block = to_utf16_environment_block(&[
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ]);

        let text: String = String::from_utf16_lossy(&block);
        assert_eq!(text, "A=1\0B=2\0\0");
    }
}
