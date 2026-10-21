use crate::core::arch::CpuArch;
use crate::core::config::{AppDefinition, AppManifests};
use crate::package::pe_info::is_console_executable;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// How a launcher starts its application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStyle {
    /// `start` the application and let the launcher's console close: right for a GUI
    /// application, which has no output to show and whose exit code nobody waits for.
    Detached,
    /// Run the application in the launcher's console and exit with its exit code: right for a
    /// console application, whose output belongs in that console and whose exit code a calling
    /// script reads.
    Attached,
}

impl LaunchStyle {
    const ALL: [LaunchStyle; 2] = [LaunchStyle::Detached, LaunchStyle::Attached];
}

/// The launcher script for one application id.
///
/// # Why CRLF
/// cmd.exe reads batch files in CRLF line units; with bare LF it can mis-parse lines that
/// follow a parenthesized block, which this script has.
fn launcher_script(app_id: &str, style: LaunchStyle) -> String {
    let run = match style {
        LaunchStyle::Detached => format!("start \"\" \"%PPM_EXE%\" run {app_id} %*"),
        LaunchStyle::Attached => format!("\"%PPM_EXE%\" run {app_id} %*\r\nexit /b %ERRORLEVEL%"),
    };
    format!(
        "@echo off\r\n\
         setlocal\r\n\
         set \"PPM_EXE=%~dp0ppm.exe\"\r\n\
         if not exist \"%PPM_EXE%\" (\r\n\
         \x20   echo [ERROR] ppm.exe not found beside this launcher: %~dp0\r\n\
         \x20   pause\r\n\
         \x20   exit /b 1\r\n\
         )\r\n\
         {run}\r\n"
    )
}

fn launcher_path(root: &Path, app_id: &str) -> PathBuf {
    root.join(format!("{app_id}.bat"))
}

/// The style an installed application's launcher needs, from its executable's PE subsystem.
///
/// An executable whose headers cannot be read is launched detached - the style every launcher
/// used before styles existed - and the cause is logged.
fn launch_style(root: &Path, app: &AppDefinition) -> LaunchStyle {
    let Some(exe) = CpuArch::all()
        .iter()
        .map(|&arch| app.executable_for_arch(root, arch))
        .find(|exe| exe.is_file())
    else {
        return LaunchStyle::Detached;
    };
    match is_console_executable(&exe) {
        Ok(true) => LaunchStyle::Attached,
        Ok(false) => LaunchStyle::Detached,
        Err(error) => {
            tracing::warn!("{error:#}; its launcher starts it detached");
            LaunchStyle::Detached
        }
    }
}

/// Removes `app_id`'s launcher, returning whether one was removed.
///
/// # Why only an exact match is removed
/// The launcher lives in the root beside anything else the user keeps there. A `.bat` file of
/// the same name that is not byte-for-byte what `ppm` writes is the user's, not ours, and is
/// left untouched.
pub fn remove_launcher(root: &Path, app_id: &str) -> Result<bool> {
    let path = launcher_path(root, app_id);
    let contents = match fs::read(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("Failed to read '{}'", path.display())),
    };
    let generated = LaunchStyle::ALL
        .iter()
        .any(|&style| contents == launcher_script(app_id, style).as_bytes());
    if !generated {
        tracing::warn!(
            "Leaving '{}' in place: it is not a launcher ppm generated",
            path.display()
        );
        return Ok(false);
    }
    fs::remove_file(&path).with_context(|| format!("Failed to remove '{}'", path.display()))?;
    Ok(true)
}

/// Writes one application's launcher and returns its file name.
pub fn write_launcher(root: &Path, app_id: &str, app: &AppDefinition) -> Result<String> {
    let path = launcher_path(root, app_id);
    fs::write(&path, launcher_script(app_id, launch_style(root, app)))
        .with_context(|| format!("Failed to write launcher '{}'", path.display()))?;
    Ok(format!("{app_id}.bat"))
}

/// Brings the root's launchers in line with what is installed: one for every installed
/// application, and none - among those ppm generated - for an application that is not.
pub fn generate_launchers(root: &Path, manifests: &AppManifests) -> Result<Vec<String>> {
    let mut generated = Vec::new();
    for (app_id, app) in &manifests.apps {
        if app.is_installed_any_arch(root) {
            generated.push(write_launcher(root, app_id, app)?);
        } else if remove_launcher(root, app_id)? {
            tracing::info!("✓ Removed launcher {app_id}.bat: '{app_id}' is no longer installed");
        }
    }
    Ok(generated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest(executable: &str) -> AppManifests {
        serde_json::from_value(json!({ "apps": { "tool": {
            "name": "Tool",
            "target_dir": "Tool",
            "executable": executable,
            "version_check": {"type": "github_release", "repo": "o/r"},
            "package": {"type": "zip"}
        }}}))
        .expect("invariant: test manifest is schema-valid")
    }

    const GUI: u16 = 2;
    const CONSOLE: u16 = 3;

    /// Installs, as the manifest's x64 tool, an executable of the given PE subsystem.
    fn install(root: &Path, subsystem: u16) {
        let dir = root.join("Apps").join("x64").join("Tool");
        fs::create_dir_all(&dir).unwrap();
        crate::package::pe_info::write_test_executable(&dir.join("tool.exe"), subsystem);
    }

    #[test]
    fn a_console_tool_runs_attached_and_returns_its_exit_code() {
        let root = tempfile::tempdir().unwrap();
        install(root.path(), CONSOLE);

        let manifests = manifest("tool.exe");
        assert_eq!(
            generate_launchers(root.path(), &manifests).unwrap(),
            vec!["tool.bat"]
        );

        let script = fs::read_to_string(root.path().join("tool.bat")).unwrap();
        assert!(
            script.contains("\r\n\"%PPM_EXE%\" run tool %*\r\nexit /b %ERRORLEVEL%\r\n"),
            "{script}"
        );
        assert!(!script.contains("start "), "{script}");
        assert!(
            !script.replace("\r\n", "").contains('\n'),
            "every line ends in CRLF"
        );
    }

    #[test]
    fn a_gui_application_is_started_detached() {
        let root = tempfile::tempdir().unwrap();
        install(root.path(), GUI);

        generate_launchers(root.path(), &manifest("tool.exe")).unwrap();

        let script = fs::read_to_string(root.path().join("tool.bat")).unwrap();
        assert!(
            script.contains("\r\nstart \"\" \"%PPM_EXE%\" run tool %*\r\n"),
            "{script}"
        );
    }

    /// Regression: launchers were only ever written, so an uninstalled application kept a
    /// launcher that could only fail.
    #[test]
    fn a_launcher_for_an_application_no_longer_installed_is_removed() {
        let root = tempfile::tempdir().unwrap();
        install(root.path(), GUI);
        let manifests = manifest("tool.exe");
        generate_launchers(root.path(), &manifests).unwrap();

        fs::remove_dir_all(root.path().join("Apps")).unwrap();
        assert!(generate_launchers(root.path(), &manifests).unwrap().is_empty());

        assert!(!root.path().join("tool.bat").exists());
    }

    #[test]
    fn only_a_launcher_ppm_generated_is_removed() {
        let root = tempfile::tempdir().expect("tempdir");
        let user_script = root.path().join("tool.bat");
        fs::write(&user_script, b"@echo off\r\necho the user's own script\r\n").unwrap();

        assert!(!remove_launcher(root.path(), "tool").unwrap());
        assert!(
            user_script.exists(),
            "a same-named file ppm did not write is left alone"
        );

        // Generating over it is a deliberate `ppm link`, after which it is ours to remove.
        install(root.path(), GUI);
        generate_launchers(root.path(), &manifest("tool.exe")).unwrap();
        assert!(remove_launcher(root.path(), "tool").unwrap());
        assert!(!user_script.exists());

        assert!(!remove_launcher(root.path(), "absent").unwrap());
    }
}
