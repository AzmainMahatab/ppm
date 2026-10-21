use crate::core::config::AppManifests;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// The launcher script for one application id.
///
/// # Why one builder
/// `generate_launchers` and `generate_single_launcher` each carried a full copy of this
/// template, so every change to the script had to be made twice or the two would drift.
fn launcher_script(app_id: &str) -> String {
    format!(
        "@echo off
        setlocal
        set \"ROOT_DIR=%~dp0\"
        set \"PPM_EXE=%ROOT_DIR%ppm.exe\"
        
        if not exist \"%PPM_EXE%\" (
            echo [ERROR] ppm.exe not found at root: %ROOT_DIR%
            pause
            exit /b 1
        )
        
        start \"\" \"%PPM_EXE%\" run {app_id} %*
        exit /b 0
"
    )
}

fn launcher_path(root: &Path, app_id: &str) -> std::path::PathBuf {
    root.join(format!("{app_id}.bat"))
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
    if contents != launcher_script(app_id).as_bytes() {
        tracing::warn!(
            "Leaving '{}' in place: it is not a launcher ppm generated",
            path.display()
        );
        return Ok(false);
    }
    fs::remove_file(&path).with_context(|| format!("Failed to remove '{}'", path.display()))?;
    Ok(true)
}

/// Writes one launcher and returns its file name.
fn write_launcher(root: &Path, app_id: &str) -> Result<String> {
    let bat_filename = format!("{app_id}.bat");
    let bat_path = launcher_path(root, app_id);
    fs::write(&bat_path, launcher_script(app_id))
        .with_context(|| format!("Failed to write launcher '{}'", bat_path.display()))?;
    Ok(bat_filename)
}

pub fn generate_launchers(root: &Path, manifests: &AppManifests) -> Result<Vec<String>> {
    let mut generated = Vec::new();

    for (app_id, app_def) in &manifests.apps {
        if app_def.is_installed_any_arch(root) {
            generated.push(write_launcher(root, app_id)?);
        }
    }

    Ok(generated)
}

pub fn generate_single_launcher(root: &Path, app_id: &str) -> Result<()> {
    write_launcher(root, app_id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_single_launcher_content() {
        let temp_dir = std::env::temp_dir().join(format!("ppm_test_launch_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        generate_single_launcher(&temp_dir, "myapp").expect("Should generate launcher");

        let bat_path = temp_dir.join("myapp.bat");
        assert!(bat_path.is_file(), "myapp.bat should be created");

        let content = fs::read_to_string(&bat_path).unwrap();
        assert!(content.contains("start \"\" \"%PPM_EXE%\" run myapp %*"));
        assert!(content.contains("set \"ROOT_DIR=%~dp0\""));

        let _ = fs::remove_file(&bat_path);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn only_a_launcher_ppm_generated_is_removed() {
        let root = tempfile::tempdir().expect("tempdir");
        generate_single_launcher(root.path(), "mine").unwrap();
        let user_script = root.path().join("theirs.bat");
        fs::write(&user_script, b"@echo off\r\necho the user's own script\r\n").unwrap();

        assert!(remove_launcher(root.path(), "mine").unwrap());
        assert!(!root.path().join("mine.bat").exists());

        assert!(!remove_launcher(root.path(), "theirs").unwrap());
        assert!(user_script.exists(), "a same-named file ppm did not write is left alone");

        assert!(!remove_launcher(root.path(), "absent").unwrap());
    }
}
