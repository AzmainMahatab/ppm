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

/// Writes one launcher and returns its file name.
fn write_launcher(root: &Path, app_id: &str) -> Result<String> {
    let bat_filename = format!("{app_id}.bat");
    let bat_path = root.join(&bat_filename);
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
}
