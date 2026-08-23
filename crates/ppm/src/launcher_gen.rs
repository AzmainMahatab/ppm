use crate::config::AppManifests;
use std::fs;
use std::path::Path;

pub fn generate_launchers(root: &Path, manifests: &AppManifests) -> Result<Vec<String>, String> {
    let mut generated = Vec::new();

    for (app_id, app_def) in &manifests.apps {
        if app_def.is_installed_any_arch(root) {
            let bat_filename = format!("{}.bat", app_id);
            let bat_path = root.join(&bat_filename);
            let bat_content = format!(
                "@echo off\r\nsetlocal\r\nstart \"\" \"%~dp0ppm.exe\" run {}\r\n",
                app_id
            );

            fs::write(&bat_path, bat_content)
                .map_err(|e| format!("Failed to write '{}': {}", bat_path.display(), e))?;

            generated.push(bat_filename);
        }
    }

    Ok(generated)
}

pub fn generate_single_launcher(root: &Path, app_id: &str) -> Result<(), String> {
    let bat_filename = format!("{}.bat", app_id);
    let bat_path = root.join(&bat_filename);
    let bat_content = format!(
        "@echo off\r\nsetlocal\r\nstart \"\" \"%~dp0ppm.exe\" run {}\r\n",
        app_id
    );

    fs::write(&bat_path, bat_content)
        .map_err(|e| format!("Failed to write '{}': {}", bat_path.display(), e))?;

    Ok(())
}
