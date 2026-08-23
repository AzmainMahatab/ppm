use crate::core::config::AppManifests;
use std::fs;
use std::path::Path;

pub fn generate_launchers(root: &Path, manifests: &AppManifests) -> Result<Vec<String>, String> {
    let mut generated = Vec::new();

    for (app_id, app_def) in &manifests.apps {
        if app_def.is_installed_any_arch(root) {
            let bat_filename = format!("{}.bat", app_id);
            let bat_path = root.join(&bat_filename);

            let content = format!(
                "@echo off\r\n\
                setlocal\r\n\
                set \"ROOT_DIR=%~dp0\"\r\n\
                set \"PPM_EXE=%ROOT_DIR%ppm.exe\"\r\n\
                \r\n\
                if not exist \"%PPM_EXE%\" (\r\n\
                    echo [ERROR] ppm.exe not found at root: %ROOT_DIR%\r\n\
                    pause\r\n\
                    exit /b 1\r\n\
                )\r\n\
                \r\n\
                start \"\" \"%PPM_EXE%\" run {} %*\r\n\
                exit /b 0\r\n",
                app_id
            );

            fs::write(&bat_path, content)
                .map_err(|e| format!("Failed to write launcher '{}': {}", bat_path.display(), e))?;

            generated.push(bat_filename);
        }
    }

    Ok(generated)
}

pub fn generate_single_launcher(root: &Path, app_id: &str) -> Result<(), String> {
    let bat_filename = format!("{}.bat", app_id);
    let bat_path = root.join(&bat_filename);

    let content = format!(
        "@echo off\r\n\
        setlocal\r\n\
        set \"ROOT_DIR=%~dp0\"\r\n\
        set \"PPM_EXE=%ROOT_DIR%ppm.exe\"\r\n\
        \r\n\
        if not exist \"%PPM_EXE%\" (\r\n\
            echo [ERROR] ppm.exe not found at root: %ROOT_DIR%\r\n\
            pause\r\n\
            exit /b 1\r\n\
        )\r\n\
        \r\n\
        start \"\" \"%PPM_EXE%\" run {} %*\r\n\
        exit /b 0\r\n",
        app_id
    );

    fs::write(&bat_path, content)
        .map_err(|e| format!("Failed to write launcher '{}': {}", bat_path.display(), e))?;

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
