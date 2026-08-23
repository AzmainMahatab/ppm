use crate::core::config::PostInstallConfig;
use std::fs;
use std::path::Path;

pub fn sanitize_package(
    target_dir: &Path,
    post_install: Option<&PostInstallConfig>,
) -> Result<(), String> {
    // 1. Universal portable sanitization: remove auto-updater manifest
    let auto_updater_yml = target_dir.join("resources").join("app-update.yml");
    if auto_updater_yml.exists() {
        fs::remove_file(&auto_updater_yml).map_err(|e| {
            format!(
                "Failed to remove auto-updater manifest '{}': {}",
                auto_updater_yml.display(),
                e
            )
        })?;
        println!("  ✓ Sanitized: Removed auto-updater manifest 'resources/app-update.yml'");
    }

    // 2. Custom post-install rules
    if let Some(cfg) = post_install {
        if let Some(files) = &cfg.remove_files {
            for file_rel in files {
                let target = target_dir.join(file_rel);
                if target.exists() {
                    fs::remove_file(&target).map_err(|e| {
                        format!("Failed to remove file '{}': {}", target.display(), e)
                    })?;
                    println!("  ✓ Removed file: {}", file_rel);
                }
            }
        }

        if let Some(dirs) = &cfg.remove_dirs {
            for dir_rel in dirs {
                let target = target_dir.join(dir_rel);
                if target.exists() {
                    fs::remove_dir_all(&target).map_err(|e| {
                        format!("Failed to remove directory '{}': {}", target.display(), e)
                    })?;
                    println!("  ✓ Removed directory: {}", dir_rel);
                }
            }
        }
    }

    Ok(())
}
