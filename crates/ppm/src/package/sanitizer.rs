use crate::core::config::PostInstallConfig;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn sanitize_package(target_dir: &Path, post_install: Option<&PostInstallConfig>) -> Result<()> {
    // 1. Universal portable sanitization: remove auto-updater manifest
    let auto_updater_yml = target_dir.join("resources").join("app-update.yml");
    if auto_updater_yml.exists() {
        fs::remove_file(&auto_updater_yml)?;
        println!("  ✓ Sanitized: Removed auto-updater manifest 'resources/app-update.yml'");
    }

    // 2. Custom post-install rules
    if let Some(cfg) = post_install {
        if let Some(files) = &cfg.remove_files {
            for file_rel in files {
                let target = target_dir.join(file_rel);
                if target.exists() {
                    fs::remove_file(&target)?;
                    println!("  ✓ Removed file: {}", file_rel);
                }
            }
        }

        if let Some(dirs) = &cfg.remove_dirs {
            for dir_rel in dirs {
                let target = target_dir.join(dir_rel);
                if target.exists() {
                    fs::remove_dir_all(&target)?;
                    println!("  ✓ Removed directory: {}", dir_rel);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn post_install(value: serde_json::Value) -> PostInstallConfig {
        serde_json::from_value(value).expect("invariant: test post-install config is schema-valid")
    }

    #[test]
    fn removes_auto_updater_manifest_and_custom_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let updater = dir.path().join("resources").join("app-update.yml");
        std::fs::create_dir_all(updater.parent().unwrap()).unwrap();
        std::fs::write(&updater, b"update: true").unwrap();
        let stale_dir = dir.path().join("cache").join("stale.tmp");
        std::fs::create_dir_all(&stale_dir).unwrap();
        std::fs::write(dir.path().join("telemetry.dll"), b"x").unwrap();

        let cfg = post_install(json!({
            "remove_files": ["telemetry.dll"],
            "remove_dirs": ["cache/stale.tmp"]
        }));
        sanitize_package(dir.path(), Some(&cfg)).unwrap();

        assert!(!updater.exists(), "auto-updater manifest must be removed");
        assert!(!dir.path().join("telemetry.dll").exists());
        assert!(!stale_dir.exists());
    }

    #[test]
    fn absent_targets_are_tolerated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = post_install(json!({
            "remove_files": ["does-not-exist.dll"],
            "remove_dirs": ["does-not-exist-dir"]
        }));

        sanitize_package(dir.path(), Some(&cfg)).unwrap();

        assert!(dir.path().exists());
    }

    #[test]
    fn no_post_install_section_is_a_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("keep.txt");
        std::fs::write(&marker, b"x").unwrap();

        sanitize_package(dir.path(), None).unwrap();

        assert!(marker.exists());
    }
}
