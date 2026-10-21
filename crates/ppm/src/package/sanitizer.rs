use crate::core::config::PostInstallConfig;
use crate::core::relpath::confined;
use anyhow::{Context, Result};
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
    let Some(cfg) = post_install else {
        return Ok(());
    };

    for file_rel in cfg.remove_files.iter().flatten() {
        let target = target_dir.join(confined(file_rel)?);
        if target.exists() {
            fs::remove_file(&target).with_context(|| format!("Failed to remove '{}'", target.display()))?;
            println!("  ✓ Removed file: {}", file_rel);
        }
    }

    for dir_rel in cfg.remove_dirs.iter().flatten() {
        let target = target_dir.join(confined(dir_rel)?);
        if target.exists() {
            fs::remove_dir_all(&target)
                .with_context(|| format!("Failed to remove '{}'", target.display()))?;
            println!("  ✓ Removed directory: {}", dir_rel);
        }
    }

    for dir_rel in cfg.create_dirs.iter().flatten() {
        let target = target_dir.join(confined(dir_rel)?);
        fs::create_dir_all(&target).with_context(|| format!("Failed to create '{}'", target.display()))?;
        println!("  ✓ Created directory: {}", dir_rel);
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
            "remove_dirs": ["cache/stale.tmp"],
            "create_dirs": ["data/portable"]
        }));
        sanitize_package(dir.path(), Some(&cfg)).unwrap();

        assert!(!updater.exists(), "auto-updater manifest must be removed");
        assert!(!dir.path().join("telemetry.dll").exists());
        assert!(!stale_dir.exists());
        // Regression: `create_dirs` was accepted by the schema but never applied.
        assert!(dir.path().join("data").join("portable").is_dir());
    }

    /// Regression: rules were joined unchecked, so `..` or an absolute path removed files
    /// outside the installation.
    #[test]
    fn a_rule_that_escapes_the_installation_is_refused_and_touches_nothing() {
        let outer = tempfile::tempdir().expect("tempdir");
        let install = outer.path().join("App");
        std::fs::create_dir_all(&install).unwrap();
        let bystander = outer.path().join("bystander.txt");
        std::fs::write(&bystander, b"x").unwrap();

        let cfg = post_install(json!({ "remove_files": ["../bystander.txt"] }));
        assert!(sanitize_package(&install, Some(&cfg)).is_err());

        let absolute = bystander.to_string_lossy().into_owned();
        let cfg = post_install(json!({ "remove_files": [absolute] }));
        assert!(sanitize_package(&install, Some(&cfg)).is_err());

        assert!(bystander.exists());
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
