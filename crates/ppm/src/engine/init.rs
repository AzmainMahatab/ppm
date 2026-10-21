use crate::core::assets::{DEFAULT_APPS_JSON, EMBEDDED_REDIRECTOR_DLL};
use crate::core::layout::PortableLayout;
use crate::core::schema::write_schema_artifacts;
use anyhow::{Context, bail};
use std::fs;
use std::path::Path;

pub fn init_environment(root: &Path) -> anyhow::Result<()> {
    scaffold_directories(root)?;
    extract_redirector_dll(root)?;
    ensure_default_config(root)?;
    regenerate_schema(root)?;

    Ok(())
}

fn scaffold_directories(root: &Path) -> anyhow::Result<()> {
    let ppm_dir = root.join(".ppm");
    let home_dir = root.join("Home");

    let directories = [
        ppm_dir.join("system"),
        ppm_dir.join("lib"),
        ppm_dir.join("cache"),
        ppm_dir.join("logs"),
        root.join("Apps").join("x64"),
        root.join("Apps").join("arm64"),
        home_dir.join("AppData").join("Local"),
        home_dir.join("AppData").join("Roaming"),
        home_dir.join("AppData").join("WebViewData"),
        home_dir.join("Documents"),
    ];

    for directory in &directories {
        fs::create_dir_all(directory)
            .with_context(|| format!("Failed to scaffold directory '{}'", directory.display()))?;
    }

    Ok(())
}

// Intention: Unconditionally deploy a fresh copy of the virtualization engine DLL.
// Why: A previously extracted 0-byte or stale DLL must never survive an `init`; the embedded
//      artifact is rebuilt by Cargo on every redirector change and always reflects ground truth.
fn extract_redirector_dll(root: &Path) -> anyhow::Result<()> {
    if EMBEDDED_REDIRECTOR_DLL.is_empty() {
        bail!("Embedded redirector.dll is empty; the build did not capture a valid redirector artifact");
    }

    let dll_path = root.join(".ppm").join("lib").join("redirector.dll");
    fs::write(&dll_path, EMBEDDED_REDIRECTOR_DLL)
        .with_context(|| format!("Failed to deploy '{}'", dll_path.display()))?;

    tracing::info!("✓ Deployed .ppm/lib/redirector.dll");

    Ok(())
}

// Intention: Seed configuration exactly once; user-authored manifests are authoritative.
fn ensure_default_config(root: &Path) -> anyhow::Result<()> {
    let apps_json_path = PortableLayout::new(root).deployed_manifest();
    let config_is_absent = !apps_json_path.exists();

    if config_is_absent {
        fs::write(&apps_json_path, DEFAULT_APPS_JSON)
            .with_context(|| format!("Failed to initialize '{}'", apps_json_path.display()))?;
        tracing::info!("✓ Initialized .ppm/apps.json (default configuration)");
    }

    Ok(())
}

// Intention: Always regenerate schema artifacts so they can never drift from the code-defined model.
fn regenerate_schema(root: &Path) -> anyhow::Result<()> {
    write_schema_artifacts(root)?;
    tracing::info!("✓ Regenerated apps.schema.json");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_scaffolds_directories_deploys_engine_and_seeds_config() {
        let root = tempfile::tempdir().expect("tempdir");

        init_environment(root.path()).unwrap();

        for dir in [
            ".ppm/system",
            ".ppm/lib",
            ".ppm/cache",
            ".ppm/logs",
            "Apps/x64",
            "Apps/arm64",
            "Home/AppData/Local",
            "Home/AppData/Roaming",
            "Home/AppData/WebViewData",
            "Home/Documents",
        ] {
            assert!(
                root.path().join(dir).is_dir(),
                "missing scaffolded directory: {dir}"
            );
        }

        let deployed = std::fs::read(root.path().join(".ppm/lib/redirector.dll")).unwrap();
        assert_eq!(deployed, EMBEDDED_REDIRECTOR_DLL);
        assert_eq!(
            std::fs::read_to_string(root.path().join(".ppm/apps.json")).unwrap(),
            DEFAULT_APPS_JSON
        );
        assert!(root.path().join(".ppm/apps.schema.json").is_file());
    }

    #[test]
    fn reinit_never_clobbers_a_user_authored_manifest() {
        let root = tempfile::tempdir().expect("tempdir");
        init_environment(root.path()).unwrap();

        let user_manifest = r#"{"apps": {}}"#;
        std::fs::write(root.path().join(".ppm/apps.json"), user_manifest).unwrap();

        init_environment(root.path()).unwrap();

        assert_eq!(
            std::fs::read_to_string(root.path().join(".ppm/apps.json")).unwrap(),
            user_manifest
        );
    }
}
