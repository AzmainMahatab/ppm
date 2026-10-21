use crate::core::assets::{DEFAULT_APPS_JSON, ENGINE_FILES};
use crate::core::layout::PortableLayout;
use crate::core::schema::write_schema_artifacts;
use anyhow::{Context, bail};
use std::fs;
use std::path::Path;

pub fn init_environment(root: &Path) -> anyhow::Result<()> {
    scaffold_directories(root)?;
    deploy_engines(root)?;
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

// Intention: Unconditionally deploy a fresh copy of every engine build into its machine folder.
// Why: A previously extracted 0-byte or stale DLL must never survive an `init`; the embedded
//      artifacts are rebuilt by Cargo on every redirector change and always reflect ground truth.
fn deploy_engines(root: &Path) -> anyhow::Result<()> {
    let lib_dir = PortableLayout::new(root).engine_lib_dir();
    for engine in ENGINE_FILES {
        if engine.bytes.is_empty() {
            bail!(
                "Embedded {}/{} is empty; the build did not capture a valid redirector artifact",
                engine.folder,
                engine.file_name
            );
        }
        let folder = lib_dir.join(engine.folder.as_str());
        fs::create_dir_all(&folder).with_context(|| format!("Failed to create '{}'", folder.display()))?;
        let dll_path = folder.join(engine.file_name);
        fs::write(&dll_path, engine.bytes)
            .with_context(|| format!("Failed to deploy '{}'", dll_path.display()))?;
        tracing::info!("✓ Deployed .ppm/lib/{}/{}", engine.folder, engine.file_name);
    }
    remove_single_build_engine(&lib_dir)
}

/// Removes the engine an earlier `ppm` deployed as `.ppm/lib/redirector.dll`, before engines
/// were split per machine. Nothing loads it any more, and leaving it would suggest otherwise.
fn remove_single_build_engine(lib_dir: &Path) -> anyhow::Result<()> {
    let superseded = lib_dir.join("redirector.dll");
    match fs::remove_file(&superseded) {
        Ok(()) => {
            tracing::info!("✓ Removed the superseded .ppm/lib/redirector.dll");
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Failed to remove '{}'", superseded.display())),
    }
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

        for engine in ENGINE_FILES {
            let path = root
                .path()
                .join(".ppm/lib")
                .join(engine.folder.as_str())
                .join(engine.file_name);
            assert_eq!(std::fs::read(&path).unwrap(), engine.bytes, "{}", path.display());
        }
        assert_eq!(
            std::fs::read_to_string(root.path().join(".ppm/apps.json")).unwrap(),
            DEFAULT_APPS_JSON
        );
        assert!(root.path().join(".ppm/apps.schema.json").is_file());
    }

    #[test]
    fn init_removes_the_superseded_single_build_engine() {
        let root = tempfile::tempdir().expect("tempdir");
        let superseded = root.path().join(".ppm/lib/redirector.dll");
        std::fs::create_dir_all(superseded.parent().unwrap()).unwrap();
        std::fs::write(&superseded, b"MZ old engine").unwrap();

        init_environment(root.path()).unwrap();

        assert!(!superseded.exists());
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
