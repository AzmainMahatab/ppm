//! Removing what installs leave behind: an application (`ppm uninstall`) and stale download and
//! staging debris (`ppm clean`).

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::arch::CpuArch;
use crate::core::config::AppManifests;
use crate::core::layout::PortableLayout;
use crate::package::extractor::{remove_tree_if_present, swap_paths_for};

/// Removes `app_id`'s installation for each of `archs`, returning the architectures it was
/// actually removed from.
///
/// # Why dependents block the removal
/// An installed application that declares `app_id` as a dependency would be left unable to
/// start (`ppm run` refuses a launch whose dependency is missing). Refusing up front, naming
/// the dependents, keeps the root consistent; the user removes them first or not at all.
pub fn uninstall(
    root: &Path,
    manifests: &AppManifests,
    app_id: &str,
    archs: &[CpuArch],
) -> Result<Vec<CpuArch>> {
    let Some(app) = manifests.apps.get(app_id) else {
        bail!("Application '{app_id}' is not defined in apps.json");
    };

    let installed: Vec<CpuArch> = archs
        .iter()
        .copied()
        .filter(|&arch| app.app_dir_for_arch(root, arch).exists())
        .collect();
    if installed.is_empty() {
        bail!("'{app_id}' is not installed for {}", describe(archs));
    }

    for &arch in &installed {
        let dependents = installed_dependents(root, manifests, app_id, arch);
        if !dependents.is_empty() {
            bail!(
                "'{app_id}' [{arch}] is required by installed {}: {} - uninstall {} first",
                if dependents.len() == 1 {
                    "application"
                } else {
                    "applications"
                },
                dependents.join(", "),
                if dependents.len() == 1 { "it" } else { "them" },
            );
        }
    }

    for &arch in &installed {
        let app_dir = app.app_dir_for_arch(root, arch);
        let scratch = swap_paths_for(&app_dir)?;
        fs::remove_dir_all(&app_dir).with_context(|| {
            format!(
                "Failed to remove '{}' - a file in it is most likely still open",
                app_dir.display()
            )
        })?;
        remove_tree_if_present(&scratch.staging)?;
        remove_tree_if_present(&scratch.retired)?;
        tracing::info!("✓ Removed {} [{arch}]", app.name);
    }
    Ok(installed)
}

/// The installed applications that declare `app_id` as a dependency on `arch`.
fn installed_dependents(root: &Path, manifests: &AppManifests, app_id: &str, arch: CpuArch) -> Vec<String> {
    manifests
        .apps
        .iter()
        .filter(|(_, other)| {
            other
                .dependencies
                .iter()
                .flatten()
                .any(|dependency| dependency == app_id)
        })
        .filter(|(_, other)| other.is_installed_for_arch(root, arch))
        .map(|(id, _)| id.clone())
        .collect()
}

fn describe(archs: &[CpuArch]) -> String {
    archs
        .iter()
        .map(|arch| arch.as_str())
        .collect::<Vec<_>>()
        .join("/")
}

/// What `clean` removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CleanReport {
    /// Entries removed from `.ppm/cache`.
    pub cache_entries: usize,
    /// Staging or retired trees an interrupted install left beside an application.
    pub scratch_trees: Vec<PathBuf>,
}

/// Empties the download cache and removes the staging and retired trees that an interrupted
/// install leaves beside an application directory.
///
/// # Why scratch trees are located from the manifest
/// Their names are derived from each application's install directory (`swap_paths_for`), so the
/// exact paths to remove are known; nothing is matched by name pattern, and a directory the user
/// created that merely looks similar is never touched.
pub fn clean(root: &Path, manifests: &AppManifests) -> Result<CleanReport> {
    let mut report = CleanReport::default();

    let cache = PortableLayout::new(root).ppm_dir().join("cache");
    if cache.is_dir() {
        for entry in fs::read_dir(&cache).with_context(|| format!("Failed to read '{}'", cache.display()))? {
            let path = entry
                .with_context(|| format!("Failed to read '{}'", cache.display()))?
                .path();
            let removed = match path.is_dir() {
                true => fs::remove_dir_all(&path),
                false => fs::remove_file(&path),
            };
            removed.with_context(|| format!("Failed to remove '{}'", path.display()))?;
            report.cache_entries += 1;
        }
    }

    for app in manifests.apps.values() {
        for &arch in CpuArch::all() {
            let scratch = swap_paths_for(&app.app_dir_for_arch(root, arch))?;
            for tree in [scratch.staging, scratch.retired] {
                if tree.exists() {
                    remove_tree_if_present(&tree)?;
                    report.scratch_trees.push(tree);
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> AppManifests {
        let app = |deps: Vec<&str>| {
            json!({
                "name": "App",
                "target_dir": "Dir",
                "executable": "app.exe",
                "version_check": {"type": "github_release", "repo": "o/r"},
                "package": {"type": "zip"},
                "dependencies": deps
            })
        };
        let mut lib = app(vec![]);
        lib["target_dir"] = json!("Lib");
        lib["executable"] = json!("lib.exe");
        serde_json::from_value(json!({ "apps": { "app": app(vec!["lib"]), "lib": lib } }))
            .expect("invariant: test manifest is schema-valid")
    }

    fn install(root: &Path, dir: &str, exe: &str, arch: &str) {
        let app_dir = root.join("Apps").join(arch).join(dir);
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(app_dir.join(exe), b"MZ").unwrap();
    }

    #[test]
    fn uninstall_removes_only_the_requested_architectures() {
        let root = tempfile::tempdir().unwrap();
        install(root.path(), "Dir", "app.exe", "x64");
        install(root.path(), "Dir", "app.exe", "arm64");

        let removed = uninstall(root.path(), &manifest(), "app", &[CpuArch::X64]).unwrap();

        assert_eq!(removed, vec![CpuArch::X64]);
        assert!(!root.path().join("Apps/x64/Dir").exists());
        assert!(root.path().join("Apps/arm64/Dir/app.exe").is_file());
    }

    #[test]
    fn a_dependency_of_an_installed_app_is_not_removed() {
        let root = tempfile::tempdir().unwrap();
        install(root.path(), "Lib", "lib.exe", "x64");
        install(root.path(), "Dir", "app.exe", "x64");

        let error = uninstall(root.path(), &manifest(), "lib", &[CpuArch::X64]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("required by installed application: app"),
            "{error}"
        );
        assert!(root.path().join("Apps/x64/Lib/lib.exe").is_file());

        // Once the dependent is gone, the dependency can go too.
        uninstall(root.path(), &manifest(), "app", &[CpuArch::X64]).unwrap();
        uninstall(root.path(), &manifest(), "lib", &[CpuArch::X64]).unwrap();
        assert!(!root.path().join("Apps/x64/Lib").exists());
    }

    #[test]
    fn uninstalling_something_absent_is_an_error() {
        let root = tempfile::tempdir().unwrap();
        let error = uninstall(root.path(), &manifest(), "app", CpuArch::all()).unwrap_err();
        assert!(error.to_string().contains("not installed"), "{error}");
        assert!(uninstall(root.path(), &manifest(), "ghost", CpuArch::all()).is_err());
    }

    #[test]
    fn clean_empties_the_cache_and_removes_only_known_scratch_trees() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join(".ppm/cache");
        fs::create_dir_all(cache.join("partial-dir")).unwrap();
        fs::write(cache.join("app_x64_1.0.zip"), b"zip").unwrap();
        let staging = root.path().join("Apps/x64/.Dir.staging");
        fs::create_dir_all(&staging).unwrap();
        // A user folder whose name merely resembles the scheme is not ours to remove.
        let lookalike = root.path().join("Apps/x64/.Notes.staging");
        fs::create_dir_all(&lookalike).unwrap();
        install(root.path(), "Dir", "app.exe", "x64");

        let report = clean(root.path(), &manifest()).unwrap();

        assert_eq!(report.cache_entries, 2);
        assert_eq!(report.scratch_trees, vec![staging.clone()]);
        assert!(fs::read_dir(&cache).unwrap().next().is_none());
        assert!(!staging.exists());
        assert!(lookalike.exists());
        assert!(
            root.path().join("Apps/x64/Dir/app.exe").is_file(),
            "installations are untouched"
        );
    }
}
