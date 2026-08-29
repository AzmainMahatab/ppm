use std::collections::HashSet;
use std::path::Path;

use ppm::core::arch::CpuArch;
use ppm::core::config::{AppDefinition, AppManifests};
use ppm::package;

/// Resolves the dependency-closed install/update order for the target application.
///
/// Dependencies are emitted before dependents; cycles are rejected outright.
pub(crate) fn resolve_install_order(
    manifests: &AppManifests,
    target_app_id: &str,
) -> anyhow::Result<Vec<String>> {
    let mut order = Vec::new();
    let mut visited = HashSet::new();
    let mut visiting = HashSet::new();

    fn dfs(
        app_id: &str,
        manifests: &AppManifests,
        order: &mut Vec<String>,
        visited: &mut HashSet<String>,
        visiting: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        if visiting.contains(app_id) {
            anyhow::bail!("Circular dependency detected involving '{}'", app_id);
        }
        if visited.contains(app_id) {
            return Ok(());
        }

        visiting.insert(app_id.to_string());

        let app_def = manifests
            .apps
            .get(app_id)
            .ok_or_else(|| anyhow::anyhow!("Dependency '{}' not defined in apps.json", app_id))?;

        if let Some(deps) = &app_def.dependencies {
            for dep in deps {
                dfs(dep, manifests, order, visited, visiting)?;
            }
        }

        visiting.remove(app_id);
        visited.insert(app_id.to_string());
        order.push(app_id.to_string());

        Ok(())
    }

    if target_app_id == "all" {
        for app_id in manifests.apps.keys() {
            if !visited.contains(app_id) {
                dfs(app_id, manifests, &mut order, &mut visited, &mut visiting)?;
            }
        }
    } else {
        dfs(target_app_id, manifests, &mut order, &mut visited, &mut visiting)?;
    }

    Ok(order)
}

/// Installs a single application: fetch, download, extract, sanitize, clean.
pub(crate) fn perform_install(
    root: &Path,
    app_id: &str,
    app_def: &AppDefinition,
    arch: CpuArch,
) -> anyhow::Result<()> {
    if !app_def.is_supported_on_arch(arch) {
        println!(
            "  • Skipping '{}' (Not supported on {})",
            app_def.name,
            arch.as_str()
        );
        return Ok(());
    }

    println!(
        "\n▶ Processing '{}' ({}) for architecture [{}]",
        app_def.name,
        app_id,
        arch.as_str()
    );

    // 1. Fetch remote release metadata
    println!("  • Checking online release for {}...", arch.as_str());
    let release = package::version::check_remote_version(&app_def.version_check, arch)?;
    println!(
        "  • Found version {} at: {}",
        release.version, release.download_url
    );

    // 2. Download archive to isolated .ppm/cache/
    let temp_cache_dir = root.join(".ppm").join("cache");
    std::fs::create_dir_all(&temp_cache_dir)?;

    let ext = release
        .download_url
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or("pkg");
    let temp_archive = temp_cache_dir.join(format!(
        "{}_{}_{}.{}",
        app_id,
        arch.as_str(),
        release.version,
        ext
    ));

    println!("  • Downloading package...");
    package::downloader::download_file(
        &release.download_url,
        &temp_archive,
        &format!("{} ({})", app_def.name, arch.as_str()),
    )?;

    // 3. Extract to target directory: Apps/<arch>/<target_dir>
    let target_dir = app_def.app_dir_for_arch(root, arch);
    println!("  • Unpacking to '{}'...", target_dir.display());
    package::extractor::extract_package(&temp_archive, &app_def.package, &target_dir)?;

    // 4. Sanitize payload
    println!("  • Sanitizing installation...");
    package::sanitizer::sanitize_package(&target_dir, app_def.post_install.as_ref())?;

    // 5. Clean temporary download
    if let Err(error) = std::fs::remove_file(&temp_archive) {
        eprintln!(
            "Warning: failed to remove cached archive '{}': {error}",
            temp_archive.display()
        );
    }

    println!(
        "  ✓ Successfully installed {} [{}] (v{})",
        app_def.name,
        arch.as_str(),
        release.version
    );

    Ok(())
}
