use std::path::Path;

use ppm::engine;

use crate::cli::context::load_manifest;

pub(crate) fn run(root: &Path, app: &str) -> anyhow::Result<()> {
    let manifests = load_manifest(root)?;

    if app == "all" {
        let generated = engine::launcher::generate_launchers(root, &manifests)?;
        tracing::info!("⚡ Generated root launchers:");
        for g in generated {
            tracing::info!("✓ {}", g);
        }
    } else if manifests.apps.contains_key(app) {
        engine::launcher::generate_single_launcher(root, app)?;
        tracing::info!("✓ Generated root launcher: {}.bat", app);
    } else {
        anyhow::bail!("App '{}' not found in apps.json", app);
    }

    Ok(())
}
