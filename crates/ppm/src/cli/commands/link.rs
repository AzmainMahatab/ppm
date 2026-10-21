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
        return Ok(());
    }

    let Some(app_def) = manifests.apps.get(app) else {
        anyhow::bail!("App '{}' not found in apps.json", app);
    };
    let file_name = engine::launcher::write_launcher(root, app, app_def)?;
    tracing::info!("✓ Generated root launcher: {file_name}");
    Ok(())
}
