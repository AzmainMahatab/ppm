use std::path::Path;

use ppm::engine;

pub(crate) fn run(root: &Path) -> anyhow::Result<()> {
    tracing::info!("⚡ Initializing Portable Environment in '{}'...", root.display());
    engine::init::init_environment(root)?;
    tracing::info!("✓ Portable environment initialized successfully!");
    Ok(())
}
