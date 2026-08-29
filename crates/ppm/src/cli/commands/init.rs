use std::path::Path;

use ppm::engine;

pub(crate) fn run(root: &Path) -> anyhow::Result<()> {
    println!("⚡ Initializing Portable Environment in '{}'...", root.display());
    engine::init::init_environment(root)?;
    println!("\n✓ Portable environment initialized successfully!");
    Ok(())
}
