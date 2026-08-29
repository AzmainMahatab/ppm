use std::path::Path;

use crate::cli::context::load_manifest;

pub(crate) fn run(root: &Path) -> anyhow::Result<()> {
    let manifests = load_manifest(root)?;
    println!(
        "✓ Manifest is valid! Configured applications ({}):",
        manifests.apps.len()
    );
    for (id, app) in manifests.apps {
        println!("  • {} ({}) -> {}", app.name, id, app.executable);
    }
    Ok(())
}
