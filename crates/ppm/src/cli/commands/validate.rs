use std::path::Path;

use crate::cli::context::load_manifest;
use crate::cli::pipeline::resolve_install_order;

pub(crate) fn run(root: &Path) -> anyhow::Result<()> {
    let manifests = load_manifest(root)?;
    // Loading already checks paths and dependency references; ordering every app is what
    // surfaces a dependency cycle, which would otherwise only fail at install time.
    resolve_install_order(&manifests, "all")?;
    println!(
        "✓ Manifest is valid! Configured applications ({}):",
        manifests.apps.len()
    );
    for (id, app) in manifests.apps {
        println!("  • {} ({}) -> {}", app.name, id, app.executable);
    }
    Ok(())
}
