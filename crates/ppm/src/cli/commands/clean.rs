use std::path::Path;

use ppm::package::removal;

use crate::cli::context::load_manifest;

pub(crate) fn run(root: &Path) -> anyhow::Result<()> {
    let manifests = load_manifest(root)?;
    let report = removal::clean(root, &manifests)?;
    for tree in &report.scratch_trees {
        tracing::info!("✓ Removed interrupted-install debris '{}'", tree.display());
    }
    tracing::info!(
        "✓ Cleaned {} cache entr{} and {} scratch tree{}",
        report.cache_entries,
        if report.cache_entries == 1 { "y" } else { "ies" },
        report.scratch_trees.len(),
        if report.scratch_trees.len() == 1 { "" } else { "s" }
    );
    Ok(())
}
