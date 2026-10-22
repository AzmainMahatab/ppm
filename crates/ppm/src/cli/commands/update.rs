use std::path::Path;

use ppm::core::arch::{ArchTarget, CpuArch};
use ppm::package::http::{HttpClients, TrustRoots};

use crate::cli::context::load_manifest;
use crate::cli::pipeline::{ReinstallPolicy, UpdateTarget, run_install_cycle, update_plan};

/// Refreshes installed applications to their latest release; `app` is `None` for `--all`.
pub(crate) fn run(root: &Path, app: Option<&str>, arch: Option<ArchTarget>) -> anyhow::Result<()> {
    let target_archs = arch
        .map(|a| a.resolve())
        .unwrap_or_else(|| vec![CpuArch::current()]);
    let target = app.map_or(UpdateTarget::AllInstalled, UpdateTarget::App);

    let manifests = load_manifest(root)?;
    let plan = update_plan(root, &manifests, target, &target_archs)?;
    if plan.is_empty() {
        tracing::info!(
            "Nothing to update: no configured application is installed for the targeted architecture"
        );
        return Ok(());
    }
    let clients = HttpClients::new(&TrustRoots::Platform)?;
    run_install_cycle(
        &clients,
        root,
        &manifests,
        &plan,
        ReinstallPolicy::SkipWhenCurrent,
    )?;

    tracing::info!("✓ Update check and upgrade cycle complete!");
    Ok(())
}
