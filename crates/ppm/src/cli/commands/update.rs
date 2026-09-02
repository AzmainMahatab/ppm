use std::path::Path;

use ppm::core::arch::{ArchTarget, CpuArch};

use crate::cli::context::load_manifest;
use crate::cli::pipeline::{ReinstallPolicy, run_install_cycle};

pub(crate) fn run(root: &Path, app: &str, arch: Option<ArchTarget>) -> anyhow::Result<()> {
    let target_archs = arch
        .map(|a| a.resolve())
        .unwrap_or_else(|| vec![CpuArch::current()]);

    let manifests = load_manifest(root)?;
    run_install_cycle(
        root,
        &manifests,
        app,
        &target_archs,
        ReinstallPolicy::SkipWhenCurrent,
    )?;

    println!("\n✓ Update check and upgrade cycle complete!");
    Ok(())
}
