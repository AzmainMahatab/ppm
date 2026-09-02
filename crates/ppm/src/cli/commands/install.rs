use std::path::Path;

use ppm::core::arch::{ArchTarget, CpuArch};

use crate::cli::context::load_manifest;
use crate::cli::pipeline::{ReinstallPolicy, run_install_cycle};

pub(crate) fn run(root: &Path, app: &str, arch: Option<ArchTarget>, force: bool) -> anyhow::Result<()> {
    let target_archs = arch
        .map(|a| a.resolve())
        .unwrap_or_else(|| vec![CpuArch::current()]);

    // Installing something already present is a refresh, not a re-download: an application whose
    // installed version already matches the latest release is left alone unless asked otherwise.
    let policy = match force {
        true => ReinstallPolicy::Always,
        false => ReinstallPolicy::SkipWhenCurrent,
    };

    let manifests = load_manifest(root)?;
    run_install_cycle(root, &manifests, app, &target_archs, policy)?;

    println!("\n✓ All requested installations completed successfully!");
    Ok(())
}
