use std::path::Path;

use ppm::core::arch::{ArchTarget, CpuArch};
use ppm::engine;

use crate::cli::context::load_manifest;
use crate::cli::pipeline::{perform_install, resolve_install_order};

pub(crate) fn run(root: &Path, app: &str, arch: Option<ArchTarget>) -> anyhow::Result<()> {
    let target_archs = arch
        .map(|a| a.resolve())
        .unwrap_or_else(|| vec![CpuArch::current()]);

    let manifests = load_manifest(root)?;
    let install_order = resolve_install_order(&manifests, app)?;

    for &target_arch in &target_archs {
        println!("\n=======================================================");
        println!("  Targeting Architecture: [{}]", target_arch.as_str());
        println!("=======================================================");

        for app_id in &install_order {
            if let Some(app_def) = manifests.apps.get(app_id) {
                perform_install(root, app_id, app_def, target_arch)?;
            }
        }
    }

    // Refresh batch launchers
    engine::launcher::generate_launchers(root, &manifests)?;
    println!("\n✓ All requested installations completed successfully!");
    Ok(())
}
