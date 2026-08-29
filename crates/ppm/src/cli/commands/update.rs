use std::path::Path;

use ppm::core::arch::{ArchTarget, CpuArch};
use ppm::engine;
use ppm::package;

use crate::cli::context::load_manifest;
use crate::cli::pipeline::{perform_install, resolve_install_order};

pub(crate) fn run(root: &Path, app: &str, arch: Option<ArchTarget>) -> anyhow::Result<()> {
    let target_archs = arch
        .map(|a| a.resolve())
        .unwrap_or_else(|| vec![CpuArch::current()]);

    let manifests = load_manifest(root)?;
    let update_order = resolve_install_order(&manifests, app)?;

    for &target_arch in &target_archs {
        println!("\n=======================================================");
        println!("  Checking Updates for Architecture: [{}]", target_arch.as_str());
        println!("=======================================================");

        for app_id in &update_order {
            if let Some(app_def) = manifests.apps.get(app_id) {
                if !app_def.is_supported_on_arch(target_arch) {
                    continue;
                }

                println!(
                    "\n▶ Checking update for '{}' [{}]...",
                    app_def.name,
                    target_arch.as_str()
                );
                let local_v = package::version::detect_local_version(root, app_def, target_arch);
                let remote_res = package::version::check_remote_version(&app_def.version_check, target_arch);

                match (local_v, remote_res) {
                    (Some(loc), Ok(remote)) if loc == remote.version => {
                        println!(
                            "  ✓ {} [{}] is already up to date (v{})",
                            app_def.name,
                            target_arch.as_str(),
                            loc
                        );
                    }
                    (_, Ok(_)) => {
                        perform_install(root, app_id, app_def, target_arch)?;
                    }
                    (_, Err(e)) => {
                        eprintln!("  ✗ Failed to check remote version: {}", e);
                    }
                }
            }
        }
    }

    engine::launcher::generate_launchers(root, &manifests)?;
    println!("\n✓ Update check and upgrade cycle complete!");
    Ok(())
}
