use std::path::Path;

use ppm::core::arch::ArchTarget;
use ppm::engine::launcher;
use ppm::package::removal;

use crate::cli::context::load_manifest;

pub(crate) fn run(root: &Path, app: &str, arch: ArchTarget) -> anyhow::Result<()> {
    let manifests = load_manifest(root)?;
    removal::uninstall(root, &manifests, app, &arch.resolve())?;

    let app_def = manifests
        .apps
        .get(app)
        .expect("invariant: uninstall succeeded, so the app is defined");
    if !app_def.is_installed_any_arch(root) && launcher::remove_launcher(root, app)? {
        tracing::info!("✓ Removed launcher {app}.bat");
    }
    Ok(())
}
