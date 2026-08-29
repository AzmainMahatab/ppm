use std::env;
use std::path::{Path, PathBuf};

use ppm::core::config::AppManifests;

/// Resolves the portable environment root.
///
/// Precedence: explicit `PPM_ROOT` override, then a working directory that already
/// carries a portable environment, then the executable's own location.
pub(crate) fn resolve_root() -> PathBuf {
    // 1. Explicit environment variable override
    if let Ok(ppm_root) = env::var("PPM_ROOT") {
        let p = PathBuf::from(ppm_root);
        if p.is_dir() {
            return p;
        }
    }

    // 2. If current working directory has a portable environment (.ppm/apps.json or manifests/apps.json)
    if let Ok(cwd) = env::current_dir()
        && (cwd.join(".ppm").join("apps.json").is_file() || cwd.join("manifests").join("apps.json").is_file())
    {
        return cwd;
    }

    // 3. Fallback to executable location
    let current_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("ppm.exe"));
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));

    let last_comp = exe_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if matches!(last_comp, ".ppm" | "Engine" | "lib" | "dist") {
        exe_dir.parent().unwrap_or(exe_dir).to_path_buf()
    } else if matches!(last_comp, "release" | "debug") {
        exe_dir
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(exe_dir)
            .to_path_buf()
    } else {
        exe_dir.to_path_buf()
    }
}

/// Loads the application manifest, preferring the deployed `.ppm/apps.json` over the
/// development-time `manifests/apps.json`.
pub(crate) fn load_manifest(root: &Path) -> anyhow::Result<AppManifests> {
    let apps_json_path = root.join(".ppm").join("apps.json");
    if apps_json_path.exists() {
        AppManifests::load_from_file(&apps_json_path)
    } else {
        let dev_manifest = root.join("manifests").join("apps.json");
        if dev_manifest.exists() {
            AppManifests::load_from_file(&dev_manifest)
        } else {
            anyhow::bail!(
                "Manifest file not found at '{}'. Run 'ppm init' to generate default configuration.",
                apps_json_path.display()
            );
        }
    }
}
