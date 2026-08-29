use std::env;
use std::path::{Path, PathBuf};

use ppm::core::config::AppManifests;

/// Resolves the portable environment root.
///
/// Precedence: explicit `PPM_ROOT` override, then a working directory that already
/// carries a portable environment, then the executable's own location.
pub(crate) fn resolve_root() -> PathBuf {
    let ppm_root = env::var("PPM_ROOT").ok();
    let cwd = env::current_dir().ok();
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));

    resolve_root_from(ppm_root.as_deref(), cwd.as_deref(), exe_dir.as_deref())
}

/// Pure resolution core behind [`resolve_root`]: `ppm_root` override, then a working
/// directory that carries a portable environment, then the executable's location with
/// known engine-layout awareness (`.ppm`/`Engine`/`lib`/`dist` parents, `release`/`debug`
/// grandparents). A missing executable directory degenerates to the working directory.
fn resolve_root_from(ppm_root: Option<&str>, cwd: Option<&Path>, exe_dir: Option<&Path>) -> PathBuf {
    // 1. Explicit environment variable override
    if let Some(root) = ppm_root {
        let p = PathBuf::from(root);
        if p.is_dir() {
            return p;
        }
    }

    // 2. If current working directory has a portable environment (.ppm/apps.json or manifests/apps.json)
    if let Some(cwd) = cwd
        && (cwd.join(".ppm").join("apps.json").is_file() || cwd.join("manifests").join("apps.json").is_file())
    {
        return cwd.to_path_buf();
    }

    // 3. Fallback to executable location
    let Some(exe_dir) = exe_dir else {
        return PathBuf::from(".");
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    fn portable_dir(tag: &str, with_manifest: bool) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ppm_ctx_{tag}_{}", std::process::id()));
        let manifest = dir.join(".ppm").join("apps.json");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        if with_manifest {
            std::fs::write(&manifest, b"{}").unwrap();
        }
        dir
    }

    #[test]
    fn ppm_root_override_wins_even_with_portable_cwd() {
        let override_dir = portable_dir("ovr", true);
        let cwd = portable_dir("cwd", true);

        let root = resolve_root_from(Some(override_dir.to_str().unwrap()), Some(&cwd), None);

        assert_eq!(root, override_dir);
        let _ = std::fs::remove_dir_all(override_dir);
        let _ = std::fs::remove_dir_all(cwd);
    }

    #[test]
    fn non_directory_override_falls_through_to_portable_cwd() {
        let cwd = portable_dir("fall", true);

        let root = resolve_root_from(Some(r"Q:\definitely\missing"), Some(&cwd), None);

        assert_eq!(root, cwd);
        let _ = std::fs::remove_dir_all(cwd);
    }

    #[test]
    fn cwd_without_portable_env_is_skipped() {
        let bare = portable_dir("bare", false);
        let portable_exe_dir = portable_dir("exe", true).join(".ppm");

        let root = resolve_root_from(None, Some(&bare), Some(&portable_exe_dir));

        assert_eq!(root, portable_exe_dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(bare);
        let _ = std::fs::remove_dir_all(portable_exe_dir.parent().unwrap());
    }

    #[test]
    fn engine_layout_parents_and_release_grandparents_resolve() {
        let engine = PathBuf::from(r"Q:\root\Engine");
        assert_eq!(
            resolve_root_from(None, None, Some(&engine)),
            PathBuf::from(r"Q:\root")
        );

        let dist = PathBuf::from(r"Q:\root\dist");
        assert_eq!(
            resolve_root_from(None, None, Some(&dist)),
            PathBuf::from(r"Q:\root")
        );

        let release = PathBuf::from(r"Q:\root\target\release");
        assert_eq!(
            resolve_root_from(None, None, Some(&release)),
            PathBuf::from(r"Q:\root")
        );

        let plain = PathBuf::from(r"Q:\elsewhere");
        assert_eq!(resolve_root_from(None, None, Some(&plain)), plain);
    }
}

