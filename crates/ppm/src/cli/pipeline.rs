use std::collections::HashSet;
use std::path::Path;

use ppm::core::arch::CpuArch;
use ppm::core::config::{AppDefinition, AppManifests, PackageKind};
use ppm::engine;
use ppm::package;
use ppm::package::http::HttpClients;

/// Resolves the dependency-closed install/update order for the target application.
///
/// Dependencies are emitted before dependents; cycles are rejected outright.
pub(crate) fn resolve_install_order(
    manifests: &AppManifests,
    target_app_id: &str,
) -> anyhow::Result<Vec<String>> {
    let mut order = Vec::new();
    let mut visited = HashSet::new();
    let mut visiting = HashSet::new();

    fn dfs(
        app_id: &str,
        manifests: &AppManifests,
        order: &mut Vec<String>,
        visited: &mut HashSet<String>,
        visiting: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        if visiting.contains(app_id) {
            anyhow::bail!("Circular dependency detected involving '{}'", app_id);
        }
        if visited.contains(app_id) {
            return Ok(());
        }

        visiting.insert(app_id.to_string());

        let app_def = manifests
            .apps
            .get(app_id)
            .ok_or_else(|| anyhow::anyhow!("Dependency '{}' not defined in apps.json", app_id))?;

        if let Some(deps) = &app_def.dependencies {
            for dep in deps {
                dfs(dep, manifests, order, visited, visiting)?;
            }
        }

        visiting.remove(app_id);
        visited.insert(app_id.to_string());
        order.push(app_id.to_string());

        Ok(())
    }

    if target_app_id == "all" {
        for app_id in manifests.apps.keys() {
            if !visited.contains(app_id) {
                dfs(app_id, manifests, &mut order, &mut visited, &mut visiting)?;
            }
        }
    } else {
        if !manifests.apps.contains_key(target_app_id) {
            anyhow::bail!("Application '{target_app_id}' is not defined in apps.json");
        }
        dfs(target_app_id, manifests, &mut order, &mut visited, &mut visiting)?;
    }

    Ok(order)
}

/// The file extension a downloaded package is cached under.
///
/// # Why the URL is parsed rather than split
/// This used to be `rsplit_once('.')` over the whole URL, which is a guess about a structured
/// value: `https://host/v1.2/download` yields "2/download", producing a cache path with a
/// separator inside it. Parsing the URL and reading the extension of its final path segment asks
/// the question properly, and the manifest's declared package type answers it when the URL
/// carries no extension at all.
///
/// # Ex
/// `https://h/App-1.0.zip` -> `zip`; `https://h/v1.2/download` (nsis_7z) -> `exe`
fn cache_extension(download_url: &str, kind: PackageKind) -> String {
    let from_url = reqwest::Url::parse(download_url)
        .ok()
        .and_then(|url| {
            url.path_segments()
                .and_then(|mut segments| segments.next_back().map(str::to_string))
        })
        .and_then(|segment| {
            Path::new(&segment)
                .extension()
                .map(|extension| extension.to_string_lossy().into_owned())
        })
        .filter(|extension| !extension.is_empty());

    from_url.unwrap_or_else(|| declared_extension(kind).to_string())
}

/// The archive extension implied by a manifest package type.
fn declared_extension(kind: PackageKind) -> &'static str {
    match kind {
        // An NSIS installer is an executable carrying a 7z payload.
        PackageKind::Nsis7z => "exe",
        PackageKind::SevenZ => "7z",
        PackageKind::Zip => "zip",
        PackageKind::Cab => "cab",
        PackageKind::Msi => "msi",
        PackageKind::Tar => "tar",
        PackageKind::Binary => "bin",
    }
}

/// What to do about an application that is already installed for the target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReinstallPolicy {
    /// Leave it alone when its installed version already matches the latest release. This is
    /// what both `install` and `update` do: installing something already current is a refresh,
    /// and re-downloading it would be pure cost.
    SkipWhenCurrent,
    /// Fetch and reinstall regardless of what is present, for a repair after a damaged install.
    Always,
}

/// What happened to one application for one architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallOutcome {
    Installed { version: String },
    AlreadyCurrent { version: String },
    Unsupported,
}

/// Decides whether `installed` already satisfies `available` under `policy`.
///
/// Extracted so the rule is testable without a network round trip: the whole point of the
/// policy is what it does with a version pair.
fn is_already_current(policy: ReinstallPolicy, installed: Option<&str>, available: &str) -> bool {
    match policy {
        ReinstallPolicy::Always => false,
        ReinstallPolicy::SkipWhenCurrent => installed == Some(available),
    }
}

/// Installs or refreshes a single application: resolve, fetch, download, extract, sanitize.
pub(crate) fn install_app(
    clients: &HttpClients,
    root: &Path,
    app_id: &str,
    app_def: &AppDefinition,
    arch: CpuArch,
    policy: ReinstallPolicy,
) -> anyhow::Result<InstallOutcome> {
    if !app_def.is_supported_on_arch(arch) {
        return Ok(InstallOutcome::Unsupported);
    }

    tracing::info!(
        "▶ Processing '{}' ({}) for architecture [{}]",
        app_def.name,
        app_id,
        arch.as_str()
    );

    // 1. Fetch remote release metadata.
    //
    // Why once: the update path used to check the remote version here and then call an
    // installer that checked it again, paying two round trips per application to learn the
    // same answer.
    tracing::info!("• Checking online release for {}...", arch.as_str());
    let release = package::version::check_remote_version(clients, &app_def.version_check, arch)?;
    tracing::info!("• Found version {} at: {}", release.version, release.download_url);

    let installed = package::version::detect_local_version(root, app_def, arch);
    if is_already_current(policy, installed.as_deref(), &release.version) {
        return Ok(InstallOutcome::AlreadyCurrent {
            version: release.version,
        });
    }

    // 2. Download archive to isolated .ppm/cache/
    let temp_cache_dir = root.join(".ppm").join("cache");
    std::fs::create_dir_all(&temp_cache_dir)?;

    let temp_archive = temp_cache_dir.join(format!(
        "{}_{}_{}.{}",
        app_id,
        arch.as_str(),
        release.version,
        cache_extension(&release.download_url, app_def.package.kind)
    ));

    tracing::info!("• Downloading package...");
    package::downloader::download_file(
        clients,
        &release.download_url,
        &temp_archive,
        &format!("{} ({})", app_def.name, arch.as_str()),
    )?;

    // 3. Extract to target directory: Apps/<arch>/<target_dir>
    let target_dir = app_def.app_dir_for_arch(root, arch);
    tracing::info!("• Unpacking to '{}'...", target_dir.display());
    package::extractor::extract_package(&temp_archive, &app_def.package, &target_dir)?;

    // 4. Sanitize payload
    tracing::info!("• Sanitizing installation...");
    package::sanitizer::sanitize_package(&target_dir, app_def.post_install.as_ref())?;

    // 5. Clean temporary download
    if let Err(error) = std::fs::remove_file(&temp_archive) {
        tracing::warn!(
            "Failed to remove cached archive '{}': {error}",
            temp_archive.display()
        );
    }

    Ok(InstallOutcome::Installed {
        version: release.version,
    })
}

/// One application to process for one architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CycleStep {
    pub(crate) arch: CpuArch,
    pub(crate) app_id: String,
}

/// What `install` processes: `app` (or every application) and its dependencies, dependencies
/// first, for each architecture.
pub(crate) fn install_plan(
    manifests: &AppManifests,
    app: &str,
    archs: &[CpuArch],
) -> anyhow::Result<Vec<CycleStep>> {
    let order = resolve_install_order(manifests, app)?;
    Ok(archs
        .iter()
        .flat_map(|&arch| {
            order.iter().map(move |app_id| CycleStep {
                arch,
                app_id: app_id.clone(),
            })
        })
        .collect())
}

/// Which applications `update` refreshes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateTarget<'a> {
    /// One named application.
    App(&'a str),
    /// Every installed application.
    AllInstalled,
}

/// What `update` processes: installed applications only, in dependency order, for each
/// architecture they are installed for.
///
/// # Why update never installs
/// `install` brings an application (and its dependencies) onto the root; `update` only refreshes
/// what is already there. A named application installed for none of the architectures is an
/// error that points at `install`, rather than an install the user did not ask for.
pub(crate) fn update_plan(
    root: &Path,
    manifests: &AppManifests,
    target: UpdateTarget<'_>,
    archs: &[CpuArch],
) -> anyhow::Result<Vec<CycleStep>> {
    if let UpdateTarget::App(app_id) = target
        && !manifests.apps.contains_key(app_id)
    {
        anyhow::bail!("Application '{app_id}' is not defined in apps.json");
    }

    // Ordering every application, not just the targets, keeps dependencies ahead of their
    // dependents when `--all` refreshes both.
    let order = resolve_install_order(manifests, "all")?;
    let plan: Vec<CycleStep> = archs
        .iter()
        .flat_map(|&arch| {
            order
                .iter()
                .filter(move |app_id| match target {
                    UpdateTarget::App(named) => app_id.as_str() == named,
                    UpdateTarget::AllInstalled => true,
                })
                .filter(move |app_id| manifests.apps[app_id.as_str()].is_installed_for_arch(root, arch))
                .map(move |app_id| CycleStep {
                    arch,
                    app_id: app_id.clone(),
                })
        })
        .collect();

    if let UpdateTarget::App(app_id) = target
        && plan.is_empty()
    {
        let archs = archs
            .iter()
            .map(|arch| arch.as_str())
            .collect::<Vec<_>>()
            .join("/");
        anyhow::bail!("'{app_id}' is not installed for {archs}; use 'ppm install {app_id}' to install it");
    }
    Ok(plan)
}

/// Runs one install/refresh cycle over `plan`.
///
/// # Why `install` and `update` share this
/// They differ in *what* they process (see [`install_plan`] and [`update_plan`]), not in how one
/// application is refreshed. The copies of this loop had already drifted once: the update loop
/// swallowed a failed remote check and still reported success, so `ppm update all` exited 0 with
/// nothing updated. One cycle attempts every step and then reports what failed.
pub(crate) fn run_install_cycle(
    clients: &HttpClients,
    root: &Path,
    manifests: &AppManifests,
    plan: &[CycleStep],
    policy: ReinstallPolicy,
) -> anyhow::Result<()> {
    let mut failures: Vec<String> = Vec::new();
    let mut current_arch = None;

    for step in plan {
        if current_arch != Some(step.arch) {
            tracing::info!("Targeting architecture [{}]", step.arch.as_str());
            current_arch = Some(step.arch);
        }
        let app_def = manifests
            .apps
            .get(&step.app_id)
            .expect("invariant: plans only name applications the manifest defines");
        let arch = step.arch;

        match install_app(clients, root, &step.app_id, app_def, arch, policy) {
            Ok(InstallOutcome::Installed { version }) => tracing::info!(
                "✓ Successfully installed {} [{}] (v{version})",
                app_def.name,
                arch.as_str()
            ),
            Ok(InstallOutcome::AlreadyCurrent { version }) => tracing::info!(
                "✓ {} [{}] is already up to date (v{version})",
                app_def.name,
                arch.as_str()
            ),
            Ok(InstallOutcome::Unsupported) => tracing::info!(
                "• Skipping '{}' (Not supported on {})",
                app_def.name,
                arch.as_str()
            ),
            Err(error) => {
                // Keep going so one unreachable endpoint does not strand every other
                // application, but remember it: the cycle must not report success.
                tracing::error!("✗ {} [{}]: {error:#}", app_def.name, arch.as_str());
                failures.push(format!("{} [{}]: {error:#}", app_def.name, arch.as_str()));
            }
        }
    }

    engine::launcher::generate_launchers(root, manifests)?;

    if !failures.is_empty() {
        anyhow::bail!(
            "{} of the requested applications failed:\n  - {}",
            failures.len(),
            failures.join("\n  - ")
        );
    }

    Ok(())
}

#[cfg(test)]
mod install_over_https;

#[cfg(test)]
mod tests {
    use super::*;
    use ppm::core::config::AppManifests;
    use serde_json::json;

    fn manifest(apps: serde_json::Value) -> AppManifests {
        serde_json::from_value(apps).expect("invariant: test manifest is schema-valid")
    }

    fn app(deps: Option<Vec<&str>>) -> serde_json::Value {
        let mut def = json!({
            "name": "App",
            "target_dir": "App",
            "executable": "app.exe",
            "version_check": {"type": "github_release", "repo": "a/b"},
            "package": {"type": "nsis_7z"}
        });
        if let Some(deps) = deps {
            def["dependencies"] = json!(deps);
        }
        def
    }

    #[test]
    fn a_current_installation_is_skipped_unless_forced() {
        assert!(is_already_current(
            ReinstallPolicy::SkipWhenCurrent,
            Some("1.2.3"),
            "1.2.3"
        ));
        assert!(!is_already_current(
            ReinstallPolicy::SkipWhenCurrent,
            Some("1.2.2"),
            "1.2.3"
        ));
        // Nothing installed is never "already current", whatever the policy.
        assert!(!is_already_current(
            ReinstallPolicy::SkipWhenCurrent,
            None,
            "1.2.3"
        ));
        // Force reinstalls even an exact match - that is what repairs a damaged install.
        assert!(!is_already_current(
            ReinstallPolicy::Always,
            Some("1.2.3"),
            "1.2.3"
        ));
    }

    #[test]
    fn the_cache_extension_comes_from_the_url_path() {
        assert_eq!(
            cache_extension("https://host/releases/App-1.0.zip", PackageKind::Zip),
            "zip"
        );
        assert_eq!(
            cache_extension("https://host/releases/App.tar.gz", PackageKind::Zip),
            "gz"
        );
        // Query strings and fragments are not part of the path.
        assert_eq!(
            cache_extension("https://host/App-1.0.7z?token=abc", PackageKind::SevenZ),
            "7z"
        );
    }

    /// Regression: the extension was taken by splitting the whole URL on its last dot, so a
    /// versioned path with no file extension produced a cache name containing a separator.
    #[test]
    fn an_extensionless_url_falls_back_to_the_declared_package_type() {
        assert_eq!(
            cache_extension("https://host/v1.2/download", PackageKind::Nsis7z),
            "exe"
        );
        assert_eq!(cache_extension("https://host/download", PackageKind::Msi), "msi");
        assert_eq!(cache_extension("not a url at all", PackageKind::Zip), "zip");
    }

    #[test]
    fn dependency_is_installed_before_dependent() {
        let manifests = manifest(json!({
            "apps": {
                "app": app(Some(vec!["lib"])),
                "lib": app(None),
            }
        }));
        assert_eq!(
            resolve_install_order(&manifests, "app").unwrap(),
            vec!["lib", "app"]
        );
    }

    #[test]
    fn diamond_dependency_is_deduplicated() {
        let manifests = manifest(json!({
            "apps": {
                "app": app(Some(vec!["left", "right"])),
                "left": app(Some(vec!["base"])),
                "right": app(Some(vec!["base"])),
                "base": app(None),
            }
        }));

        let order = resolve_install_order(&manifests, "app").unwrap();
        assert_eq!(*order.last().unwrap(), "app");
        assert_eq!(order.iter().filter(|id| *id == "base").count(), 1);
        let base = order.iter().position(|id| *id == "base").unwrap();
        assert!(base < order.iter().position(|id| *id == "left").unwrap());
        assert!(base < order.iter().position(|id| *id == "right").unwrap());
    }

    #[test]
    fn circular_dependency_is_rejected() {
        let manifests = manifest(json!({
            "apps": {
                "a": app(Some(vec!["b"])),
                "b": app(Some(vec!["a"])),
            }
        }));
        let err = resolve_install_order(&manifests, "a").unwrap_err().to_string();
        assert!(err.contains("Circular"), "{err}");
    }

    #[test]
    fn undefined_dependency_is_rejected() {
        let manifests = manifest(json!({ "apps": { "app": app(Some(vec!["ghost"])) } }));
        let err = resolve_install_order(&manifests, "app").unwrap_err().to_string();
        assert!(err.contains("Dependency 'ghost'"), "{err}");

        // Regression: an unknown requested app was reported as an undefined *dependency*.
        let err = resolve_install_order(&manifests, "nope").unwrap_err().to_string();
        assert!(err.contains("Application 'nope'"), "{err}");
    }

    #[test]
    fn all_mode_orders_every_app() {
        let manifests = manifest(json!({
            "apps": {
                "app": app(Some(vec!["lib"])),
                "lib": app(None),
                "solo": app(None),
            }
        }));

        let order = resolve_install_order(&manifests, "all").unwrap();
        assert_eq!(order.len(), 3);
        assert!(order.iter().position(|id| *id == "lib") < order.iter().position(|id| *id == "app"));
    }

    /// Three applications with their own directories: `app` depends on `lib`; `solo` stands alone.
    fn distinct_manifest() -> AppManifests {
        let entry = |dir: &str, deps: Vec<&str>| {
            json!({
                "name": dir,
                "target_dir": dir,
                "executable": "main.exe",
                "version_check": {"type": "github_release", "repo": "a/b"},
                "package": {"type": "zip"},
                "dependencies": deps
            })
        };
        manifest(json!({ "apps": {
            "app": entry("App", vec!["lib"]),
            "lib": entry("Lib", vec![]),
            "solo": entry("Solo", vec![]),
        }}))
    }

    fn install_fixture(root: &Path, dir: &str, arch: CpuArch) {
        let app_dir = root.join("Apps").join(arch.as_str()).join(dir);
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::write(app_dir.join("main.exe"), b"MZ").unwrap();
    }

    fn step(arch: CpuArch, app_id: &str) -> CycleStep {
        CycleStep {
            arch,
            app_id: app_id.to_string(),
        }
    }

    #[test]
    fn update_all_refreshes_installed_apps_in_dependency_order_and_installs_nothing() {
        let root = tempfile::tempdir().unwrap();
        install_fixture(root.path(), "App", CpuArch::X64);
        install_fixture(root.path(), "Lib", CpuArch::X64);
        install_fixture(root.path(), "Solo", CpuArch::Arm64);

        let plan = update_plan(
            root.path(),
            &distinct_manifest(),
            UpdateTarget::AllInstalled,
            &[CpuArch::X64, CpuArch::Arm64],
        )
        .unwrap();

        // `solo` is not installed for x64 and `app`/`lib` are not installed for arm64: none of
        // those is planned, and `lib` precedes its dependent.
        assert_eq!(
            plan,
            vec![
                step(CpuArch::X64, "lib"),
                step(CpuArch::X64, "app"),
                step(CpuArch::Arm64, "solo"),
            ]
        );
    }

    #[test]
    fn update_of_a_named_app_touches_only_that_app() {
        let root = tempfile::tempdir().unwrap();
        install_fixture(root.path(), "App", CpuArch::X64);
        install_fixture(root.path(), "Lib", CpuArch::X64);

        let plan = update_plan(
            root.path(),
            &distinct_manifest(),
            UpdateTarget::App("app"),
            &[CpuArch::X64],
        )
        .unwrap();

        assert_eq!(plan, vec![step(CpuArch::X64, "app")]);
    }

    #[test]
    fn updating_an_app_that_is_not_installed_points_at_install() {
        let root = tempfile::tempdir().unwrap();
        let manifests = distinct_manifest();

        let error = update_plan(
            root.path(),
            &manifests,
            UpdateTarget::App("solo"),
            &[CpuArch::X64],
        )
        .unwrap_err();
        assert!(error.to_string().contains("ppm install solo"), "{error}");

        let error = update_plan(
            root.path(),
            &manifests,
            UpdateTarget::App("ghost"),
            &[CpuArch::X64],
        )
        .unwrap_err();
        assert!(error.to_string().contains("not defined"), "{error}");

        // `--all` with nothing installed is an empty plan, not an error.
        assert!(
            update_plan(
                root.path(),
                &manifests,
                UpdateTarget::AllInstalled,
                &[CpuArch::X64]
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn install_plans_dependencies_first_for_every_architecture() {
        let plan = install_plan(&distinct_manifest(), "app", &[CpuArch::X64, CpuArch::Arm64]).unwrap();
        assert_eq!(
            plan,
            vec![
                step(CpuArch::X64, "lib"),
                step(CpuArch::X64, "app"),
                step(CpuArch::Arm64, "lib"),
                step(CpuArch::Arm64, "app"),
            ]
        );
    }
}
