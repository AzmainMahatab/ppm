mod core;
mod engine;
mod package;

use crate::core::arch::{ArchTarget, CpuArch};
use crate::core::config::{AppDefinition, AppManifests};
use clap::{Parser, Subcommand};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "ppm",
    about = "Portable Package Manager & Virtualization Runner",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the portable environment and scaffold directories
    Init {
        /// Force re-initialization and overwrite files
        #[arg(short, long)]
        force: bool,
    },

    /// Launch an application with virtualization and taskbar badging
    Run {
        /// Application identifier from apps.json or raw executable path
        app: String,

        /// Additional arguments passed directly to the application
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Check for online updates across configured applications
    Check {
        /// Target CPU architecture (x64, arm64, or all)
        #[arg(short, long, default_value = "all")]
        arch: ArchTarget,
    },

    /// Install one or all configured applications (resolves dependencies)
    Install {
        /// Application identifier to install, or 'all'
        app: String,

        /// Target CPU architecture (defaults to current host architecture)
        #[arg(short, long)]
        arch: Option<ArchTarget>,
    },

    /// Update outdated applications to the latest online release
    Update {
        /// Application identifier to update, or 'all'
        app: String,

        /// Target CPU architecture (defaults to current host architecture)
        #[arg(short, long)]
        arch: Option<ArchTarget>,
    },

    /// Generate or refresh 1-click .bat launchers in the root directory
    #[command(alias = "create-launchers")]
    Link {
        /// Specific application identifier, or 'all'
        #[arg(default_value = "all")]
        app: String,
    },

    /// List all configured applications and their dynamic installation status
    List {
        /// Target CPU architecture (x64, arm64, or all)
        #[arg(short, long, default_value = "all")]
        arch: ArchTarget,
    },

    /// Generate or update the JSON schema (apps.schema.json)
    Schema,

    /// Validate apps.json against the schema
    Validate,
}

fn resolve_root() -> PathBuf {
    let current_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("ppm.exe"));
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));

    let last_comp = exe_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

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

fn load_manifest(root: &Path) -> Result<AppManifests, String> {
    let apps_json_path = root.join(".ppm").join("apps.json");
    if apps_json_path.exists() {
        AppManifests::load_from_file(&apps_json_path)
    } else {
        let dev_manifest = root.join("manifests").join("apps.json");
        if dev_manifest.exists() {
            AppManifests::load_from_file(&dev_manifest)
        } else {
            Err(format!(
                "Manifest file not found at '{}'. Run 'ppm init' to generate default configuration.",
                apps_json_path.display()
            ))
        }
    }
}

fn resolve_install_order(
    manifests: &AppManifests,
    target_app_id: &str,
) -> Result<Vec<String>, String> {
    let mut order = Vec::new();
    let mut visited = HashSet::new();
    let mut visiting = HashSet::new();

    fn dfs(
        app_id: &str,
        manifests: &AppManifests,
        order: &mut Vec<String>,
        visited: &mut HashSet<String>,
        visiting: &mut HashSet<String>,
    ) -> Result<(), String> {
        if visiting.contains(app_id) {
            return Err(format!("Circular dependency detected involving '{}'", app_id));
        }
        if visited.contains(app_id) {
            return Ok(());
        }

        visiting.insert(app_id.to_string());

        let app_def = manifests
            .apps
            .get(app_id)
            .ok_or_else(|| format!("Dependency '{}' not defined in apps.json", app_id))?;

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
        dfs(
            target_app_id,
            manifests,
            &mut order,
            &mut visited,
            &mut visiting,
        )?;
    }

    Ok(order)
}

fn perform_install(
    root: &Path,
    app_id: &str,
    app_def: &AppDefinition,
    arch: CpuArch,
) -> Result<(), String> {
    if !app_def.is_supported_on_arch(arch) {
        println!("  • Skipping '{}' (Not supported on {})", app_def.name, arch.as_str());
        return Ok(());
    }

    println!("\n▶ Processing '{}' ({}) for architecture [{}]", app_def.name, app_id, arch.as_str());

    // 1. Fetch remote release metadata
    println!("  • Checking online release for {}...", arch.as_str());
    let release = package::version::check_remote_version(&app_def.version_check, arch)?;
    println!(
        "  • Found version {} at: {}",
        release.version, release.download_url
    );

    // 2. Download archive to isolated .ppm/cache/
    let temp_cache_dir = root.join(".ppm").join("cache");
    let _ = std::fs::create_dir_all(&temp_cache_dir);

    let ext = release
        .download_url
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or("pkg");
    let temp_archive = temp_cache_dir.join(format!("{}_{}_{}.{}", app_id, arch.as_str(), release.version, ext));

    println!("  • Downloading package...");
    package::downloader::download_file(&release.download_url, &temp_archive, &format!("{} ({})", app_def.name, arch.as_str()))?;

    // 3. Extract to target directory: Apps/<arch>/<target_dir>
    let target_dir = app_def.app_dir_for_arch(root, arch);
    println!("  • Unpacking to '{}'...", target_dir.display());
    package::extractor::extract_package(&temp_archive, &app_def.package, &target_dir)?;

    // 4. Sanitize payload
    println!("  • Sanitizing installation...");
    package::sanitizer::sanitize_package(&target_dir, app_def.post_install.as_ref())?;

    // 5. Clean temporary download
    let _ = std::fs::remove_file(&temp_archive);

    println!(
        "  ✓ Successfully installed {} [{}] (v{})",
        app_def.name, arch.as_str(), release.version
    );

    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let root = resolve_root();

    match cli.command {
        Commands::Init { force } => {
            println!("⚡ Initializing Portable Environment in '{}'...", root.display());
            match engine::init::init_environment(&root, force) {
                Ok(()) => println!("\n✓ Portable environment initialized successfully!"),
                Err(e) => {
                    eprintln!("\n✗ Error initializing environment: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Run { app, args } => {
            match engine::runner::run_app(&root, &app, &args) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("✗ Failed to run '{}': {}", app, e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Check { arch } => {
            let target_archs = arch.resolve();
            println!("🔍 Checking configured applications for architectures {:?}...\n", target_archs.iter().map(|a| a.as_str()).collect::<Vec<_>>());
            let manifests = match load_manifest(&root) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("✗ {}", e);
                    std::process::exit(1);
                }
            };

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    "App ID",
                    "Name",
                    "Arch",
                    "Local Version",
                    "Remote Version",
                    "Status",
                ]);

            for (app_id, app_def) in &manifests.apps {
                for &target_arch in &target_archs {
                    if !app_def.is_supported_on_arch(target_arch) {
                        table.add_row(vec![
                            Cell::new(app_id),
                            Cell::new(&app_def.name),
                            Cell::new(target_arch.as_str()).fg(Color::DarkGrey),
                            Cell::new("N/A").fg(Color::DarkGrey),
                            Cell::new("N/A").fg(Color::DarkGrey),
                            Cell::new("UNSUPPORTED").fg(Color::DarkGrey),
                        ]);
                        continue;
                    }

                    // 100% Dynamic presence-based local version detection from PE header
                    let local_v = package::version::detect_local_version(&root, app_def, target_arch);
                    let remote_res = package::version::check_remote_version(&app_def.version_check, target_arch);

                    let local_display = local_v.as_deref().unwrap_or("Not Installed");

                    match remote_res {
                        Ok(remote) => {
                            let status_cell = match &local_v {
                                None => Cell::new("NOT INSTALLED").fg(Color::Yellow),
                                Some(loc) if loc == &remote.version => {
                                    Cell::new("UP TO DATE").fg(Color::Green)
                                }
                                Some(_) => Cell::new("UPDATE AVAILABLE").fg(Color::Cyan),
                            };

                            table.add_row(vec![
                                Cell::new(app_id),
                                Cell::new(&app_def.name),
                                Cell::new(target_arch.as_str()).fg(Color::Magenta),
                                Cell::new(local_display),
                                Cell::new(&remote.version),
                                status_cell,
                            ]);
                        }
                        Err(e) => {
                            table.add_row(vec![
                                Cell::new(app_id),
                                Cell::new(&app_def.name),
                                Cell::new(target_arch.as_str()).fg(Color::Magenta),
                                Cell::new(local_display),
                                Cell::new(format!("Error: {}", e)).fg(Color::Red),
                                Cell::new("CHECK FAILED").fg(Color::Red),
                            ]);
                        }
                    }
                }
            }

            println!("{}", table);
        }

        Commands::Install { app, arch } => {
            let target_archs = arch
                .map(|a| a.resolve())
                .unwrap_or_else(|| vec![CpuArch::current()]);

            let manifests = match load_manifest(&root) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("✗ {}", e);
                    std::process::exit(1);
                }
            };

            let install_order = match resolve_install_order(&manifests, &app) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("✗ Failed to resolve dependency order: {}", e);
                    std::process::exit(1);
                }
            };

            for &target_arch in &target_archs {
                println!("\n=======================================================");
                println!("  Targeting Architecture: [{}]", target_arch.as_str());
                println!("=======================================================");

                for app_id in &install_order {
                    if let Some(app_def) = manifests.apps.get(app_id) {
                        if let Err(e) = perform_install(&root, app_id, app_def, target_arch) {
                            eprintln!("\n✗ Installation failed for '{}' [{}]: {}", app_id, target_arch.as_str(), e);
                            std::process::exit(1);
                        }
                    }
                }
            }

            // Refresh batch launchers
            let _ = engine::launcher::generate_launchers(&root, &manifests);
            println!("\n✓ All requested installations completed successfully!");
        }

        Commands::Update { app, arch } => {
            let target_archs = arch
                .map(|a| a.resolve())
                .unwrap_or_else(|| vec![CpuArch::current()]);

            let manifests = match load_manifest(&root) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("✗ {}", e);
                    std::process::exit(1);
                }
            };

            let update_order = match resolve_install_order(&manifests, &app) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("✗ Failed to resolve dependency order: {}", e);
                    std::process::exit(1);
                }
            };

            for &target_arch in &target_archs {
                println!("\n=======================================================");
                println!("  Checking Updates for Architecture: [{}]", target_arch.as_str());
                println!("=======================================================");

                for app_id in &update_order {
                    if let Some(app_def) = manifests.apps.get(app_id) {
                        if !app_def.is_supported_on_arch(target_arch) {
                            continue;
                        }

                        println!("\n▶ Checking update for '{}' [{}]...", app_def.name, target_arch.as_str());
                        let local_v = package::version::detect_local_version(&root, app_def, target_arch);
                        let remote_res = package::version::check_remote_version(&app_def.version_check, target_arch);

                        match (local_v, remote_res) {
                            (Some(loc), Ok(remote)) if loc == remote.version => {
                                println!("  ✓ {} [{}] is already up to date (v{})", app_def.name, target_arch.as_str(), loc);
                            }
                            (_, Ok(_)) => {
                                if let Err(e) = perform_install(&root, app_id, app_def, target_arch) {
                                    eprintln!("\n✗ Update failed for '{}' [{}]: {}", app_id, target_arch.as_str(), e);
                                    std::process::exit(1);
                                }
                            }
                            (_, Err(e)) => {
                                eprintln!("  ✗ Failed to check remote version: {}", e);
                            }
                        }
                    }
                }
            }

            let _ = engine::launcher::generate_launchers(&root, &manifests);
            println!("\n✓ Update check and upgrade cycle complete!");
        }

        Commands::Link { app } => {
            let manifests = match load_manifest(&root) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("✗ {}", e);
                    std::process::exit(1);
                }
            };

            if app == "all" {
                match engine::launcher::generate_launchers(&root, &manifests) {
                    Ok(generated) => {
                        println!("⚡ Generated root launchers:");
                        for g in generated {
                            println!("  ✓ {}", g);
                        }
                    }
                    Err(e) => {
                        eprintln!("✗ Error generating launchers: {}", e);
                        std::process::exit(1);
                    }
                }
            } else if manifests.apps.contains_key(&app) {
                match engine::launcher::generate_single_launcher(&root, &app) {
                    Ok(()) => println!("✓ Generated root launcher: {}.bat", app),
                    Err(e) => {
                        eprintln!("✗ Error generating launcher: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("✗ App '{}' not found in apps.json", app);
                std::process::exit(1);
            }
        }

        Commands::List { arch } => {
            let target_archs = arch.resolve();
            let manifests = match load_manifest(&root) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("✗ {}", e);
                    std::process::exit(1);
                }
            };

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    "App ID",
                    "Name",
                    "Arch",
                    "Version",
                    "Target Directory",
                    "Executable Path",
                    "Dependencies",
                    "Installed",
                ]);

            for (app_id, app_def) in &manifests.apps {
                for &target_arch in &target_archs {
                    if !app_def.is_supported_on_arch(target_arch) {
                        let deps_str = app_def
                            .dependencies
                            .as_ref()
                            .map(|d| d.join(", "))
                            .unwrap_or_else(|| "-".to_string());

                        table.add_row(vec![
                            Cell::new(app_id),
                            Cell::new(&app_def.name),
                            Cell::new(target_arch.as_str()).fg(Color::DarkGrey),
                            Cell::new("-").fg(Color::DarkGrey),
                            Cell::new(&app_def.target_dir).fg(Color::DarkGrey),
                            Cell::new("-").fg(Color::DarkGrey),
                            Cell::new(deps_str).fg(Color::DarkGrey),
                            Cell::new("UNSUPPORTED").fg(Color::DarkGrey),
                        ]);
                        continue;
                    }

                    let local_v = package::version::detect_local_version(&root, app_def, target_arch);
                    let is_installed = if local_v.is_some() {
                        Cell::new("YES").fg(Color::Green)
                    } else {
                        Cell::new("NO").fg(Color::Red)
                    };

                    let version_str = local_v.unwrap_or_else(|| "-".to_string());

                    let deps_str = app_def
                        .dependencies
                        .as_ref()
                        .map(|d| d.join(", "))
                        .unwrap_or_else(|| "-".to_string());

                    let rel_exe_path = format!("Apps/{}/{}/{}", target_arch.as_str(), app_def.target_dir, app_def.executable);

                    table.add_row(vec![
                        Cell::new(app_id),
                        Cell::new(&app_def.name),
                        Cell::new(target_arch.as_str()).fg(Color::Magenta),
                        Cell::new(version_str),
                        Cell::new(&app_def.target_dir),
                        Cell::new(rel_exe_path),
                        Cell::new(deps_str),
                        is_installed,
                    ]);
                }
            }

            println!("{}", table);
        }

        Commands::Schema => {
            let schema = schemars::schema_for!(AppManifests);
            let schema_json = serde_json::to_string_pretty(&schema).unwrap();

            let schema_path = root.join(".ppm").join("apps.schema.json");
            if let Some(p) = schema_path.parent() {
                let _ = std::fs::create_dir_all(p);
            }

            let _ = std::fs::write(&schema_path, &schema_json);

            let ref_schema = root.join("manifests").join("apps.schema.json");
            if let Some(p) = ref_schema.parent() {
                let _ = std::fs::create_dir_all(p);
                let _ = std::fs::write(&ref_schema, &schema_json);
            }

            println!("✓ JSON Schema generated at '{}'", schema_path.display());
        }

        Commands::Validate => match load_manifest(&root) {
            Ok(manifests) => {
                println!(
                    "✓ Manifest is valid! Configured applications ({}):",
                    manifests.apps.len()
                );
                for (id, app) in manifests.apps {
                    println!("  • {} ({}) -> {}", app.name, id, app.executable);
                }
            }
            Err(e) => {
                eprintln!("✗ Manifest validation failed: {}", e);
                std::process::exit(1);
            }
        },
    }
}
