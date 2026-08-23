mod assets;
mod config;
mod downloader;
mod extractor;
mod init;
mod launcher_gen;
mod runner;
mod sanitizer;
mod version;

use clap::{Parser, Subcommand};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use config::{load_manifest, AppDefinition, AppManifests};
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use version::{
    check_remote_version, detect_local_version, load_state_ledger, save_state_ledger,
};

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
    Check,

    /// Install one or all configured applications (resolves dependencies)
    Install {
        /// Application identifier to install, or 'all'
        app: String,
    },

    /// Update outdated applications to the latest online release
    Update {
        /// Application identifier to update, or 'all'
        app: String,
    },

    /// Generate or refresh 1-click .bat launchers in the root directory
    #[command(alias = "create-launchers")]
    Link {
        /// Specific application identifier, or 'all'
        #[arg(default_value = "all")]
        app: String,
    },

    /// List all configured applications and their installation status
    List,

    /// Generate or update the JSON schema (apps.schema.json)
    Schema,

    /// Validate apps.json against the schema
    Validate,
}

fn resolve_root() -> PathBuf {
    let current_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("ppm.exe"));
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));

    if exe_dir.ends_with(".ppm")
        || exe_dir.ends_with("Engine")
        || exe_dir.ends_with("lib")
        || exe_dir.ends_with("dist")
    {
        exe_dir.parent().unwrap_or(exe_dir).to_path_buf()
    } else if exe_dir.ends_with("release") || exe_dir.ends_with("debug") {
        exe_dir
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(exe_dir)
            .to_path_buf()
    } else {
        exe_dir.to_path_buf()
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
    ledger: &mut HashMap<String, String>,
) -> Result<(), String> {
    println!("\n▶ Processing '{}' ({})", app_def.name, app_id);

    // 1. Fetch remote release metadata
    println!("  • Checking online release...");
    let release = check_remote_version(&app_def.version_check)?;
    println!(
        "  • Found version {} at: {}",
        release.version, release.download_url
    );

    // 2. Download archive to temp file
    let temp_cache_dir = root.join(".ppm").join("cache");
    let _ = std::fs::create_dir_all(&temp_cache_dir);

    let ext = release
        .download_url
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or("pkg");
    let temp_archive = temp_cache_dir.join(format!("{}_{}.{}", app_id, release.version, ext));

    println!("  • Downloading package...");
    downloader::download_file(&release.download_url, &temp_archive, &app_def.name)?;

    // 3. Extract to target directory
    let target_dir = root.join(&app_def.target_dir);
    println!("  • Unpacking to '{}'...", target_dir.display());
    extractor::extract_package(&temp_archive, &app_def.package, &target_dir)?;

    // 4. Sanitize payload
    println!("  • Sanitizing installation...");
    sanitizer::sanitize_package(&target_dir, app_def.post_install.as_ref())?;

    // 5. Update state ledger
    ledger.insert(app_id.to_string(), release.version.clone());
    save_state_ledger(root, ledger)?;

    // 6. Clean temporary download
    let _ = std::fs::remove_file(&temp_archive);

    println!(
        "  ✓ Successfully installed {} (v{})",
        app_def.name, release.version
    );

    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let root = resolve_root();

    match cli.command {
        Commands::Init { force } => {
            println!("⚡ Initializing Portable Environment in '{}'...", root.display());
            match init::init_environment(&root, force) {
                Ok(()) => println!("\n✓ Portable environment initialized successfully!"),
                Err(e) => {
                    eprintln!("\n✗ Error initializing environment: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Run { app, args } => {
            match runner::run_app(&root, &app, &args) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("✗ Failed to run '{}': {}", app, e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Check => {
            println!("🔍 Checking configured applications...\n");
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
                    "Local Version",
                    "Remote Version",
                    "Status",
                ]);

            for (app_id, app_def) in &manifests.apps {
                let local_v = detect_local_version(&root, app_id, app_def);
                let remote_res = check_remote_version(&app_def.version_check);

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
                            Cell::new(local_display),
                            Cell::new(&remote.version),
                            status_cell,
                        ]);
                    }
                    Err(e) => {
                        table.add_row(vec![
                            Cell::new(app_id),
                            Cell::new(&app_def.name),
                            Cell::new(local_display),
                            Cell::new(format!("Error: {}", e)).fg(Color::Red),
                            Cell::new("CHECK FAILED").fg(Color::Red),
                        ]);
                    }
                }
            }

            println!("{}", table);
        }

        Commands::Install { app } => {
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

            let mut ledger = load_state_ledger(&root);

            for app_id in install_order {
                if let Some(app_def) = manifests.apps.get(&app_id) {
                    if let Err(e) = perform_install(&root, &app_id, app_def, &mut ledger) {
                        eprintln!("\n✗ Installation failed for '{}': {}", app_id, e);
                        std::process::exit(1);
                    }
                }
            }

            // Refresh batch launchers
            let _ = launcher_gen::generate_launchers(&root, &manifests);
            println!("\n✓ All requested installations completed successfully!");
        }

        Commands::Update { app } => {
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

            let mut ledger = load_state_ledger(&root);

            for app_id in update_order {
                if let Some(app_def) = manifests.apps.get(&app_id) {
                    println!("\n▶ Checking update for '{}'...", app_def.name);
                    let local_v = detect_local_version(&root, &app_id, app_def);
                    let remote_res = check_remote_version(&app_def.version_check);

                    match (local_v, remote_res) {
                        (Some(loc), Ok(remote)) if loc == remote.version => {
                            println!("  ✓ {} is already up to date (v{})", app_def.name, loc);
                        }
                        (_, Ok(_)) => {
                            if let Err(e) = perform_install(&root, &app_id, app_def, &mut ledger) {
                                eprintln!("\n✗ Update failed for '{}': {}", app_id, e);
                                std::process::exit(1);
                            }
                        }
                        (_, Err(e)) => {
                            eprintln!("  ✗ Failed to check remote version: {}", e);
                        }
                    }
                }
            }

            let _ = launcher_gen::generate_launchers(&root, &manifests);
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
                match launcher_gen::generate_launchers(&root, &manifests) {
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
                match launcher_gen::generate_single_launcher(&root, &app) {
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

        Commands::List => {
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
                    "Target Directory",
                    "Executable",
                    "Dependencies",
                    "Installed",
                ]);

            for (app_id, app_def) in &manifests.apps {
                let full_exe = root.join(&app_def.target_dir).join(&app_def.executable);
                let is_installed = if full_exe.exists() {
                    Cell::new("YES").fg(Color::Green)
                } else {
                    Cell::new("NO").fg(Color::Red)
                };

                let deps_str = app_def
                    .dependencies
                    .as_ref()
                    .map(|d| d.join(", "))
                    .unwrap_or_else(|| "-".to_string());

                table.add_row(vec![
                    Cell::new(app_id),
                    Cell::new(&app_def.name),
                    Cell::new(&app_def.target_dir),
                    Cell::new(&app_def.executable),
                    Cell::new(deps_str),
                    is_installed,
                ]);
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

            // Also update manifests/apps.schema.json if manifests/ exists
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
