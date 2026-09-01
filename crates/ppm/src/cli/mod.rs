pub(crate) mod commands;
pub(crate) mod context;
pub(crate) mod pipeline;

use clap::{Parser, Subcommand};
use std::path::Path;

use ppm::core::arch::ArchTarget;

#[derive(Parser)]
// `version` with no value takes CARGO_PKG_VERSION, so `ppm --version` can never drift from
// the crate version the way the previous hard-coded literal did.
#[command(
    name = "ppm",
    about = "Portable Package Manager & Virtualization Runner",
    version
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Initialize the portable environment and scaffold directories
    Init,

    /// Launch an application with virtualization and taskbar badging
    #[command(disable_help_flag = true)]
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

/// Executes the parsed command against the resolved portable root.
pub(crate) fn execute(command: &Commands, root: &Path) -> anyhow::Result<()> {
    match command {
        Commands::Init => commands::init::run(root),
        Commands::Run { app, args } => commands::run::run(root, app, args),
        Commands::Check { arch } => commands::check::run(root, *arch),
        Commands::Install { app, arch } => commands::install::run(root, app, *arch),
        Commands::Update { app, arch } => commands::update::run(root, app, *arch),
        Commands::Link { app } => commands::link::run(root, app),
        Commands::List { arch } => commands::list::run(root, *arch),
        Commands::Schema => commands::schema::run(root),
        Commands::Validate => commands::validate::run(root),
    }
}
