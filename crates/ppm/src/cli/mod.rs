pub(crate) mod commands;
pub(crate) mod context;
pub(crate) mod logging;
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
    // Why not `global = true`: `ppm run <app> <args...>` hands every argument after the app to
    // the application, and a global `-v` would be taken from that list. Verbosity is therefore
    // given before the subcommand: `ppm -v install all`.
    /// Show debug messages on the console
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Show only warnings and errors on the console
    #[arg(short, long)]
    quiet: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

impl Cli {
    pub(crate) fn verbosity(&self) -> logging::ConsoleVerbosity {
        match (self.verbose, self.quiet) {
            (true, _) => logging::ConsoleVerbosity::Verbose,
            (_, true) => logging::ConsoleVerbosity::Quiet,
            _ => logging::ConsoleVerbosity::Normal,
        }
    }
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

    /// Install or refresh one or all configured applications (resolves dependencies).
    ///
    /// An application already installed at the latest version is left alone, so `install`
    /// doubles as `update`; pass `--force` to reinstall it regardless.
    Install {
        /// Application identifier to install, or 'all'
        app: String,

        /// Target CPU architecture (defaults to current host architecture)
        #[arg(short, long)]
        arch: Option<ArchTarget>,

        /// Reinstall even when the installed version is already current
        #[arg(short, long)]
        force: bool,
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

    /// Remove an installed application (and its launcher once no copy remains)
    Uninstall {
        /// Application identifier to remove
        app: String,

        /// Architecture to remove (x64, arm64, or all)
        #[arg(short, long, default_value = "all")]
        arch: ArchTarget,
    },

    /// Empty the download cache and remove debris left by interrupted installs
    Clean,
}

/// Executes the parsed command against the resolved portable root and returns the process exit
/// code: the launched application's own code for `run`, zero for every other command.
pub(crate) fn execute(command: &Commands, root: &Path) -> anyhow::Result<i32> {
    match command {
        Commands::Run { app, args } => return commands::run::run(root, app, args),
        Commands::Init => commands::init::run(root),
        Commands::Check { arch } => commands::check::run(root, *arch),
        Commands::Install { app, arch, force } => commands::install::run(root, app, *arch, *force),
        Commands::Update { app, arch } => commands::update::run(root, app, *arch),
        Commands::Link { app } => commands::link::run(root, app),
        Commands::List { arch } => commands::list::run(root, *arch),
        Commands::Schema => commands::schema::run(root),
        Commands::Validate => commands::validate::run(root),
        Commands::Uninstall { app, arch } => commands::uninstall::run(root, app, *arch),
        Commands::Clean => commands::clean::run(root),
    }?;
    Ok(0)
}
