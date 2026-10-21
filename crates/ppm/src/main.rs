//! ppm — Portable Package Manager & Virtualization Runner (CLI entry point).
//!
//! Command implementations live in `cli/commands/`, shared install machinery in
//! `cli/pipeline.rs`, root/manifest resolution in `cli/context.rs`, and log sinks in
//! `cli/logging.rs`.

mod cli;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let root = cli::context::resolve_root();

    let log_guard = match cli::logging::init(&root, cli.verbosity()) {
        Ok(guard) => guard,
        Err(error) => {
            // Why a direct write: the logger itself failed to start, so there is no sink to
            // route this through.
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
    };

    let exit_code = match cli::execute(&cli.command, &root) {
        Ok(code) => code,
        Err(error) => {
            tracing::error!("{error:#}");
            1
        }
    };

    // Why an explicit drop: `process::exit` runs no destructors, and the guard is what flushes
    // the file sink's buffered lines.
    drop(log_guard);
    std::process::exit(exit_code);
}
