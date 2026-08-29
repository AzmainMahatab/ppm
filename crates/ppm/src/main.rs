//! ppm — Portable Package Manager & Virtualization Runner (CLI entry point).
//!
//! Command implementations live in `cli/commands/`, shared install machinery in
//! `cli/pipeline.rs`, and root/manifest resolution in `cli/context.rs`.

mod cli;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let root = cli::context::resolve_root();
    cli::execute(&cli.command, &root)
}
