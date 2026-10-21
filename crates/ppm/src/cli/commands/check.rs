use std::path::Path;

use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use ppm::core::arch::ArchTarget;
use ppm::package;

use crate::cli::context::load_manifest;

pub(crate) fn run(root: &Path, arch: ArchTarget) -> anyhow::Result<()> {
    let target_archs = arch.resolve();
    tracing::info!(
        "🔍 Checking configured applications for architectures {:?}...",
        target_archs.iter().map(|a| a.as_str()).collect::<Vec<_>>()
    );
    let manifests = load_manifest(root)?;

    let mut table = Table::new();
    table
        .load_style(UTF8_FULL.with_rounded_corners())
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
            let local_v = package::version::detect_local_version(root, app_def, target_arch);
            let remote_res = package::version::check_remote_version(&app_def.version_check, target_arch);

            let is_installed = app_def.is_installed_for_arch(root, target_arch);
            let local_display = match (&local_v, is_installed) {
                (Some(v), _) => v.as_str(),
                (None, true) => "Installed (Unversioned)",
                (None, false) => "Not Installed",
            };

            match remote_res {
                Ok(remote) => {
                    let status_cell = match (&local_v, is_installed) {
                        (_, false) => Cell::new("NOT INSTALLED").fg(Color::Yellow),
                        (Some(loc), true) if loc == &remote.version => {
                            Cell::new("UP TO DATE").fg(Color::Green)
                        }
                        _ => Cell::new("UPDATE AVAILABLE").fg(Color::Cyan),
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

    // Why stdout: the table is the command's data output, meant to be piped or redirected.
    println!("{}", table);
    Ok(())
}
