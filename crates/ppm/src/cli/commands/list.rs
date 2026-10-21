use std::path::Path;

use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use ppm::core::arch::ArchTarget;
use ppm::package;

use crate::cli::context::load_manifest;

pub(crate) fn run(root: &Path, arch: ArchTarget) -> anyhow::Result<()> {
    let target_archs = arch.resolve();
    let manifests = load_manifest(root)?;

    let mut table = Table::new();
    table
        .load_style(UTF8_FULL.with_rounded_corners())
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

            let local_v = package::version::detect_local_version(root, app_def, target_arch);
            let is_installed = app_def.is_installed_for_arch(root, target_arch);
            let installed_cell = if is_installed {
                Cell::new("YES").fg(Color::Green)
            } else {
                Cell::new("NO").fg(Color::Red)
            };

            let version_str = match (local_v, is_installed) {
                (Some(v), _) => v,
                (None, true) => "Unversioned".to_string(),
                (None, false) => "-".to_string(),
            };

            let deps_str = app_def
                .dependencies
                .as_ref()
                .map(|d| d.join(", "))
                .unwrap_or_else(|| "-".to_string());

            let rel_exe_path = format!(
                "Apps/{}/{}/{}",
                target_arch.as_str(),
                app_def.target_dir,
                app_def.executable
            );

            table.add_row(vec![
                Cell::new(app_id),
                Cell::new(&app_def.name),
                Cell::new(target_arch.as_str()).fg(Color::Magenta),
                Cell::new(version_str),
                Cell::new(&app_def.target_dir),
                Cell::new(rel_exe_path),
                Cell::new(deps_str),
                installed_cell,
            ]);
        }
    }

    // Why stdout: the table is the command's data output, meant to be piped or redirected.
    println!("{}", table);
    Ok(())
}
