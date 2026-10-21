//! Where each file of an MSI package lands, derived from its `Directory`, `Component`, `File`
//! and `Media` tables.
//!
//! # Why the tables are resolved instead of extracting the cabinets flat
//! An MSI cabinet names its entries by `File` table key, not by path. Writing every entry into
//! one folder lost the directory tree, and two files with the same name in different folders -
//! `lib_1.1\nunit.core.dll` and `lib_2.0\nunit.core.dll` - overwrote each other. The layout here
//! is the one an administrative install (`msiexec /a`) produces: each directory's *source* name,
//! long form, nested under its parent - so the pure extraction and the `msiexec` fallback agree.
//!
//! The resolution is pure: rows in, relative paths out. Reading the tables is the caller's job.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::core::relpath::confined;

pub struct DirectoryRow {
    pub id: String,
    pub parent: Option<String>,
    pub default_dir: String,
}

pub struct ComponentRow {
    pub id: String,
    pub directory: String,
}

pub struct FileRow {
    pub key: String,
    pub component: String,
    pub file_name: String,
}

pub struct MediaRow {
    pub disk_id: i32,
    pub cabinet: Option<String>,
}

/// Where a cabinet named by the `Media` table is stored.
#[derive(Debug, PartialEq, Eq)]
pub enum CabinetSource {
    /// A stream inside the package (`#name` in the table).
    Embedded(String),
    /// A file beside the package.
    External(PathBuf),
}

/// The long form of an MSI `short|long` name.
fn long_name(name: &str) -> &str {
    name.split_once('|').map_or(name, |(_, long)| long)
}

/// The path segment a directory contributes to an administrative image, or `None` for `.`,
/// which means "the parent directory itself".
///
/// # Ex
/// `PFiles` -> `PFiles`; `qktpwm64|Antigravity Tools` -> `Antigravity Tools`;
/// `NUnit:Src|Source Files` -> `Source Files`; `.` -> none
fn source_segment(default_dir: &str) -> Option<&str> {
    // `target:source`; without a source part the target name is used for both.
    let side = default_dir
        .split_once(':')
        .map_or(default_dir, |(_, source)| source);
    Some(long_name(side)).filter(|segment| *segment != ".")
}

fn is_root(row: &DirectoryRow) -> bool {
    row.parent
        .as_deref()
        .is_none_or(|parent| parent.is_empty() || parent == row.id)
}

/// Resolves every directory to its path relative to the administrative image root.
pub fn resolve_directories(rows: &[DirectoryRow]) -> Result<HashMap<String, PathBuf>> {
    let by_id: HashMap<&str, &DirectoryRow> = rows.iter().map(|row| (row.id.as_str(), row)).collect();
    let mut resolved = HashMap::new();
    for row in rows {
        resolved.insert(row.id.clone(), resolve_one(row, &by_id)?);
    }
    Ok(resolved)
}

fn resolve_one(row: &DirectoryRow, by_id: &HashMap<&str, &DirectoryRow>) -> Result<PathBuf> {
    let mut segments = Vec::new();
    let mut current = row;
    // Why bounded by the row count: a well-formed table is a tree, so a chain longer than the
    // number of rows can only be a cycle.
    for _ in 0..=by_id.len() {
        if is_root(current) {
            let mut path = PathBuf::new();
            for segment in segments.iter().rev() {
                path.push(segment);
            }
            return Ok(path);
        }
        if let Some(segment) = source_segment(&current.default_dir) {
            segments.push(
                confined(segment)
                    .with_context(|| format!("MSI directory '{}' has an unsafe name", current.id))?,
            );
        }
        let parent = current
            .parent
            .as_deref()
            .expect("invariant: a non-root row has a parent");
        current = by_id
            .get(parent)
            .with_context(|| format!("MSI directory '{}' names a missing parent '{parent}'", current.id))?;
    }
    bail!("MSI directory '{}' is part of a parent cycle", row.id)
}

/// Maps every `File` table key - the name its cabinet entry carries - to its relative path.
pub fn file_paths(
    directories: &[DirectoryRow],
    components: &[ComponentRow],
    files: &[FileRow],
) -> Result<HashMap<String, PathBuf>> {
    let directory_paths = resolve_directories(directories)?;
    let component_dirs: HashMap<&str, &str> = components
        .iter()
        .map(|component| (component.id.as_str(), component.directory.as_str()))
        .collect();

    let mut paths = HashMap::new();
    for file in files {
        let directory = component_dirs.get(file.component.as_str()).with_context(|| {
            format!(
                "MSI file '{}' names a missing component '{}'",
                file.key, file.component
            )
        })?;
        let directory_path = directory_paths.get(*directory).with_context(|| {
            format!(
                "MSI component '{}' names a missing directory '{directory}'",
                file.component
            )
        })?;
        let name = confined(long_name(&file.file_name))
            .with_context(|| format!("MSI file '{}' has an unsafe name", file.key))?;
        paths.insert(file.key.clone(), directory_path.join(name));
    }
    Ok(paths)
}

/// The cabinets the `Media` table names, in disk order. Rows without a cabinet describe
/// uncompressed source media and contribute nothing.
pub fn cabinets(media: &[MediaRow]) -> Result<Vec<CabinetSource>> {
    let ordered: BTreeMap<i32, &str> = media
        .iter()
        .filter_map(|row| {
            row.cabinet
                .as_deref()
                .filter(|name| !name.is_empty())
                .map(|name| (row.disk_id, name))
        })
        .collect();

    ordered
        .into_values()
        .map(|name| match name.strip_prefix('#') {
            Some(stream) => Ok(CabinetSource::Embedded(stream.to_string())),
            None => Ok(CabinetSource::External(confined(name).with_context(|| {
                format!("MSI media names an unsafe cabinet '{name}'")
            })?)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(id: &str, parent: Option<&str>, default_dir: &str) -> DirectoryRow {
        DirectoryRow {
            id: id.to_string(),
            parent: parent.map(str::to_string),
            default_dir: default_dir.to_string(),
        }
    }

    /// The real directory table of the Antigravity Tools 4.9.8 MSI (WiX, Tauri).
    fn antigravity_tools_directories() -> Vec<DirectoryRow> {
        vec![
            dir(
                "INSTALLDIR",
                Some("ProgramFiles64Folder"),
                "qktpwm64|Antigravity Tools",
            ),
            dir("DesktopFolder", Some("TARGETDIR"), "Desktop"),
            dir(
                "ApplicationProgramsFolder",
                Some("ProgramMenuFolder"),
                "bntwlgzn|Antigravity Tools",
            ),
            dir("TARGETDIR", None, "SourceDir"),
            dir("ProgramFiles64Folder", Some("TARGETDIR"), "PFiles"),
            dir("ProgramMenuFolder", Some("TARGETDIR"), "."),
        ]
    }

    #[test]
    fn directories_resolve_to_the_administrative_image_layout() {
        let resolved = resolve_directories(&antigravity_tools_directories()).unwrap();

        assert_eq!(resolved["TARGETDIR"], PathBuf::new());
        assert_eq!(resolved["INSTALLDIR"], PathBuf::from(r"PFiles\Antigravity Tools"));
        // `.` contributes no segment of its own.
        assert_eq!(
            resolved["ApplicationProgramsFolder"],
            PathBuf::from("Antigravity Tools")
        );
    }

    #[test]
    fn the_source_side_of_a_target_source_pair_names_the_directory() {
        let resolved = resolve_directories(&[
            dir("TARGETDIR", None, "SourceDir"),
            dir("APP", Some("TARGETDIR"), "APP|Application:SRC|Source Tree"),
        ])
        .unwrap();
        assert_eq!(resolved["APP"], PathBuf::from("Source Tree"));
    }

    /// Regression: entries were written flat, so same-named files in different directories
    /// overwrote each other.
    #[test]
    fn same_named_files_in_different_directories_keep_distinct_paths() {
        let directories = vec![
            dir("TARGETDIR", None, "SourceDir"),
            dir("INSTALLDIR", Some("TARGETDIR"), "NUnit|NUnit 2.5.2"),
            dir("lib_1.1", Some("INSTALLDIR"), "lib"),
            dir("lib_2.0", Some("INSTALLDIR"), "net-2.0"),
        ];
        let components = vec![
            ComponentRow {
                id: "core_1.1".to_string(),
                directory: "lib_1.1".to_string(),
            },
            ComponentRow {
                id: "core_2.0".to_string(),
                directory: "lib_2.0".to_string(),
            },
        ];
        let files = vec![
            FileRow {
                key: "core.dll_1.1".to_string(),
                component: "core_1.1".to_string(),
                file_name: "NUNITC~1.DLL|nunit.core.dll".to_string(),
            },
            FileRow {
                key: "core.dll_2.0".to_string(),
                component: "core_2.0".to_string(),
                file_name: "NUNITC~1.DLL|nunit.core.dll".to_string(),
            },
        ];

        let paths = file_paths(&directories, &components, &files).unwrap();

        assert_eq!(
            paths["core.dll_1.1"],
            PathBuf::from(r"NUnit 2.5.2\lib\nunit.core.dll")
        );
        assert_eq!(
            paths["core.dll_2.0"],
            PathBuf::from(r"NUnit 2.5.2\net-2.0\nunit.core.dll")
        );
    }

    #[test]
    fn malformed_tables_are_rejected() {
        let cycle = [dir("A", Some("B"), "a"), dir("B", Some("A"), "b")];
        assert!(resolve_directories(&cycle).is_err());

        let orphan = [dir("A", Some("GHOST"), "a")];
        assert!(resolve_directories(&orphan).is_err());

        let escaping = [
            dir("TARGETDIR", None, "SourceDir"),
            dir("A", Some("TARGETDIR"), ".."),
        ];
        assert!(resolve_directories(&escaping).is_err());

        let files = [FileRow {
            key: "f".to_string(),
            component: "missing".to_string(),
            file_name: "f.txt".to_string(),
        }];
        assert!(file_paths(&[dir("TARGETDIR", None, "SourceDir")], &[], &files).is_err());
    }

    #[test]
    fn cabinets_come_from_the_media_table_in_disk_order() {
        let media = [
            MediaRow {
                disk_id: 2,
                cabinet: Some("disk2.cab".to_string()),
            },
            MediaRow {
                disk_id: 1,
                cabinet: Some("#app.cab".to_string()),
            },
            MediaRow {
                disk_id: 3,
                cabinet: None,
            },
        ];
        assert_eq!(
            cabinets(&media).unwrap(),
            vec![
                CabinetSource::Embedded("app.cab".to_string()),
                CabinetSource::External(PathBuf::from("disk2.cab")),
            ]
        );

        let escaping = [MediaRow {
            disk_id: 1,
            cabinet: Some(r"..\other.cab".to_string()),
        }];
        assert!(cabinets(&escaping).is_err());
    }
}
