//! Relative paths that cannot leave the directory they are joined onto.
//!
//! # Why this exists
//! Manifest fields (`target_dir`, `executable`, `extract_subpath`, `post_install` rules) and
//! archive entry names (CAB files, MSI `File` rows) are joined onto an install directory.
//! `Path::join` replaces the base outright when handed an absolute or drive-qualified path, and
//! a `..` component walks out of it, so an unchecked join can write or delete anywhere on disk.

use anyhow::{Result, bail};
use std::path::{Component, Path, PathBuf};

/// Parses `raw` as a path that stays inside whatever directory it is joined onto.
///
/// `.` components are dropped; an empty path, a root, a drive or UNC prefix, or a `..`
/// component is rejected.
///
/// # Ex
/// `resources\app-update.yml` -> `resources\app-update.yml`; `..\x`, `C:\x`, `\x` -> error
pub fn confined(raw: &str) -> Result<PathBuf> {
    let mut confined = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(part) => confined.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("Path '{raw}' must stay inside its base directory")
            }
        }
    }
    if confined.as_os_str().is_empty() {
        bail!("Path '{raw}' names no file or directory");
    }
    Ok(confined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_relative_paths_are_accepted_in_either_separator_spelling() {
        assert_eq!(
            confined("resources/app-update.yml").unwrap(),
            PathBuf::from("resources").join("app-update.yml")
        );
        assert_eq!(
            confined(r".\cache\stale.tmp").unwrap(),
            PathBuf::from("cache").join("stale.tmp")
        );
    }

    #[test]
    fn paths_that_escape_the_base_are_rejected() {
        for escaping in [
            r"..\Windows",
            "a/../../b",
            r"C:\Windows\System32",
            r"\Windows",
            r"\\server\share\x",
            "",
            ".",
        ] {
            assert!(confined(escaping).is_err(), "'{escaping}' must be rejected");
        }
    }
}
