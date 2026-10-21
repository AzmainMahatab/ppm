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

/// A manifest path that has already been [`confined`]: it can only exist in that form, so code
/// joining it onto a directory needs no check of its own.
///
/// It keeps the text the manifest gave, which is what messages show and what serializes back.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelativePath {
    raw: String,
    path: PathBuf,
}

impl RelativePath {
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl TryFrom<String> for RelativePath {
    type Error = anyhow::Error;

    fn try_from(raw: String) -> Result<Self> {
        let path = confined(&raw)?;
        Ok(RelativePath { raw, path })
    }
}

impl From<RelativePath> for String {
    fn from(path: RelativePath) -> String {
        path.raw
    }
}

impl AsRef<Path> for RelativePath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Display for RelativePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// In the published schema a relative path is a plain string, exactly as it was before the type
/// existed; the confinement rule is enforced at load and documented in SPEC section 2.1.
impl schemars::JsonSchema for RelativePath {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        String::schema_name()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(generator)
    }
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
