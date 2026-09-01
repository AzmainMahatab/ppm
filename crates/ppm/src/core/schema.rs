//! Generation of the tracked JSON Schema artifacts.
//!
//! # Why this is not inlined at its two call sites
//! `ppm init` and `ppm schema` each built the target list and wrote it themselves. The copies
//! diverged - only one filtered targets whose parent directory is absent - which made
//! `ppm schema` fail in a deployed root. The schema is derived from one type model; it deserves
//! one writer.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::config::AppManifests;
use crate::core::layout::PortableLayout;

/// Regenerates the JSON Schema from the Rust type model and publishes it to every applicable
/// target, returning the files actually written.
pub fn write_schema_artifacts(root: &Path) -> Result<Vec<PathBuf>> {
    let schema = schemars::schema_for!(AppManifests);
    let schema_json = serde_json::to_string_pretty(&schema).context("Failed to serialize apps schema")?;

    let targets = PortableLayout::new(root).schema_targets();
    for target in &targets {
        fs::write(target, &schema_json).with_context(|| format!("Failed to write '{}'", target.display()))?;
    }

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_schema_is_published_to_every_existing_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(".ppm")).unwrap();
        std::fs::create_dir_all(dir.path().join("manifests")).unwrap();

        let written = write_schema_artifacts(dir.path()).expect("schema generation");

        assert_eq!(written.len(), 2);
        for target in written {
            let contents = std::fs::read_to_string(&target).expect("schema file");
            serde_json::from_str::<serde_json::Value>(&contents).expect("schema must be valid JSON");
        }
    }

    /// Regression: writing to a `manifests/` directory that does not exist used to fail the
    /// whole command instead of publishing the targets that do exist.
    #[test]
    fn a_deployed_root_without_a_manifests_directory_still_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(".ppm")).unwrap();

        let written = write_schema_artifacts(dir.path()).expect("schema generation must succeed");

        assert_eq!(written, vec![dir.path().join(".ppm").join("apps.schema.json")]);
    }
}
