//! The single owner of the portable layout's on-disk locations.
//!
//! # Why this exists
//! `.ppm/apps.json`, the `manifests/apps.json` development fallback, and the pair of schema
//! targets were each spelled out independently in the CLI context, the runner and the
//! initializer. The copies drifted: `ppm schema` wrote both schema targets unconditionally
//! while `ppm init` guarded the second one, so regenerating the schema in a deployed root -
//! which has no `manifests/` directory - failed. Layout is a contract (SPEC §1, §4); it belongs
//! in one place.

use std::path::{Path, PathBuf};

/// The on-disk locations the portable layout defines, all resolved from one root.
#[derive(Debug, Clone, Copy)]
pub struct PortableLayout<'a> {
    root: &'a Path,
}

impl<'a> PortableLayout<'a> {
    pub fn new(root: &'a Path) -> Self {
        PortableLayout { root }
    }

    pub fn root(&self) -> &Path {
        self.root
    }

    /// `<root>/.ppm` - the engine's runtime directory.
    pub fn ppm_dir(&self) -> PathBuf {
        self.root.join(".ppm")
    }

    /// `<root>/.ppm/lib` - holds one folder of engine builds per 64-bit machine.
    pub fn engine_lib_dir(&self) -> PathBuf {
        self.ppm_dir().join("lib")
    }

    /// The deployed manifest a `ppm init` writes and every command prefers.
    pub fn deployed_manifest(&self) -> PathBuf {
        self.ppm_dir().join("apps.json")
    }

    /// The repository-maintained manifest, used when running from a source checkout.
    pub fn repo_manifest(&self) -> PathBuf {
        self.root.join("manifests").join("apps.json")
    }

    /// The manifest to load, deployed copy first, or `None` when the root carries neither.
    pub fn manifest_source(&self) -> Option<PathBuf> {
        [self.deployed_manifest(), self.repo_manifest()]
            .into_iter()
            .find(|candidate| candidate.is_file())
    }

    /// Whether this directory already carries a portable environment (SPEC §1, step 2).
    pub fn carries_portable_environment(&self) -> bool {
        self.manifest_source().is_some()
    }

    /// Every location the generated JSON Schema is published to.
    ///
    /// A target whose parent directory does not exist is not a target: a deployed root has no
    /// `manifests/` directory, and writing there would fail rather than mean anything.
    pub fn schema_targets(&self) -> Vec<PathBuf> {
        [
            self.ppm_dir().join("apps.schema.json"),
            self.root.join("manifests").join("apps.schema.json"),
        ]
        .into_iter()
        .filter(|target| target.parent().is_some_and(Path::is_dir))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deployed_manifest_is_preferred_over_the_repository_copy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = PortableLayout::new(dir.path());

        assert!(layout.manifest_source().is_none());
        assert!(!layout.carries_portable_environment());

        std::fs::create_dir_all(dir.path().join("manifests")).unwrap();
        std::fs::write(layout.repo_manifest(), b"{}").unwrap();
        assert_eq!(layout.manifest_source(), Some(layout.repo_manifest()));
        assert!(layout.carries_portable_environment());

        std::fs::create_dir_all(layout.ppm_dir()).unwrap();
        std::fs::write(layout.deployed_manifest(), b"{}").unwrap();
        assert_eq!(layout.manifest_source(), Some(layout.deployed_manifest()));
    }

    /// Regression: `ppm schema` wrote both targets unconditionally, so it failed in a deployed
    /// root that has no `manifests/` directory.
    #[test]
    fn schema_targets_skip_directories_that_do_not_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = PortableLayout::new(dir.path());

        assert!(
            layout.schema_targets().is_empty(),
            "neither parent directory exists yet"
        );

        std::fs::create_dir_all(layout.ppm_dir()).unwrap();
        assert_eq!(
            layout.schema_targets(),
            vec![layout.ppm_dir().join("apps.schema.json")],
            "a deployed root publishes only the .ppm copy"
        );

        std::fs::create_dir_all(dir.path().join("manifests")).unwrap();
        assert_eq!(
            layout.schema_targets().len(),
            2,
            "a source checkout publishes both copies"
        );
    }
}
