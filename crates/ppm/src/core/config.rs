use crate::core::arch::CpuArch;
use crate::core::relpath::confined;
use anyhow::Context;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A string field that can be defined either as a single template string (with `{arch}`)
/// or as an explicit per-architecture mapping (e.g. `{"x64": "...", "arm64": "..."}`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum ArchString {
    Single(String),
    PerArch(BTreeMap<String, String>),
}

impl ArchString {
    /// Resolves the string value for a specific CPU architecture.
    pub fn resolve(&self, arch: CpuArch) -> Option<String> {
        match self {
            ArchString::Single(s) => Some(s.replace("{arch}", arch.as_str())),
            ArchString::PerArch(map) => map.get(arch.as_str()).map(|s| s.replace("{arch}", arch.as_str())),
        }
    }
}

impl From<String> for ArchString {
    fn from(s: String) -> Self {
        ArchString::Single(s)
    }
}

impl From<&str> for ArchString {
    fn from(s: &str) -> Self {
        ArchString::Single(s.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppManifests {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    // Why: `install all`, `list`, `check`, launcher generation and `global_env` collection all
    //      iterate this map; an ordered map makes their output and install order reproducible
    //      across runs instead of following a randomized hash seed.
    pub apps: BTreeMap<String, AppDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppDefinition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    pub target_dir: String,
    pub executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_arch: Option<Vec<CpuArch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
    /// Environment injected when *any* app launches, not just this one. Entries carrying
    /// shared runtimes (engines/SDKs) own their variables here, so one block can provision
    /// the whole portable environment without per-app opt-in lists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_env: Option<BTreeMap<String, String>>,
    pub version_check: VersionCheckConfig,
    pub package: PackageConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_install: Option<PostInstallConfig>,
}

impl AppDefinition {
    /// Returns the target directory for a specific CPU architecture: `<root>/Apps/<arch>/<target_dir>`
    pub fn app_dir_for_arch(&self, root: &Path, arch: CpuArch) -> PathBuf {
        root.join("Apps").join(arch.as_str()).join(&self.target_dir)
    }

    /// Returns the full executable path for a specific CPU architecture: `<root>/Apps/<arch>/<target_dir>/<executable>`
    pub fn executable_for_arch(&self, root: &Path, arch: CpuArch) -> PathBuf {
        self.app_dir_for_arch(root, arch).join(&self.executable)
    }

    /// Checks if this application explicitly supports the requested architecture.
    pub fn is_supported_on_arch(&self, arch: CpuArch) -> bool {
        if let Some(supported) = &self.supported_arch {
            supported.contains(&arch)
        } else {
            true
        }
    }

    /// Checks if the application is installed for a specific CPU architecture.
    pub fn is_installed_for_arch(&self, root: &Path, arch: CpuArch) -> bool {
        self.executable_for_arch(root, arch).is_file()
    }

    /// Checks if the application is installed on any supported CPU architecture.
    pub fn is_installed_any_arch(&self, root: &Path) -> bool {
        CpuArch::all()
            .iter()
            .any(|&arch| self.is_installed_for_arch(root, arch))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
// Why each variant wraps its own struct: serde ignores `deny_unknown_fields` on an internally
//      tagged enum, so with inline variant fields a typo such as `"asset_patern"` was dropped
//      without a word. serde removes the `type` tag before deserializing a newtype variant's
//      content, so a struct that denies unknown fields rejects the typo instead.
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VersionCheckConfig {
    ElectronManifest(ElectronManifestCheck),
    #[serde(rename = "github_release", alias = "git_hub_release")]
    GitHubRelease(GitHubReleaseCheck),
    JsonApi(JsonApiCheck),
    RegexUrl(RegexUrlCheck),
}

/// An electron-builder `latest.yml` update manifest.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ElectronManifestCheck {
    pub url: ArchString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_template: Option<ArchString>,
}

/// The latest release of a GitHub repository.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitHubReleaseCheck {
    pub repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_pattern: Option<ArchString>,
}

/// A JSON document queried with ppm's path-and-predicate syntax.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonApiCheck {
    pub url: ArchString,
    pub version_key: ArchString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_key: Option<ArchString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_template: Option<ArchString>,
}

/// A page scraped with a regular expression whose first group is the version.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegexUrlCheck {
    pub url: ArchString,
    pub regex: ArchString,
    pub url_template: ArchString,
}

/// The archive format a package is distributed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    #[serde(rename = "nsis_7z")]
    Nsis7z,
    #[serde(rename = "7z", alias = "seven_z")]
    SevenZ,
    Zip,
    Cab,
    Msi,
    Tar,
    Binary,
}

/// How an installed package is unpacked.
///
/// # Why a struct with a `type` discriminant instead of one enum variant per format
/// Six of the seven formats carried an identical `extract_subpath` field, so the internally
/// tagged enum repeated the same four-line serde attribute block six times. Worse, serde
/// silently ignores `deny_unknown_fields` for internally tagged enums, so a typo inside a
/// `package` block was dropped without a word. A plain struct keeps the JSON shape
/// byte-for-byte identical and makes the strictness real instead of advertised.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageConfig {
    #[serde(rename = "type")]
    pub kind: PackageKind,
    /// Subdirectory of the extracted payload to install. Not meaningful for `binary`, which
    /// has no archive to descend into.
    #[serde(
        default,
        rename = "extract_subpath",
        alias = "subpath",
        skip_serializing_if = "Option::is_none"
    )]
    pub extract_subpath: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PostInstallConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_dirs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_dirs: Option<Vec<String>>,
}

impl AppManifests {
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest '{}'", path.display()))?;
        let manifests: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse manifest '{}'", path.display()))?;
        manifests
            .check_references()
            .with_context(|| format!("Invalid manifest '{}'", path.display()))?;
        Ok(manifests)
    }

    /// Checks what the type model alone cannot: that every app id is safe as a launcher name, that
    /// every path a field contributes stays inside the directory it is joined onto, and that every
    /// dependency names a defined application.
    pub fn check_references(&self) -> anyhow::Result<()> {
        for (app_id, app) in &self.apps {
            if !is_valid_app_id(app_id) {
                anyhow::bail!("App id '{app_id}' may only use ASCII letters, digits, '.', '_' and '-'");
            }

            let paths = [&app.target_dir, &app.executable]
                .into_iter()
                .chain(app.package.extract_subpath.as_ref())
                .chain(app.post_install.iter().flat_map(PostInstallConfig::paths));
            for raw in paths {
                confined(raw).with_context(|| format!("App '{app_id}'"))?;
            }

            for dependency in app.dependencies.iter().flatten() {
                if !self.apps.contains_key(dependency) {
                    anyhow::bail!(
                        "App '{app_id}' depends on '{dependency}', which apps.json does not define"
                    );
                }
            }
        }
        Ok(())
    }
}

/// Whether `id` is usable as an app id.
///
/// # Why so narrow
/// The id becomes a file name in the root (`<id>.bat`) and text inside that batch script, where
/// characters such as `&`, `|`, `%` or `"` are commands rather than text. Restricting ids to
/// characters with no meaning to cmd.exe or the file system keeps both uses safe by construction.
fn is_valid_app_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl PostInstallConfig {
    /// Every installation-relative path these rules name.
    fn paths(&self) -> impl Iterator<Item = &String> {
        [&self.remove_files, &self.remove_dirs, &self.create_dirs]
            .into_iter()
            .flatten()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assets::DEFAULT_APPS_JSON;

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        let rejected = [
            ("top level", r#"{"apps": {},"stray": 1}"#),
            (
                "app entry",
                r#"{"apps": {"a": {"name": "A","target_dir": "t","executable": "a.exe","version_check": {"type": "github_release","repo": "o/r"},"package": {"type": "binary"},"bogus": 1}}}"#,
            ),
            (
                "package",
                r#"{"apps": {"a": {"name": "A","target_dir": "t","executable": "a.exe","version_check": {"type": "github_release","repo": "o/r"},"package": {"type": "binary","bogus": 1}}}}"#,
            ),
            // Regression: serde ignores deny_unknown_fields on an internally tagged enum, so a
            // typo inside version_check was silently dropped until each variant became a struct.
            (
                "version_check variant",
                r#"{"apps": {"a": {"name": "A","target_dir": "t","executable": "a.exe","version_check": {"type": "github_release","repo": "o/r","asset_patern": "x"},"package": {"type": "binary"}}}}"#,
            ),
        ];
        for (level, json) in rejected {
            let err = serde_json::from_str::<AppManifests>(json)
                .expect_err("deny_unknown_fields must reject unknown fields");
            assert!(
                err.to_string().contains("unknown field"),
                "strictness must reject unknown field at {level}: {err}"
            );
        }
    }

    #[test]
    fn escaping_paths_and_undefined_dependencies_are_rejected() {
        let manifest = |app: serde_json::Value| -> AppManifests {
            let mut def = serde_json::json!({
                "name": "A",
                "target_dir": "A",
                "executable": "a.exe",
                "version_check": {"type": "github_release", "repo": "o/r"},
                "package": {"type": "zip"}
            });
            def.as_object_mut()
                .expect("invariant: literal object")
                .extend(app.as_object().expect("invariant: literal object").clone());
            serde_json::from_value(serde_json::json!({ "apps": { "a": def } }))
                .expect("invariant: shape is schema-valid")
        };

        assert!(manifest(serde_json::json!({})).check_references().is_ok());
        for broken in [
            serde_json::json!({"target_dir": "../Outside"}),
            serde_json::json!({"executable": r"C:\Windows\notepad.exe"}),
            serde_json::json!({"package": {"type": "zip", "extract_subpath": "../x"}}),
            serde_json::json!({"post_install": {"remove_dirs": [r"..\.."]}}),
            serde_json::json!({"dependencies": ["ghost"]}),
        ] {
            assert!(
                manifest(broken.clone()).check_references().is_err(),
                "{broken} must be rejected"
            );
        }
    }

    /// An app id is written into a batch script; one carrying cmd.exe syntax would run commands.
    #[test]
    fn app_ids_that_would_inject_into_a_launcher_are_rejected() {
        for valid in ["webview2", "antigravity-manager", "tool_1.2"] {
            assert!(is_valid_app_id(valid), "{valid}");
        }
        for invalid in ["", "a&calc", "a b", "100%", "x|y", r"..\x", "café"] {
            assert!(!is_valid_app_id(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn tracked_schema_is_fresh_against_the_type_model() {
        let schema = schemars::schema_for!(AppManifests);
        let generated = serde_json::to_string_pretty(&schema).expect("invariant: schema serializes");
        let tracked = include_str!("../../../../manifests/apps.schema.json");
        assert_eq!(
            generated, tracked,
            "manifests/apps.schema.json is stale: regenerate it by running `ppm init` at the repo root"
        );
    }

    #[test]
    fn default_manifest_satisfies_the_tracked_schema() {
        let schema_json = include_str!("../../../../manifests/apps.schema.json");
        let schema_value: serde_json::Value =
            serde_json::from_str(schema_json).expect("invariant: tracked schema is valid JSON");
        let validator = jsonschema::validator_for(&schema_value).expect("invariant: tracked schema compiles");
        let default_value: serde_json::Value =
            serde_json::from_str(DEFAULT_APPS_JSON).expect("invariant: default manifest is valid JSON");
        validator
            .validate(&default_value)
            .expect("default manifest must satisfy the tracked schema");
    }

    #[test]
    fn test_app_manifests_json_roundtrip() {
        let manifest_json = r#"{
            "$schema": "./apps.schema.json",
            "apps": {
                "demo-app": {
                    "name": "Demo Application",
                    "target_dir": "DemoApp",
                    "executable": "demo.exe",
                    "version_check": {
                        "type": "github_release",
                        "repo": "owner/repo"
                    },
                    "package": {
                        "type": "zip"
                    },
                    "description": "A demo application for testing"
                }
            }
        }"#;

        let parsed: AppManifests =
            serde_json::from_str(manifest_json).expect("Should parse valid manifest JSON");
        assert_eq!(parsed.schema, Some("./apps.schema.json".to_string()));
        assert!(parsed.apps.contains_key("demo-app"));

        let demo = &parsed.apps["demo-app"];
        assert_eq!(demo.name, "Demo Application");
        assert_eq!(demo.target_dir, "DemoApp");
        let exe = demo.executable_for_arch(Path::new("C:\\Root"), crate::core::arch::CpuArch::X64);
        assert_eq!(exe, PathBuf::from("C:\\Root\\Apps\\x64\\DemoApp\\demo.exe"));

        // Round-trip test
        let serialized = serde_json::to_string_pretty(&parsed).expect("Should serialize back to JSON");
        let reloaded: AppManifests =
            serde_json::from_str(&serialized).expect("Should reload serialized JSON");
        assert_eq!(reloaded.schema, parsed.schema);
    }
}
