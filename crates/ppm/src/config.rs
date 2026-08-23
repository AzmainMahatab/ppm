use crate::arch::CpuArch;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A string field that can be defined either as a single template string (with `{arch}`)
/// or as an explicit per-architecture mapping (e.g. `{"x64": "...", "arm64": "..."}`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum ArchString {
    Single(String),
    PerArch(HashMap<String, String>),
}

impl ArchString {
    /// Resolves the string value for a specific CPU architecture.
    pub fn resolve(&self, arch: CpuArch) -> Option<String> {
        match self {
            ArchString::Single(s) => Some(s.replace("{arch}", arch.as_str())),
            ArchString::PerArch(map) => map
                .get(arch.as_str())
                .map(|s| s.replace("{arch}", arch.as_str())),
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
pub struct AppManifests {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub apps: HashMap<String, AppDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    pub env: Option<HashMap<String, String>>,
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VersionCheckConfig {
    ElectronManifest {
        url: ArchString,
        #[serde(skip_serializing_if = "Option::is_none")]
        version_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        url_template: Option<ArchString>,
    },
    #[serde(rename = "github_release", alias = "git_hub_release")]
    GitHubRelease {
        repo: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        asset_pattern: Option<ArchString>,
    },
    JsonApi {
        url: ArchString,
        version_key: ArchString,
        #[serde(skip_serializing_if = "Option::is_none")]
        url_key: Option<ArchString>,
        #[serde(skip_serializing_if = "Option::is_none")]
        url_template: Option<ArchString>,
    },
    RegexUrl {
        url: ArchString,
        regex: ArchString,
        url_template: ArchString,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PackageConfig {
    #[serde(rename = "nsis_7z")]
    Nsis7z {
        #[serde(rename = "extract_subpath", alias = "subpath", skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    #[serde(rename = "7z", alias = "seven_z")]
    SevenZ {
        #[serde(rename = "extract_subpath", alias = "subpath", skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Zip {
        #[serde(rename = "extract_subpath", alias = "subpath", skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Cab {
        #[serde(rename = "extract_subpath", alias = "subpath", skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Msi {
        #[serde(rename = "extract_subpath", alias = "subpath", skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Tar {
        #[serde(rename = "extract_subpath", alias = "subpath", skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PostInstallConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_dirs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_dirs: Option<Vec<String>>,
}

impl AppManifests {
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read manifest file at '{}': {}", path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON manifest at '{}': {}", path.display(), e))
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed to create parent directory for '{}': {}",
                    path.display(),
                    e
                )
            })?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
        fs::write(path, json)
            .map_err(|e| format!("Failed to write manifest file at '{}': {}", path.display(), e))
    }
}
