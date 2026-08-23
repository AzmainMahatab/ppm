use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VersionCheckConfig {
    ElectronManifest {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        version_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        url_template: Option<String>,
    },
    #[serde(rename = "github_release", alias = "git_hub_release")]
    GitHubRelease {
        repo: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        asset_pattern: Option<String>,
    },
    JsonApi {
        url: String,
        version_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        url_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        url_template: Option<String>,
    },
    RegexUrl {
        url: String,
        regex: String,
        url_template: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PackageConfig {
    #[serde(rename = "nsis_7z")]
    Nsis7z {
        #[serde(skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Zip {
        #[serde(skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Tar {
        #[serde(skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    #[serde(rename = "7z", alias = "seven_z")]
    SevenZ {
        #[serde(skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Cab {
        #[serde(skip_serializing_if = "Option::is_none")]
        extract_subpath: Option<String>,
    },
    Msi {
        #[serde(skip_serializing_if = "Option::is_none")]
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
}

pub fn get_manifest_path(root: &Path) -> PathBuf {
    let p1 = root.join(".ppm").join("apps.json");
    if p1.exists() {
        return p1;
    }
    let p2 = root.join("manifests").join("apps.json");
    if p2.exists() {
        return p2;
    }
    p1
}

pub fn load_manifest(root: &Path) -> Result<AppManifests, String> {
    let path = get_manifest_path(root);
    if !path.exists() {
        return Err(format!(
            "Manifest file not found at '{}'. Run 'ppm init' to generate default configuration.",
            path.display()
        ));
    }

    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read manifest '{}': {}", path.display(), e))?;

    let manifests: AppManifests = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid manifest JSON in '{}': {}", path.display(), e))?;

    Ok(manifests)
}

pub fn save_manifest(root: &Path, manifests: &AppManifests) -> Result<(), String> {
    let path = root.join(".ppm").join("apps.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory '{}': {}", parent.display(), e))?;
    }

    let json = serde_json::to_string_pretty(manifests)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;

    fs::write(&path, json)
        .map_err(|e| format!("Failed to write manifest to '{}': {}", path.display(), e))?;

    Ok(())
}
