use crate::config::{AppDefinition, VersionCheckConfig};
use regex::Regex;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RemoteRelease {
    pub version: String,
    pub download_url: String,
}

pub fn check_remote_version(config: &VersionCheckConfig) -> Result<RemoteRelease, String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("ppm/0.1.0")
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    match config {
        VersionCheckConfig::ElectronManifest {
            url,
            version_key,
            url_template,
        } => {
            let res = client
                .get(url)
                .send()
                .map_err(|e| format!("Failed to fetch Electron manifest from '{}': {}", url, e))?;

            let text = res
                .text()
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            let yaml: YamlValue = serde_yaml::from_str(&text)
                .map_err(|e| format!("Failed to parse YAML manifest: {}", e))?;

            let key_name = version_key.as_deref().unwrap_or("version");
            let version_str = yaml
                .get(key_name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Key '{}' not found in YAML manifest", key_name))?;

            let download_url = if let Some(tmpl) = url_template {
                tmpl.replace("{version}", version_str)
            } else if let Some(path_val) = yaml.get("path").and_then(|v| v.as_str()) {
                if path_val.starts_with("http://") || path_val.starts_with("https://") {
                    path_val.to_string()
                } else {
                    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(url);
                    format!("{}/{}", base, path_val)
                }
            } else {
                return Err("No download URL or template found in Electron manifest".to_string());
            };

            Ok(RemoteRelease {
                version: version_str.to_string(),
                download_url,
            })
        }
        VersionCheckConfig::GitHubRelease {
            repo,
            asset_pattern,
        } => {
            let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
            let res = client.get(&api_url).send().map_err(|e| {
                format!("Failed to fetch GitHub release from '{}': {}", api_url, e)
            })?;

            let json: JsonValue = res
                .json()
                .map_err(|e| format!("Failed to parse GitHub release JSON: {}", e))?;

            let tag = json
                .get("tag_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "tag_name not found in GitHub release".to_string())?;

            let clean_version = tag.trim_start_matches('v').to_string();

            let assets = json
                .get("assets")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "assets array not found in GitHub release".to_string())?;

            let pattern = asset_pattern.as_deref().unwrap_or(".*");
            let re = Regex::new(pattern)
                .map_err(|e| format!("Invalid regex asset pattern '{}': {}", pattern, e))?;

            let mut download_url: Option<String> = None;
            for asset in assets {
                if let Some(name) = asset.get("name").and_then(|v| v.as_str()) {
                    if re.is_match(name) {
                        if let Some(url_str) =
                            asset.get("browser_download_url").and_then(|v| v.as_str())
                        {
                            download_url = Some(url_str.to_string());
                            break;
                        }
                    }
                }
            }

            let download_url = download_url.ok_or_else(|| {
                format!(
                    "No asset matching pattern '{}' found in GitHub release {}",
                    pattern, tag
                )
            })?;

            Ok(RemoteRelease {
                version: clean_version,
                download_url,
            })
        }
        VersionCheckConfig::JsonApi {
            url,
            version_key,
            url_key,
            url_template,
        } => {
            let res = client
                .get(url)
                .send()
                .map_err(|e| format!("Failed to fetch JSON API from '{}': {}", url, e))?;

            let json: JsonValue = res
                .json()
                .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

            let version_str = json
                .pointer(version_key)
                .or_else(|| json.get(version_key))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Key '{}' not found in JSON response", version_key))?;

            let download_url = if let Some(key) = url_key {
                json.pointer(key)
                    .or_else(|| json.get(key))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| format!("URL key '{}' not found in JSON response", key))?
            } else if let Some(tmpl) = url_template {
                tmpl.replace("{version}", version_str)
            } else {
                return Err("Either url_key or url_template is required for json_api version check".to_string());
            };

            Ok(RemoteRelease {
                version: version_str.to_string(),
                download_url,
            })
        }
        VersionCheckConfig::RegexUrl {
            url,
            regex,
            url_template,
        } => {
            let res = client
                .get(url)
                .send()
                .map_err(|e| format!("Failed to fetch page from '{}': {}", url, e))?;

            let text = res
                .text()
                .map_err(|e| format!("Failed to read page text: {}", e))?;

            let re = Regex::new(regex)
                .map_err(|e| format!("Invalid regex pattern '{}': {}", regex, e))?;

            let caps = re
                .captures(&text)
                .ok_or_else(|| format!("Pattern '{}' not matched on '{}'", regex, url))?;

            let version_str = caps
                .get(1)
                .map(|m| m.as_str())
                .ok_or_else(|| "Regex capture group 1 not found".to_string())?;

            let download_url = url_template.replace("{version}", version_str);

            Ok(RemoteRelease {
                version: version_str.to_string(),
                download_url,
            })
        }
    }
}

pub fn get_state_file_path(root: &Path) -> std::path::PathBuf {
    root.join(".ppm").join("state.json")
}

pub fn load_state_ledger(root: &Path) -> HashMap<String, String> {
    let state_file = get_state_file_path(root);
    if state_file.exists() {
        if let Ok(content) = fs::read_to_string(&state_file) {
            if let Ok(ledger) = serde_json::from_str::<HashMap<String, String>>(&content) {
                return ledger;
            }
        }
    }
    HashMap::new()
}

pub fn save_state_ledger(root: &Path, ledger: &HashMap<String, String>) -> Result<(), String> {
    let state_file = get_state_file_path(root);
    if let Some(parent) = state_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(ledger)
        .map_err(|e| format!("Failed to serialize state ledger: {}", e))?;
    fs::write(&state_file, json)
        .map_err(|e| format!("Failed to write state ledger: {}", e))?;
    Ok(())
}

pub fn detect_local_version(
    root: &Path,
    app_id: &str,
    app_def: &AppDefinition,
) -> Option<String> {
    let exe_path = root.join(&app_def.target_dir).join(&app_def.executable);
    if !exe_path.exists() {
        return None;
    }

    // 1. Check state ledger first
    let ledger = load_state_ledger(root);
    if let Some(v) = ledger.get(app_id) {
        return Some(v.clone());
    }

    Some("installed".to_string())
}
