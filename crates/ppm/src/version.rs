use crate::arch::CpuArch;
use crate::config::{AppDefinition, VersionCheckConfig};
use regex::Regex;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RemoteRelease {
    pub version: String,
    pub download_url: String,
}

/// Resolves a JSON path with support for standard JSON Pointers and predicate filters:
/// e.g. `/0/Releases[Platform=Windows,Architecture=x64]/ProductVersion`
pub fn resolve_json_query<'a>(json: &'a JsonValue, query: &'a str) -> Option<&'a JsonValue> {
    let clean_query = query.trim_start_matches('/');
    if clean_query.is_empty() {
        return Some(json);
    }

    let mut current = json;
    for segment in clean_query.split('/') {
        if segment.is_empty() {
            continue;
        }

        // Check if segment has predicate filter: e.g. "Releases[Platform=Windows,Architecture=x64]"
        if let Some(open_bracket) = segment.find('[') {
            if segment.ends_with(']') {
                let key = &segment[..open_bracket];
                let predicate = &segment[open_bracket + 1..segment.len() - 1];

                let target_array = if key.is_empty() {
                    current.as_array()?
                } else {
                    current.get(key)?.as_array()?
                };

                // Parse key-value predicates: "Platform=Windows,Architecture=x64"
                let filters: Vec<(&str, &str)> = predicate
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .collect();

                let mut matched_item: Option<&JsonValue> = None;
                for item in target_array {
                    let mut all_match = true;
                    for (k, v) in &filters {
                        let item_val = item.get(*k).and_then(|val| val.as_str());
                        if item_val != Some(*v) {
                            all_match = false;
                            break;
                        }
                    }
                    if all_match {
                        matched_item = Some(item);
                        break;
                    }
                }

                current = matched_item?;
                continue;
            }
        }

        // Standard numeric index
        if let Ok(idx) = segment.parse::<usize>() {
            current = current.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }

    Some(current)
}

pub fn check_remote_version(
    config: &VersionCheckConfig,
    arch: CpuArch,
) -> Result<RemoteRelease, String> {
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
            let resolved_url = url.resolve(arch).ok_or_else(|| {
                format!(
                    "Manifest URL not configured for architecture '{}'",
                    arch.as_str()
                )
            })?;

            let res = client.get(&resolved_url).send().map_err(|e| {
                format!(
                    "Failed to fetch Electron manifest from '{}': {}",
                    resolved_url, e
                )
            })?;

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

            let resolved_tmpl = url_template.as_ref().and_then(|t| t.resolve(arch));

            let download_url = if let Some(tmpl) = resolved_tmpl {
                tmpl.replace("{version}", version_str)
            } else if let Some(path_val) = yaml.get("path").and_then(|v| v.as_str()) {
                if path_val.starts_with("http://") || path_val.starts_with("https://") {
                    path_val.to_string()
                } else {
                    let base = resolved_url
                        .rsplit_once('/')
                        .map(|(b, _)| b)
                        .unwrap_or(&resolved_url);
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

            let pattern_str = asset_pattern
                .as_ref()
                .and_then(|p| p.resolve(arch))
                .unwrap_or_else(|| format!(".*{}.*", arch.as_str()));

            let re = Regex::new(&pattern_str)
                .map_err(|e| format!("Invalid regex asset pattern '{}': {}", pattern_str, e))?;

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
                    "No asset matching pattern '{}' found in GitHub release {} for arch '{}'",
                    pattern_str,
                    tag,
                    arch.as_str()
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
            let resolved_url = url.resolve(arch).ok_or_else(|| {
                format!(
                    "JSON API URL not configured for architecture '{}'",
                    arch.as_str()
                )
            })?;

            let resolved_version_key = version_key.resolve(arch).ok_or_else(|| {
                format!(
                    "version_key not configured for architecture '{}'",
                    arch.as_str()
                )
            })?;

            let res = client.get(&resolved_url).send().map_err(|e| {
                format!("Failed to fetch JSON API from '{}': {}", resolved_url, e)
            })?;

            let json: JsonValue = res
                .json()
                .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

            let version_node = resolve_json_query(&json, &resolved_version_key)
                .or_else(|| json.pointer(&resolved_version_key))
                .or_else(|| json.get(&resolved_version_key));

            let version_str = version_node
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    format!("Key '{}' not found in JSON response", resolved_version_key)
                })?;

            let resolved_url_key = url_key.as_ref().and_then(|k| k.resolve(arch));
            let resolved_tmpl = url_template.as_ref().and_then(|t| t.resolve(arch));

            let download_url = if let Some(key) = resolved_url_key {
                let url_node = resolve_json_query(&json, &key)
                    .or_else(|| json.pointer(&key))
                    .or_else(|| json.get(&key));

                url_node
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| format!("URL key '{}' not found in JSON response", key))?
            } else if let Some(tmpl) = resolved_tmpl {
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
            let resolved_url = url.resolve(arch).ok_or_else(|| {
                format!(
                    "Regex URL not configured for architecture '{}'",
                    arch.as_str()
                )
            })?;

            let resolved_regex = regex.resolve(arch).ok_or_else(|| {
                format!(
                    "Regex pattern not configured for architecture '{}'",
                    arch.as_str()
                )
            })?;

            let resolved_tmpl = url_template.resolve(arch).ok_or_else(|| {
                format!(
                    "URL template not configured for architecture '{}'",
                    arch.as_str()
                )
            })?;

            let res = client.get(&resolved_url).send().map_err(|e| {
                format!("Failed to fetch page from '{}': {}", resolved_url, e)
            })?;

            let text = res
                .text()
                .map_err(|e| format!("Failed to read page text: {}", e))?;

            let re = Regex::new(&resolved_regex).map_err(|e| {
                format!("Invalid regex pattern '{}': {}", resolved_regex, e)
            })?;

            let caps = re.captures(&text).ok_or_else(|| {
                format!(
                    "Pattern '{}' not matched on '{}'",
                    resolved_regex, resolved_url
                )
            })?;

            let version_str = caps
                .get(1)
                .map(|m| m.as_str())
                .ok_or_else(|| "Regex capture group 1 not found".to_string())?;

            let download_url = resolved_tmpl.replace("{version}", version_str);

            Ok(RemoteRelease {
                version: version_str.to_string(),
                download_url,
            })
        }
    }
}

pub fn get_state_file_path(root: &Path) -> PathBuf {
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
    arch: CpuArch,
) -> Option<String> {
    if !app_def.is_installed_for_arch(root, arch) {
        return None;
    }

    let ledger = load_state_ledger(root);
    let arch_key = format!("{}:{}", app_id, arch.as_str());

    if let Some(v) = ledger.get(&arch_key) {
        return Some(v.clone());
    }

    if let Some(v) = ledger.get(app_id) {
        return Some(v.clone());
    }

    Some("installed".to_string())
}
