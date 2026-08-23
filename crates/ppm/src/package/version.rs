use crate::core::arch::CpuArch;
use crate::core::config::{AppDefinition, VersionCheckConfig};
use crate::package::pe_info::{get_electron_package_version, get_pe_product_version};
use regex::Regex;
use serde_json::Value;
use std::path::Path;

pub struct RemoteRelease {
    pub version: String,
    pub download_url: String,
}

/// Dynamically detects the local version directly from the executable on disk.
/// Zero static state files; 100% presence-based.
pub fn detect_local_version(
    root: &Path,
    app_def: &AppDefinition,
    arch: CpuArch,
) -> Option<String> {
    let exe_path = app_def.executable_for_arch(root, arch);
    if !exe_path.is_file() {
        return None;
    }

    // 1. Try extracting version from PE binary header
    if let Some(v) = get_pe_product_version(&exe_path) {
        return Some(v);
    }

    // 2. Try Electron package.json
    if let Some(v) = get_electron_package_version(&exe_path) {
        return Some(v);
    }

    // 3. If binary exists but has no extractable PE version or package.json version
    None
}

/// Fetches the latest upstream version and resolved download URL for a specific CPU architecture.
pub fn check_remote_version(
    config: &VersionCheckConfig,
    arch: CpuArch,
) -> Result<RemoteRelease, String> {
    match config {
        VersionCheckConfig::ElectronManifest {
            url,
            version_key,
            url_template,
        } => {
            let manifest_url = url
                .resolve(arch)
                .ok_or_else(|| format!("No manifest URL configured for arch '{}'", arch.as_str()))?;

            let client = reqwest::blocking::Client::builder()
                .user_agent("ppm-portable-package-manager/0.1")
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

            let response = client
                .get(&manifest_url)
                .send()
                .map_err(|e| format!("Failed to fetch manifest at '{}': {}", manifest_url, e))?;

            let text = response
                .text()
                .map_err(|e| format!("Failed to read manifest text: {}", e))?;

            let yaml: serde_yml::Value = serde_yml::from_str(&text)
                .map_err(|e| format!("Failed to parse YAML manifest: {}", e))?;

            let key_name = version_key.as_deref().unwrap_or("version");
            let version_val = yaml
                .get(key_name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Key '{}' not found in YAML manifest", key_name))?
                .to_string();

            let download_url = if let Some(tpl) = url_template {
                let resolved_tpl = tpl.resolve(arch).ok_or_else(|| {
                    format!("No URL template configured for arch '{}'", arch.as_str())
                })?;
                resolved_tpl
                    .replace("{version}", &version_val)
                    .replace("{arch}", arch.as_str())
            } else if let Some(files) = yaml.get("files").and_then(|f| f.as_sequence()) {
                let first_file = files
                    .first()
                    .and_then(|f| f.get("url"))
                    .and_then(|u| u.as_str())
                    .ok_or_else(|| "No file URL found in Electron manifest files array".to_string())?;

                if first_file.starts_with("http://") || first_file.starts_with("https://") {
                    first_file.to_string()
                } else {
                    let base_url = manifest_url
                        .rsplit_once('/')
                        .map(|(b, _)| b)
                        .unwrap_or(&manifest_url);
                    format!("{}/{}", base_url, first_file)
                }
            } else if let Some(path) = yaml.get("path").and_then(|p| p.as_str()) {
                let base_url = manifest_url
                    .rsplit_once('/')
                    .map(|(b, _)| b)
                    .unwrap_or(&manifest_url);
                format!("{}/{}", base_url, path)
            } else {
                return Err("Could not resolve download URL from Electron manifest".to_string());
            };

            Ok(RemoteRelease {
                version: version_val,
                download_url,
            })
        }

        VersionCheckConfig::GitHubRelease { repo, asset_pattern } => {
            let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
            let client = reqwest::blocking::Client::builder()
                .user_agent("ppm-portable-package-manager/0.1")
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

            let resp = client
                .get(&api_url)
                .send()
                .map_err(|e| format!("GitHub API request failed for '{}': {}", repo, e))?;

            let json: Value = resp
                .json()
                .map_err(|e| format!("Failed to parse GitHub release JSON: {}", e))?;

            let tag_name = json
                .get("tag_name")
                .and_then(|t| t.as_str())
                .ok_or_else(|| "Missing tag_name in GitHub release".to_string())?;

            let version = tag_name.strip_prefix('v').unwrap_or(tag_name).to_string();

            let assets = json
                .get("assets")
                .and_then(|a| a.as_array())
                .ok_or_else(|| "Missing assets array in GitHub release".to_string())?;

            let pattern_str = match asset_pattern {
                Some(p) => p.resolve(arch).ok_or_else(|| {
                    format!("No asset pattern defined for arch '{}'", arch.as_str())
                })?,
                None => format!(".*{}.*\\.zip", arch.as_str()),
            };

            let re = Regex::new(&pattern_str)
                .map_err(|e| format!("Invalid asset regex pattern '{}': {}", pattern_str, e))?;

            let mut matched_url = None;
            for asset in assets {
                let name = asset.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if re.is_match(name) {
                    if let Some(dl_url) = asset.get("browser_download_url").and_then(|u| u.as_str()) {
                        matched_url = Some(dl_url.to_string());
                        break;
                    }
                }
            }

            let download_url = matched_url.ok_or_else(|| {
                format!(
                    "No asset matching pattern '{}' found in GitHub release {} for arch '{}'",
                    pattern_str, tag_name, arch.as_str()
                )
            })?;

            Ok(RemoteRelease {
                version,
                download_url,
            })
        }

        VersionCheckConfig::JsonApi {
            url,
            version_key,
            url_key,
            url_template,
        } => {
            let api_url = url
                .resolve(arch)
                .ok_or_else(|| format!("No JSON API URL configured for arch '{}'", arch.as_str()))?;

            let v_key = version_key.resolve(arch).ok_or_else(|| {
                format!("No version_key configured for arch '{}'", arch.as_str())
            })?;

            let client = reqwest::blocking::Client::builder()
                .user_agent("ppm-portable-package-manager/0.1")
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

            let resp = client
                .get(&api_url)
                .send()
                .map_err(|e| format!("HTTP request failed for '{}': {}", api_url, e))?;

            let json: Value = resp
                .json()
                .map_err(|e| format!("Failed to parse JSON response from '{}': {}", api_url, e))?;

            let version = resolve_json_query(&json, &v_key)?
                .as_str()
                .ok_or_else(|| format!("Value at '{}' is not a string in JSON", v_key))?
                .to_string();

            let download_url = if let Some(tpl) = url_template {
                let resolved_tpl = tpl.resolve(arch).ok_or_else(|| {
                    format!("No URL template configured for arch '{}'", arch.as_str())
                })?;
                resolved_tpl
                    .replace("{version}", &version)
                    .replace("{arch}", arch.as_str())
            } else if let Some(uk) = url_key {
                let resolved_uk = uk.resolve(arch).ok_or_else(|| {
                    format!("No url_key configured for arch '{}'", arch.as_str())
                })?;
                resolve_json_query(&json, &resolved_uk)?
                    .as_str()
                    .ok_or_else(|| format!("Value at '{}' is not a string in JSON", resolved_uk))?
                    .to_string()
            } else {
                return Err("Either url_key or url_template must be provided for json_api".to_string());
            };

            Ok(RemoteRelease {
                version,
                download_url,
            })
        }

        VersionCheckConfig::RegexUrl {
            url,
            regex,
            url_template,
        } => {
            let scrape_url = url
                .resolve(arch)
                .ok_or_else(|| format!("No scrape URL configured for arch '{}'", arch.as_str()))?;

            let regex_str = regex
                .resolve(arch)
                .ok_or_else(|| format!("No regex configured for arch '{}'", arch.as_str()))?;

            let tpl_str = url_template
                .resolve(arch)
                .ok_or_else(|| format!("No URL template configured for arch '{}'", arch.as_str()))?;

            let client = reqwest::blocking::Client::builder()
                .user_agent("ppm-portable-package-manager/0.1")
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

            let resp = client
                .get(&scrape_url)
                .send()
                .map_err(|e| format!("HTTP request failed for '{}': {}", scrape_url, e))?;

            let body = resp
                .text()
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            let re = Regex::new(&regex_str)
                .map_err(|e| format!("Invalid regex pattern '{}': {}", regex_str, e))?;

            let caps = re
                .captures(&body)
                .ok_or_else(|| format!("Regex '{}' did not match body of '{}'", regex_str, scrape_url))?;

            let version = caps
                .get(1)
                .map(|m| m.as_str().to_string())
                .ok_or_else(|| "Regex did not capture group 1 for version".to_string())?;

            let download_url = tpl_str
                .replace("{version}", &version)
                .replace("{arch}", arch.as_str());

            Ok(RemoteRelease {
                version,
                download_url,
            })
        }
    }
}

/// Resolves a JSON pointer / query string supporting predicates (e.g. `/0/Releases[Platform=Windows,Architecture=x64]/ProductVersion`).
fn resolve_json_query<'a>(mut current: &'a Value, query: &str) -> Result<&'a Value, String> {
    let parts = query.trim_start_matches('/').split('/');

    for part in parts {
        if part.is_empty() {
            continue;
        }

        if let Some((array_name, predicate_str)) = part.split_once('[') {
            let predicate = predicate_str.trim_end_matches(']');
            if !array_name.is_empty() {
                current = current.get(array_name).ok_or_else(|| {
                    format!("Key '{}' not found in JSON object", array_name)
                })?;
            }

            let array = current.as_array().ok_or_else(|| {
                format!("Expected array at '{}' but found other JSON type", part)
            })?;

            let mut matched = None;
            let conditions: Vec<(&str, &str)> = predicate
                .split(',')
                .filter_map(|cond| cond.split_once('='))
                .collect();

            for item in array {
                let mut all_match = true;
                for &(key, expected_val) in &conditions {
                    let actual = item.get(key).and_then(|v| v.as_str()).unwrap_or("");
                    if !actual.eq_ignore_ascii_case(expected_val) {
                        all_match = false;
                        break;
                    }
                }
                if all_match {
                    matched = Some(item);
                    break;
                }
            }

            current = matched.ok_or_else(|| {
                format!(
                    "No element matching predicate '[{}]' found in array",
                    predicate
                )
            })?;
        } else if let Ok(idx) = part.parse::<usize>() {
            current = current.get(idx).ok_or_else(|| {
                format!("Index {} out of bounds in JSON array", idx)
            })?;
        } else {
            current = current.get(part).ok_or_else(|| {
                format!("Key '{}' not found in JSON object", part)
            })?;
        }
    }

    Ok(current)
}
