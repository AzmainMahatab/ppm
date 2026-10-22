use crate::core::arch::CpuArch;
use crate::core::config::{
    AppDefinition, ElectronManifestCheck, GitHubReleaseCheck, JsonApiCheck, RegexUrlCheck, VersionCheckConfig,
};
use crate::package::http::HttpClients;
use crate::package::pe_info::{get_electron_package_version, get_pe_product_version};
use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde_json::Value;
use std::path::Path;

pub struct RemoteRelease {
    pub version: String,
    pub download_url: String,
}

/// Dynamically detects the local version directly from the executable on disk.
/// Zero static state files; 100% presence-based.
pub fn detect_local_version(root: &Path, app_def: &AppDefinition, arch: CpuArch) -> Option<String> {
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

/// Substitutes the release-template placeholders a `url_template` may carry.
///
/// # Why one expander
/// Three of the four strategies spelled out the same two `replace` calls, so a new placeholder
/// had to be added in three places or the strategies would diverge.
fn expand_release_template(template: &str, version: &str, arch: CpuArch) -> String {
    template
        .replace("{version}", version)
        .replace("{arch}", arch.as_str())
}

/// Resolves a file reference from an Electron update manifest against the manifest's own URL.
///
/// # Why `Url::join` rather than splitting on the last `/`
/// A reference may be absolute, relative, or root-relative, and the manifest URL may carry a
/// query string; standard URL resolution handles each, where string splitting kept the query
/// and mis-joined root-relative paths.
///
/// # Ex
/// `https://h/m/latest.yml?x=1` + `App 1.0.exe` -> `https://h/m/App%201.0.exe`
fn resolve_manifest_reference(manifest_url: &str, reference: &str) -> Result<String> {
    let base = reqwest::Url::parse(manifest_url)
        .map_err(|error| anyhow!("Malformed Electron manifest URL '{manifest_url}': {error}"))?;
    let resolved = base
        .join(reference)
        .map_err(|error| anyhow!("Cannot resolve '{reference}' against '{manifest_url}': {error}"))?;
    Ok(resolved.into())
}

/// Fetches the latest upstream version and resolved download URL for a specific CPU architecture.
pub fn check_remote_version(
    clients: &HttpClients,
    config: &VersionCheckConfig,
    arch: CpuArch,
) -> Result<RemoteRelease> {
    let release = fetch_release(clients, config, arch)?;
    check_version_text(&release.version)?;
    Ok(release)
}

/// Rejects a remote version string that is not plain version text.
///
/// # Why
/// The version comes from a server response and becomes part of the cached archive's file name
/// and of what `ppm check` prints. A value carrying a path separator, a drive colon or a control
/// character would turn that file name into a different path; real version strings never need
/// anything beyond the characters allowed here.
///
/// # Ex
/// `1.2.3`, `2024.10.1-beta+7`, `1.0_rc1` -> accepted; `../x`, `1.0\evil`, `` -> rejected
fn check_version_text(version: &str) -> Result<()> {
    let is_version_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_');
    if version.is_empty() || !version.chars().all(is_version_char) || version.chars().all(|c| c == '.') {
        bail!("Remote release reported an unusable version string {version:?}");
    }
    Ok(())
}

/// Requests a release-metadata document, accepting only a successful response.
///
/// # Why the status is checked before the body is read
/// An error page is still a body: a 404 or 503 carrying JSON or HTML used to be parsed as the
/// release document, surfacing as a missing-key error - or, when the error body happened to hold
/// the expected keys, as a release that was never published.
fn fetch_metadata(clients: &HttpClients, url: &str) -> Result<reqwest::blocking::Response> {
    let response = clients
        .metadata()
        .get(url)
        .send()
        .with_context(|| format!("Failed to request release metadata from '{url}'"))?;
    response
        .error_for_status()
        .with_context(|| format!("Release endpoint '{url}' did not serve its document"))
}

fn fetch_release(clients: &HttpClients, config: &VersionCheckConfig, arch: CpuArch) -> Result<RemoteRelease> {
    match config {
        VersionCheckConfig::ElectronManifest(ElectronManifestCheck {
            url,
            version_key,
            url_template,
        }) => {
            let manifest_url = url
                .resolve(arch)
                .ok_or_else(|| anyhow!("No manifest URL configured for arch '{}'", arch.as_str()))?;

            let response = fetch_metadata(clients, &manifest_url)?;
            let text = response.text()?;

            let yaml: Value = serde_saphyr::from_str(&text)
                .with_context(|| format!("Electron update manifest '{manifest_url}' is not valid YAML"))?;

            let key_name = version_key.as_deref().unwrap_or("version");
            let version_val = yaml
                .get(key_name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Key '{}' not found in YAML manifest", key_name))?
                .to_string();

            let download_url = if let Some(tpl) = url_template {
                let resolved_tpl = tpl
                    .resolve(arch)
                    .ok_or_else(|| anyhow!("No URL template configured for arch '{}'", arch.as_str()))?;
                expand_release_template(&resolved_tpl, &version_val, arch)
            } else if let Some(files) = yaml.get("files").and_then(|f| f.as_array()) {
                let first_file = files
                    .first()
                    .and_then(|f| f.get("url"))
                    .and_then(|u| u.as_str())
                    .ok_or_else(|| anyhow!("No file URL found in Electron manifest files array"))?;
                resolve_manifest_reference(&manifest_url, first_file)?
            } else if let Some(path) = yaml.get("path").and_then(|p| p.as_str()) {
                resolve_manifest_reference(&manifest_url, path)?
            } else {
                bail!("Could not resolve download URL from Electron manifest");
            };

            Ok(RemoteRelease {
                version: version_val,
                download_url,
            })
        }

        VersionCheckConfig::GitHubRelease(GitHubReleaseCheck { repo, asset_pattern }) => {
            let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
            let resp = fetch_metadata(clients, &api_url)?;
            let json: Value = resp.json()?;

            let tag_name = json
                .get("tag_name")
                .and_then(|t| t.as_str())
                .ok_or_else(|| anyhow!("Missing tag_name in GitHub release"))?;

            let version = tag_name.strip_prefix('v').unwrap_or(tag_name).to_string();

            let assets = json
                .get("assets")
                .and_then(|a| a.as_array())
                .ok_or_else(|| anyhow!("Missing assets array in GitHub release"))?;

            let pattern_str = match asset_pattern {
                Some(p) => p
                    .resolve(arch)
                    .ok_or_else(|| anyhow!("No asset pattern defined for arch '{}'", arch.as_str()))?,
                None => format!(".*{}.*\\.zip", arch.as_str()),
            };

            let re = Regex::new(&pattern_str)?;

            let mut matched_url = None;
            for asset in assets {
                let name = asset.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if re.is_match(name)
                    && let Some(dl_url) = asset.get("browser_download_url").and_then(|u| u.as_str())
                {
                    matched_url = Some(dl_url.to_string());
                    break;
                }
            }

            let download_url = matched_url.ok_or_else(|| {
                anyhow!(
                    "No asset matching pattern '{}' found in GitHub release {} for arch '{}'",
                    pattern_str,
                    tag_name,
                    arch.as_str()
                )
            })?;

            Ok(RemoteRelease {
                version,
                download_url,
            })
        }

        VersionCheckConfig::JsonApi(JsonApiCheck {
            url,
            version_key,
            url_key,
            url_template,
        }) => {
            let api_url = url
                .resolve(arch)
                .ok_or_else(|| anyhow!("No JSON API URL configured for arch '{}'", arch.as_str()))?;

            let v_key = version_key
                .resolve(arch)
                .ok_or_else(|| anyhow!("No version_key configured for arch '{}'", arch.as_str()))?;

            let resp = fetch_metadata(clients, &api_url)?;
            let json: Value = resp.json()?;

            let version = resolve_json_query(&json, &v_key)?
                .as_str()
                .ok_or_else(|| anyhow!("Value at '{}' is not a string in JSON", v_key))?
                .to_string();

            let download_url = if let Some(tpl) = url_template {
                let resolved_tpl = tpl
                    .resolve(arch)
                    .ok_or_else(|| anyhow!("No URL template configured for arch '{}'", arch.as_str()))?;
                expand_release_template(&resolved_tpl, &version, arch)
            } else if let Some(uk) = url_key {
                let resolved_uk = uk
                    .resolve(arch)
                    .ok_or_else(|| anyhow!("No url_key configured for arch '{}'", arch.as_str()))?;
                resolve_json_query(&json, &resolved_uk)?
                    .as_str()
                    .ok_or_else(|| anyhow!("Value at '{}' is not a string in JSON", resolved_uk))?
                    .to_string()
            } else {
                bail!("Either url_key or url_template must be provided for json_api");
            };

            Ok(RemoteRelease {
                version,
                download_url,
            })
        }

        VersionCheckConfig::RegexUrl(RegexUrlCheck {
            url,
            regex,
            url_template,
        }) => {
            let scrape_url = url
                .resolve(arch)
                .ok_or_else(|| anyhow!("No scrape URL configured for arch '{}'", arch.as_str()))?;

            let regex_str = regex
                .resolve(arch)
                .ok_or_else(|| anyhow!("No regex configured for arch '{}'", arch.as_str()))?;

            let tpl_str = url_template
                .resolve(arch)
                .ok_or_else(|| anyhow!("No URL template configured for arch '{}'", arch.as_str()))?;

            let resp = fetch_metadata(clients, &scrape_url)?;
            let body = resp.text()?;

            let re = Regex::new(&regex_str)?;

            let caps = re
                .captures(&body)
                .ok_or_else(|| anyhow!("Regex '{}' did not match body of '{}'", regex_str, scrape_url))?;

            let matched_url = caps
                .get(0)
                .expect("invariant: capture group 0 (the whole match) is always present")
                .as_str()
                .replace(r"\u002F", "/");

            let version = caps
                .get(1)
                .map(|m| m.as_str().to_string())
                .ok_or_else(|| anyhow!("Regex did not capture group 1 for version"))?;

            let download_url = if tpl_str.contains("{url}") || tpl_str == "{0}" {
                tpl_str
                    .replace("{url}", &matched_url)
                    .replace("{0}", &matched_url)
            } else {
                expand_release_template(&tpl_str, &version, arch)
            };

            Ok(RemoteRelease {
                version,
                download_url,
            })
        }
    }
}

/// Resolves a JSON pointer / query string supporting predicates (e.g. `/0/Releases[Platform=Windows,Architecture=x64]/ProductVersion`).
fn resolve_json_query<'a>(mut current: &'a Value, query: &str) -> Result<&'a Value> {
    let parts = query.trim_start_matches('/').split('/');

    for part in parts {
        if part.is_empty() {
            continue;
        }

        if let Some((array_name, predicate_str)) = part.split_once('[') {
            let predicate = predicate_str.trim_end_matches(']');
            if !array_name.is_empty() {
                current = current
                    .get(array_name)
                    .ok_or_else(|| anyhow!("Key '{}' not found in JSON object", array_name))?;
            }

            let array = current
                .as_array()
                .ok_or_else(|| anyhow!("Expected array at '{}' but found other JSON type", part))?;

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

            current = matched
                .ok_or_else(|| anyhow!("No element matching predicate '[{}]' found in array", predicate))?;
        } else if let Ok(idx) = part.parse::<usize>() {
            current = current
                .get(idx)
                .ok_or_else(|| anyhow!("Index {} out of bounds in JSON array", idx))?;
        } else {
            current = current
                .get(part)
                .ok_or_else(|| anyhow!("Key '{}' not found in JSON object", part))?;
        }
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::http::TrustRoots;
    use serde_json::json;

    #[test]
    fn an_error_status_from_a_release_endpoint_is_reported_not_parsed() {
        let server = httpmock::MockServer::start();
        // Why a well-formed release document as the error body: it is exactly what a parser
        // would accept, so only the status can tell this response apart from a real release.
        server.mock(|when, then| {
            when.path("/latest.json");
            then.status(503)
                .json_body(json!({ "tag": "9.9.9", "url": "https://h/App.zip" }));
        });
        let config: VersionCheckConfig = serde_json::from_value(json!({
            "type": "json_api",
            "url": server.url("/latest.json"),
            "version_key": "/tag",
            "url_key": "/url"
        }))
        .expect("schema-valid check");
        let authority = reqwest::Certificate::from_pem(httpmock::server::DEFAULT_CA_CERTIFICATE.as_bytes())
            .expect("httpmock's CA certificate is valid PEM");
        let clients = HttpClients::new(&TrustRoots::Only(vec![authority])).expect("clients");

        let error = match check_remote_version(&clients, &config, CpuArch::X64) {
            Ok(release) => panic!("a 503 was taken as release {}", release.version),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("503"), "{error}");
    }

    #[test]
    fn only_plain_version_text_is_accepted_from_a_remote() {
        for accepted in ["1.2.3", "2024.10.1-beta+7", "1.0_rc1", "138.0.3351.83"] {
            assert!(check_version_text(accepted).is_ok(), "{accepted}");
        }
        for rejected in [
            "",
            "..",
            "../x",
            r"1.0\evil",
            "1.0/evil",
            "C:1",
            "1.0 beta",
            "1\n2",
        ] {
            assert!(check_version_text(rejected).is_err(), "{rejected:?}");
        }
    }

    #[test]
    fn electron_file_references_resolve_against_the_manifest_url() {
        let manifest = "https://updates.example.com/win/latest.yml?channel=stable";
        assert_eq!(
            resolve_manifest_reference(manifest, "App Setup 1.0.exe").unwrap(),
            "https://updates.example.com/win/App%20Setup%201.0.exe"
        );
        assert_eq!(
            resolve_manifest_reference(manifest, "/dl/App.exe").unwrap(),
            "https://updates.example.com/dl/App.exe"
        );
        assert_eq!(
            resolve_manifest_reference(manifest, "https://cdn.example.com/App.exe").unwrap(),
            "https://cdn.example.com/App.exe"
        );
    }

    #[test]
    fn resolves_nested_keys_and_array_indices() {
        let value = json!({"a": {"b": [10, 20]}});
        assert_eq!(resolve_json_query(&value, "/a/b/1").unwrap(), &json!(20));
    }

    #[test]
    fn resolves_predicate_selected_array_element() {
        let value = json!({"Releases": [
            {"Platform": "win32", "Architecture": "x64", "ProductVersion": "1.2.3"},
            {"Platform": "win32", "Architecture": "arm64", "ProductVersion": "2.0.0"}
        ]});

        let selected = resolve_json_query(
            &value,
            "/Releases[Platform=win32,Architecture=x64]/ProductVersion",
        )
        .unwrap();
        assert_eq!(selected.as_str().unwrap(), "1.2.3");
    }

    #[test]
    fn missing_key_and_unmatched_predicate_are_errors() {
        let value = json!({"a": 1});
        assert!(resolve_json_query(&value, "/missing").is_err());

        let array = json!({"Releases": [{"Platform": "linux"}]});
        assert!(resolve_json_query(&array, "/Releases[Platform=win32]/X").is_err());
    }
}
