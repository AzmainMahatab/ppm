//! The HTTP clients every remote operation shares.
//!
//! # Why this module exists
//! The version resolver built a client in each of its four strategies and the downloader built
//! a fifth. Each copy hard-coded the same User-Agent string with a version literal that had
//! already drifted from the crate version, none of them set any timeout, and no connection was
//! ever reused across the `apps x architectures` check matrix.

use anyhow::{Context, Result};
use std::sync::OnceLock;
use std::time::Duration;

// Intention: Bound how long a metadata request may take in total.
// Why: A release endpoint that completes the TCP handshake and then stalls would hang
//      `ppm check` or `ppm install` indefinitely, and neither command has an interactive
//      cancel. Metadata responses are small JSON or YAML documents, so a whole-request budget
//      is safe here - unlike a package download, which legitimately runs much longer.
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

// Intention: Bound connection establishment for every request, downloads included.
// Why: An unreachable or black-holed host otherwise blocks until the OS TCP timeout, which is
//      minutes. This is the one bound a download can safely carry.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

static METADATA_CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
static DOWNLOAD_CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

/// The User-Agent every request carries, derived from the crate version so it cannot drift.
fn user_agent() -> String {
    format!("ppm-portable-package-manager/{}", env!("CARGO_PKG_VERSION"))
}

fn build(total_timeout: Option<Duration>) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .user_agent(user_agent())
        .connect_timeout(CONNECT_TIMEOUT);
    if let Some(timeout) = total_timeout {
        builder = builder.timeout(timeout);
    }
    builder.build().context("Failed to build the HTTP client")
}

/// The shared client for release-metadata requests: small responses, whole-request timeout.
pub fn metadata_client() -> Result<&'static reqwest::blocking::Client> {
    if let Some(existing) = METADATA_CLIENT.get() {
        return Ok(existing);
    }
    let built = build(Some(METADATA_TIMEOUT))?;
    Ok(METADATA_CLIENT.get_or_init(|| built))
}

/// The shared client for package downloads.
///
/// # Why no whole-request timeout
/// A package is hundreds of megabytes; any fixed budget would abort legitimate slow transfers.
/// Connection establishment is still bounded. A transfer that stalls mid-body is therefore not
/// bounded by this client - progress is reported instead, so a stall is visible to the user.
pub fn download_client() -> Result<&'static reqwest::blocking::Client> {
    if let Some(existing) = DOWNLOAD_CLIENT.get() {
        return Ok(existing);
    }
    let built = build(None)?;
    Ok(DOWNLOAD_CLIENT.get_or_init(|| built))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_agent_tracks_the_crate_version() {
        let agent = user_agent();
        assert!(agent.starts_with("ppm-portable-package-manager/"));
        assert!(
            agent.ends_with(env!("CARGO_PKG_VERSION")),
            "the User-Agent must not carry a literal that drifts from the crate version"
        );
    }

    #[test]
    fn each_shared_client_is_built_once() {
        let first = metadata_client().expect("metadata client");
        let second = metadata_client().expect("metadata client");
        assert!(std::ptr::eq(first, second));

        let download = download_client().expect("download client");
        assert!(
            !std::ptr::eq(first, download),
            "downloads must not inherit the metadata whole-request timeout"
        );
    }
}
