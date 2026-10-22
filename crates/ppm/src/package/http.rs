//! The HTTP clients every remote operation shares.
//!
//! # Why one value passed down rather than process-wide clients
//! The version resolver built a client in each of its four strategies and the downloader built
//! a fifth. Each copy hard-coded the same User-Agent string with a version literal that had
//! already drifted from the crate version, none of them set any timeout, and no connection was
//! ever reused across the `apps x architectures` check matrix. A command now builds one
//! [`HttpClients`] and hands it to everything that goes to the network, which also lets a test
//! decide which certificate authorities the whole install pipeline trusts.

use anyhow::{Context, Result};
use reqwest::Certificate;
use reqwest::blocking::{Client, ClientBuilder};
use std::time::Duration;

// How reqwest's blocking client applies `timeout`: to each blocking wait separately - `send()`
// until the response headers, then every `Read::read` of the body, and `text()`/`json()` as one
// wait over the whole body. It is not a budget for the request as a whole. Leaving it unset
// does not disable it either: the blocking builder defaults it to 30 seconds.

// Intention: Bound how long a metadata request may wait for its headers and then for its body.
// Why: A release endpoint that completes the TCP handshake and then stalls would hang
//      `ppm check` or `ppm install` indefinitely, and neither command has an interactive
//      cancel. Metadata bodies are small JSON or YAML documents read in one wait.
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

// Intention: Bound how long a download may go without receiving any bytes.
// Why: The download body is read in 64 KiB chunks, so this applies per chunk: a slow transfer
//      that keeps delivering never trips it, while a connection that has stopped delivering
//      fails instead of hanging. 30 s matches the client default; raise it if real mirrors are
//      seen pausing longer than that mid-transfer.
const DOWNLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(30);

// Intention: Bound connection establishment for every request, downloads included.
// Why: An unreachable or black-holed host otherwise blocks until the OS TCP timeout, which is
//      minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Which certificate authorities a TLS server must chain to.
#[derive(Debug, Clone)]
pub enum TrustRoots {
    /// The operating system's trust store, as a browser on the same machine would use.
    Platform,
    /// Exactly these roots and no others, such as the authority of a local test server.
    Only(Vec<Certificate>),
}

/// The clients one command uses for all of its requests.
#[derive(Debug, Clone)]
pub struct HttpClients {
    metadata: Client,
    download: Client,
}

impl HttpClients {
    pub fn new(trust: &TrustRoots) -> Result<Self> {
        Ok(Self {
            metadata: build(METADATA_TIMEOUT, trust)?,
            download: build(DOWNLOAD_STALL_TIMEOUT, trust)?,
        })
    }

    /// The client for release-metadata requests: small responses, each wait bounded.
    pub fn metadata(&self) -> &Client {
        &self.metadata
    }

    /// The client for package downloads.
    ///
    /// # Why a stall bound rather than a whole-request budget
    /// A package is hundreds of megabytes; any fixed budget for the whole transfer would abort
    /// legitimate slow downloads. Bounding each chunk read instead fails only a transfer that has
    /// stopped delivering bytes.
    pub fn download(&self) -> &Client {
        &self.download
    }
}

/// The User-Agent every request carries, derived from the crate version so it cannot drift.
fn user_agent() -> String {
    format!("ppm-portable-package-manager/{}", env!("CARGO_PKG_VERSION"))
}

fn build(wait_timeout: Duration, trust: &TrustRoots) -> Result<Client> {
    let builder = Client::builder()
        .user_agent(user_agent())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(wait_timeout);
    trusting(builder, trust)
        .build()
        .context("Failed to build the HTTP client")
}

fn trusting(builder: ClientBuilder, trust: &TrustRoots) -> ClientBuilder {
    match trust {
        TrustRoots::Platform => builder,
        TrustRoots::Only(roots) => builder.tls_certs_only(roots.iter().cloned()),
    }
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
}
