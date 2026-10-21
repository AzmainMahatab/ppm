use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{Read, Write};
use std::path::Path;

// Intention: Accept a package download only over TLS.
// Why: The trust model is that the upstream host's latest release is authoritative (SPEC 6),
//      which rests entirely on the transport authenticating that host. A plain-http URL in a
//      manifest would quietly reduce that to no authentication at all - and the payload is
//      executed afterwards. Refusing is the only honest response, since there is nothing else
//      to fall back on.
const REQUIRED_SCHEME: &str = "https";

const CHUNK_SIZE: usize = 64 * 1024;

pub fn download_file(url: &str, dest_path: &Path, display_name: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("Malformed download URL '{url}'"))?;
    if parsed.scheme() != REQUIRED_SCHEME {
        bail!(
            "Refusing to download '{display_name}' over '{}': package downloads require {REQUIRED_SCHEME}, which is what authenticates the release host",
            parsed.scheme()
        );
    }

    let response = crate::package::http::download_client()?
        .get(url)
        .send()
        .with_context(|| format!("Failed to request '{url}'"))?;

    if !response.status().is_success() {
        bail!("Download failed with HTTP status code: {}", response.status());
    }

    let expected_len = response.content_length();
    let progress = progress_bar(expected_len, display_name);
    write_verified(response, expected_len, dest_path, &progress)
        .with_context(|| format!("Failed to download '{url}'"))?;
    progress.finish_with_message(format!("  ✓ Downloaded {}", display_name));
    Ok(())
}

fn progress_bar(expected_len: Option<u64>, display_name: &str) -> ProgressBar {
    let progress = ProgressBar::new(expected_len.unwrap_or(0));
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n[{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .expect("invariant: hard-coded progress template is valid")
            .progress_chars("#>-"),
    );
    progress.set_message(format!("  • Downloading {}", display_name));
    progress
}

/// Streams `body` into `dest_path`, publishing the file only once it is complete.
///
/// # Why a temporary file beside the destination
/// Writing straight to `dest_path` left a truncated archive behind whenever a transfer failed,
/// and nothing could tell it from a complete one. The bytes go to a temporary file in the same
/// directory - removed automatically if anything fails - and are renamed into place only after
/// the length check passes, so `dest_path` holds a whole download or nothing.
///
/// # Why the length is checked
/// A connection the server closes early ends the body cleanly, as if the transfer had finished.
/// The declared `Content-Length` is the only signal that bytes are missing.
fn write_verified(
    mut body: impl Read,
    expected_len: Option<u64>,
    dest_path: &Path,
    progress: &ProgressBar,
) -> Result<()> {
    let parent = dest_path.parent().with_context(|| {
        format!(
            "Download target '{}' has no parent directory",
            dest_path.display()
        )
    })?;
    std::fs::create_dir_all(parent).with_context(|| format!("Failed to create '{}'", parent.display()))?;

    let mut partial = tempfile::Builder::new()
        .suffix(".part")
        .tempfile_in(parent)
        .with_context(|| format!("Failed to create a partial download in '{}'", parent.display()))?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut received: u64 = 0;
    loop {
        let read = body.read(&mut buffer).context("Transfer interrupted")?;
        if read == 0 {
            break;
        }
        partial
            .write_all(&buffer[..read])
            .context("Failed to write the partial download")?;
        received += read as u64;
        progress.set_position(received);
    }

    if let Some(expected) = expected_len
        && received != expected
    {
        bail!("Transfer ended after {received} of {expected} bytes");
    }

    partial
        .persist(dest_path)
        .with_context(|| format!("Failed to move the download into '{}'", dest_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn leftover_entries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("readable dir")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn a_complete_body_is_published_at_the_destination_and_nothing_else_remains() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("app.zip");
        let payload = vec![7u8; CHUNK_SIZE * 2 + 5];

        write_verified(
            Cursor::new(payload.clone()),
            Some(payload.len() as u64),
            &dest,
            &ProgressBar::hidden(),
        )
        .expect("complete download");

        assert_eq!(std::fs::read(&dest).expect("published file"), payload);
        assert_eq!(leftover_entries(dir.path()), vec!["app.zip".to_string()]);
    }

    /// Regression: a body shorter than its Content-Length was accepted as a finished download,
    /// and the truncated archive was left at the destination.
    #[test]
    fn a_short_body_fails_and_leaves_neither_destination_nor_partial_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("app.zip");

        let error = write_verified(
            Cursor::new(vec![1u8; 100]),
            Some(250),
            &dest,
            &ProgressBar::hidden(),
        )
        .expect_err("100 of 250 bytes is not a download");

        assert!(error.to_string().contains("100 of 250"), "{error:#}");
        assert!(leftover_entries(dir.path()).is_empty());
    }

    #[test]
    fn a_body_without_a_declared_length_is_accepted_as_received() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("app.bin");

        write_verified(Cursor::new(b"abc".to_vec()), None, &dest, &ProgressBar::hidden()).expect("download");

        assert_eq!(std::fs::read(&dest).expect("published file"), b"abc");
    }
}
