use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn download_file(url: &str, dest_path: &Path, display_name: &str) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("ppm-portable-package-manager/0.1")
        .build()?;

    let mut response = client.get(url).send()?;

    if !response.status().is_success() {
        bail!("Download failed with HTTP status code: {}", response.status());
    }

    let total_size = response.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n[{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .expect("invariant: hard-coded progress template is valid")
            .progress_chars("#>-"),
    );
    pb.set_message(format!("  • Downloading {}", display_name));

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(dest_path)?;

    let mut buffer = [0u8; 65536];
    let mut downloaded: u64 = 0;

    loop {
        use std::io::Read;
        let bytes_read = response.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        file.write_all(&buffer[..bytes_read])?;

        downloaded += bytes_read as u64;
        pb.set_position(downloaded);
    }

    pb.finish_with_message(format!("  ✓ Downloaded {}", display_name));
    Ok(())
}
