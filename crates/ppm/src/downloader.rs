use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub fn download_file(url: &str, dest: &Path, label: &str) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("ppm/0.1.0")
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let mut response = client
        .get(url)
        .send()
        .map_err(|e| format!("Failed to initiate download from '{}': {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "HTTP error {} downloading from '{}'",
            response.status(),
            url
        ));
    }

    let total_size = response.content_length().unwrap_or(0);

    let pb = if total_size > 0 {
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .map_err(|e| e.to_string())?
                .progress_chars("#>-"),
        );
        pb.set_message(label.to_string());
        Some(pb)
    } else {
        println!("Downloading {} (unknown size)...", label);
        None
    };

    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let part_path = dest.with_extension("part");
    let mut file = File::create(&part_path)
        .map_err(|e| format!("Failed to create temporary file '{}': {}", part_path.display(), e))?;

    let mut buffer = [0u8; 65536];
    let mut downloaded: u64 = 0;

    loop {
        let bytes_read = response
            .read(&mut buffer)
            .map_err(|e| format!("Error reading network stream: {}", e))?;

        if bytes_read == 0 {
            break;
        }

        file.write_all(&buffer[..bytes_read])
            .map_err(|e| format!("Error writing to file: {}", e))?;

        downloaded += bytes_read as u64;
        if let Some(ref p) = pb {
            p.set_position(downloaded);
        }
    }

    if let Some(ref p) = pb {
        p.finish_with_message(format!("{} [Download Complete]", label));
    }

    // Rename .part to final destination
    if dest.exists() {
        let _ = std::fs::remove_file(dest);
    }

    std::fs::rename(&part_path, dest)
        .map_err(|e| format!("Failed to finalize file to '{}': {}", dest.display(), e))?;

    Ok(())
}
