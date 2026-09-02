use crate::core::config::{PackageConfig, PackageKind};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

const SEVENZ_SIGNATURE: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// The scratch directories one extraction needs.
///
/// Both sit beside the destination rather than inside it, so they share its volume - which is
/// what lets the payload be moved into place by rename instead of copied - and so a staging
/// directory can never be mistaken for part of the payload it is feeding.
struct SwapPaths {
    staging: PathBuf,
    retired: PathBuf,
}

fn swap_paths_for(dest_dir: &Path) -> Result<SwapPaths> {
    let parent = dest_dir.parent().with_context(|| {
        format!(
            "Install destination '{}' has no parent directory to stage beside",
            dest_dir.display()
        )
    })?;
    let name = dest_dir
        .file_name()
        .with_context(|| format!("Install destination '{}' has no name", dest_dir.display()))?
        .to_string_lossy()
        .into_owned();

    Ok(SwapPaths {
        staging: parent.join(format!(".{name}.staging")),
        retired: parent.join(format!(".{name}.previous")),
    })
}

/// Removes a directory tree, treating its absence as success.
fn remove_tree_if_present(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Failed to remove directory '{}'", path.display())),
    }
}

struct StagingGuard(PathBuf);

impl Drop for StagingGuard {
    fn drop(&mut self) {
        // The staging directory is often already gone by now - it becomes the installation
        // itself when the payload sits at the archive root - so only a real failure is worth
        // reporting.
        if let Err(error) = remove_tree_if_present(&self.0) {
            eprintln!("Warning: {error:#}");
        }
    }
}

/// Moves the extracted payload into place, replacing any previous installation wholesale.
///
/// # Why a rename rather than a copy
/// Copying the payload over the previous installation left behind every file the new version no
/// longer ships, so an update produced the union of both releases - which is how an application
/// ends up loading a module its own release notes say was removed. Replacing the directory
/// deletes what is gone by construction. The move is also a metadata operation instead of a byte
/// copy of a payload that routinely runs to hundreds of megabytes.
///
/// # Why the previous tree is set aside rather than deleted
/// Deleting first would leave the application missing outright if the new payload then failed to
/// move into place. Retiring it keeps a restore available for exactly that window.
fn install_payload(source_root: &Path, dest_dir: &Path, retired: &Path) -> Result<()> {
    // A retired tree can only be left over from an interrupted run; the current one is about to
    // take its place.
    remove_tree_if_present(retired)?;

    if let Some(parent) = dest_dir.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create the install parent directory '{}'",
                parent.display()
            )
        })?;
    }

    let had_previous = dest_dir.exists();
    if had_previous {
        fs::rename(dest_dir, retired).with_context(|| {
            format!(
                "Failed to set aside the previous installation at '{}' - a file in it is most likely still open",
                dest_dir.display()
            )
        })?;
    }

    if let Err(error) = fs::rename(source_root, dest_dir) {
        if had_previous && let Err(restore) = fs::rename(retired, dest_dir) {
            bail!(
                "Failed to move the new payload into '{}' ({error}), and the previous installation could not be restored from '{}' ({restore}) - the application is left retired at that path",
                dest_dir.display(),
                retired.display()
            );
        }
        return Err(error).with_context(|| {
            format!(
                "Failed to move the extracted payload into '{}'",
                dest_dir.display()
            )
        });
    }

    remove_tree_if_present(retired)
}

fn to_cmd_path(path: &Path) -> String {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let s = abs.to_string_lossy().to_string();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        s
    }
}

pub fn find_7z_offset(path: &Path) -> Result<u64> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut buffer = [0u8; 65536];
    let mut current_offset: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read < 6 {
            break;
        }

        for i in 0..=(bytes_read - 6) {
            if &buffer[i..i + 6] == SEVENZ_SIGNATURE {
                return Ok(current_offset + i as u64);
            }
        }

        current_offset += (bytes_read - 5) as u64;
        reader.seek(SeekFrom::Start(current_offset))?;
    }

    bail!(
        "Could not find embedded 7-Zip payload header in NSIS installer '{}'",
        path.display()
    )
}

pub fn extract_7z_stream(archive_path: &Path, offset: u64, dest_dir: &Path) -> Result<()> {
    let mut file = File::open(archive_path)?;
    file.seek(SeekFrom::Start(offset))?;

    let temp_7z = dest_dir.join("__temp_payload.7z");
    let mut temp_file = File::create(&temp_7z)?;

    std::io::copy(&mut file, &mut temp_file)?;
    drop(temp_file);

    let res = sevenz_rust::decompress_file(&temp_7z, dest_dir);
    if let Err(error) = fs::remove_file(&temp_7z) {
        eprintln!(
            "Warning: failed to remove temporary archive '{}': {error}",
            temp_7z.display()
        );
    }
    if let Err(e) = res {
        bail!(
            "7-Zip decompression failed for '{}': {}",
            archive_path.display(),
            e
        );
    }
    Ok(())
}

pub fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let outpath = match entry.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue,
        };

        if entry.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent()
                && !p.exists()
            {
                fs::create_dir_all(p)?;
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut entry, &mut outfile)?;
        }
    }

    Ok(())
}

pub fn extract_cab(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    fs::create_dir_all(dest_dir)?;

    #[cfg(windows)]
    {
        let abs_archive = to_cmd_path(archive_path);
        let abs_dest = to_cmd_path(dest_dir);

        if let Ok(status) = Command::new("expand.exe")
            .arg(&abs_archive)
            .arg("-F:*")
            .arg(&abs_dest)
            .status()
            && status.success()
        {
            return Ok(());
        }
    }

    if let Ok(file) = File::open(archive_path)
        && let Ok(mut cabinet) = cab::Cabinet::new(file)
    {
        let file_names: Vec<String> = cabinet
            .folder_entries()
            .flat_map(|f| f.file_entries().map(|e| e.name().to_string()))
            .collect();

        for name in file_names {
            let Some(mut reader) = cabinet.read_file(&name).ok() else {
                bail!("CAB entry '{name}' could not be opened for reading");
            };
            let out_path = dest_dir.join(&name);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory '{}'", parent.display()))?;
            }
            let mut out_file = File::create(&out_path)
                .with_context(|| format!("Failed to create '{}'", out_path.display()))?;
            std::io::copy(&mut reader, &mut out_file)
                .with_context(|| format!("Failed to extract CAB entry '{name}'"))?;
        }
        return Ok(());
    }

    bail!("Failed to extract CAB package '{}'", archive_path.display())
}

pub fn extract_msi(msi_path: &Path, dest_dir: &Path) -> Result<()> {
    // 1. Pure-Rust extraction for standard WiX/MSI relational packages
    if let Ok(file) = File::open(msi_path)
        && let Ok(mut package) = msi::Package::open(file)
    {
        let mut file_map: HashMap<String, String> = HashMap::new();
        if let Ok(file_rows) = package.select_rows(msi::Select::table("File")) {
            for row in file_rows {
                let file_key = row[0].as_str().unwrap_or("").to_string();
                let raw_name = row[2].as_str().unwrap_or("");
                let clean_name = if let Some((_, long_name)) = raw_name.split_once('|') {
                    long_name
                } else {
                    raw_name
                };
                if !file_key.is_empty() && !clean_name.is_empty() {
                    file_map.insert(file_key, clean_name.to_string());
                }
            }
        }

        let stream_names: Vec<String> = package.streams().map(|s| s.to_string()).collect();
        let mut extracted_any = false;

        for stream_name in &stream_names {
            let mut stream_reader = match package.read_stream(stream_name) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let mut stream_bytes = Vec::new();
            if stream_reader.read_to_end(&mut stream_bytes).is_err() {
                continue;
            }

            if stream_bytes.starts_with(b"MSCF")
                && let Ok(mut cabinet) = cab::Cabinet::new(Cursor::new(stream_bytes))
            {
                let cab_entries: Vec<String> = cabinet
                    .folder_entries()
                    .flat_map(|f| f.file_entries().map(|e| e.name().to_string()))
                    .collect();

                for cab_file_key in cab_entries {
                    if let Ok(mut reader) = cabinet.read_file(&cab_file_key) {
                        let target_name = file_map
                            .get(&cab_file_key)
                            .cloned()
                            .unwrap_or_else(|| cab_file_key.clone());

                        let out_file_path = dest_dir.join(&target_name);
                        if let Some(parent) = out_file_path.parent() {
                            fs::create_dir_all(parent).with_context(|| {
                                format!("Failed to create directory '{}'", parent.display())
                            })?;
                        }

                        let mut out_file = File::create(&out_file_path)
                            .with_context(|| format!("Failed to create '{}'", out_file_path.display()))?;
                        std::io::copy(&mut reader, &mut out_file).with_context(|| {
                            format!("Failed to extract MSI stream entry '{cab_file_key}'")
                        })?;
                        extracted_any = true;
                    }
                }
            }
        }

        // Check external CAB files if referenced
        if !extracted_any
            && let Some(parent_dir) = msi_path.parent()
            && let Ok(entries) = fs::read_dir(parent_dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("cab"))
                        .unwrap_or(false)
                    && extract_cab(&path, dest_dir).is_ok()
                {
                    extracted_any = true;
                }
            }
        }

        if extracted_any {
            return Ok(());
        }
    }

    // 2. Fallback for custom-action wrapped MSIs (e.g. Microsoft Edge Enterprise)
    let abs_msi = to_cmd_path(msi_path);
    let abs_dest = to_cmd_path(dest_dir);
    fs::create_dir_all(dest_dir)?;

    let status = Command::new("msiexec.exe")
        .arg("/a")
        .arg(&abs_msi)
        .arg("/qn")
        .arg(format!("TARGETDIR={}", abs_dest))
        .status()?;

    if !status.success() {
        bail!("msiexec extraction failed with exit status: {:?}", status.code());
    }

    // Clean up any stray .msi files dropped into dest_dir by msiexec /a
    if let Ok(entries) = fs::read_dir(dest_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("msi"))
                    .unwrap_or(false)
                && let Err(error) = fs::remove_file(&p)
            {
                eprintln!("Warning: failed to remove stray msi '{}': {error}", p.display());
            }
        }
    }

    Ok(())
}

pub fn extract_package(archive_path: &Path, package_config: &PackageConfig, dest_dir: &Path) -> Result<()> {
    let swap = swap_paths_for(dest_dir)?;
    // Anything left at these paths is debris from an interrupted run.
    remove_tree_if_present(&swap.staging)?;
    fs::create_dir_all(&swap.staging).with_context(|| {
        format!(
            "Failed to create the staging directory '{}'",
            swap.staging.display()
        )
    })?;

    let stage_dir = swap.staging.clone();
    let _guard = StagingGuard(swap.staging);

    match package_config.kind {
        PackageKind::Nsis7z => {
            let offset = find_7z_offset(archive_path)?;
            extract_7z_stream(archive_path, offset, &stage_dir)?;
        }
        PackageKind::SevenZ => {
            if let Err(e) = sevenz_rust::decompress_file(archive_path, &stage_dir) {
                bail!(
                    "7-Zip decompression failed for '{}': {}",
                    archive_path.display(),
                    e
                );
            }
        }
        PackageKind::Zip => extract_zip(archive_path, &stage_dir)?,
        PackageKind::Cab => extract_cab(archive_path, &stage_dir)?,
        PackageKind::Msi => extract_msi(archive_path, &stage_dir)?,
        PackageKind::Tar => {
            // Honest halt: this arm used to dispatch to `extract_zip`, which cannot read a tar
            // archive and failed with a ZIP parse error that named the wrong format. No tar
            // reader is linked into this build, so the manifest declares a format the engine
            // cannot unpack - say so instead of mis-dispatching.
            bail!(
                "package type 'tar' is declared for '{}' but no tar extractor is implemented in this build; repackage the release as zip/7z or add a tar reader",
                archive_path.display()
            );
        }
        PackageKind::Binary => {
            let file_name = archive_path.file_name().unwrap_or_default();
            let dest_file = stage_dir.join(file_name);
            fs::copy(archive_path, &dest_file)?;
        }
    }

    // `binary` has no archive to descend into, so a subpath cannot apply to it.
    let extract_subpath = match package_config.kind {
        PackageKind::Binary => None,
        _ => package_config.extract_subpath.as_deref(),
    };

    let source_root = match extract_subpath {
        Some(sub) => {
            let declared = stage_dir.join(sub);
            if !declared.is_dir() {
                bail!(
                    "extract_subpath '{sub}' does not exist in the extracted payload of '{}'; refusing to install the archive root instead of the declared subdirectory",
                    archive_path.display()
                );
            }
            declared
        }
        None => find_payload_root(&stage_dir),
    };

    install_payload(&source_root, dest_dir, &swap.retired)
}

fn find_payload_root(dir: &Path) -> PathBuf {
    // 1. Explicit app-64 / app-32 / app conventions
    for sub in &["app-64", "app-32", "app"] {
        let p = dir.join(sub);
        if p.is_dir() {
            return p;
        }
    }

    // 2. Standard MSI directory hierarchies: PFiles/<App>/, Program Files/<Vendor>/<App>/
    for prefix in &["PFiles", "Program Files", "Program Files (x86)"] {
        let p = dir.join(prefix);
        if p.is_dir() {
            if let Ok(mut entries) = fs::read_dir(&p)
                && let Some(Ok(child)) = entries.next()
            {
                let child_path = child.path();
                if child_path.is_dir() {
                    return child_path;
                }
            }
            return p;
        }
    }

    // 3. Common enterprise MSI payload subdirectories
    for candidate in &[
        dir.join("Microsoft").join("Edge").join("Application"),
        dir.join("Microsoft").join("Edge Dev").join("Application"),
        dir.join("Microsoft").join("Edge Beta").join("Application"),
    ] {
        if candidate.is_dir() {
            return candidate.clone();
        }
    }

    // 4. Single nested folder flattening
    if let Ok(entries) = fs::read_dir(dir) {
        let items: Vec<_> = entries.flatten().collect();
        if items.len() == 1 && items[0].path().is_dir() {
            return items[0].path();
        }
    }

    dir.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_7z_offset_detection() {
        let mut sample_nsis = Vec::new();
        sample_nsis.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00");
        sample_nsis.resize(1024, 0);
        sample_nsis.extend_from_slice(SEVENZ_SIGNATURE);
        sample_nsis.extend_from_slice(b"sample_7z_stream_payload");

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &sample_nsis).unwrap();

        let offset = find_7z_offset(temp_file.path()).expect("Should detect 7z offset");
        assert_eq!(offset, 1024);
    }
}
