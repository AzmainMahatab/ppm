use crate::config::PackageConfig;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const SEVEN_ZIP_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

fn find_7z_offset(path: &Path) -> Result<u64, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open installer '{}': {}", path.display(), e))?;

    let file_len = file
        .metadata()
        .map_err(|e| format!("Failed to get metadata: {}", e))?
        .len();

    let mut buffer = vec![0u8; 4 * 1024 * 1024]; // Scan first 4 MB
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|e| format!("Failed to read installer: {}", e))?;

    for i in 0..bytes_read.saturating_sub(SEVEN_ZIP_MAGIC.len()) {
        if buffer[i..i + SEVEN_ZIP_MAGIC.len()] == SEVEN_ZIP_MAGIC {
            return Ok(i as u64);
        }
    }

    // If not found in first 4MB, search whole file
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek failed: {}", e))?;
    let mut full_buf = Vec::new();
    file.read_to_end(&mut full_buf)
        .map_err(|e| format!("Failed to read entire file: {}", e))?;

    for i in 0..full_buf.len().saturating_sub(SEVEN_ZIP_MAGIC.len()) {
        if full_buf[i..i + SEVEN_ZIP_MAGIC.len()] == SEVEN_ZIP_MAGIC {
            return Ok(i as u64);
        }
    }

    Err(format!(
        "Embedded 7-Zip stream signature not found in '{}' (size {} bytes)",
        path.display(),
        file_len
    ))
}

fn extract_7z_stream(archive_path: &Path, offset: u64, target_dir: &Path) -> Result<(), String> {
    let mut src_file = File::open(archive_path)
        .map_err(|e| format!("Failed to open archive '{}': {}", archive_path.display(), e))?;

    src_file
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to 7z offset {}: {}", offset, e))?;

    let temp_7z = target_dir
        .parent()
        .unwrap_or(target_dir)
        .join(format!("temp_stream_{}.7z", std::process::id()));

    let mut dest_file = File::create(&temp_7z)
        .map_err(|e| format!("Failed to create temp 7z file '{}': {}", temp_7z.display(), e))?;

    std::io::copy(&mut src_file, &mut dest_file)
        .map_err(|e| format!("Failed to copy 7z payload stream: {}", e))?;

    drop(dest_file);

    let result = sevenz_rust::decompress_file(&temp_7z, target_dir)
        .map_err(|e| format!("7-Zip decompression failed: {}", e));

    let _ = fs::remove_file(&temp_7z);
    result
}

fn extract_zip(archive_path: &Path, target_dir: &Path) -> Result<(), String> {
    let file = File::open(archive_path)
        .map_err(|e| format!("Failed to open zip archive '{}': {}", archive_path.display(), e))?;

    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("Failed to read zip archive: {}", e))?;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Error reading zip entry #{}: {}", i, e))?;

        let outpath = match file.enclosed_name() {
            Some(path) => target_dir.join(path),
            None => continue,
        };

        if file.is_dir() {
            fs::create_dir_all(&outpath)
                .map_err(|e| format!("Failed to create directory '{}': {}", outpath.display(), e))?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p).map_err(|e| {
                        format!("Failed to create parent directory '{}': {}", p.display(), e)
                    })?;
                }
            }
            let mut outfile = File::create(&outpath)
                .map_err(|e| format!("Failed to create output file '{}': {}", outpath.display(), e))?;
            std::io::copy(&mut file, &mut outfile)
                .map_err(|e| format!("Failed to extract file '{}': {}", outpath.display(), e))?;
        }
    }

    Ok(())
}

fn extract_cab(archive_path: &Path, target_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(target_dir)
        .map_err(|e| format!("Failed to create target directory: {}", e))?;

    // Native Windows expand.exe utility handles Microsoft CABs perfectly
    let mut cmd = std::process::Command::new("expand.exe");
    cmd.arg("-F:*");
    cmd.arg(archive_path);
    cmd.arg(target_dir);

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to invoke expand.exe for CAB unpacking: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "expand.exe failed with code {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

fn extract_msi(archive_path: &Path, target_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(target_dir)
        .map_err(|e| format!("Failed to create target directory: {}", e))?;

    let mut cmd = std::process::Command::new("msiexec.exe");
    cmd.arg("/a");
    cmd.arg(archive_path);
    cmd.arg("/qn");
    cmd.arg(format!("TARGETDIR={}", target_dir.display()));

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to invoke msiexec.exe for MSI unpacking: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "msiexec.exe failed with code {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub fn extract_package(
    archive_path: &Path,
    package_config: &PackageConfig,
    target_dir: &Path,
) -> Result<(), String> {
    // Stage extraction into a temporary directory
    let stage_dir = target_dir
        .parent()
        .unwrap_or(target_dir)
        .join(format!("{}.stage_{}", target_dir.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));

    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir)
        .map_err(|e| format!("Failed to create staging directory '{}': {}", stage_dir.display(), e))?;

    let (extract_subpath, extract_result) = match package_config {
        PackageConfig::Nsis7z { extract_subpath } => {
            let offset = find_7z_offset(archive_path)?;
            let res = extract_7z_stream(archive_path, offset, &stage_dir);
            (extract_subpath.as_deref(), res)
        }
        PackageConfig::SevenZ { extract_subpath } => {
            let res = sevenz_rust::decompress_file(archive_path, &stage_dir)
                .map_err(|e| format!("7-Zip decompression failed: {}", e));
            (extract_subpath.as_deref(), res)
        }
        PackageConfig::Zip { extract_subpath } => {
            let res = extract_zip(archive_path, &stage_dir);
            (extract_subpath.as_deref(), res)
        }
        PackageConfig::Cab { extract_subpath } => {
            let res = extract_cab(archive_path, &stage_dir);
            (extract_subpath.as_deref(), res)
        }
        PackageConfig::Msi { extract_subpath } => {
            let res = extract_msi(archive_path, &stage_dir);
            (extract_subpath.as_deref(), res)
        }
        PackageConfig::Tar { extract_subpath } => {
            let res = extract_zip(archive_path, &stage_dir);
            (extract_subpath.as_deref(), res)
        }
        PackageConfig::Binary => {
            let file_name = archive_path.file_name().unwrap_or_default();
            let dest_file = stage_dir.join(file_name);
            let res = fs::copy(archive_path, &dest_file)
                .map(|_| ())
                .map_err(|e| format!("Failed to copy binary: {}", e));
            (None, res)
        }
    };

    if let Err(e) = extract_result {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(e);
    }

    // Resolve source directory (if subpath is specified)
    let source_dir = if let Some(sub) = extract_subpath {
        stage_dir.join(sub)
    } else {
        // Auto-detect common subpaths like $PLUGINSDIR or app-64
        let plugins_app = stage_dir.join("$PLUGINSDIR").join("app-64");
        if plugins_app.exists() {
            plugins_app
        } else {
            stage_dir.clone()
        }
    };

    // Atomic move / swap into target_dir
    let backup_dir = target_dir
        .parent()
        .unwrap_or(target_dir)
        .join(format!("{}.old_{}", target_dir.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));

    if target_dir.exists() {
        let _ = fs::rename(target_dir, &backup_dir);
    }

    if let Some(p) = target_dir.parent() {
        let _ = fs::create_dir_all(p);
    }

    let move_res = if source_dir == stage_dir {
        fs::rename(&stage_dir, target_dir)
    } else {
        // Move contents of source_dir to target_dir
        fs::rename(&source_dir, target_dir)
    };

    if let Err(e) = move_res {
        // Fallback: copy recursively
        if let Err(copy_err) = copy_dir_all(&source_dir, target_dir) {
            // Restore backup on failure
            if backup_dir.exists() {
                let _ = fs::rename(&backup_dir, target_dir);
            }
            let _ = fs::remove_dir_all(&stage_dir);
            return Err(format!("Failed to move unpacked files into target directory: {} (Copy error: {})", e, copy_err));
        }
    }

    // Clean up temporary staging and backup
    let _ = fs::remove_dir_all(&stage_dir);
    let _ = fs::remove_dir_all(&backup_dir);

    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}
