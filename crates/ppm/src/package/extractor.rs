use crate::core::config::PackageConfig;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

const SEVENZ_SIGNATURE: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

pub fn find_7z_offset(path: &Path) -> Result<u64, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open package file '{}': {}", path.display(), e))?;
    let mut reader = BufReader::new(file);

    let mut buffer = [0u8; 65536];
    let mut current_offset: u64 = 0;

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read package file: {}", e))?;
        if bytes_read < 6 {
            break;
        }

        for i in 0..=(bytes_read - 6) {
            if &buffer[i..i + 6] == SEVENZ_SIGNATURE {
                return Ok(current_offset + i as u64);
            }
        }

        current_offset += (bytes_read - 5) as u64;
        reader
            .seek(SeekFrom::Start(current_offset))
            .map_err(|e| format!("Failed to seek file: {}", e))?;
    }

    Err("Could not find embedded 7-Zip payload header in NSIS installer".to_string())
}

pub fn extract_7z_stream(archive_path: &Path, offset: u64, dest_dir: &Path) -> Result<(), String> {
    let mut file = File::open(archive_path)
        .map_err(|e| format!("Failed to open archive '{}': {}", archive_path.display(), e))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to 7z offset {}: {}", offset, e))?;

    let temp_7z = dest_dir.join("__temp_payload.7z");
    let mut temp_file = File::create(&temp_7z)
        .map_err(|e| format!("Failed to create temporary 7z payload: {}", e))?;

    std::io::copy(&mut file, &mut temp_file)
        .map_err(|e| format!("Failed to copy 7z payload: {}", e))?;
    drop(temp_file);

    let res = sevenz_rust::decompress_file(&temp_7z, dest_dir)
        .map_err(|e| format!("7-Zip extraction failed: {}", e));

    let _ = fs::remove_file(&temp_7z);
    res
}

pub fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<(), String> {
    let file = File::open(archive_path)
        .map_err(|e| format!("Failed to open zip file '{}': {}", archive_path.display(), e))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("Failed to parse zip archive: {}", e))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Failed to read zip entry #{}: {}", i, e))?;
        let outpath = match entry.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue,
        };

        if entry.is_dir() {
            fs::create_dir_all(&outpath)
                .map_err(|e| format!("Failed to create dir '{}': {}", outpath.display(), e))?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p).map_err(|e| {
                        format!("Failed to create parent dir '{}': {}", p.display(), e)
                    })?;
                }
            }
            let mut outfile = File::create(&outpath).map_err(|e| {
                format!("Failed to create output file '{}': {}", outpath.display(), e)
            })?;
            std::io::copy(&mut entry, &mut outfile)
                .map_err(|e| format!("Failed to write entry content: {}", e))?;
        }
    }

    Ok(())
}

pub fn extract_cab(archive_path: &Path, dest_dir: &Path) -> Result<(), String> {
    let expand_cmd = format!(
        "expand.exe -F:* \"{}\" \"{}\"",
        archive_path.display(),
        dest_dir.display()
    );

    let status = Command::new("cmd")
        .args(["/C", &expand_cmd])
        .status()
        .map_err(|e| format!("Failed to spawn expand.exe: {}", e))?;

    if !status.success() {
        return Err(format!("expand.exe failed with exit code: {:?}", status.code()));
    }

    Ok(())
}

pub fn extract_msi(archive_path: &Path, dest_dir: &Path) -> Result<(), String> {
    let msiexec_cmd = format!(
        "msiexec.exe /a \"{}\" /qb TARGETDIR=\"{}\"",
        archive_path.display(),
        dest_dir.display()
    );

    let status = Command::new("cmd")
        .args(["/C", &msiexec_cmd])
        .status()
        .map_err(|e| format!("Failed to spawn msiexec.exe: {}", e))?;

    if !status.success() {
        return Err(format!("msiexec.exe administrative extract failed: {:?}", status.code()));
    }

    Ok(())
}

pub fn extract_package(
    archive_path: &Path,
    package_config: &PackageConfig,
    dest_dir: &Path,
) -> Result<(), String> {
    let stage_dir = dest_dir.join("__stage_extract");
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
                .map_err(|e| format!("Failed to copy binary payload: {}", e));
            (None, res)
        }
    };

    extract_result?;

    let source_root = if let Some(sub) = extract_subpath {
        let custom_sub = stage_dir.join(sub);
        if custom_sub.exists() {
            custom_sub
        } else {
            stage_dir.clone()
        }
    } else {
        find_payload_root(&stage_dir)
    };

    let _ = fs::create_dir_all(dest_dir);
    copy_dir_recursive(&source_root, dest_dir)?;

    let _ = fs::remove_dir_all(&stage_dir);
    Ok(())
}

fn find_payload_root(dir: &Path) -> std::path::PathBuf {
    let app_64 = dir.join("app-64");
    if app_64.is_dir() {
        return app_64;
    }
    let app_32 = dir.join("app-32");
    if app_32.is_dir() {
        return app_32;
    }
    let app = dir.join("app");
    if app.is_dir() {
        return app;
    }

    dir.to_path_buf()
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    if !src.exists() {
        return Ok(());
    }

    if src.is_dir() {
        let _ = fs::create_dir_all(dst);
        let entries = fs::read_dir(src)
            .map_err(|e| format!("Failed to read dir '{}': {}", src.display(), e))?;

        for entry in entries.flatten() {
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                let _ = fs::copy(&src_path, &dst_path);
            }
        }
    } else {
        let _ = fs::copy(src, dst);
    }

    Ok(())
}
