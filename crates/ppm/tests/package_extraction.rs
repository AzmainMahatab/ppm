use ppm::core::config::{PackageConfig, PostInstallConfig};
use ppm::package::extractor::extract_package;
use ppm::package::sanitizer::sanitize_package;
use std::fs::{self, File};
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn test_real_zip_package_extraction() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let zip_path = temp_dir.path().join("package.zip");
    let dest_dir = temp_dir.path().join("extracted_zip");

    // 1. Build a real ZIP package containing app-64 hierarchy
    {
        let file = File::create(&zip_path).expect("Failed to create zip file");
        let mut zip = ZipWriter::new(file);

        zip.start_file("app-64/app.exe", SimpleFileOptions::default()).unwrap();
        zip.write_all(b"MZ\x90\x00_real_zip_executable_bytes").unwrap();

        zip.start_file("app-64/resources/settings.json", SimpleFileOptions::default()).unwrap();
        zip.write_all(b"{\"portable\": true}").unwrap();

        zip.finish().unwrap();
    }

    // 2. Extract using PackageConfig::Zip
    let config = PackageConfig::Zip { extract_subpath: None };
    let res = extract_package(&zip_path, &config, &dest_dir);
    assert!(res.is_ok(), "Zip extraction must succeed: {:?}", res);

    // 3. Verify that app-64 was automatically flattened and files exist at root
    let exe_path = dest_dir.join("app.exe");
    let config_path = dest_dir.join("resources").join("settings.json");

    assert!(exe_path.is_file(), "app.exe must exist at destination root");
    assert_eq!(fs::read(&exe_path).unwrap(), b"MZ\x90\x00_real_zip_executable_bytes");

    assert!(config_path.is_file(), "settings.json must exist in resources");
    assert_eq!(fs::read_to_string(&config_path).unwrap(), "{\"portable\": true}");
}

#[test]
fn test_real_7z_package_extraction() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let src_dir = temp_dir.path().join("source_7z");
    let archive_path = temp_dir.path().join("package.7z");
    let dest_dir = temp_dir.path().join("extracted_7z");

    // 1. Create source payload
    fs::create_dir_all(src_dir.join("app-64")).unwrap();
    fs::write(src_dir.join("app-64").join("app.exe"), b"MZ\x90\x00_7z_binary").unwrap();
    fs::write(src_dir.join("app-64").join("data.bin"), b"7z_payload_data").unwrap();

    // 2. Compress to real 7z archive
    sevenz_rust::compress_to_path(&src_dir, &archive_path).expect("Failed to create 7z archive");
    assert!(archive_path.is_file());

    // 3. Extract using PackageConfig::SevenZ
    let config = PackageConfig::SevenZ { extract_subpath: None };
    let res = extract_package(&archive_path, &config, &dest_dir);
    assert!(res.is_ok(), "7z extraction must succeed: {:?}", res);

    // 4. Verify extracted files
    assert!(dest_dir.join("app.exe").is_file());
    assert_eq!(fs::read(dest_dir.join("app.exe")).unwrap(), b"MZ\x90\x00_7z_binary");
    assert!(dest_dir.join("data.bin").is_file());
    assert_eq!(fs::read(dest_dir.join("data.bin")).unwrap(), b"7z_payload_data");
}

#[test]
fn test_real_nsis_7z_embedded_package_extraction() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let payload_src = temp_dir.path().join("nsis_payload_src");
    let raw_7z_path = temp_dir.path().join("payload.7z");
    let nsis_exe_path = temp_dir.path().join("installer_setup.exe");
    let dest_dir = temp_dir.path().join("extracted_nsis");

    // 1. Create payload and compress to 7z
    fs::create_dir_all(payload_src.join("app-64")).unwrap();
    fs::write(payload_src.join("app-64").join("tool.exe"), b"MZ\x90\x00_nsis_embedded_tool").unwrap();
    sevenz_rust::compress_to_path(&payload_src, &raw_7z_path).expect("Failed to create 7z payload");

    // 2. Build synthetic NSIS binary (PE executable header + padding + embedded 7z stream)
    let mut nsis_binary_data = Vec::new();
    nsis_binary_data.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"); // DOS header
    nsis_binary_data.resize(32768, 0xAA); // 32KB NSIS installer stub
    let raw_7z_bytes = fs::read(&raw_7z_path).unwrap();
    nsis_binary_data.extend_from_slice(&raw_7z_bytes); // Append 7z stream starting with 37 7A BC AF 27 1C

    fs::write(&nsis_exe_path, &nsis_binary_data).unwrap();

    // 3. Extract using PackageConfig::Nsis7z
    let config = PackageConfig::Nsis7z { extract_subpath: None };
    let res = extract_package(&nsis_exe_path, &config, &dest_dir);
    assert!(res.is_ok(), "NSIS 7z stream extraction must succeed: {:?}", res);

    // 4. Verify extracted payload
    assert!(dest_dir.join("tool.exe").is_file());
    assert_eq!(fs::read(dest_dir.join("tool.exe")).unwrap(), b"MZ\x90\x00_nsis_embedded_tool");
}

#[test]
fn test_real_binary_package_deployment() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let bin_path = temp_dir.path().join("standalone_utility.exe");
    let dest_dir = temp_dir.path().join("installed_bin");

    let binary_bytes = b"MZ\x90\x00_standalone_utility_raw_bytes";
    fs::write(&bin_path, binary_bytes).unwrap();

    let config = PackageConfig::Binary;
    let res = extract_package(&bin_path, &config, &dest_dir);
    assert!(res.is_ok(), "Binary package deployment must succeed: {:?}", res);

    let installed_file = dest_dir.join("standalone_utility.exe");
    assert!(installed_file.is_file());
    assert_eq!(fs::read(&installed_file).unwrap(), binary_bytes);
}

#[test]
fn test_post_install_sanitization_rules() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let target_dir = temp_dir.path().join("installed_app");

    // Create installed app tree
    fs::create_dir_all(target_dir.join("resources")).unwrap();
    fs::create_dir_all(target_dir.join("unwanted_dir")).unwrap();
    fs::write(target_dir.join("app.exe"), b"executable").unwrap();
    fs::write(target_dir.join("resources").join("app-update.yml"), b"version: 1.0.0").unwrap();
    fs::write(target_dir.join("unwanted.log"), b"log_data").unwrap();
    fs::write(target_dir.join("unwanted_dir").join("trash.tmp"), b"temp").unwrap();

    let post_install = PostInstallConfig {
        remove_files: Some(vec!["unwanted.log".to_string()]),
        remove_dirs: Some(vec!["unwanted_dir".to_string()]),
        create_dirs: None,
    };

    let res = sanitize_package(&target_dir, Some(&post_install));
    assert!(res.is_ok(), "Sanitization must succeed");

    // Assert universal auto-updater yml removal
    assert!(!target_dir.join("resources").join("app-update.yml").exists());
    // Assert explicit remove_files
    assert!(!target_dir.join("unwanted.log").exists());
    // Assert explicit remove_dirs
    assert!(!target_dir.join("unwanted_dir").exists());
    // Assert legitimate payload remains untouched
    assert!(target_dir.join("app.exe").is_file());
}
