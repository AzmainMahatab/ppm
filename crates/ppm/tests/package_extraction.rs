use ppm::core::config::{PackageConfig, PackageKind, PostInstallConfig};
use ppm::package::extractor::extract_package;
use ppm::package::sanitizer::sanitize_package;
use std::fs;
use std::path::PathBuf;

fn find_fixture_path(name: &str) -> PathBuf {
    let candidates = [
        PathBuf::from("crates/ppm/tests/fixtures").join(name),
        PathBuf::from("tests/fixtures").join(name),
        PathBuf::from("../fixtures").join(name),
        PathBuf::from("../../crates/ppm/tests/fixtures").join(name),
    ];
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("Fixture '{}' not found on disk", name))
}

#[test]
fn test_zip_extraction_with_real_fixture() {
    let fixture_path = find_fixture_path("sample_files_dirs.zip");
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let dest_dir = temp_dir.path().join("extracted_zip");

    let config = PackageConfig {
        kind: PackageKind::Zip,
        extract_subpath: None,
    };
    let res = extract_package(&fixture_path, &config, &dest_dir);
    assert!(res.is_ok(), "Zip extraction must succeed: {:?}", res);

    assert!(dest_dir.is_dir());
    let mut entries = fs::read_dir(&dest_dir).unwrap();
    assert!(entries.next().is_some(), "Extracted zip dir should contain files");
}

#[test]
fn test_sevenz_extraction_with_real_fixture() {
    let fixture_path = find_fixture_path("sample_lzma2.7z");
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let dest_dir = temp_dir.path().join("extracted_7z");

    let config = PackageConfig {
        kind: PackageKind::SevenZ,
        extract_subpath: None,
    };
    let res = extract_package(&fixture_path, &config, &dest_dir);
    assert!(res.is_ok(), "7-Zip extraction must succeed: {:?}", res);

    assert!(dest_dir.is_dir());
    let mut entries = fs::read_dir(&dest_dir).unwrap();
    assert!(entries.next().is_some(), "Extracted 7z dir should contain files");
}

#[test]
fn test_cab_pure_rust_extraction_with_real_fixture() {
    let fixture_path = find_fixture_path("sample_vcredis.cab");
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let dest_dir = temp_dir.path().join("extracted_cab");

    let config = PackageConfig {
        kind: PackageKind::Cab,
        extract_subpath: None,
    };
    let res = extract_package(&fixture_path, &config, &dest_dir);
    assert!(res.is_ok(), "CAB pure Rust extraction must succeed: {:?}", res);

    assert!(dest_dir.is_dir());
    let mut entries = fs::read_dir(&dest_dir).unwrap();
    assert!(entries.next().is_some(), "Extracted cab dir should contain files");
}

#[test]
fn test_msi_embedded_pure_rust_extraction_with_real_fixture() {
    let fixture_path = find_fixture_path("sample_embedded.msi");
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let dest_dir = temp_dir.path().join("extracted_msi_embedded");

    let config = PackageConfig {
        kind: PackageKind::Msi,
        extract_subpath: None,
    };
    let res = extract_package(&fixture_path, &config, &dest_dir);
    assert!(
        res.is_ok(),
        "MSI embedded pure Rust extraction must succeed: {:?}",
        res
    );

    assert!(dest_dir.is_dir());
    let mut entries = fs::read_dir(&dest_dir).unwrap();
    assert!(entries.next().is_some(), "Extracted MSI dir should contain files");
}

#[test]
fn test_msi_external_cab_pure_rust_extraction_with_real_fixture() {
    let fixture_path = find_fixture_path("msi_with_external_cab.msi");
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let dest_dir = temp_dir.path().join("extracted_msi_external");

    let config = PackageConfig {
        kind: PackageKind::Msi,
        extract_subpath: None,
    };
    let res = extract_package(&fixture_path, &config, &dest_dir);
    assert!(
        res.is_ok(),
        "MSI external cab pure Rust extraction must succeed: {:?}",
        res
    );

    assert!(dest_dir.is_dir());
    let mut entries = fs::read_dir(&dest_dir).unwrap();
    assert!(entries.next().is_some(), "Extracted MSI dir should contain files");
}

#[test]
fn test_binary_package_deployment() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let bin_path = temp_dir.path().join("standalone_utility.exe");
    let dest_dir = temp_dir.path().join("installed_bin");

    let binary_bytes = b"MZ\x90\x00_standalone_utility_raw_bytes";
    fs::write(&bin_path, binary_bytes).unwrap();

    let config = PackageConfig {
        kind: PackageKind::Binary,
        extract_subpath: None,
    };
    let res = extract_package(&bin_path, &config, &dest_dir);
    assert!(res.is_ok(), "Binary package deployment must succeed: {:?}", res);

    let installed_file = dest_dir.join("standalone_utility.exe");
    assert!(installed_file.is_file());
    assert_eq!(fs::read(&installed_file).unwrap(), binary_bytes);
}

#[test]
fn test_staging_directory_raii_cleanup_on_failure() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let invalid_file = temp_dir.path().join("corrupted.zip");
    fs::write(&invalid_file, b"corrupted_non_zip_header").unwrap();

    let dest_dir = temp_dir.path().join("test_app_dir");
    let config = PackageConfig {
        kind: PackageKind::Zip,
        extract_subpath: None,
    };

    let res = extract_package(&invalid_file, &config, &dest_dir);
    assert!(res.is_err(), "Corrupted package extraction must fail");

    // Staging directory __stage_extract must be completely cleaned up by RAII guard
    let stage_dir = dest_dir.join("__stage_extract");
    assert!(
        !stage_dir.exists(),
        "Staging directory must not remain on failure"
    );
}

#[test]
fn test_post_install_sanitization_rules() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let target_dir = temp_dir.path().join("installed_app");

    // Create installed app tree
    fs::create_dir_all(target_dir.join("resources")).unwrap();
    fs::create_dir_all(target_dir.join("unwanted_dir")).unwrap();
    fs::write(target_dir.join("app.exe"), b"executable").unwrap();
    fs::write(
        target_dir.join("resources").join("app-update.yml"),
        b"version: 1.0.0",
    )
    .unwrap();
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
