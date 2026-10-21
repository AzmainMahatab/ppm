use ppm::core::config::{PackageConfig, PackageKind, PostInstallConfig};
use ppm::package::extractor::extract_package;
use ppm::package::sanitizer::sanitize_package;
use std::fs;
use std::path::{Path, PathBuf};

fn find_fixture_path(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    assert!(path.is_file(), "Fixture '{}' not found on disk", path.display());
    path
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

    // The payload root is INSTALLDIR (`PFiles\NUnit 2.5.2` in the administrative image), and the
    // Directory table's tree is preserved beneath it.
    assert!(dest_dir.join("Logo.ico").is_file());
    let core_1_1 = dest_dir.join(r"bin\net-1.1\lib\nunit.core.dll");
    let core_2_0 = dest_dir.join(r"bin\net-2.0\lib\nunit.core.dll");
    // Regression: entries were written flat, so these two same-named files overwrote each other.
    assert_ne!(
        fs::read(&core_1_1).expect("the .NET 1.1 build is extracted"),
        fs::read(&core_2_0).expect("the .NET 2.0 build is extracted"),
        "each build must keep its own copy"
    );
}

/// Regression: external cabinets were found by scanning the package's directory for any `.cab`,
/// so a stray cabinet in the download cache was extracted into the application.
#[test]
fn msi_extraction_reads_only_the_cabinets_its_media_table_names() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let package_dir = temp_dir.path().join("cache");
    fs::create_dir_all(&package_dir).unwrap();
    for fixture in ["msi_with_external_cab.msi", "msi_with_external_cab.cab"] {
        fs::copy(find_fixture_path(fixture), package_dir.join(fixture)).unwrap();
    }
    fs::copy(
        find_fixture_path("sample_vcredis.cab"),
        package_dir.join("unrelated.cab"),
    )
    .unwrap();

    let dest_dir = temp_dir.path().join("installed");
    let config = PackageConfig {
        kind: PackageKind::Msi,
        extract_subpath: None,
    };
    extract_package(&package_dir.join("msi_with_external_cab.msi"), &config, &dest_dir).expect("extraction");

    let installed: Vec<String> = fs::read_dir(&dest_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(installed, vec!["create_msi_with_external_cab.wxs".to_string()]);
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

    // The staging directory is a sibling of the destination and must not survive the failure.
    let staging = dest_dir.parent().unwrap().join(format!(
        ".{}.staging",
        dest_dir.file_name().unwrap().to_string_lossy()
    ));
    assert!(!staging.exists(), "Staging directory must not remain on failure");
}
/// Regression: the payload was copied over the previous installation, so every file the new
/// release no longer ships survived - an update produced the union of both versions.
#[test]
fn reinstall_removes_files_the_new_release_no_longer_ships() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let dest_dir = temp_dir.path().join("Apps").join("x64").join("DemoApp");
    let config = PackageConfig {
        kind: PackageKind::Zip,
        extract_subpath: None,
    };

    // A first release carrying a module that the second one drops.
    let first = temp_dir.path().join("first.zip");
    write_zip(&first, &[("app.exe", b"v1"), ("legacy_module.dll", b"obsolete")]);
    extract_package(&first, &config, &dest_dir).expect("first install");
    assert!(dest_dir.join("legacy_module.dll").is_file());

    // The second release ships only the executable.
    let second = temp_dir.path().join("second.zip");
    write_zip(&second, &[("app.exe", b"v2")]);
    extract_package(&second, &config, &dest_dir).expect("reinstall");

    assert_eq!(
        fs::read(dest_dir.join("app.exe")).unwrap(),
        b"v2",
        "the new payload must be in place"
    );
    assert!(
        !dest_dir.join("legacy_module.dll").exists(),
        "a file the new release no longer ships must not survive the update"
    );
}

/// The scratch directories live beside the destination so the payload can be moved into place,
/// and neither may outlive the extraction.
#[test]
fn swap_scratch_directories_do_not_survive_an_install() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let dest_dir = temp_dir.path().join("Apps").join("x64").join("DemoApp");
    let config = PackageConfig {
        kind: PackageKind::Zip,
        extract_subpath: None,
    };

    let archive = temp_dir.path().join("payload.zip");
    write_zip(&archive, &[("app.exe", b"v1")]);
    extract_package(&archive, &config, &dest_dir).expect("install");

    let parent = dest_dir.parent().unwrap();
    assert!(
        !parent.join(".DemoApp.staging").exists(),
        "staging must be cleaned"
    );
    assert!(
        !parent.join(".DemoApp.previous").exists(),
        "retired tree must be cleaned"
    );
    assert!(dest_dir.join("app.exe").is_file());
}

/// Builds a zip fixture from in-memory entries.
fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    use std::io::Write;
    let file = fs::File::create(path).expect("create zip");
    let mut zip = zip::ZipWriter::new(file);
    for (name, contents) in entries {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .expect("start entry");
        zip.write_all(contents).expect("write entry");
    }
    zip.finish().expect("finish zip");
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

fn tar_config() -> PackageConfig {
    PackageConfig {
        kind: PackageKind::Tar,
        extract_subpath: None,
    }
}

/// Builds tar bytes from in-memory entries; a `None` body makes a directory entry.
fn tar_bytes(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut header = tar::Header::new_gnu();
        match body {
            Some(bytes) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                builder
                    .append_data(&mut header, name, *bytes)
                    .expect("append file");
            }
            None => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .expect("append dir");
            }
        }
    }
    builder.into_inner().expect("finish tar")
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("compress");
    encoder.finish().expect("finish gzip")
}

/// Regression: `tar` was accepted by the manifest schema but every install of it failed.
#[test]
fn tar_packages_install_whether_gzip_compressed_or_plain() {
    let entries: &[(&str, Option<&[u8]>)] = &[
        ("App-1.0/", None),
        ("App-1.0/app.exe", Some(b"exe")),
        ("App-1.0/res/data.bin", Some(b"data")),
    ];
    for (label, archive) in [("gzip", gzip(&tar_bytes(entries))), ("plain", tar_bytes(entries))] {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let package = temp_dir.path().join("download.bin");
        fs::write(&package, archive).unwrap();
        let dest_dir = temp_dir.path().join("Apps").join("App");

        extract_package(&package, &tar_config(), &dest_dir)
            .unwrap_or_else(|error| panic!("{label}: {error:#}"));

        // The single top-level folder is flattened, as for every other archive format.
        assert_eq!(fs::read(dest_dir.join("app.exe")).unwrap(), b"exe", "{label}");
        assert_eq!(
            fs::read(dest_dir.join("res").join("data.bin")).unwrap(),
            b"data",
            "{label}"
        );
    }
}

#[test]
fn archive_entries_that_escape_the_install_directory_fail_the_install() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let bystander = temp_dir.path().join("evil.txt");

    // tar::Builder refuses `..` paths, so the hostile name is written into the header directly.
    let mut header = tar::Header::new_gnu();
    let name = b"../evil.txt";
    header.as_gnu_mut().expect("gnu header").name[..name.len()].copy_from_slice(name);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    let mut builder = tar::Builder::new(Vec::new());
    builder.append(&header, &b"evil"[..]).expect("append");
    let hostile_tar = temp_dir.path().join("hostile.tar");
    fs::write(&hostile_tar, builder.into_inner().unwrap()).unwrap();

    let hostile_zip = temp_dir.path().join("hostile.zip");
    write_zip(&hostile_zip, &[("app.exe", b"ok"), ("../evil.txt", b"evil")]);

    let deep = temp_dir.path().join("a").join("b");
    for (archive, kind) in [(&hostile_tar, PackageKind::Tar), (&hostile_zip, PackageKind::Zip)] {
        let config = PackageConfig {
            kind,
            extract_subpath: None,
        };
        let error = extract_package(archive, &config, &deep.join("App"))
            .expect_err("an archive with an escaping entry must fail");
        // The failure must name the hostile entry, not be some unrelated parse error.
        assert!(format!("{error:#}").contains("evil.txt"), "{kind:?}: {error:#}");
    }
    assert!(!bystander.exists());
    assert!(!deep.join("evil.txt").exists());
    assert!(
        !deep.join("App").exists(),
        "nothing is installed from a hostile archive"
    );
}

#[test]
fn a_tar_link_fails_the_install_instead_of_being_dropped() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    builder
        .append_link(&mut header, "app.lnk", "app.exe")
        .expect("append link");
    let package = temp_dir.path().join("links.tar");
    fs::write(&package, builder.into_inner().unwrap()).unwrap();

    let error = extract_package(&package, &tar_config(), &temp_dir.path().join("App"))
        .expect_err("a link cannot be reproduced");
    assert!(format!("{error:#}").contains("app.lnk"), "{error:#}");
}
