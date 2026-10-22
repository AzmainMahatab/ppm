//! The install cycle end to end against a local HTTPS release host: version check, download,
//! extraction, swap-in over a previous install, sanitizing, and launcher generation.

use std::io::{Cursor, Write};
use std::path::Path;

use httpmock::MockServer;
use httpmock::server::DEFAULT_CA_CERTIFICATE;
use ppm::core::arch::CpuArch;
use ppm::core::config::AppManifests;
use ppm::package::http::{HttpClients, TrustRoots};
use serde_json::json;
use zip::write::SimpleFileOptions;

use super::{ReinstallPolicy, install_plan, run_install_cycle};

const APP_ID: &str = "sample";
const RELEASE_VERSION: &str = "1.4.2";
const PAYLOAD_DIR: &str = "Sample-1.4.2";

/// A release zip in the shape upstream projects ship: one top-level folder holding the
/// executable, a data file, and a readme the manifest removes after install.
fn release_archive(executable: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    for (name, bytes) in [
        ("sample.exe", executable),
        ("data/settings.ini", b"[sample]\r\ntheme=teal\r\n".as_slice()),
        ("README.txt", b"upstream readme".as_slice()),
    ] {
        archive
            .start_file(format!("{PAYLOAD_DIR}/{name}"), options)
            .expect("start zip entry");
        archive.write_all(bytes).expect("write zip entry");
    }
    archive.finish().expect("finish zip").into_inner()
}

fn manifest(release_json_url: &str) -> AppManifests {
    serde_json::from_value(json!({
        "apps": {
            APP_ID: {
                "name": "Sample",
                "target_dir": "Sample",
                "executable": "sample.exe",
                "version_check": {
                    "type": "json_api",
                    "url": release_json_url,
                    "version_key": "/tag",
                    "url_key": "/assets[platform=windows]/url"
                },
                "package": { "type": "zip", "extract_subpath": PAYLOAD_DIR },
                "post_install": { "remove_files": ["README.txt"], "create_dirs": ["cache"] }
            }
        }
    }))
    .expect("invariant: test manifest is schema-valid")
}

/// Serves the release document and the archive it points at.
fn serve_release(server: &MockServer, archive: Vec<u8>) -> (httpmock::Mock<'_>, httpmock::Mock<'_>) {
    let release = server.mock(|when, then| {
        when.method("GET").path("/releases/latest.json");
        then.status(200).json_body(json!({
            "tag": RELEASE_VERSION,
            "assets": [
                { "platform": "linux", "url": server.url("/downloads/Sample-1.4.2-linux.tar.gz") },
                { "platform": "windows", "url": server.url("/downloads/Sample-1.4.2-win.zip") }
            ]
        }));
    });
    let download = server.mock(|when, then| {
        when.method("GET").path("/downloads/Sample-1.4.2-win.zip");
        then.status(200)
            .header("content-type", "application/zip")
            .body(archive);
    });
    (release, download)
}

fn trusting_the_test_server() -> HttpClients {
    let authority = reqwest::Certificate::from_pem(DEFAULT_CA_CERTIFICATE.as_bytes())
        .expect("httpmock's CA certificate is valid PEM");
    HttpClients::new(&TrustRoots::Only(vec![authority])).expect("build HTTP clients")
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("readable dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn install_fetches_the_latest_release_over_https_and_swaps_it_in() {
    let executable =
        std::fs::read(std::env::current_exe().expect("test binary path")).expect("read test binary");
    let server = MockServer::start();
    let (release, download) = serve_release(&server, release_archive(&executable));

    let root = tempfile::tempdir().expect("temp root");
    let arch = CpuArch::current();
    let manifests = manifest(&server.url("/releases/latest.json"));
    let app_dir = manifests.apps[APP_ID].app_dir_for_arch(root.path(), arch);
    std::fs::create_dir_all(&app_dir).expect("previous install dir");
    std::fs::write(app_dir.join("from-1.3.0.dll"), b"previous release").expect("previous install file");

    let plan = install_plan(&manifests, APP_ID, &[arch]).expect("plan");
    run_install_cycle(
        &trusting_the_test_server(),
        root.path(),
        &manifests,
        &plan,
        ReinstallPolicy::SkipWhenCurrent,
    )
    .expect("install cycle succeeds against the local release host");

    release.assert();
    download.assert();
    // The payload folder's contents land in the target directory, replacing the previous
    // install as a whole; the readme is removed and the declared directory created.
    assert_eq!(entries(&app_dir), ["cache", "data", "sample.exe"]);
    assert_eq!(
        std::fs::read(app_dir.join("sample.exe")).expect("installed exe"),
        executable
    );
    assert_eq!(
        std::fs::read_to_string(app_dir.join("data").join("settings.ini")).expect("installed data"),
        "[sample]\r\ntheme=teal\r\n"
    );
    // The test binary is a console executable, so its launcher runs it attached.
    let launcher = std::fs::read_to_string(root.path().join("sample.bat")).expect("launcher generated");
    assert!(
        launcher.contains("\"%PPM_EXE%\" run sample %*\r\nexit /b %ERRORLEVEL%"),
        "{launcher}"
    );
    // The downloaded archive does not outlive the install.
    assert_eq!(
        entries(&root.path().join(".ppm").join("cache")),
        Vec::<String>::new()
    );
}

#[test]
fn install_refuses_a_release_host_whose_certificate_the_platform_does_not_trust() {
    let server = MockServer::start();
    let (release, download) = serve_release(&server, release_archive(b"never served"));

    let root = tempfile::tempdir().expect("temp root");
    let arch = CpuArch::current();
    let manifests = manifest(&server.url("/releases/latest.json"));
    let plan = install_plan(&manifests, APP_ID, &[arch]).expect("plan");
    let platform = HttpClients::new(&TrustRoots::Platform).expect("build HTTP clients");

    let outcome = run_install_cycle(&platform, root.path(), &manifests, &plan, ReinstallPolicy::Always);

    let error = format!(
        "{:#}",
        outcome.expect_err("a host signed by an untrusted authority must fail the install")
    );
    assert!(
        error.contains("certificate"),
        "the failure must be the TLS check: {error}"
    );
    release.assert_calls(0);
    download.assert_calls(0);
    assert!(
        !manifests.apps[APP_ID]
            .app_dir_for_arch(root.path(), arch)
            .exists()
    );
}
