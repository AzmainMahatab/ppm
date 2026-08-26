use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn fresh_root() -> TempDir {
    tempfile::tempdir().expect("failed to create temp root")
}

fn dll_path(root: &Path) -> PathBuf {
    root.join(".ppm").join("lib").join("redirector.dll")
}

fn config_path(root: &Path) -> PathBuf {
    root.join(".ppm").join("apps.json")
}

fn schema_path(root: &Path) -> PathBuf {
    root.join(".ppm").join("apps.schema.json")
}

#[test]
fn init_deploys_non_empty_embedded_dll() {
    let root = fresh_root();
    ppm::engine::init::init_environment(root.path()).expect("init must succeed");

    let deployed = fs::read(dll_path(root.path())).expect("deployed dll must be readable");
    assert!(!deployed.is_empty(), "deployed redirector.dll must not be empty");
    // MZ header: a real PE image, not a placeholder payload.
    assert_eq!(&deployed[..2], b"MZ", "deployed dll must be a PE image");
}

#[test]
fn init_replaces_zero_byte_dll_without_force() {
    let root = fresh_root();
    fs::create_dir_all(dll_path(root.path()).parent().unwrap()).unwrap();
    fs::write(dll_path(root.path()), b"").expect("seed zero-byte dll");

    ppm::engine::init::init_environment(root.path()).expect("init must succeed");

    let deployed = fs::read(dll_path(root.path())).expect("dll must exist");
    assert!(
        !deployed.is_empty(),
        "0-byte dll must be replaced by the embedded engine"
    );
}

#[test]
fn init_replaces_stale_dll_content() {
    let root = fresh_root();
    fs::create_dir_all(dll_path(root.path()).parent().unwrap()).unwrap();
    fs::write(dll_path(root.path()), b"STALE_ENGINE_PAYLOAD").expect("seed stale dll");

    ppm::engine::init::init_environment(root.path()).expect("init must succeed");

    let deployed = fs::read(dll_path(root.path())).expect("dll must exist");
    assert_ne!(
        deployed, b"STALE_ENGINE_PAYLOAD",
        "stale dll must always be overwritten"
    );
    assert_eq!(&deployed[..2], b"MZ");
}

#[test]
fn init_creates_default_config_only_when_absent() {
    let root = fresh_root();
    assert!(!config_path(root.path()).exists());

    ppm::engine::init::init_environment(root.path()).expect("first init must succeed");
    let seeded = fs::read_to_string(config_path(root.path())).expect("default config must exist");
    assert!(!seeded.is_empty(), "default config must have content");
}

#[test]
fn init_never_overwrites_user_authored_config() {
    let root = fresh_root();
    ppm::engine::init::init_environment(root.path()).expect("seeding init must succeed");

    const CUSTOM: &str = r#"{ "custom": true }"#;
    fs::write(config_path(root.path()), CUSTOM).expect("user config write");

    ppm::engine::init::init_environment(root.path()).expect("second init must succeed");

    let after = fs::read_to_string(config_path(root.path())).expect("config must remain readable");
    assert_eq!(after, CUSTOM, "user-authored apps.json must never be replaced");
}

#[test]
fn init_regenerates_corrupted_schema() {
    let root = fresh_root();
    ppm::engine::init::init_environment(root.path()).expect("first init must succeed");

    fs::write(schema_path(root.path()), "CORRUPTED").expect("corrupt schema");
    ppm::engine::init::init_environment(root.path()).expect("second init must succeed");

    let regenerated = fs::read_to_string(schema_path(root.path())).expect("schema must exist");
    assert_ne!(regenerated, "CORRUPTED", "schema must always be regenerated");
    assert!(
        regenerated.contains("apps"),
        "regenerated schema must describe the app model"
    );
}
