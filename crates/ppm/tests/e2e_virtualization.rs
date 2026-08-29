use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SINGLE_PROBE_MANIFEST: &str = r#"{
        "$schema": "./apps.schema.json",
        "apps": {
            "test-probe": {
                "name": "Virtualization Test Probe",
                "target_dir": "TestProbe",
                "executable": "test-probe.exe",
                "version_check": {
                    "type": "github_release",
                    "repo": "owner/repo"
                },
                "package": {
                    "type": "zip"
                }
            }
        }
    }"#;

#[cfg(windows)]
struct TestEnvironment {
    temp_dir: tempfile::TempDir,
    ppm_exe: PathBuf,
    test_probe_exe: PathBuf,
    arch: &'static str,
}

#[cfg(windows)]
impl TestEnvironment {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let root = temp_dir.path();

        // Intention: Resolve product binary and probe artifact purely through Cargo's build graph.
        // Why: The probe ships as a bin-artifact dev-dependency (`artifact = "bin"`, gated by the
        //      `[unstable] bindeps` opt-in on the toolchain pinned in rust-toolchain.toml). Cargo
        //      compiles it whenever test targets are built and exports the absolute artifact path as
        //      CARGO_BIN_FILE_TEST_PROBE_test-probe. Dev-dependencies are structurally absent from
        //      release graphs: no feature flags, no membership carve-outs, no runtime bootstrap.
        let ppm_exe = PathBuf::from(env!("CARGO_BIN_EXE_ppm"));
        let test_probe_exe = PathBuf::from(env!("CARGO_BIN_FILE_TEST_PROBE_test-probe"));

        // Copy ppm.exe to root
        fs::copy(&ppm_exe, root.join("ppm.exe")).expect("Failed to copy ppm.exe to test root");

        // PPM_ROOT pins root resolution even if the host exports one.
        let status = Command::new(root.join("ppm.exe"))
            .arg("init")
            .current_dir(root)
            .env("PPM_ROOT", root)
            .status()
            .expect("Failed to run ppm init");
        assert!(status.success(), "ppm init should succeed");

        // Regression guard: init must deploy a real (non-empty) embedded engine DLL.
        let extracted_dll = fs::read(root.join(".ppm").join("lib").join("redirector.dll"))
            .expect("init must deploy .ppm/lib/redirector.dll");
        assert!(
            !extracted_dll.is_empty(),
            "embedded redirector.dll must not be empty"
        );

        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        };

        Self {
            temp_dir,
            ppm_exe,
            test_probe_exe,
            arch,
        }
    }

    fn root(&self) -> &Path {
        self.temp_dir.path()
    }

    fn deploy_binary(&self, target_dir_name: &str, exe_name: &str) -> PathBuf {
        let dest_dir = self.root().join("Apps").join(self.arch).join(target_dir_name);
        fs::create_dir_all(&dest_dir).expect("Failed to create app dir");
        let dest_exe = dest_dir.join(exe_name);
        fs::copy(&self.test_probe_exe, &dest_exe).expect("Failed to copy probe binary");
        dest_exe
    }

    fn write_manifest(&self, apps_json: &str) {
        fs::write(self.root().join(".ppm").join("apps.json"), apps_json).expect("Failed to write apps.json");
    }
}

#[test]
#[cfg(windows)]
fn test_e2e_virtualization_with_probe() {
    let env = TestEnvironment::new();
    env.deploy_binary("TestProbe", "test-probe.exe");
    let apps_json = SINGLE_PROBE_MANIFEST;
    env.write_manifest(apps_json);

    let output = Command::new(env.root().join("ppm.exe"))
        .args(["run", "test-probe"])
        .current_dir(env.root())
        .env("PPM_ROOT", env.root())
        .output()
        .expect("Failed to run ppm run test-probe");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    println!("=== STDOUT ===\n{}", stdout_str);
    println!("=== STDERR ===\n{}", stderr_str);

    assert!(
        output.status.success(),
        "ppm run test-probe must succeed with exit code 0. Stderr: {}",
        stderr_str
    );

    let reg_json = env.root().join(".ppm").join("system").join("registry.json");
    assert!(reg_json.is_file(), "registry.json should exist in .ppm/system");
    let reg_content = fs::read_to_string(reg_json).unwrap();
    assert!(
        reg_content.contains("PPMTESTPROBE") || reg_content.contains("PPMTestProbe"),
        "registry.json must contain intercepted keys"
    );

    let cred_json = env.root().join(".ppm").join("system").join("credentials.json");
    assert!(
        cred_json.is_file(),
        "credentials.json should exist in .ppm/system"
    );

    // Boundary verification guard: the probe must have exercised and passed the process
    // identity boundary; a silent AUMID regression can no longer pass the suite.
    assert!(
        stdout_str.contains("Process Identity Boundary"),
        "Probe must verify the process identity boundary contract. Stdout: {}",
        stdout_str
    );
}

#[test]
#[cfg(windows)]
fn test_e2e_cli_argument_and_help_passthrough() {
    let env = TestEnvironment::new();
    env.deploy_binary("TestProbe", "test-probe.exe");
    let apps_json = SINGLE_PROBE_MANIFEST;
    env.write_manifest(apps_json);

    // 1. Test passing --help flag directly through to child app without clap swallowing it
    let help_output = Command::new(env.root().join("ppm.exe"))
        .args(["run", "test-probe", "--help"])
        .current_dir(env.root())
        .env("PPM_ROOT", env.root())
        .output()
        .expect("Failed to run ppm run test-probe --help");

    let help_stdout = String::from_utf8_lossy(&help_output.stdout);
    println!("=== HELP STDOUT ===\n{}", help_stdout);
    assert!(
        help_output.status.success(),
        "ppm run test-probe --help must exit with code 0"
    );
    assert!(
        help_stdout.contains("[PROBE_HELP] Custom test probe help output"),
        "Child process must receive and handle --help flag"
    );

    // 2. Test passing custom trailing args to child app
    let args_output = Command::new(env.root().join("ppm.exe"))
        .args(["run", "test-probe", "--echo-args", "--custom-param", "42"])
        .current_dir(env.root())
        .env("PPM_ROOT", env.root())
        .output()
        .expect("Failed to run ppm run with custom args");

    let args_stdout = String::from_utf8_lossy(&args_output.stdout);
    println!("=== ARGS STDOUT ===\n{}", args_stdout);
    assert!(
        args_output.status.success(),
        "ppm run test-probe with args must exit with code 0"
    );
    assert!(
        args_stdout.contains("[ARGS_ECHO]"),
        "Child process must receive custom arguments"
    );
    assert!(
        args_stdout.contains("--custom-param") && args_stdout.contains("42"),
        "Child process arguments must contain --custom-param and 42"
    );
}

#[test]
#[cfg(windows)]
fn test_e2e_dependency_resolution_and_enforcement() {
    let env = TestEnvironment::new();

    // Define main-app that depends on dep-service
    let apps_json = r#"{
        "$schema": "./apps.schema.json",
        "apps": {
            "main-app": {
                "name": "Main Application",
                "target_dir": "MainApp",
                "executable": "main-app.exe",
                "dependencies": [
                    "dep-service"
                ],
                "version_check": {
                    "type": "github_release",
                    "repo": "owner/main-app"
                },
                "package": {
                    "type": "zip"
                }
            },
            "dep-service": {
                "name": "Dependency Service",
                "target_dir": "DepService",
                "executable": "dep-service.exe",
                "version_check": {
                    "type": "github_release",
                    "repo": "owner/dep-service"
                },
                "package": {
                    "type": "zip"
                }
            }
        }
    }"#;
    env.write_manifest(apps_json);

    // 1. Deploy ONLY main-app.exe (dep-service.exe is missing)
    env.deploy_binary("MainApp", "main-app.exe");

    // Running main-app MUST fail because dep-service is not installed
    let fail_output = Command::new(env.root().join("ppm.exe"))
        .args(["run", "main-app"])
        .current_dir(env.root())
        .env("PPM_ROOT", env.root())
        .output()
        .expect("Failed to execute ppm run main-app");

    assert!(
        !fail_output.status.success(),
        "ppm run main-app must fail when dependency is missing"
    );
    let fail_stderr = String::from_utf8_lossy(&fail_output.stderr);
    let fail_stdout = String::from_utf8_lossy(&fail_output.stdout);
    let combined_err = format!("{}\n{}", fail_stderr, fail_stdout);
    println!("=== DEPENDENCY ERROR OUTPUT ===\n{}", combined_err);
    assert!(
        combined_err.contains("Required dependency 'Dependency Service' is not installed")
            || combined_err.contains("dep-service"),
        "Error output must explicitly identify the missing dependency"
    );

    // 2. Deploy dep-service.exe to satisfy dependency
    env.deploy_binary("DepService", "dep-service.exe");

    // Running main-app MUST now succeed
    let success_output = Command::new(env.root().join("ppm.exe"))
        .args(["run", "main-app", "--echo-args"])
        .current_dir(env.root())
        .env("PPM_ROOT", env.root())
        .output()
        .expect("Failed to execute ppm run main-app after dependency deployment");

    let success_stdout = String::from_utf8_lossy(&success_output.stdout);
    let success_stderr = String::from_utf8_lossy(&success_output.stderr);
    println!("=== SUCCESS STDOUT ===\n{}", success_stdout);
    assert!(
        success_output.status.success(),
        "ppm run main-app must succeed once dependency is present. Stderr: {}",
        success_stderr
    );
}

#[test]
#[cfg(windows)]
fn test_e2e_cross_directory_invocation() {
    let env = TestEnvironment::new();
    env.deploy_binary("TestProbe", "test-probe.exe");
    let apps_json = SINGLE_PROBE_MANIFEST;
    env.write_manifest(apps_json);

    // Invoke ppm_exe directly from its build output directory (without copying to test root)
    // and rely on .current_dir(env.root())
    let output = Command::new(&env.ppm_exe)
        .args(["run", "test-probe", "--echo-args", "--cross-dir-test"])
        .current_dir(env.root())
        .env("PPM_ROOT", env.root())
        .output()
        .expect("Failed to run ppm from build path");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    println!("=== CROSS DIR STDOUT ===\n{}", stdout_str);
    println!("=== CROSS DIR STDERR ===\n{}", stderr_str);

    assert!(
        output.status.success(),
        "Cross-directory ppm invocation must succeed. Stderr: {}",
        stderr_str
    );
    assert!(
        stdout_str.contains("[ARGS_ECHO]"),
        "Child process must run and echo args in cross-directory invocation"
    );
}
