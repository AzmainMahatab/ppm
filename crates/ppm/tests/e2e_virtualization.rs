use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(windows)]
#[path = "e2e_support/host_registry.rs"]
mod host_registry;

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
                },
                "global_env": {
                    "PPM_TEST_GLOBAL_ENV": "{root}/injected-by-global-env"
                },
                "env": {
                    "PPM_TEST_PEER_PROBE": "{root}/Apps/{arch}/TestProbe/test-probe-x86.exe"
                }
            },
            "test-probe-x86": {
                "name": "Virtualization Test Probe (x86)",
                "target_dir": "TestProbe",
                "executable": "test-probe-x86.exe",
                "version_check": {
                    "type": "github_release",
                    "repo": "owner/repo"
                },
                "package": {
                    "type": "zip"
                },
                "env": {
                    "PPM_TEST_PEER_PROBE": "{root}/Apps/{arch}/TestProbe/test-probe.exe"
                }
            }
        }
    }"#;

#[cfg(windows)]
struct TestEnvironment {
    // Held for its Drop: the temporary directory the root lives in is removed with it.
    _temp_dir: tempfile::TempDir,
    root: PathBuf,
    ppm_exe: PathBuf,
    test_probe_exe: PathBuf,
    x86_probe_exe: PathBuf,
    arch: &'static str,
}

#[cfg(windows)]
impl TestEnvironment {
    fn new() -> Self {
        Self::with_root_name("root")
    }

    /// An initialized portable root in a fresh temporary directory, in a folder named `root_name`.
    fn with_root_name(root_name: &str) -> Self {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let root_path = temp_dir.path().join(root_name);
        fs::create_dir(&root_path).expect("Failed to create the root folder");
        let root = root_path.as_path();

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

        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        };

        Self {
            root: root_path.clone(),
            _temp_dir: temp_dir,
            ppm_exe,
            test_probe_exe,
            x86_probe_exe: PathBuf::from(probe_x86::PROBE_EXE),
            arch,
        }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn deploy_binary(&self, target_dir_name: &str, exe_name: &str) -> PathBuf {
        let dest_dir = self.root().join("Apps").join(self.arch).join(target_dir_name);
        fs::create_dir_all(&dest_dir).expect("Failed to create app dir");
        let dest_exe = dest_dir.join(exe_name);
        fs::copy(&self.test_probe_exe, &dest_exe).expect("Failed to copy probe binary");
        dest_exe
    }

    /// Deploys the probe and its x86 build side by side, as the manifest's peer paths expect.
    fn deploy_probe_pair(&self) {
        let native = self.deploy_binary("TestProbe", "test-probe.exe");
        fs::copy(&self.x86_probe_exe, native.with_file_name("test-probe-x86.exe"))
            .expect("Failed to copy the x86 probe binary");
    }

    /// Deploys the x64 build of the probe, with its x86 peer, as the only installation: with no
    /// ARM64 build present, `ppm run` takes its emulation fallback and launches the x64 one.
    #[cfg(target_arch = "aarch64")]
    fn deploy_emulated_x64_probe_pair(&self) {
        let dest_dir = self.root().join("Apps").join("x64").join("TestProbe");
        fs::create_dir_all(&dest_dir).expect("Failed to create the x64 app dir");
        fs::copy(probe_x64::PROBE_EXE, dest_dir.join("test-probe.exe"))
            .expect("Failed to copy the x64 probe binary");
        fs::copy(&self.x86_probe_exe, dest_dir.join("test-probe-x86.exe"))
            .expect("Failed to copy the x86 probe binary");
    }

    /// Runs `app` through `ppm run` with its registry suite pointed at a freshly seeded host
    /// tree, and asserts afterwards that the run left the real tree exactly as seeded.
    fn run_probe(&self, app: &str) -> Output {
        let host_keys = host_registry::SeededProbeRoot::seed(app);
        let output = Command::new(self.root().join("ppm.exe"))
            .args(["run", app])
            .current_dir(self.root())
            .env("PPM_ROOT", self.root())
            .env("PPM_TEST_REGISTRY_ROOT", host_keys.path())
            .output()
            .unwrap_or_else(|error| panic!("Failed to run ppm run {app}: {error}"));
        host_keys.assert_untouched();
        output
    }

    fn write_manifest(&self, apps_json: &str) {
        fs::write(self.root().join(".ppm").join("apps.json"), apps_json).expect("Failed to write apps.json");
    }
}

#[test]
#[cfg(windows)]
fn test_e2e_virtualization_with_probe() {
    let env = TestEnvironment::new();
    env.deploy_probe_pair();
    let apps_json = SINGLE_PROBE_MANIFEST;
    env.write_manifest(apps_json);

    let output = env.run_probe("test-probe");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    println!("=== STDOUT ===\n{}", stdout_str);
    println!("=== STDERR ===\n{}", stderr_str);

    assert!(
        output.status.success(),
        "ppm run test-probe must succeed with exit code 0. Stderr: {}",
        stderr_str
    );

    // The hive is an append-only journal: one record per intercepted mutation, so the probe's
    // registry writes must be durable in it rather than in a rewritten snapshot file.
    let reg_journal = env.root().join(".ppm").join("system").join("registry.jsonl");
    assert!(
        reg_journal.is_file(),
        "registry.jsonl should exist in .ppm/system"
    );
    let reg_content = fs::read_to_string(&reg_journal).unwrap();
    assert!(
        reg_content.contains("PPMTESTPROBE") || reg_content.contains("PPMTestProbe"),
        "the registry journal must contain the intercepted keys"
    );
    // Every record is one line of JSON; a torn or concatenated record would break replay.
    for (index, line) in reg_content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("registry journal record {index} is not valid JSON: {e}"));
    }

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

/// The root launch obeys the same fail-fast injection contract as a spawned child (ADR-006):
/// without the engine deployed, `ppm run` must refuse rather than start the application
/// unvirtualized, where it would write to the real registry and the real user profile while
/// reporting success.
#[test]
#[cfg(windows)]
fn test_e2e_run_refuses_to_launch_without_the_engine() {
    let env = TestEnvironment::new();
    env.deploy_binary("TestProbe", "test-probe.exe");
    env.write_manifest(SINGLE_PROBE_MANIFEST);

    let engine = env
        .root()
        .join(".ppm")
        .join("lib")
        .join(env.arch)
        .join(injection::ENGINE_DLL_64);
    assert!(engine.is_file(), "init must have deployed the engine");
    fs::remove_file(&engine).expect("the engine must be removable for this test");

    let output = Command::new(env.root().join("ppm.exe"))
        .args(["run", "test-probe"])
        .current_dir(env.root())
        .env("PPM_ROOT", env.root())
        .output()
        .expect("Failed to run ppm run test-probe");

    assert!(
        !output.status.success(),
        "ppm run must fail when the engine is absent instead of launching unvirtualized"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("engine is missing"),
        "the refusal must name the missing engine. Stderr: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("PPM Virtualization Test Probe"),
        "the probe must not have started at all"
    );
    assert!(
        stderr.contains("ppm init"),
        "the refusal must tell the user how to fix it. Stderr: {stderr}"
    );
}

/// Regression: the engine came in one build, for ppm's own machine, so a 32-bit application
/// could not be launched virtualized at all. The x86 probe runs every boundary suite inside a
/// 32-bit process; its injection suite also spawns the 64-bit probe, which exercises the
/// 32-to-64-bit helper route.
#[test]
#[cfg(windows)]
fn test_e2e_x86_application_runs_virtualized() {
    let env = TestEnvironment::new();
    env.deploy_probe_pair();
    env.write_manifest(SINGLE_PROBE_MANIFEST);

    let output = env.run_probe("test-probe-x86");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the x86 probe must pass every boundary suite. Stdout: {stdout}\nStderr: {stderr}"
    );
    assert!(
        stdout.contains("ALL 5 BOUNDARY SUITES PASSED"),
        "every suite must have run. Stdout: {stdout}"
    );
}

/// Regression: the engine path was handed to Detours as UTF-8, which the loader decodes with the
/// system ANSI code page, so a portable root with any non-ASCII character in its path failed every
/// launch. `é` exists in every Western ANSI code page and in UTF-8; on a code page without it the
/// engine falls back to the 8.3 short path.
#[test]
#[cfg(windows)]
fn test_e2e_root_with_a_non_ascii_path_runs_virtualized() {
    let env = TestEnvironment::with_root_name("Portable Café");
    env.deploy_probe_pair();
    env.write_manifest(SINGLE_PROBE_MANIFEST);

    let output = env.run_probe("test-probe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a root under 'Portable Café' must launch virtualized. Stdout: {stdout}\nStderr: {stderr}"
    );
    assert!(
        stdout.contains("ALL 5 BOUNDARY SUITES PASSED"),
        "every suite must have run. Stdout: {stdout}"
    );
}

/// An x64 application on an ARM64 host runs emulated and can only load an x64 DLL. Before
/// per-machine engines, the ARM64 build injected its own engine into it and the launch failed.
/// The x64 probe runs every boundary suite as the root application, and its injection suite
/// spawns the x86 peer, which an emulated x64 parent can only reach through the ARM64 host's
/// x86 engine.
#[test]
#[cfg(all(windows, target_arch = "aarch64"))]
fn test_e2e_emulated_x64_application_runs_virtualized_on_arm64() {
    let env = TestEnvironment::new();
    env.deploy_emulated_x64_probe_pair();
    env.write_manifest(SINGLE_PROBE_MANIFEST);

    let output = env.run_probe("test-probe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the emulated x64 probe must pass every boundary suite. Stdout: {stdout}\nStderr: {stderr}"
    );
    assert!(
        stdout.contains("ALL 5 BOUNDARY SUITES PASSED"),
        "every suite must have run. Stdout: {stdout}"
    );
}

/// Regression: when the x86 engine could not load, Detours' `rundll32` helper still exited 0, so
/// a 64-bit application's x86 child was resumed with no engine and ran outside virtualization.
/// The x86 engine is replaced here by the native build, which the x86 helper cannot load.
#[test]
#[cfg(windows)]
fn test_e2e_a_child_the_engine_cannot_reach_is_refused_rather_than_run_unvirtualized() {
    let env = TestEnvironment::new();
    env.deploy_probe_pair();
    env.write_manifest(SINGLE_PROBE_MANIFEST);
    let lib = env.root().join(".ppm").join("lib").join(env.arch);
    fs::copy(lib.join("redirector64.dll"), lib.join("redirector32.dll")).expect("replace the x86 engine");

    let output = env.run_probe("test-probe");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to spawn child test probe"),
        "the x86 child must be refused at spawn. Stderr: {stderr}"
    );
    assert!(
        !stderr.contains("[CHILD"),
        "the x86 child must never run without its engine. Stderr: {stderr}"
    );
}
