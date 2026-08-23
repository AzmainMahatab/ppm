use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
#[cfg(windows)]
fn test_e2e_virtualization_with_probe() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let root = temp_dir.path();

    // 1. Locate ppm.exe and test-probe.exe
    let ppm_exe = PathBuf::from(env!("CARGO_BIN_EXE_ppm"));
    let test_probe_exe = ppm_exe.with_file_name("test-probe.exe");

    assert!(ppm_exe.is_file(), "ppm.exe must exist at {:?}", ppm_exe);
    assert!(test_probe_exe.is_file(), "test-probe.exe must exist at {:?}", test_probe_exe);

    // Copy ppm.exe to root
    fs::copy(&ppm_exe, root.join("ppm.exe")).expect("Failed to copy ppm.exe to test root");

    // 2. Run ppm.exe init in temp root
    let status = Command::new(root.join("ppm.exe"))
        .arg("init")
        .current_dir(root)
        .status()
        .expect("Failed to run ppm init");
    assert!(status.success(), "ppm init should succeed");

    // 3. Detect host arch directory and place test-probe.exe in Apps/<arch>/TestProbe/test-probe.exe
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
    let probe_dir = root.join("Apps").join(arch).join("TestProbe");
    fs::create_dir_all(&probe_dir).expect("Failed to create probe dir");
    fs::copy(&test_probe_exe, probe_dir.join("test-probe.exe")).expect("Failed to copy test-probe.exe");

    let mut search_dir = ppm_exe.parent();
    let mut found_dll = None;
    while let Some(d) = search_dir {
        let candidate = d.join("redirector.dll");
        if candidate.is_file() {
            found_dll = Some(candidate);
            break;
        }
        search_dir = d.parent();
    }

    if let Some(dll) = found_dll {
        println!("  -> Testing with live compiled redirector.dll at: {:?}", dll);
        fs::copy(&dll, root.join(".ppm").join("lib").join("redirector.dll"))
            .expect("Failed to copy redirector.dll");
    }

    // 4. Write apps.json configuring test-probe
    let apps_json = r#"{
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
    fs::write(root.join(".ppm").join("apps.json"), apps_json).expect("Failed to write apps.json");

    // 5. Run ppm.exe run test-probe
    let output = Command::new(root.join("ppm.exe"))
        .args(["run", "test-probe"])
        .current_dir(root)
        .output()
        .expect("Failed to run ppm run test-probe");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    println!("=== STDOUT ===\n{}", stdout_str);
    println!("=== STDERR ===\n{}", stderr_str);

    let log_file = root.join(".ppm").join("logs").join("redirector.log");
    if log_file.is_file() {
        let log_content = fs::read_to_string(&log_file).unwrap_or_default();
        println!("=== REDIRECTOR.LOG ===\n{}", log_content);
    } else {
        println!("=== REDIRECTOR.LOG NOT FOUND ===");
    }

    assert!(
        output.status.success(),
        "ppm run test-probe must succeed with exit code 0. Stderr: {}",
        stderr_str
    );

    // 6. Verify virtualized system files exist and contain records
    let reg_json = root.join(".ppm").join("system").join("registry.json");
    assert!(reg_json.is_file(), "registry.json should exist in .ppm/system");
    let reg_content = fs::read_to_string(reg_json).unwrap();
    assert!(
        reg_content.contains("PPMTESTPROBE") || reg_content.contains("PPMTestProbe"),
        "registry.json must contain intercepted keys"
    );

    let cred_json = root.join(".ppm").join("system").join("credentials.json");
    assert!(cred_json.is_file(), "credentials.json should exist in .ppm/system");
}
