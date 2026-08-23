use crate::assets::{DEFAULT_APPS_JSON, EMBEDDED_REDIRECTOR_DLL};
use crate::config::{load_manifest, save_manifest, AppManifests};
use crate::launcher_gen::generate_launchers;
use std::fs;
use std::path::Path;

pub fn init_environment(root: &Path, force: bool) -> Result<(), String> {
    // 1. Scaffold canonical directory hierarchy
    let apps_dir = root.join("Apps");
    let ppm_dir = root.join(".ppm");
    let logs_dir = ppm_dir.join("logs");
    let home_dir = root.join("Home");
    let local_appdata = home_dir.join("AppData").join("Local");
    let roaming_appdata = home_dir.join("AppData").join("Roaming");
    let documents_dir = home_dir.join("Documents");

    fs::create_dir_all(&apps_dir)
        .map_err(|e| format!("Failed to create Apps directory: {}", e))?;
    fs::create_dir_all(&logs_dir)
        .map_err(|e| format!("Failed to create .ppm/logs directory: {}", e))?;
    fs::create_dir_all(&local_appdata)
        .map_err(|e| format!("Failed to create Home/AppData/Local directory: {}", e))?;
    fs::create_dir_all(&roaming_appdata)
        .map_err(|e| format!("Failed to create Home/AppData/Roaming directory: {}", e))?;
    fs::create_dir_all(&documents_dir)
        .map_err(|e| format!("Failed to create Home/Documents directory: {}", e))?;

    // 2. Provision .ppm/redirector.dll
    let redirector_dll_path = ppm_dir.join("redirector.dll");
    if (!redirector_dll_path.exists() || force) && !EMBEDDED_REDIRECTOR_DLL.is_empty() {
        fs::write(&redirector_dll_path, EMBEDDED_REDIRECTOR_DLL)
            .map_err(|e| format!("Failed to extract embedded redirector.dll: {}", e))?;
        println!("  ✓ Extracted .ppm/redirector.dll");
    }

    // 3. Non-destructive apps.json initialization
    let apps_json_path = ppm_dir.join("apps.json");
    if !apps_json_path.exists() || force {
        let manifests: AppManifests = serde_json::from_str(DEFAULT_APPS_JSON)
            .map_err(|e| format!("Failed to parse default apps.json: {}", e))?;
        save_manifest(root, &manifests)?;
        println!("  ✓ Initialized .ppm/apps.json (Default configuration)");
    } else {
        println!("  ✓ Preserved existing .ppm/apps.json");
    }

    // 4. Generate batch launchers for installed apps
    if let Ok(manifests) = load_manifest(root) {
        if let Ok(generated) = generate_launchers(root, &manifests) {
            for launcher in generated {
                println!("  ✓ Generated root launcher: {}", launcher);
            }
        }
    }

    Ok(())
}
