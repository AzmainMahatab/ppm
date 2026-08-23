use crate::core::assets::{DEFAULT_APPS_JSON, EMBEDDED_REDIRECTOR_DLL};
use crate::core::config::AppManifests;
use std::fs;
use std::path::Path;

pub fn init_environment(root: &Path, force: bool) -> Result<(), String> {
    // 1. Scaffold semantic .ppm directories
    let ppm_dir = root.join(".ppm");
    let system_dir = ppm_dir.join("system");
    let lib_dir = ppm_dir.join("lib");
    let cache_dir = ppm_dir.join("cache");
    let logs_dir = ppm_dir.join("logs");

    fs::create_dir_all(&system_dir)
        .map_err(|e| format!("Failed to create .ppm/system directory: {}", e))?;
    fs::create_dir_all(&lib_dir)
        .map_err(|e| format!("Failed to create .ppm/lib directory: {}", e))?;
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create .ppm/cache directory: {}", e))?;
    fs::create_dir_all(&logs_dir)
        .map_err(|e| format!("Failed to create .ppm/logs directory: {}", e))?;

    // 2. Scaffold Multi-Arch Apps/ directories
    let apps_x64 = root.join("Apps").join("x64");
    let apps_arm64 = root.join("Apps").join("arm64");
    fs::create_dir_all(&apps_x64)
        .map_err(|e| format!("Failed to create Apps/x64 directory: {}", e))?;
    fs::create_dir_all(&apps_arm64)
        .map_err(|e| format!("Failed to create Apps/arm64 directory: {}", e))?;

    // 3. Scaffold 100% Pure Home/ directories (Zero .ppm files)
    let home_dir = root.join("Home");
    let appdata_local = home_dir.join("AppData").join("Local");
    let appdata_roaming = home_dir.join("AppData").join("Roaming");
    let appdata_webview = home_dir.join("AppData").join("WebViewData");
    let documents_dir = home_dir.join("Documents");

    fs::create_dir_all(&appdata_local)
        .map_err(|e| format!("Failed to create Home/AppData/Local: {}", e))?;
    fs::create_dir_all(&appdata_roaming)
        .map_err(|e| format!("Failed to create Home/AppData/Roaming: {}", e))?;
    fs::create_dir_all(&appdata_webview)
        .map_err(|e| format!("Failed to create Home/AppData/WebViewData: {}", e))?;
    fs::create_dir_all(&documents_dir)
        .map_err(|e| format!("Failed to create Home/Documents: {}", e))?;

    // 4. Extract embedded redirector.dll to .ppm/lib/redirector.dll
    let redirector_dll_path = lib_dir.join("redirector.dll");
    if force || !redirector_dll_path.exists() {
        fs::write(&redirector_dll_path, EMBEDDED_REDIRECTOR_DLL)
            .map_err(|e| format!("Failed to extract embedded redirector.dll: {}", e))?;
        println!("  ✓ Extracted .ppm/lib/redirector.dll");
    }

    // 5. Initialize .ppm/apps.json
    let apps_json_path = ppm_dir.join("apps.json");
    if force || !apps_json_path.exists() {
        fs::write(&apps_json_path, DEFAULT_APPS_JSON)
            .map_err(|e| format!("Failed to initialize .ppm/apps.json: {}", e))?;
        println!("  ✓ Initialized .ppm/apps.json (Default configuration)");
    }

    // 6. Generate JSON schema (.ppm/apps.schema.json)
    let schema = schemars::schema_for!(AppManifests);
    let schema_json = serde_json::to_string_pretty(&schema)
        .map_err(|e| format!("Failed to serialize schema: {}", e))?;
    let schema_path = ppm_dir.join("apps.schema.json");
    let _ = fs::write(&schema_path, &schema_json);

    // Also update dev manifests/apps.schema.json if manifests/ exists
    let dev_schema = root.join("manifests").join("apps.schema.json");
    if let Some(p) = dev_schema.parent() {
        if p.exists() {
            let _ = fs::write(&dev_schema, &schema_json);
        }
    }

    Ok(())
}
