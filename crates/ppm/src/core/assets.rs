// Intention: Embed the redirector engine binary produced by the workspace dependency.
// Why: The cdylib artifact dependency (`artifact = "cdylib"`) makes Cargo build redirector.dll
//      as part of ppm's build graph and export its exact staging path via
//      CARGO_CDYLIB_FILE_REDIRECTOR_redirector - no layout guessing, no build-script race.
pub const EMBEDDED_REDIRECTOR_DLL: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_REDIRECTOR_redirector"));

pub const DEFAULT_APPS_JSON: &str = r#"{
  "$schema": "./apps.schema.json",
  "apps": {
    "antigravity": {
      "name": "Google Antigravity IDE",
      "description": "Next-generation agentic AI development environment",
      "homepage": "https://antigravity.google.com",
      "target_dir": "Antigravity",
      "executable": "Antigravity.exe",
      "version_check": {
        "type": "electron_manifest",
        "url": "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest/latest-{arch}-win.yml"
      },
      "package": {
        "type": "nsis_7z"
      },
      "post_install": {
        "remove_files": [
          "resources/app-update.yml"
        ]
      }
    },
    "antigravity-manager": {
      "name": "Antigravity Tools Manager",
      "description": "Central management console for Antigravity tools and local runtime dependencies",
      "homepage": "https://github.com/lbjlaq/Antigravity-Manager",
      "target_dir": "AntigravityManager",
      "executable": "antigravity_tools.exe",
      "supported_arch": [
        "x64"
      ],
      "dependencies": [
        "webview2"
      ],
      "version_check": {
        "type": "github_release",
        "repo": "lbjlaq/Antigravity-Manager",
        "asset_pattern": ".*_{arch}.*\\.msi"
      },
      "package": {
        "type": "msi"
      }
    },
    "webview2": {
      "name": "Microsoft Edge WebView2 Runtime (Fixed Version)",
      "description": "Embedded WebView2 browser runtime for host-independent portable execution",
      "homepage": "https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
      "target_dir": "WebView2",
      "executable": "msedgewebview2.exe",
      "version_check": {
        "type": "regex_url",
        "url": "https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
        "regex": "https:[^\"'\\s]+?Microsoft\\.WebView2\\.FixedVersionRuntime\\.([0-9\\.]+)\\.{arch}\\.cab",
        "url_template": "{url}"
      },
      "package": {
        "type": "cab"
      }
    }
  }
}"#;
