# Architecture & Engineering Manual: `ppm` (Portable Package Manager)

This document provides a comprehensive technical overview of the **`ppm` (Portable Package Manager)** virtualization suite.

---

## 1. Executive Summary

`ppm` is a 100% native Rust, zero-dependency master runner and multi-architecture package manager distributed as a **pure single executable (`ppm.exe`)**. It eliminates host file-system pollution, host registry tampering, and process interference by implementing **canonical Windows NT user profile virtualization** combined with **inline API detours** and **declarative multi-architecture package management**.

```mermaid
graph TD
    subgraph Single Binary Distribution Product (USB Flash Drive)
        PPM[ppm.exe - Master Binary at Root]
        PPMDir[".ppm/ (redirector.dll, apps.json, logs/)"]
        HomeDir["Home/ (Shared %USERPROFILE% & %HOME% for all architectures)"]
        BatLaunchers["Clean Root .bat Shortcuts (antigravity.bat, antigravity-manager.bat)"]

        subgraph Apps/ Top-Level Architecture
            X64Dir["Apps/x64/ (Intel / AMD 64-bit Binaries)"]
            ARM64Dir["Apps/arm64/ (Snapdragon / Surface ARM64 Binaries)"]
        end
    end

    PPM -->|ppm init| PPMDir & X64Dir & ARM64Dir & HomeDir & BatLaunchers
    PPM -->|ppm install <app>| DepResolver[Resolves Dependencies via DAG -> Installs to Apps/arch/target_dir]
    PPM -->|ppm run <app>| HostDetect[Detects Host CPU via GetNativeSystemInfo]
    HostDetect -->|Routes to Apps/host_arch/target_dir| Virtualize[Injects .ppm/redirector.dll & Spawns Target App]
    PPM -->|ppm link| BatLaunchers
```

---

## 2. The Multi-Architecture Directory Model

Every path is calculated dynamically relative to the drive root where `ppm.exe` resides:

```
<USB_ROOT>/
├── ppm.exe                             # Master CLI & Virtualized Runner (Single Binary)
├── antigravity.bat                     # 1-Click IDE Shortcut (@start "" "%~dp0ppm.exe" run antigravity)
├── antigravity-manager.bat             # 1-Click Manager Shortcut (@start "" "%~dp0ppm.exe" run antigravity-manager)
│
├── .ppm/                               # [INTERNAL TOOL ASSETS, CONFIG & LOGS]
│   ├── redirector.dll                  # Native API Detours & Badging Hook
│   ├── apps.json                       # Declarative Application Manifest
│   ├── apps.schema.json                # Auto-Generated JSON Schema (via schemars)
│   ├── state.json                      # Local installation state ledger
│   └── logs/                           # [PPM TOOL DIAGNOSTIC LOGS HUB]
│       ├── ppm.log                     # Package Manager & Downloader Log
│       └── redirector.log              # Real-Time Win32 API Interception Trace
│
├── Apps/                               # [ALL MANAGED PACKAGES & BINARIES]
│   ├── x64/                            # [INTEL / AMD 64-BIT ARCHITECTURE]
│   │   ├── Antigravity/                # Google Antigravity IDE (Antigravity.exe)
│   │   ├── AntigravityManager/         # Antigravity Tools Manager (Antigravity Tools.exe)
│   │   └── WebView2/                   # Microsoft Edge WebView2 Fixed Version (msedge.exe)
│   └── arm64/                          # [QUALCOMM SNAPDRAGON / SURFACE ARM64 ARCHITECTURE]
│       ├── Antigravity/                # Native ARM64 Antigravity IDE
│       └── WebView2/                   # Native ARM64 WebView2 Browser Engine
│
└── Home/                               # [CANONICAL PORTABLE USER PROFILE: %USERPROFILE% & %HOME%]
    ├── AppData/
    │   ├── Local/                      # %LOCALAPPDATA% (Caches, local app data)
    │   ├── Roaming/                    # %APPDATA% (Roaming configs)
    │   │   └── credentials.json        # Virtualized Windows Credential Vault
    │   └── WebViewData/                # %WEBVIEW2_USER_DATA_FOLDER% (IndexedDB, cookies)
    ├── Documents/                      # Standard user documents folder
    └── ...                             # User dotfiles (.gitconfig, .ssh), projects, and code workspaces
```

---

## 3. Host Architecture Auto-Detection & Routing

When `ppm.exe run <app>` or a `.bat` launcher executes:
1. `ppm.exe` invokes Win32 `GetNativeSystemInfo()` to inspect `SYSTEM_INFO.wProcessorArchitecture`.
2. It detects if the physical machine is `PROCESSOR_ARCHITECTURE_ARM64 (12)` or `PROCESSOR_ARCHITECTURE_AMD64 (9)`, even when running under emulation.
3. Automatically routes the spawn target to `Apps/<host_arch>/<target_dir>/<executable>`.
4. Sets `%WEBVIEW2_BROWSER_EXECUTABLE_FOLDER%` pointing to `Apps/<host_arch>/WebView2` if present.

---

## 4. Win32 API Interception & Virtualization Matrix (`redirector.dll`)

| Target Win32 API | Interception Strategy | Portable Redirection Target |
| :--- | :--- | :--- |
| `SHGetKnownFolderPath` | Inline Detour Hook (`retour`) | Redirects `FOLDERID_Profile`, `FOLDERID_LocalAppData`, `FOLDERID_RoamingAppData`, `FOLDERID_Documents` to `<root>\Home\...` |
| `SHGetFolderPathW` | Inline Detour Hook (`retour`) | Redirects `CSIDL_PROFILE`, `CSIDL_LOCAL_APPDATA`, `CSIDL_APPDATA`, `CSIDL_PERSONAL` to `<root>\Home\...` |
| `GetUserProfileDirectoryW` | Inline Detour Hook (`retour`) | Writes `<root>\Home` into the destination buffer |
| `CredReadW` | Win32 Hook | Reads credentials from `<root>\Home\AppData\Roaming\credentials.json` |
| `CredWriteW` | Win32 Hook | Encrypts & persists credentials into `<root>\Home\AppData\Roaming\credentials.json` |
| `CredDeleteW` | Win32 Hook | Deletes key from `<root>\Home\AppData\Roaming\credentials.json` |
| `SetCurrentProcessExplicitAppUserModelID` | Win32 Hook | Forces AppUserModelID to `Google.Antigravity.Portable` |

---

## 5. Declarative Multi-Arch Manifest (`apps.json`)

```json
{
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
        "url": "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest/latest-{arch}-win.yml",
        "url_template": "https://storage.googleapis.com/antigravity-public/antigravity-hub/{version}-6512087774658560/windows-{arch}/Antigravity-{arch}.exe"
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
      "executable": "Antigravity Tools.exe",
      "supported_arch": [
        "x64"
      ],
      "dependencies": [
        "webview2"
      ],
      "version_check": {
        "type": "github_release",
        "repo": "lbjlaq/Antigravity-Manager",
        "asset_pattern": ".*_{arch}-setup\\.exe"
      },
      "package": {
        "type": "nsis_7z"
      }
    },
    "webview2": {
      "name": "Microsoft Edge Enterprise Runtime",
      "description": "Embedded WebView2 browser engine for host-independent GUI execution",
      "homepage": "https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
      "target_dir": "WebView2",
      "executable": "msedge.exe",
      "version_check": {
        "type": "json_api",
        "url": "https://edgeupdates.microsoft.com/api/products?view=enterprise",
        "version_key": "/0/Releases[Platform=Windows,Architecture={arch}]/ProductVersion",
        "url_key": "/0/Releases[Platform=Windows,Architecture={arch}]/Artifacts/0/Location"
      },
      "package": {
        "type": "cab"
      }
    }
  }
}
```

---

## 6. Developer Build Workflow

To compile the entire suite and produce the single-binary release artifact:

```bash
# 100% Native Cargo Build
cargo build --release
```

**Build Output**: `target/release/ppm.exe` (~4.7 MB). This single binary is the only file required for end-user distribution. It self-provisions `.ppm/`, extracts embedded `redirector.dll`, and scaffolds the entire portable multi-architecture environment upon running `ppm.exe init`.
