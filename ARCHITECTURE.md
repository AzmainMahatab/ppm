# Architecture & Engineering Manual: `ppm` (Portable Package Manager)

This document provides a comprehensive technical overview of the **`ppm` (Portable Package Manager)** virtualization suite.

---

## 1. Executive Summary

`ppm` is a 100% native Rust, zero-dependency master runner and package manager distributed as a **pure single executable (`ppm.exe`)**. It eliminates host file-system pollution, host registry tampering, and process interference by implementing **canonical Windows NT user profile virtualization** combined with **inline API detours** and **declarative package lifecycle management**.

```mermaid
graph TD
    subgraph Single Binary Distribution Product (USB Flash Drive)
        PPM[ppm.exe - Master Binary at Root]
        PPMDir[".ppm/ (redirector.dll, apps.json, logs/)"]
        AppsDir["Apps/ (All Managed Packages & Binaries)"]
        HomeDir["Home/ (%USERPROFILE% / %HOME%)"]
        BatLaunchers["Clean Root .bat Shortcuts (antigravity.bat, antigravity-manager.bat)"]
    end

    PPM -->|ppm init| PPMDir & AppsDir & HomeDir & BatLaunchers
    PPM -->|ppm install <app>| DepResolver[Resolves Dependencies via DAG -> Installs Prereqs First]
    PPM -->|ppm run <app>| Virtualize[Injects .ppm/redirector.dll & Spawns Target App]
    PPM -->|ppm link| BatLaunchers
```

---

## 2. The Minimalist Two-Pillar Directory Model

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
│   ├── Antigravity/                    # Antigravity IDE (Antigravity.exe)
│   ├── AntigravityManager/             # Antigravity Tools Manager (antigravity_tools.exe)
│   └── WebView2/                       # Microsoft Edge WebView2 Fixed Version (msedgewebview2.exe)
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

## 3. Canonical Environment Invariants & Path Mapping

When `ppm run <app>` launches a target process, it applies standard Windows NT user environment block variables before spawning:

| Environment Variable | Canonical Target Path | Engineering Purpose |
| :--- | :--- | :--- |
| `USERPROFILE` & `HOME` | `<root>\Home` | Canonical root user profile on the portable drive |
| `LOCALAPPDATA` | `<root>\Home\AppData\Local` | Local caches and temporary application data |
| `APPDATA` | `<root>\Home\AppData\Roaming` | Roaming configurations and virtual credential store |
| `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` | `<root>\Apps\WebView2` | Points generic Tauri/WebView2 apps to bundled offline runtime in `Apps/` |
| `WEBVIEW2_USER_DATA_FOLDER` | `<root>\Home\AppData\WebViewData` | Isolates WebView2 IndexedDB, cookies, and local cache |
| `ELECTRON_NO_UPDATER` | `1` | Disables automated background desktop setup wizards |
| `PORTABLE_APP` & `PORTABLE_ROOT` | `<root>` | Open-source portable environment invariants |
| `PORTABLE_EXECUTABLE_DIR` | `<root>` | Standard portable executable directory indicator |

*(Custom application environment variables can be declared in `apps.json` via the optional `"env": { "KEY": "VALUE" }` block).*

---

## 4. Virtualization Engine (`crates/redirector`)

`redirector.dll` is injected into target processes before their `main()` entrypoint via `DetourCreateProcessWithDllExW`.

### A. Shell Redirection Layer
Hooks `SHGetKnownFolderPath`, `SHGetFolderPathW`, and `GetUserProfileDirectoryW` via inline function detours (`retour`):
* `FOLDERID_Profile` $\rightarrow$ `<root>\Home`
* `FOLDERID_LocalAppData` $\rightarrow$ `<root>\Home\AppData\Local`
* `FOLDERID_RoamingAppData` $\rightarrow$ `<root>\Home\AppData\Roaming`
* `FOLDERID_Documents` $\rightarrow$ `<root>\Home\Documents`

### B. Unified Credential Virtual Overlay (`advapi32.dll`)
Virtualizes the Windows Credential Manager APIs:
* **`CredWriteW`**: Intercepts credential writes and saves them to `<root>\Home\AppData\Roaming\credentials.json`. Zero host mutations.
* **`CredReadW`**: Reads from `credentials.json`. For generic credentials (`CRED_TYPE_GENERIC`), returns `ERROR_NOT_FOUND` if missing (Clean-Room isolation). For network/domain authentication (Types 2 & 3), safely passes through to OS.
* **`CredDeleteW`**: Deletions only modify `credentials.json` and **never delete anything from the host machine**.
* **`CredFree`**: Safely frees virtualized allocations and forwards native OS allocations.
* **Thread Safety**: Protected by `parking_lot::RwLock` with atomic write-and-rename disk serialization.

### C. Shell Identity & Taskbar Overlay Badging
* **AppUserModelID**: Calls `SetCurrentProcessExplicitAppUserModelID(L"Google.Antigravity.Portable")` on attach to isolate taskbar grouping and notification channels.
* **Badge Icon**: Dynamically builds a crisp 16x16 32-bit ARGB **"P" (Portable)** badge icon in memory via Win32 `CreateIconFromResourceEx`.
* **Window Monitor**: Background daemon thread uses COM `ITaskbarList3::SetOverlayIcon` to attach the badge to every top-level window created by the app.

---

## 5. Master CLI & Package Manager (`crates/ppm`)

### A. Dependency Resolution Engine (DAG)
When `ppm install <app>` (e.g. `ppm install antigravity-manager`) or `ppm run <app>` executes:
1. `ppm` builds a **Directed Acyclic Graph (DAG)** of all required applications.
2. Checks for circular dependencies (fails fast if detected).
3. Evaluates installation status of every prerequisite dependency in topological order.
4. Automatically downloads and installs any missing dependencies (e.g. `webview2`) before installing or launching the target app.

### B. Command Reference Matrix

| Command | Action |
| :--- | :--- |
| **`ppm init [--force]`** | Scaffolds portable directory tree, extracts embedded `.ppm/redirector.dll`, `.ppm/apps.json`, and initial launchers. |
| **`ppm run <app_name \| path> [args...]`** | Validates dependencies, ensures `redirector.dll` is provisioned, sets Win32 environment block, and launches app with Detours & Taskbar badging. |
| **`ppm check`** | Compares local installed versions vs online releases with a formatted terminal status table. |
| **`ppm install <app \| all>`** | Resolves dependency tree, downloads, unpacks, sanitizes applications, and automatically links root `<app>.bat` launchers. |
| **`ppm update <app \| all>`** | Downloads and in-place upgrades outdated applications. |
| **`ppm link [app \| all]`** *(alias: `ppm create-launchers`)* | Generates/refreshes clean root `<app>.bat` shortcuts for installed apps. |
| **`ppm list`** | Displays all configured apps, target paths, dependencies, and install status. |
| **`ppm schema`** | Auto-generates `.ppm/apps.schema.json` directly from Rust data models via `schemars`. |
| **`ppm validate`** | Validates `.ppm/apps.json` against `.ppm/apps.schema.json`. |

---

## 6. Declarative Manifest Contract (`.ppm/apps.json`)

```json
{
  "$schema": "./apps.schema.json",
  "apps": {
    "antigravity": {
      "name": "Google Antigravity IDE",
      "description": "Advanced Agentic Coding IDE",
      "target_dir": "Apps/Antigravity",
      "executable": "Antigravity.exe",
      "default_args": [
        "--user-data-dir=Home/AppData/Roaming/Antigravity"
      ],
      "version_check": {
        "type": "electron_manifest",
        "url": "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest/latest-x64-win.yml",
        "version_key": "version",
        "url_template": "https://storage.googleapis.com/antigravity-public/antigravity-hub/{version}-6512087774658560/windows-x64/Antigravity-x64.exe"
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
      "description": "Account & Workspace Manager for Antigravity",
      "target_dir": "Apps/AntigravityManager",
      "executable": "antigravity_tools.exe",
      "dependencies": [
        "webview2"
      ],
      "version_check": {
        "type": "github_release",
        "repo": "owner/antigravity-tools",
        "asset_pattern": ".*-windows-x64\\.zip"
      },
      "package": {
        "type": "zip"
      }
    },
    "webview2": {
      "name": "Microsoft Edge WebView2 Fixed Version",
      "description": "Embedded WebView2 browser engine for host-independent GUI execution",
      "target_dir": "Apps/WebView2",
      "executable": "msedgewebview2.exe",
      "version_check": {
        "type": "regex_url",
        "url": "https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
        "regex": "Fixed Version\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)",
        "url_template": "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/Microsoft.WebView2.FixedVersionRuntime.{version}.x64.cab"
      },
      "package": {
        "type": "cab"
      }
    }
  }
}
```

---

## 7. Developer Build Workflow

To compile the entire suite and produce the single-binary release artifact:

```bash
# 100% Native Cargo Build
cargo build --release
```

**Build Output**: `target/release/ppm.exe` (~4 MB). This single binary is the only file required for end-user distribution. It self-provisions `.ppm/`, extracts embedded `redirector.dll`, and scaffolds the entire portable environment upon running `ppm.exe init`.
