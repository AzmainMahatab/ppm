# Portable Package Manager (`ppm`)

A lightweight, zero-dependency, single-binary portable application runner, virtualization engine, and multi-architecture package manager for Windows.

## Features

* **Universal Multi-Architecture Support**: Organizes and manages native binaries for both **Intel/AMD x64** (`Apps/x64/`) and **Qualcomm Snapdragon / Surface ARM64** (`Apps/arm64/`).
* **Hardware CPU Auto-Detection**: Calls Win32 `GetNativeSystemInfo` on startup to automatically route execution to the native CPU architecture with zero emulation overhead.
* **Lowest-Boundary User-Mode Virtualization**:
  * **`ntdll.dll` Copy-on-Write Registry**: Intercepts NT Native system calls (`NtOpenKeyEx`, `NtCreateKey`, `NtQueryValueKey`, `NtSetValueKey`, `NtDeleteKey`, `NtClose`), saving overrides to `.ppm/system/registry.json` with **zero host registry pollution**.
  * **`kernelbase.dll` Universal Child Injection**: Intercepts `CreateProcessInternalW`, ensuring 100% of child processes, terminals, and workers inherit virtualization.
  * **`advapi32.dll` Pre-ALPC Credential Vault**: Intercepts `Cred*` calls before they can cross into `lsass.exe`, storing encrypted credentials in `.ppm/system/credentials.json`.
  * **`shell32.dll` / `userenv.dll` Shell Paths & Taskbar Badging**: Intercepts `SHGetKnownFolderPath` and renders the in-memory 16x16 ARGB "P" taskbar badge.
* **100% Dynamic Presence-Based Versioning**: Inspects PE binary headers (`GetFileVersionInfoW`) and Electron manifests directly from the disk. **Zero static `state.json` ledger drift**.
* **100% Pure User Profile (`Home/`)**: Zero internal `.ppm` or virtualization files in `Home/`. `Home/` is reserved exclusively for the user's natural `%USERPROFILE%`.
* **Semantic `.ppm/` Directory Layout**: Clear separation of `.ppm/apps.json`, `.ppm/system/`, `.ppm/lib/`, `.ppm/cache/`, and `.ppm/logs/`.
* **100% Native Cargo Build**: Zero external scripts (`build.bat`/`build.ps1`). Compiles into a single ~4.7 MB standalone executable.

---

## Directory Structure

```
<USB_ROOT>/
├── ppm.exe                             # Master CLI & Runner (Single Standalone Binary ~4.7 MB)
├── antigravity.bat                     # 1-Click Launchers (@start "" "%~dp0ppm.exe" run antigravity)
├── antigravity-manager.bat
│
├── .ppm/                               # [PPM INTERNAL MACHINERY & ENGINE DATA]
│   ├── apps.json                       # Declarative application manifest (Root config for easy access)
│   ├── apps.schema.json                # Auto-Generated JSON Schema
│   │
│   ├── system/                         # [VIRTUAL SYSTEM OVERLAYS]
│   │   ├── registry.json               # Virtual Copy-on-Write Registry Hive (Zero Host Writes)
│   │   └── credentials.json            # Virtual Windows Credential Vault (Encrypted)
│   │
│   ├── lib/                            # [INTERNAL ENGINE BINARIES]
│   │   └── redirector.dll              # Injected Win32 Virtualization & Detours Engine
│   │
│   ├── cache/                          # [TEMPORARY DOWNLOAD ARTIFACTS]
│   │   └── (Auto-cleaned temporary download archives during install/update)
│   │
│   └── logs/                           # [DIAGNOSTIC LOG HUB]
│       ├── ppm.log                     # Package Manager & Downloader Log
│       └── redirector.log              # Real-Time Win32 API Interception Trace
│
├── Apps/                               # [TOP-LEVEL MULTI-ARCHITECTURE APPLICATION BINARIES]
│   ├── x64/                            # [INTEL / AMD 64-BIT BINARIES]
│   │   ├── Antigravity/                # Google Antigravity IDE (Antigravity.exe)
│   │   ├── AntigravityManager/         # Antigravity Tools Manager (Antigravity Tools.exe)
│   │   └── WebView2/                   # Microsoft Edge WebView2 (msedge.exe)
│   └── arm64/                          # [QUALCOMM SNAPDRAGON / SURFACE ARM64 BINARIES]
│       ├── Antigravity/                # Native ARM64 Antigravity IDE
│       └── WebView2/                   # Native ARM64 WebView2
│
└── Home/                               # [100% PURE USER PROFILE - ZERO PPM INTERNAL FILES]
    ├── AppData/
    │   ├── Local/                      # %LOCALAPPDATA% (App caches, GPU shaders, LevelDB)
    │   ├── Roaming/                    # %APPDATA% (Antigravity user settings, extensions)
    │   └── WebViewData/                # %WEBVIEW2_USER_DATA_FOLDER%
    ├── Documents/                      # User documents folder
    └── ...                             # User code workspaces, git repos, dotfiles (.gitconfig, .ssh)
```

---

## Quick Start (End Users)

1. Copy **`ppm.exe`** to any directory or the root of a USB flash drive.
2. Initialize the portable environment:
   ```bash
   ppm.exe init
   ```
3. Check and install applications for your current machine:
   ```bash
   # Check available online versions
   ppm.exe check

   # Install all applications for the current host CPU
   ppm.exe install all

   # (Optional) Pre-download both x64 and arm64 binaries for multi-machine portability:
   ppm.exe install all --arch all
   ```
4. Run your applications:
   * Double-click `antigravity.bat` (or run `ppm.exe run antigravity`)
   * Double-click `antigravity-manager.bat` (or run `ppm.exe run antigravity-manager`)

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `ppm.exe init [--force]` | Scaffolds `.ppm/system/`, `.ppm/lib/`, `.ppm/cache/`, `.ppm/logs/`, `Apps/x64/`, `Apps/arm64/`, `Home/`. |
| `ppm.exe check [--arch <x64\|arm64\|all>]` | Queries remote release endpoints for the latest versions. |
| `ppm.exe install <app\|all> [--arch <x64\|arm64\|all>]` | Downloads and installs applications, resolving dependency DAGs. |
| `ppm.exe update <app\|all> [--arch <x64\|arm64\|all>]` | Upgrades installed applications to the latest upstream release. |
| `ppm.exe run <app> [args...]` | Auto-detects host architecture and launches app with lowest-boundary virtualization. |
| `ppm.exe list [--arch <x64\|arm64\|all>]` | Lists all configured apps and dynamic presence status across architectures. |
| `ppm.exe link [app\|all]` | Generates prefix-free 1-click `.bat` root launchers for installed apps. |
| `ppm.exe schema` | Regenerates JSON Schema (`apps.schema.json`) via `schemars`. |
| `ppm.exe validate` | Validates `apps.json` against the schema. |

---

## Developer Documentation

For in-depth architectural diagrams, Win32 Detours hooks matrix, and path invariants, see [ARCHITECTURE.md](ARCHITECTURE.md).

### Building from Source

```bash
git clone --recursive <repo-url>
cargo build --release
```

**Build Output**: `target/release/ppm.exe`.
