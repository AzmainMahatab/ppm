# Portable Package Manager (`ppm`)

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg)](https://www.rust-lang.org/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows_x64%20%7C%20arm64-blue.svg)](https://microsoft.com)
[![Virtualization: ntdll CoW](https://img.shields.io/badge/Virtualization-ntdll.dll%20Syscalls-green.svg)](#)
[![Isolation: Pre--ALPC Vault](https://img.shields.io/badge/Isolation-Pre--ALPC%20Vault-teal.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

A lightweight, single-binary portable application runner, virtualization engine, and multi-architecture package manager for Windows.

## Features

* **Multi-Architecture Management**: Organizes and runs native binaries for **Intel/AMD x64** (`Apps/x64/`) and **ARM64** (`Apps/arm64/`).
* **Hardware Architecture Routing**: Inspects host CPU architecture on startup via `GetNativeSystemInfo` and launches the matching native application binary.
* **User-Mode Virtualization**:
  * **Dual-Layer Copy-on-Write Registry**: Intercepts Win32 registry APIs (`advapi32.dll` / `kernelbase.dll`) and native NT syscalls (`ntdll.dll`), persisting state to `.ppm/system/registry.json`.
  * **Child Process Injection**: Injects `redirector.dll` across child processes via Microsoft Detours (`CreateProcessW`).
  * **Isolated Credential Vault**: Intercepts `Cred*` APIs (`advapi32.dll`), persisting encrypted credentials to `.ppm/system/credentials.json`.
  * **Shell Path Redirection**: Redirects `FOLDERID_Profile`, `FOLDERID_LocalAppData`, and `FOLDERID_RoamingAppData` (`shell32.dll` / `userenv.dll`) to `Home/`.
* **Dynamic Version Inspection**: Resolves installed versions directly from PE binary headers (`GetFileVersionInfoW`) and package manifests on disk.
* **Isolated User Profile**: Maps user profile directories to the portable `Home/` directory.
* **Deterministic Layout**: Structure organized into `.ppm/` (runtime configs, libraries, logs, and virtual hives), `Apps/` (binaries), and `Home/` (user data).
* **Test Suite & Verification Probe**: Includes `test-probe` CLI binary and comprehensive workspace unit and integration tests (`cargo test --workspace`).

---

## Directory Structure

```
<USB_ROOT>/
├── ppm.exe                             # Master CLI & Runner
├── antigravity.bat                     # Application Launchers
├── antigravity-manager.bat
│
├── .ppm/                               # Engine runtime data
│   ├── apps.json                       # Declarative application manifest
│   ├── apps.schema.json                # Generated JSON Schema
│   │
│   ├── system/                         # Virtual overlays
│   │   ├── registry.json               # Virtual registry hive
│   │   └── credentials.json            # Encrypted credential store
│   │
│   ├── lib/                            # Runtime libraries
│   │   └── redirector.dll              # Injected virtualization library
│   │
│   ├── cache/                          # Download cache
│   │   └── ...
│   │
│   └── logs/                           # Runtime logs
│       ├── ppm.log
│       └── redirector.log
│
├── Apps/                               # Multi-architecture binaries
│   ├── x64/                            # x64 Application Binaries
│   │   ├── Antigravity/
│   │   ├── AntigravityManager/
│   │   └── WebView2/
│   └── arm64/                          # ARM64 Application Binaries
│       ├── Antigravity/
│       └── WebView2/
│
└── Home/                               # User Profile
    ├── AppData/
    │   ├── Local/                      # %LOCALAPPDATA%
    │   ├── Roaming/                    # %APPDATA%
    │   └── WebViewData/                # %WEBVIEW2_USER_DATA_FOLDER%
    ├── Documents/
    └── ...
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

### Building & Testing from Source

```bash
# Compile entire workspace
cargo build --release

# Run full unit and live E2E virtualization test suite
cargo test --workspace
```

**Build Output**: `target/release/ppm.exe`.
