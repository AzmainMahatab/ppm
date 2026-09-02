# Portable Package Manager (`ppm`)

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg)](https://www.rust-lang.org/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows_x64%20%7C%20arm64-blue.svg)](https://microsoft.com)
[![Virtualization: Win32 CoW](https://img.shields.io/badge/Virtualization-Win32%20Registry%20CoW-green.svg)](#)
[![Isolation: Pre--ALPC Vault](https://img.shields.io/badge/Isolation-Pre--ALPC%20Vault-teal.svg)](#)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

A lightweight, single-binary portable application runner, virtualization engine, and multi-architecture package manager for Windows.

## Features

* **User-Mode Virtualization** — five isolation boundaries enforced via Microsoft Detours:
  Copy-on-Write registry, isolated credential vault, shell known-folder redirection,
  child-process re-injection, and root-scoped process identity (`AppUserModelID` +
  Portable Mode overlay badge).
* **Multi-Architecture Package Management** — x64/arm64 binary organization, host-architecture
  routing, dependency-DAG resolution, PE-header version detection, and zip/7z/CAB/MSI installs.
* **Deterministic Portable Layout** — fully self-contained `.ppm/` + `Apps/` + `Home/` structure.
* **Verified Isolation** — a live Win32 probe exercises every boundary under full injection
  as part of the standard test suite.

The complete capability matrix lives in [FEATURES.md](FEATURES.md).

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
│   │   ├── registry.jsonl              # Virtual registry hive (append-only journal)
│   │   └── credentials.json            # Portable credential store (plaintext at rest)
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
| `ppm.exe install <app\|all> [--arch <x64\|arm64\|all>] [--force]` | Downloads and installs applications, resolving dependency DAGs. An application already at the latest release is left alone, so this doubles as `update`; `--force` reinstalls it regardless. |
| `ppm.exe update <app\|all> [--arch <x64\|arm64\|all>]` | Upgrades installed applications to the latest upstream release — the same cycle `install` runs. |
| `ppm.exe run <app> [args...]` | Auto-detects host architecture and launches app with lowest-boundary virtualization. |
| `ppm.exe list [--arch <x64\|arm64\|all>]` | Lists all configured apps and dynamic presence status across architectures. |
| `ppm.exe link [app\|all]` | Generates prefix-free 1-click `.bat` root launchers for installed apps. |
| `ppm.exe schema` | Regenerates JSON Schema (`apps.schema.json`) via `schemars`. |
| `ppm.exe validate` | Validates `apps.json` against the schema. |

---

## Developer Documentation

* [FEATURES.md](FEATURES.md) — capability overview
* [SPEC.md](SPEC.md) — behavioral contracts & invariants
* [ARCHITECTURE.md](ARCHITECTURE.md) — boundary matrix, interception API map, source tree
* [docs/adr/](docs/adr/) — architecture decision records

### Building & Testing from Source

```bash
# Compile entire workspace
cargo build --release

# Run full unit and live E2E virtualization test suite
cargo test --workspace
```

**Build Output**: `target/release/ppm.exe`.
