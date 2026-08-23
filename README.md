# Portable Package Manager (`ppm`)

A lightweight, zero-dependency, single-binary portable application runner, virtualization engine, and multi-architecture package manager for Windows.

## Features

* **Universal Multi-Architecture Support**: Organizes and manages native binaries for both **Intel/AMD x64** (`Apps/x64/`) and **Qualcomm Snapdragon / Surface ARM64** (`Apps/arm64/`).
* **Hardware CPU Auto-Detection**: Calls Win32 `GetNativeSystemInfo` on startup to automatically route execution to the native CPU architecture with zero emulation overhead.
* **Shared User Profiles (`Home/`)**: Single user environment (`%USERPROFILE%`, `%HOME%`, `AppData/Local`, `AppData/Roaming`) shared seamlessly across all architectures.
* **100% Native Cargo Build**: Zero external scripts (`build.bat`/`build.ps1`). Compiles into a single ~4.7 MB standalone executable.
* **Windows NT Virtualization**: In-process Win32 API redirection for Shell Folders and Windows Credential Manager without host OS leakage.

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
| `ppm.exe init [--force]` | Scaffolds `Apps/x64/`, `Apps/arm64/`, `Home/`, `.ppm/`, and default `apps.json`. |
| `ppm.exe check [--arch <x64\|arm64\|all>]` | Queries remote release endpoints for the latest versions. |
| `ppm.exe install <app\|all> [--arch <x64\|arm64\|all>]` | Downloads and installs applications, resolving dependency DAGs. |
| `ppm.exe update <app\|all> [--arch <x64\|arm64\|all>]` | Upgrades installed applications to the latest upstream release. |
| `ppm.exe run <app> [args...]` | Auto-detects host architecture and launches app with Detours virtualization. |
| `ppm.exe list [--arch <x64\|arm64\|all>]` | Lists all configured apps and installation status across architectures. |
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

**Output Artifact**: `target/release/ppm.exe`.
