# Architecture Manual: `ppm` (Portable Package Manager)

Technical specification and architectural design of the `ppm` virtualization suite.

---

## 1. System Overview

`ppm` is a native Windows application runner and package manager. It implements user profile virtualization, system call detours, and multi-architecture package resolution.

```mermaid
graph TD
    subgraph Distribution["Distribution Layout"]
        PPM["ppm.exe - Master Binary at Root"]
        PPMDir[".ppm/ (apps.json, system/, lib/, cache/, logs/)"]
        HomeDir["Home/ (User Profile)"]
        BatLaunchers["Root .bat Launchers"]

        subgraph AppsStructure["Apps/ Hierarchy"]
            X64Dir["Apps/x64/ (x64 Binaries)"]
            ARM64Dir["Apps/arm64/ (ARM64 Binaries)"]
        end
    end

    PPM -->|ppm init| PPMDir & X64Dir & ARM64Dir & HomeDir & BatLaunchers
    PPM -->|ppm install <app>| DepResolver["Dependency Resolution -> Installs to Apps/<arch>/<target_dir>"]
    PPM -->|ppm run <app>| HostDetect["Architecture Resolution via GetNativeSystemInfo"]
    HostDetect -->|Routes to Apps/<arch>/<target_dir>| Virtualize["Injects .ppm/lib/redirector.dll & Spawns Application"]
    PPM -->|ppm link| BatLaunchers
```

---

## 2. Directory Layout

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

## 3. User-Mode Virtualization Matrix (`redirector.dll`)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   VIRTUALIZATION BOUNDARIES                             │
├──────────────────────┬───────────────────────────────┬─────────────────────────────────┤
│ Subsystem            │ Interception Boundary         │ Scope & Target DLL              │
├──────────────────────┼───────────────────────────────┼─────────────────────────────────┤
│ 1. Registry (CoW)    │ kernelbase.dll / advapi32.dll │ Win32 Application Registry APIs │
│ 2. Process Spawning  │ kernelbase.dll / kernel32.dll │ CreateProcessW                  │
│ 3. Credentials       │ advapi32.dll                  │ CredReadW / CredWriteW / Delete │
│ 4. Shell Paths       │ shell32.dll + userenv.dll     │ Known Folders / Profile Paths   │
│ 5. Taskbar Identity  │ shell32.dll                   │ SetCurrentProcessExplicitAppId  │
└──────────────────────┴───────────────────────────────┴─────────────────────────────────┘
```

| Target API | Interception Layer | Virtualization Function |
| :--- | :--- | :--- |
| **`RegOpenKeyExW`** | `kernelbase.dll` / `advapi32.dll` | Normalizes registry paths (`HKCU\...`, `HKLM\...`); tracks handle in `VirtualHandleTable`. |
| **`RegCreateKeyExW`** | `kernelbase.dll` / `advapi32.dll` | Creates key in virtual overlay; registers handle in `VirtualHandleTable`. |
| **`RegQueryValueExW`** | `kernelbase.dll` / `advapi32.dll` | Queries virtual overlay and tombstones; falls back to host OS for unshadowed reads. |
| **`RegSetValueExW`** | `kernelbase.dll` / `advapi32.dll` | Stores typed value in memory and atomically persists to `.ppm/system/registry.json`. |
| **`RegDeleteValueW` / `RegDeleteKeyW`** | `kernelbase.dll` / `advapi32.dll` | Records tombstones in virtual store, masking host values. |
| **`RegCloseKey`** | `kernelbase.dll` / `advapi32.dll` | Cleans up handles in `VirtualHandleTable`. |
| **`CreateProcessW`** | `kernelbase.dll` / `kernel32.dll` | Injects `redirector.dll` into spawned child processes via Microsoft Detours. |
| **`CredReadW`, `CredWriteW`, `CredDeleteW`** | `advapi32.dll` | Intercepts credentials and persists to encrypted `.ppm/system/credentials.json`. |
| **`SHGetKnownFolderPath`** | `shell32.dll` | Redirects `FOLDERID_Profile`, `FOLDERID_LocalAppData`, `FOLDERID_RoamingAppData`, `FOLDERID_Documents` to `<root>\Home\...`. |
| **`GetUserProfileDirectoryW`** | `userenv.dll` | Returns `<root>\Home` as user profile directory. |
| **`SetCurrentProcessExplicitAppUserModelID`** | `shell32.dll` | Proactively sets a root-scoped identity (`PPM.Portable.<root-hash>.<App>`) during DLL attach, and maps app-initiated calls into the same isolated domain. |
Kernel synchronization objects, named pipes, and host window discovery are intentionally **not**
intercepted. An exploration of that boundary (33 additional Win32 detours) is preserved on the
`explore/sync-isolation` branch and can be resurrected if a real application exhibits fixed-name
single-instance or IPC collisions.

---

## 4. Version Resolution Engine

`ppm` inspects local executables on disk dynamically without maintaining intermediate state files:

```mermaid
graph TD
    Inspect["AppDefinition.executable_for_arch"] --> Exists{File exists on disk?}
    Exists -->|No| NotInstalled["Status: NOT INSTALLED"]
    Exists -->|Yes| Win32PE["Query Win32 GetFileVersionInfoW & VerQueryValueW"]
    Win32PE -->|Found VS_VERSIONINFO| ReadPE["Extract ProductVersion from PE Header"]
    Win32PE -->|No PE Header| PkgJson["Inspect resources/app/package.json"]
    PkgJson -->|Found| ReadPkg["Read version field"]
    PkgJson -->|Not Found| FoundFallback["Status: INSTALLED"]
```

---

## 5. Source Tree Layout

### A. `crates/redirector/src/`
```
crates/redirector/src/
├── lib.rs                          # DLL Entrypoint & Hook Orchestration
├── paths.rs                        # Path Resolution (Home/, .ppm/logs/, .ppm/system/)
├── detour.rs                       # Microsoft Detours FFI Wrapper
│
├── registry/                       # Registry Virtualization
│   ├── mod.rs                      # Registry module export & initialization
│   ├── store.rs                    # In-Memory Hive & Atomic JSON Persistence (.ppm/system/registry.json)
│   ├── handle_table.rs             # Virtual Handle Table & Pseudo-Handle Mapping
│   └── hooks.rs                    # Win32 (KernelBase / advapi32) Detour Hooks
│
├── process/                        # Process Virtualization
│   ├── mod.rs                      # Process module export & initialization
│   └── hooks.rs                    # CreateProcessW Detour Hook
│
├── credentials/                    # Credential Store Virtualization
│   ├── mod.rs                      # Credentials module export & initialization
│   ├── vault.rs                    # Encrypted Credential Vault (.ppm/system/credentials.json)
│   └── hooks.rs                    # Cred* API Detours
│
└── shell/                            # Shell & Profile Virtualization
    ├── mod.rs                        # Shell module export & initialization
    ├── folders.rs                    # SHGetKnownFolderPath, GetUserProfileDirectoryW
    └── taskbar.rs                    # AUMID Identity, Overlay Badge Monitor
```

### B. `crates/ppm/src/`
```
crates/ppm/src/
├── main.rs                         # CLI Entrypoint & Subcommand Dispatch
│
├── core/                           # Core Domain
│   ├── mod.rs
│   ├── arch.rs                     # CpuArch, ArchTarget & Win32 CPU Detection (GetNativeSystemInfo)
│   ├── config.rs                   # AppManifests, AppDefinition (serde/schemars)
│   └── assets.rs                   # Embedded redirector.dll & default apps.json
│
├── engine/                         # Engine Domain
│   ├── mod.rs
│   ├── init.rs                     # Workspace Scaffolding (.ppm/, Apps/, Home/)
│   ├── runner.rs                   # Process Execution & Win32 Argument Quoting
│   └── launcher.rs                 # Launcher Script Generator
│
└── package/                        # Package Domain
    ├── mod.rs
    ├── pe_info.rs                  # PE Version Header Extractor (GetFileVersionInfoW)
    ├── version.rs                  # Version Resolution & Update Checking
    ├── downloader.rs               # HTTP Downloader with Progress Reporting
    ├── extractor.rs                # Archive Extractor (7z, Zip, Tar, MSI)
    └── sanitizer.rs                # Post-Install Cleanup
```

### C. Verification Probe & Integration Tests
```
crates/test-probe/                  # Isolated probe package (bin-artifact dev-dependency of ppm)
└── src/main.rs                     # Verifies Registry, Shell, Vault, Injection & Taskbar Identity

crates/ppm/tests/
└── e2e_virtualization.rs           # Integration test consuming the probe via CARGO_BIN_FILE_* edge
```

The toolchain is pinned to a dated nightly in `rust-toolchain.toml`; `.cargo/config.toml` opts into
the `bindeps` unstable feature that enables the bin-artifact dependency edge above.

---

## 6. Build & Test Workflow

```bash
# Run unit and integration test suite (probe builds automatically as a bin-artifact dev-dependency)
cargo test --workspace

# Run static analysis and clippy lints
cargo clippy --workspace --all-targets

# Compile release binaries (dev-dependencies absent from release graphs - probe never leaks)
cargo build --release
```

**Build Output**: `target/release/ppm.exe`.
