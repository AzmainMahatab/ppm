# Features

## Portable Virtualization Engine

`ppm` executes Windows applications from any directory (typically a USB drive) as if they
were normally installed — without touching the host operating system. At process attach,
the embedded `redirector.dll` engine enforces five isolation boundaries via Microsoft Detours:

| # | Isolation Boundary | Intercepted APIs | Effect |
| :--- | :--- | :--- | :--- |
| 1 | Registry (Copy-on-Write) | `RegCreateKeyExW`, `RegSetValueExW`, `RegQueryValueExW`, `RegDeleteValueW`, `RegEnumKeyExW`, … | Host registry reads fall through; writes persist to `.ppm/system/registry.json` |
| 2 | Process Spawning | `CreateProcessW` | Child processes are re-injected with the engine and inherit virtualization |
| 3 | Credential Vault | `CredReadW`, `CredWriteW`, `CredDeleteW` | Windows generic credentials persist encrypted to `.ppm/system/credentials.json` |
| 4 | Shell Paths | `SHGetKnownFolderPath`, `GetUserProfileDirectoryW` | Profile, AppData (Local/Roaming) and shell folders resolve into `Home/` |
| 5 | Process Identity | `SetCurrentProcessExplicitAppUserModelID` | Root-scoped identity established proactively; app-initiated calls are re-parented |

## Process Identity & Presentation

* **Root-scoped `AppUserModelID`**: `PPM.Portable.<16-hex root hash>.<app identity>` — derived
  from the canonicalized deployment root, so two deployments of the same app group separately
  on the taskbar and never collide with a host-installed copy.
* **Portable Mode overlay badge**: a background monitor stamps visible top-level windows with
  a drawn 16×16 teal "P" badge via `ITaskbarList3::SetOverlayIcon`, with continuous
  reconciliation as windows appear, hide, and restore.

## Multi-Architecture Package Management

* **Dual-target installs**: native binaries organized per CPU (`Apps/x64/`, `Apps/arm64/`),
  with host-architecture routing via `GetNativeSystemInfo`.
* **Dependency-aware operations**: `install`/`update` resolve the application dependency DAG
  (dependencies installed first, cycles rejected).
* **Broad package support**: zip, 7z (incl. LZMA2), tar, and MSI (embedded and external-CAB
  layouts), with post-install sanitization.
* **Version intelligence**: local versions extracted from PE headers
  (`GetFileVersionInfoW`); remote versions resolved from configurable release endpoints.
* **1-click launchers**: generated root-level `.bat` files for installed applications.

## Deterministic Portable Layout

`.ppm/` (runtime: manifest, schema, virtual hives, engine DLL, cache, logs), `Apps/`
(binaries), `Home/` (user profile) — fully self-contained and relocatable.

## Verification

A live Win32 probe (`test-probe`) exercises every isolation boundary under full injection:
registry CoW round-trip, folder redirection, credential vault round-trip, child-process
re-injection, and the process identity contract. It is wired into the integration test suite
as a Cargo bin-artifact dev-dependency. See [SPEC.md](SPEC.md) for the exact contracts and
[ARCHITECTURE.md](ARCHITECTURE.md) for internals.
