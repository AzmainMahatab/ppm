# Features

## Portable Virtualization Engine

`ppm` executes Windows applications from any directory (typically a USB drive) as if they
were normally installed — without touching the host operating system. At process attach,
the embedded `redirector.dll` engine enforces five isolation boundaries via Microsoft Detours:

| # | Isolation Boundary | Intercepted APIs | Effect |
| :--- | :--- | :--- | :--- |
| 1 | Registry (Copy-on-Write) | `RegOpenKeyExW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegGetValueW`, `RegSetValueExW`, `RegDeleteValueW`, `RegDeleteKeyW`, `RegDeleteKeyExW`, `RegDeleteTreeW`, `RegEnumKeyExW`, `RegEnumValueW`, `RegQueryInfoKeyW`, `RegOpenCurrentUser`, `RegCloseKey` | Host registry reads fall through; writes and deletes are virtualized into the append-only `.ppm/system/registry.jsonl` journal - O(1) per write, and no injected process can erase another's keys - with tombstones resolved through ancestors so a deleted key hides host-only children. Enumeration merges the host listing with the overlay, so an application sees its own writes and never sees what it deleted |
| 2 | Process Spawning | `CreateProcessW`, `CreateProcessA`, `CreateProcessAsUserW` | Child processes are re-injected with the engine and inherit virtualization. All three entry points are hooked because each reaches `CreateProcessInternal*` independently. Injection is policy-gated (CIG/ACG kernel query) and fail-fast - an unverifiable policy, a failed injection or a failed resume refuses the spawn with the real error instead of running an unvirtualized child. `ppm run` refuses the root launch the same way when the engine is missing |
| 3 | Credential Vault | `CredReadW`, `CredWriteW`, `CredDeleteW`, `CredEnumerateW`, `CredFree` | Credentials persist to `.ppm/system/credentials.json`, indexed by target *and* type. Plaintext at rest by design - see [SPEC.md](SPEC.md) §3. Reads, deletes and enumerations never touch or reveal the host credential store |
| 4 | Config-Driven Environment | `apps.json` `env` (per-app) and `global_env` (any-launch) blocks with `{root}`/`{home}`/`{arch}` templates; core portable vars shielded from redefinition |
| 5 | Shell Paths | `SHGetKnownFolderPath`, `GetUserProfileDirectoryW` | Profile, AppData (Local/Roaming), Documents and shell folders resolve into `Home/` |
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
  (dependencies installed first, cycles rejected). Both run the same cycle: an application
  already at the latest release is skipped, so `install` doubles as `update`, and `--force`
  reinstalls regardless. One application failing does not strand the rest, and the command
  reports that failure instead of exiting successfully with nothing done.
* **Atomic installs**: the payload is staged beside the destination and swapped in by rename,
  so an update deletes files the new release dropped instead of merging two versions, and a
  failed swap restores the previous installation. Downloads require HTTPS - see
  [SPEC.md](SPEC.md) section 6 for the trust model.
* **Broad package support**: zip, 7z (incl. LZMA2, and NSIS-embedded payloads), CAB, and MSI
  (embedded and external-CAB layouts), with post-install sanitization. A `tar` package type is
  accepted by the manifest schema but has no extractor in this build and fails loudly.
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
