# ADR-008: Engine Work Under the Loader Lock

**Status**: Accepted

## Context

`redirector.dll` installs every isolation boundary in `DllMain(DLL_PROCESS_ATTACH)`, so no
application code runs before its boundaries exist. That work runs with the loader lock held.
Microsoft's DLL best practices forbid, under that lock:

* loading libraries (`LoadLibrary` and anything that pulls in a dependency's initialization),
* waiting on other threads or on events a thread must signal,
* synchronizing with other threads.

The engine broke the first rule: `init_hooks` called `LoadLibraryW` for `advapi32.dll` (registry
and credentials), `shell32.dll` (identity and folders) and `userenv.dll` (folders). Each load ran
the new library's initialization nested inside our attach.

## Decision

**Static imports for the hooked system modules.** `crates/redirector/src/host_modules.rs` makes
`advapi32`, `shell32` and `userenv` static imports of `redirector.dll`. The loader maps and
initializes them before calling `DllMain`, so attach only looks them up with `GetModuleHandleW`,
which takes no loader action. Each import is pinned by taking the address of a function from the
module, read from live code, because a `#[used]` static alone was discarded by the linker
(`/OPT:REF`) and its import never reached the image. Verified with `dumpbin /dependents` on the
x64 and x86 builds, which list all three.

Each remaining attach-time action was assessed against the rule:

| Work under the loader lock | Assessment |
|---|---|
| Hook installation (`registry`, `process`, `credentials`) | Detours patches import tables and in-memory code. Its own calls are to modules already loaded; no library is loaded. Allowed. |
| Identity (`shell/identity.rs`) | One call, `SetCurrentProcessExplicitAppUserModelID` into `shell32`, found by `GetProcAddress`. `shell32` is a static import, so this is a lookup. Safe. |
| Folders (`shell/folders.rs`) | `SHGetKnownFolderPath` and `GetUserProfileDirectoryW` are hooked; both modules are static imports. Safe. |
| Badge monitor (`shell/badge.rs`) | `start_taskbar_monitor` spawns a thread and returns. `DllMain` never waits on it. The thread may hit an implicit DLL load while the attach thread still holds the lock; the attach thread does not wait for it, so no deadlock forms. Safe. |
| Path resolution and directory creation (`paths.rs`) | File-system calls to `kernel32`/`kernelbase`, both already loaded. No library load, no wait on another thread. Allowed. |
| Logger start-up (`paths::init_logger`, `LazyLock` worker guard) | Opens the daily log file and spawns the `tracing-appender` worker. The file write happens on that worker, not under the lock. Allowed. |

**Why not defer these to a later point.** Deferring to first use would let the first intercepted
call run before its boundary is installed, which is the exact window ADR-006 and the DllMain
ordering exist to close. The engine must act before application code, so the remaining attach
work is justified rather than moved.

## Consequences

- `init_hooks` does no `LoadLibrary` call. A new hooked module must be added to
  `host_modules.rs` as a static import, and its entry must reference one function so the linker
  keeps it. `loaded` returns null only for a name outside the engine's imports, a programming
  error that the caller reports (see `host_modules.rs`).
- Side quest S1 (badge monitor polling every 500 ms) has since replaced the polling with window
  event hooks on the same monitor thread; the loader-lock analysis above is unchanged.
