# ADR-007: Per-Machine Engine Builds and One Shared Injection Path

**Status**: Accepted

## Context

The engine shipped as one `redirector.dll`, built for `ppm`'s own target, and every injection
site handed Detours that one file:

* A 64-bit application's 32-bit child (installers, helpers, legacy tools) cannot load a 64-bit
  DLL, and a 64-bit Detours cannot patch a 32-bit process at all. Every such spawn was refused
  under ADR-006's fail-fast rule - correctly, but it made 32-bit children impossible.
* On an ARM64 host, `ppm run` falls back to an installed x64 build of an application, which runs
  emulated and can only load x64 DLLs. The ARM64 engine was injected into it, so the launch failed.
* The DLL path was passed to Detours as UTF-8. Import-table names are decoded with the system
  ANSI code page, so any portable root with a non-ASCII character in its path failed every launch.
* `ppm`'s runner and the engine's three `CreateProcess*` hooks each carried their own injection
  code, and `ppm` and `redirector` each compiled Detours separately.

## Decision

* **One engine per machine, in Detours' layout.** `.ppm/lib/<machine>/redirector64.dll` is the
  64-bit engine for `<machine>` (`x64`, `arm64`) and `redirector32.dll` beside it is the x86
  engine. The names are Detours' contract: to reach a process of the other bitness it starts a
  `rundll32` of that bitness, which loads the injector's DLL name with `64.` swapped for `32.`
  (or the reverse) from the same folder and runs its ordinal-1 export,
  `DetourFinishHelperProcess`. Each build embeds the engines its host can need: x64 builds embed
  x64 and x86; ARM64 builds also embed x64 for emulated applications.
* **The child's machine decides.** Every injection site creates the process suspended, asks the
  kernel which machine it runs as (`GetProcessInformation(ProcessMachineTypeInfo)`, falling back to
  `IsWow64Process2` on Windows 10, which has no x64 emulation), and picks file and route with a
  pure function, `injection::choose_engine`: a 64-bit child gets its own machine's engine, an x86
  child the host folder's x86 engine, directly when the bitness matches and through the helper
  when it does not.
* **One crate owns injection.** `crates/injection` compiles Detours once per target, declares its
  API (`extern "system"`, which is stdcall on x86), and implements machine detection, engine
  selection and `inject_suspended`. `ppm` and `redirector` both use it. The engine hooks all
  follow one sequence - create suspended, mitigation-policy gate (ADR-006), inject, resume - so a
  hardened child is simply started uninjected instead of being terminated and created again.
* **ANSI, or a clear refusal.** The DLL path is encoded in the system ANSI code page without
  best-fit substitution; when it has no exact form there, the 8.3 short path is tried; when that
  fails too, the launch is refused with an error naming the cause.
* **Helper processes stay inert, injected processes are restored.** `DllMain` returns at once in a
  Detours helper (`DetourIsHelperProcess`), and calls `DetourRestoreAfterWith` everywhere else, as
  Detours requires of every DLL it injects.

## Consequences

* 32-bit applications and 32-bit children run virtualized; this is verified live by an x86 build
  of the probe that runs every suite as a root application and is spawned as a child of the
  64-bit probe (and spawns it in turn).
* x64-on-ARM64 selection is covered by unit tests of `choose_engine` and runs live on the ARM64 CI
  runner (ROADMAP R32), including an emulated x64 probe and x86 children of ARM64 parents.
* Detours' own success is not taken as proof of injection: its `rundll32` helper exits 0 even
  when it cannot load the engine, which once resumed x86 children with no engine on ARM64. After
  injecting, `inject_suspended` looks for the restore payload Detours writes into the child once
  its import table is patched (`DetourFindRemotePayload`) and refuses the spawn when it is
  missing. A 32-bit injector cannot read a 64-bit child's memory above 4 GiB, so that route
  still relies on the helper's exit code (ROADMAP S5).
* An x86 process cannot inject an x64 child on an ARM64 host: Detours' helper for a 64-bit target
  is the host's native `rundll32`, which cannot load the x64 engine. Such a spawn is refused with
  `ERROR_NOT_SUPPORTED`.
* A root path with no ANSI form and no 8.3 short name cannot be used; the error says so.
* Building needs the `i686-pc-windows-msvc` target (pinned in `rust-toolchain.toml`) and the MSVC
  x86 compiler; ARM64 release builds also compile the x64 engine.
* Cargo allows one dependency edge per package, so each extra engine build (and the x86 probe) is
  reached through a one-line crate (`engine-x86`, `engine-x64`, `probe-x86`) that declares the
  artifact dependency for its target.
