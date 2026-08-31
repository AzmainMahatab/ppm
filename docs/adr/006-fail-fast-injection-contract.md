# ADR-006: Fail-Fast Injection Contract

## Status

Accepted

## Context

Every child process spawned by a virtualized app must run inside the isolation
boundaries (registry CoW, credential vault, portable profile). The original
`CreateProcessW` hook silently degraded to a **plain unvirtualized create** on
every failure path - missing `redirector.dll`, import-table rewrite failure -
with no log line. The mitigation-policy refactor (kernel-truth query replacing
the Chromium string-match bypass) initially added a fourth silent path: a
failed `GetProcessMitigationPolicy` query logged a warning and let the child
run unvirtualized, framed as "fail-safe".

That framing was wrong. For a virtualization engine, an unvirtualized child is
not a degraded-but-acceptable outcome: it writes to the **real** host registry,
reads **real** host credentials, and writes to the **real** user profile. A
boundary that quietly turns itself off on failure is a boundary breach with
extra steps - the same class as the credential-vault and `RegDeleteKeyW` holes
fixed earlier in this effort.

"Crash the host process" is not an available alternative: the check runs inside
an `extern "system"` hook in someone else's process, where deliberate aborts
are the exact disaster class (`STATUS_HEAP_CORRUPTION`) this project spent a
session repairing. The fail-fast form available at an FFI boundary is the API's
own loud-failure contract: **return `FALSE` with the real OS error code**, so
the spawning application observes a failed spawn instead of a boundary breach.

## Decision

1. **Three-state decision, typed.** The pre-boot check on the frozen child
   returns an enum, not a bool:

   - `Permitted` - policies verified clean; the injected child is resumed
     (unless the caller itself requested `CREATE_SUSPENDED`, whose contract is
     preserved).
   - `ForbiddenByPolicy` - Code Integrity Guard (MicrosoftSignedOnly, bit 0 of
     the binary-signature policy) or Arbitrary Code Guard (ProhibitDynamicCode,
     bit 0 of the dynamic-code policy) is active. The child is terminated
     pre-boot and **recreated plainly**: it runs unvirtualized inside its own
     sandbox, which is its isolation. This is the only documented plain path.
   - `Unknown(real_os_error)` - the policy query itself failed. The frozen
     child is terminated and the spawn **fails**: `SetLastError(real_code)` +
     `return FALSE`. No child ever runs outside the sandbox on an unverifiable
     state.

2. **All legacy failure paths fail fast with the real error** - no silent
   unvirtualized children remain:

   | Condition | Error surfaced |
   | :--- | :--- |
   | `redirector.dll` missing at the root | `ERROR_FILE_NOT_FOUND` |
   | Interior NUL in the DLL path | `ERROR_INVALID_PARAMETER` |
   | Detours create returned failure | the create's `last_os_error` |
   | Mitigation-policy query failed | the query's `last_os_error` |

3. **Bit layouts are grounded, not remembered.** The policy bit positions are
   verified against the local Windows SDK `winnt.h` (MicrosoftSignedOnly:
   bit 0; ProhibitDynamicCode: bit 0) and the pinned `windows-sys` type
   definitions, per the standing empirical-verification methodology.

## Alternatives Considered

- **Fail-open to unvirtualized (rejected)** - the pre-existing and initially
  reimplemented behavior. A loudly-logged boundary breach is still a breach;
  the app's children would write to the real host with no signal beyond a log
  line nobody reads until data has already leaked out of the sandbox.
- **Crash the host process (rejected)** - kills the application the user is
  running; violates FFI discipline; the doctrine's own carve-out for hook
  bodies mandates the documented-fallback pattern, and the correct fallback
  for an unverifiable spawn is refusing the spawn, not aborting the host.
- **Retry the policy query (rejected)** - a kernel query failing on a fresh,
  fully-privileged handle is structural (platform capability, handle state),
  not transient; retrying would paper over the condition.
- **Keep the string-match heuristic as a secondary filter (rejected)** - app
  knowledge in the engine; the kernel query supersedes it and generalizes to
  every hardened app.

## Consequences

- Spawns fail loudly when the engine cannot guarantee the boundary; host
  applications observe `CreateProcessW` returning `FALSE` with the real error
  code, which is the documented `CreateProcessW` failure contract.
- On platforms where `GetProcessMitigationPolicy` cannot query these policy
  classes, children will fail to spawn rather than run unvirtualized.
  Strictness over availability - consistent with the manifest-strictness
  decision (ADR-006-adjacent `deny_unknown_fields` work).
- The `ForbiddenByPolicy` path keeps hardened children running (renderers,
  GPU processes, crash handlers) - refusal to inject is not refusal to spawn.
- The policy gap for internally tagged application-level configurations
  (documented in the config module) is unrelated to this contract and remains
  recorded where it lives.
