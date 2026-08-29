# ADR-004: Reject the Kernel-Object & Window-Discovery Boundary

**Status**: Rejected for inclusion (exploration preserved)

## Context

A fifth interception boundary was explored: namespacing kernel synchronization
objects (mutexes/events/semaphores/file mappings) into per-deployment `Local\`
names, renaming named pipes, filtering window discovery (`FindWindowW`,
`EnumWindows`), dropping cross-window `WM_COPYDATA` payloads, and blocking focus
hijacking. The exploration covered 33 Win32 detours and was fully implemented and
e2e-tested.

## Decision

**Not included in the engine.** The boundary defends against a failure class
(single-instance mutexes and fixed-name IPC colliding between a portable
deployment and a host-installed copy) that no exercised application exhibited.
Notably, Chromium/Electron applications derive their singleton names from the
user-data-dir path — which the shell-path boundary already redirects — so the
largest application family self-resolves without this boundary.

33 speculative detours on an unproven premise do not justify the surface area.

## Consequences

* The complete implementation, including its test suite, is preserved on the
  `explore/sync-isolation` branch for surgical cherry-pick resurrection.
* Resurrection is gated on evidence, per [ADR-005](005-e2e-probe-as-scope-arbiter.md):
  the live e2e probe must demonstrate a contract gap first.
* Consequence for the taskbar monitor: with no window-discovery hooks present,
  the scoped shell-query exemption guard becomes moot and was removed.
