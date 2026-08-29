# ADR-005: E2E Probe as the Scope Arbiter

**Status**: Accepted

## Context

Features are easy to add and hard to remove once speculative code accretes.
The project is in a high-prototype phase where breaking changes are acceptable,
but silent scope growth is not.

## Decision

The live e2e probe is the single arbiter of engine scope:

* Every shipped boundary must have a probe suite asserting its contract under
  full injection (registry CoW, shell paths, credentials, injection, identity).
* The suite must assert outcomes, not implementation: e.g. the identity suite
  validates the structural `PPM.Portable.<16-hex>.<identity>` contract via
  `GetCurrentProcessExplicitAppUserModelID`, not the hashing internals.
* A boundary may only be re-introduced (e.g. from the `explore/sync-isolation`
  branch) if the probe demonstrates a contract gap that existing boundaries
  cannot resolve — never speculatively.
* Engine code has no test doubles for platform behavior; verification runs
  against real Win32.

## Consequences

* Minimal surface by construction: unverifiable code cannot enter the engine.
* Regression safety: a silent contract breakage fails the suite with a
  suite-specific exit code, not a generic error.
* Documentation stays honest: [SPEC.md](../../SPEC.md) contracts are exactly what
  the probe enforces.
