# ADR-001: Cargo-Native Artifact Dependency Graph

**Status**: Accepted

## Context

The build previously resolved cross-crate binary artifacts (the `test-probe`
executable consumed by integration tests, and the `redirector.dll` engine asset)
through custom build-script plumbing — locating outputs via `target/` path
heuristics and hand-rolled env-var exports.

## Decision

Adopt Cargo's unstable `bindeps` feature (nightly `nightly-2026-08-26`, pinned in
`rust-toolchain.toml`):

* `test-probe` is declared as a bin-artifact dev-dependency; tests consume it via
  `CARGO_BIN_FILE_TEST_PROBE_test-probe`.
* `redirector` is a cdylib-artifact dependency of `ppm`; the engine embeds the DLL
  via `CARGO_CDYLIB_FILE_REDIRECTOR_redirector`.
* Dev-dependencies are structurally absent from release graphs — the probe never
  leaks into shipped artifacts.

## Consequences

* The dated toolchain pin is the stability contract: `bindeps` is still RFC-pending
  upstream, so any toolchain bump must re-run the full gate battery.
* Artifact env-var naming law (runtime-observed): `CARGO_BIN_FILE_<DEP-UPPER>_<name>`
  / `CARGO_CDYLIB_FILE_<DEP-UPPER>_<name>`, with the dependency segment uppercased
  and hyphenless and the target suffix verbatim.
* No build-script path heuristics survive; the build graph is declarative.
