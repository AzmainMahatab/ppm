# Roadmap

Status as of the 2026-10-21 review. Format: `- [ ] R<n> <title> — <what done means>`;
`[ ]` open, `[~]` in progress, `[x]` done, `[-]` dropped (with the reason).

## Where the project stands

- Three crates: `ppm` (CLI + package manager, ~4.1k lines incl. unit tests), `redirector`
  (injected Detours engine, ~6.5k lines), `test-probe` (live boundary probe, ~1.1k lines). Five hooked isolation boundaries:
  registry CoW, process re-injection, credential vault, shell paths, process identity.
- Gates are green: `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`,
  and `cargo test --workspace` (130 tests, including the live e2e injection probe).
- 44 commits of isolation-boundary work (plus this review) are not on `origin/main`, and local
  `main` carries 20 of them unpushed. None of it has shipped.

## Review fixes (this branch)

- [x] R1 Confine manifest and archive paths — `target_dir`, `executable`, `extract_subpath`, `post_install` rules and CAB/MSI entry names can no longer leave their base directory; verified by new unit tests (`core::relpath`, `sanitizer`, `config`) and the full suite.
- [x] R2 Apply `post_install.create_dirs` — the field was accepted by the schema and silently ignored; verified by the extended sanitizer test.
- [x] R3 Deterministic app ordering — `apps` is a `BTreeMap`, so `install all`, `list`, `check`, launchers and `global_env` collection are reproducible; schema drift test still passes.
- [x] R4 `ppm validate` checks references — undefined dependencies fail at load, cycles fail in `validate`; verified by the config test.
- [x] R5 Electron manifest URLs resolve with `Url::join` — verified by `electron_file_references_resolve_against_the_manifest_url`.
- [x] R6 Engine log filter reads `PPM_LOG`, not the host application's `RUST_LOG` — reviewed diff; suite green.
- [x] R7 Drop the unused redirector rlib and stale comment; build script de-duplicated with `rerun-if-changed` — debug and release builds plus full suite green.
- [x] R8 CI installs the toolchain `rust-toolchain.toml` pins — local `rustup toolchain install` verified; the GitHub runs themselves are unverified (see R10).
- [x] R9 Docs corrected — edition badge, nonexistent `init --force` and `ppm.log`, duplicate boundary numbering, unnumbered SPEC sections, broken ADR links, ARCHITECTURE source tree, build prerequisites; reviewed by diff.

## Ship what exists

- [ ] R10 Land the work on `main` — this branch and `fix/isolation-boundary-escapes` merged, pushed, and CI green on GitHub with the new toolchain steps.
- [ ] R11 Prove the release workflow — a draft `workflow_dispatch` release produces x64 and arm64 zips, and the arm64 `ppm.exe` runs `init` and `run` on an arm64 host.
- [ ] R12 Resolve the pending Dependabot GitHub Actions bump — merged or closed.

## Isolation correctness

- [~] R13 Cross-architecture injection — redirector is built per architecture (x64, arm64, x86) and the runner and CreateProcess hooks choose the DLL from the target image's PE machine. Done when an x64 app on an arm64 host launches injected (today's arm64→x64 fallback injects a mismatched DLL and fails) and a 64-bit app's 32-bit child is virtualized instead of refused. x86 half verified 2026-10-21: x86 probe passes every suite as a root app, and x64/x86 probes spawn each other injected (engine log shows both helper routes); ARM64 half implemented and unit-tested (`choose_engine`) but not yet run on an ARM64 host - done with R32 (ADR-007).
- [x] R14 Non-ASCII deployment roots — `DetourCreateProcessWithDllExW` takes an ANSI DLL path but receives UTF-8 bytes; done when the e2e probe passes from a root path containing non-ASCII characters. Verified 2026-10-21: e2e suite passes under `Portable Café`; code-page encoding unit-tested against Windows-1252 literals.
- [x] R15 ANSI and legacy registry entry points — `Reg*A`, `RegOpenKeyW`, `RegSetValueW`, `RegQueryValueW` and friends are covered (hooked or routed through the wide path) with probe assertions; ARCHITECTURE's "known gap" paragraph removed. Verified 2026-10-21: the probe (`suites/registry/ansi.rs`) asserts ANSI writes, deletes, reads, enumerations, `RegQueryInfoKeyA`, and legacy `RegOpenKeyW`/`RegCreateKeyW` handles against the overlay journal and the wide read API; measured before the fix, the ANSI writers reached the real HKCU hive and the ANSI readers and enumerators returned host data only. `cargo test --workspace` passes 169 tests including the x64 and x86 e2e probes; fmt, clippy `-D warnings` and the release build are green.
- [x] R16 ANSI credential entry points — `CredReadA`, `CredWriteA`, `CredDeleteA`, `CredEnumerateA` are clean-roomed like their wide counterparts, with probe coverage. Verified 2026-10-21: the probe proved `CredWriteA` wrote to the real host store (its cleanup removed the entry; `cmdkey` confirms none left); with the hooks, crossed A/W write-read-enumerate-delete passes in the x64 and x86 probes.
- [x] R17 Engine work under the loader lock — logger start-up, file IO and hook installation run inside `DLL_PROCESS_ATTACH`; done when the risk is assessed in an ADR and either deferred safely or justified. Verified 2026-10-21: `advapi32`, `shell32` and `userenv` are static imports (`dumpbin /dependents` lists all three in the x64 and x86 builds); `cargo test --workspace` passes 169 tests including the live e2e probes; assessment in ADR-008.

## Package manager

- [x] R18 MSI fidelity — extraction honours the `Directory` table (today every file lands in the payload root, and same-named files overwrite each other) and reads only the external CABs the `Media` table names (today it extracts every `.cab` in `.ppm/cache`). Verified 2026-10-21: two fixture regressions fail on the old extractor and pass now; real `ppm install antigravity-manager` (WebView2 CAB + MSI) installs and lists as current.
- [x] R19 Download robustness — write to `.part` and rename on completion, verify `Content-Length`, bound mid-transfer stalls, and validate the remote version string before it becomes part of a cache file name. Verified 2026-10-21: downloader and version unit tests, live `ppm check` across all three release strategies.
- [x] R20 CAB failure context — when `expand.exe` fails and the pure-Rust fallback also fails, the error carries both causes instead of dropping the first. Verified 2026-10-21 by diff review and the CAB fixture and live WebView2 install; `expand.exe` output is now captured instead of flooding the console.
- [x] R21 Decide `tar` — implement a tar(.gz) extractor or remove `PackageKind::Tar` from the model and schema. Implemented with `tar` + `flate2`; verified 2026-10-21 by gzip/plain install tests and hostile-entry and link tests.
- [x] R22 Replace `serde_yml` — upstream is archived and flagged by RustSec; move to a maintained YAML parser after checking it with `cargo deny`. Done with `serde-saphyr`; verified 2026-10-21 by `cargo deny check advisories` and a live `ppm check` of the Electron manifest.
- [x] R33 Replace `sevenz-rust` — RUSTSEC-2026-0245 (path traversal in `decompress_impl`, arbitrary file write) on downloaded NSIS payloads, and unmaintained (RUSTSEC-2026-0246). Done with `sevenz-rust2`, decoders only; verified 2026-10-21 by the LZMA2 fixture and a live NSIS install of Antigravity.
- [x] R23 `ppm uninstall <app>` and `ppm clean` — remove an installation and its launcher, and prune `.ppm/cache`. Verified 2026-10-21: removal and launcher unit tests (per-arch removal, dependents refusal, user `.bat` untouched, lookalike folder untouched) and a live uninstall/clean run.
- [x] R24 Decide whether `update` stays — it runs the same cycle as `install` without `--force`; keep one command or give `update` distinct behaviour (only touch installed apps). Decided 2026-10-21 (user): `update` stays separate - `update <app>` / `update --all` refresh only installed apps and never install. Verified: update/install plan unit tests, clap usage `<APP|--all>`.
- [x] R25 Launchers that behave like the app — `.bat` launchers use `start`, so the exit code is lost and console apps detach; launchers for uninstalled apps are never removed. Done when exit codes propagate and stale launchers are cleaned. Verified 2026-10-21: launcher unit tests on built console/GUI fixtures, and a live launcher returned exit 0 and 1 from `ppm run`; app ids are now restricted so they cannot inject batch syntax.
- [x] R26 Typed manifest paths — one `RelativePath` type parsed at deserialization replaces the load-time check plus use-site confinement, with the schema regenerated. Verified 2026-10-21: escaping paths in every path field fail to deserialize (config test); the published schema is unchanged (drift test); full suite green.
- [x] R27 Strict `version_check` variants — restructure like `package` so unknown fields inside a variant are rejected at load, closing the documented serde gap. Verified 2026-10-21: an `asset_patern` typo inside `version_check` is now rejected at load (config test); the regenerated schema denies extra properties per variant; live `ppm check` still resolves all three strategies.

## Observability

- [x] R28 Leveled logging in the CLI — progress and diagnostics go through `tracing` with a console sink and a rotating `.ppm/logs/ppm.log`; tables and other data output stay on stdout. Verified 2026-10-21 live: tables alone on stdout, `-q`, dated ppm log, `ppm run` exit code 7 passed through after the log flush.
- [x] R29 Bounded engine log — `redirector.log` is never rotated, defaults to `redirector=debug`, and is shared by every injected process; done with rotation or retention and an `info` default. Verified 2026-10-21 live: dated `redirector.<date>.log` at info from an injected `cmd.exe`; full suite including the e2e probe.

## Verification and supply chain

- [ ] R30 End-to-end install test — a local HTTPS test server (e.g. WireMock) serves a release, and the test drives check → download → extract → swap-in → launcher generation.
- [~] R31 Supply-chain gate — `cargo deny` (advisories, licences, duplicate versions) runs in CI. `deny.toml` and the CI job exist and `cargo deny check` passes locally; done once the job is green on GitHub (after R10).
- [ ] R32 arm64 CI — tests run on a Windows arm64 runner, not only the cross-compiled release build.

## Side quests

- [ ] S1 Badge monitor polls every 500 ms — `crates/redirector/src/shell/badge.rs` (`start_taskbar_monitor`) re-enumerates windows on a timer; a window event hook (create/show/hide) would end the polling. Seen while assessing R17 (ADR-008).
- [ ] S2 Key creation reaches the host registry — after the e2e suites, the real `HKCU\Software\PPMTestProbe` holds 9 empty keys (`Tree\Child`, `Enumerated\Kept`, `DeleteKeyEx`, `AnsiEntryPoints\legacy_created`, ...) and no values: values are virtualized, but `RegCreateKeyEx*` creates the key on the host. Predates the ANSI work (the original suite's keys are there too). Seen 2026-10-21 reviewing `1264f02`.

## Library candidates

- [ ] L1 Multi-writer JSONL op journal — the registry journal (append-only records, atomic appends across processes, shrink-detecting readers, snapshot compaction) generalizes to any small state shared by cooperating processes without a lock server; candidate only if a second consumer appears.
