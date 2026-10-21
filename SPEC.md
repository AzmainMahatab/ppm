# Specification

Behavioral contracts and invariants. Audience: contributors and integrators.

## 1. Root Resolution Contract

The portable root is resolved with strict precedence:

1. `PPM_ROOT` environment variable, if it names an existing directory.
2. The current working directory, if it carries a portable environment
   (`.ppm/apps.json` or `manifests/apps.json` exists).
3. The executable's directory, walked up from known engine layouts
   (`.ppm`, `Engine`, `lib`, `dist` parents; `release`/`debug` grandparent).

All subsequent paths (`.ppm/`, `Apps/`, `Home/`) are relative to this root.

## 2. Manifest Contract

`apps.json` (deployed at `.ppm/apps.json`, schema at `.ppm/apps.schema.json`)
defines applications:

* Identity: unique app id (map key), display `name`, `target_dir`, `executable`.
* Distribution: `version_check` (remote release endpoint) and `package` (archive type).
* Optional `dependencies` (list of app ids — must be acyclic) and `post_install`.
* Optional per-architecture support restrictions.

`ppm schema` regenerates the JSON Schema via `schemars`; `ppm validate` checks the manifest.

### 2.1 Manifest Strictness and Freshness

- Unknown fields are rejected on every struct level of `apps.json` (`deny_unknown_fields`): typos fail loudly at load time instead of being silently dropped. The exception is the internally tagged `version_check` variants, where serde ignores the attribute; the schema catches those at authoring time.
- Every path a manifest field contributes (`target_dir`, `executable`, `extract_subpath`, `post_install` rules) must be relative and free of `..`, so it cannot leave the directory it is joined onto. Archive entry names are held to the same rule during extraction.
- Every dependency must name a defined application; `ppm validate` also rejects cycles.
- `apps.schema.json` is a derived artifact: generated from the Rust type model by `ppm init`, tracked for editor tooling, and guarded by a drift test - a schema/type mismatch fails the test battery.
- The shipped default config is `manifests/apps.json` itself, embedded into the binary at build time; `ppm init` seeds roots with that exact file.

## 3. Isolation Boundary Contracts

| # | Boundary | Guarantee |
| :--- | :--- | :--- |
| 1 | Registry (CoW) | Host reads fall through unchanged; writes and deletes are virtualized with tombstones into `.ppm/system/registry.jsonl`. A deleted key masks host-only children through ancestor resolution. Enumeration presents one merged listing - host entries minus overlay masks plus overlay additions - and `RegQueryInfoKeyW` reports counts drawn from that same listing. A mutation on a key handle the engine cannot name is refused with `ERROR_INVALID_HANDLE` rather than written through to the host. See 3.3 for durability. |
| 2 | Process Spawning | Every spawned child is re-injected with the engine and inherits all boundaries, through `CreateProcessW`, `CreateProcessA` **and** `CreateProcessAsUserW` - each reaches `CreateProcessInternal*` independently, so all three are intercepted. Injection is fail-fast: if the engine cannot verify a child as injectable (mitigation-policy query failure), cannot inject it, cannot start it, or the engine itself is missing, the spawn fails with the real OS error - a child never runs unvirtualized except when its own mitigation policy (CIG/ACG) forbids injection, in which case it runs in its own sandbox by documented design. `ppm run` applies the same rule to the root launch: a missing engine is an error, never a silent unvirtualized launch. Every process - root or child - is injected with the engine build for the machine it runs as (x86, x64, ARM64), across bitness through a Detours helper; the one combination with no route, an x64 child of an x86 process on an ARM64 host, is refused with `ERROR_NOT_SUPPORTED`. The engine path reaches the loader in the system ANSI code page (or as its 8.3 short name); a root path with neither form is refused with that cause (ADR-007). |
| 3 | Credentials | Credentials are stored in `.ppm/system/credentials.json`, indexed by target name *and* credential type. The host credential store is never written, never deleted from, and never enumerated into the application. See 3.2 for the at-rest representation. |
| 4 | Shell Paths | `FOLDERID_Profile`, `FOLDERID_LocalAppData`, `FOLDERID_RoamingAppData`, `FOLDERID_Documents` resolve under `Home/`. |
| 5 | Process Identity | A root-scoped identity exists from the first instant of process execution; app-initiated identity calls are re-parented into the same namespace. |

### 3.1 Identity Format

```
PPM.Portable.<root-hash-16hex>.<identity>
```

* `root-hash`: FNV-1a-64 over the canonicalized, lowercased deployment root —
  stable across reboots and path-case differences.
* `identity`: application name injected by the runner (`PPM_APP_NAME`), falling
  back to the executable stem.

Two deployment roots therefore never share the same identity, regardless of the
application's own `SetCurrentProcessExplicitAppUserModelID` calls.

### 3.2 Credential Store At Rest

Credential blobs are stored hex-encoded. That is an encoding, **not** encryption: anyone who
can read `.ppm/system/credentials.json` can recover every secret in it.

This follows from the goal rather than from an omission. A store that must decrypt itself on
any machine the volume is plugged into has nowhere to keep a key that an attacker holding the
volume does not also hold. DPAPI would bind the file to one user on one machine and destroy
portability; a key kept beside the ciphertext protects nothing while claiming to.

The guarantee this boundary provides is therefore **isolation, not confidentiality**:
application secrets never reach the host credential manager, and the real user's secrets never
reach the application. Treat the deployment volume itself as the secret.

### 3.3 Registry Durability

`registry.jsonl` is an append-only journal: one JSON record per line, one line per intercepted
mutation, replayed in order at process attach. A record is written with a single append, which
Windows makes atomic with respect to the end of file, so concurrent injected processes interleave
whole records.

Two properties follow, neither of which the previous whole-hive snapshot file could provide:

* A write costs one small append instead of re-serializing the entire hive, so writing n values
  is O(n) rather than O(n squared).
* No writer can erase another writer's data, because no writer rewrites the file. An application
  running a dozen injected processes previously lost whichever keys the last snapshot did not
  happen to contain.

A process adopts other processes' records whenever it writes one of its own, so writers converge.
Reads are served from the in-process hive - a snapshot as of that process's most recent write.

The journal is collapsed to a single `snapshot` record at attach, when it has grown to several
times the size of the snapshot it would collapse to. Exclusivity for that rewrite comes from
opening the file with no sharing, so it never runs beside an appender; a reader whose offset the
rewrite invalidated detects the shrink and replays from the start. A pre-journal `registry.json`
is migrated into the journal's first snapshot record rather than discarded.

### 3.4 Launch Environment Precedence

Highest wins; conflicts resolve case-insensitively, and duplicate keys never reach the child block:
1. Portable core vars - `USERPROFILE`, `HOME`, `LOCALAPPDATA`, `APPDATA`, `PPM_ROOT`, `PPM_APP_NAME`. These are the isolation boundary itself and cannot be redefined by any manifest block.
2. The launching app's `env` block - app-specific values beat global ones.
3. `global_env` blocks from every manifest entry - injected when *any* app launches, so an engine entry (e.g. `webview2`) provisions its SDK variables for all apps from its own block. Values expand the `{root}`, `{home}`, `{arch}` templates. No presence gating: the vars inject as declared; delete the block (or entry) to disable.

## 4. On-Disk Layout Invariants

```
.ppm/apps.json           deployed manifest
.ppm/apps.schema.json   generated schema
.ppm/system/            registry.jsonl (op journal), credentials.json (virtual hives)
.ppm/lib/<machine>/     redirector64.dll + redirector32.dll per 64-bit machine (deployed by init; ADR-007)
.ppm/cache/             download staging
.ppm/logs/              ppm.<date>.log, redirector.<date>.log (daily, 7 kept; filter: PPM_LOG, default info)
Apps/<arch>/<target>/    installed binaries
Home/                    virtualized user profile
```

## 5. Probe & Exit-Code Contract

`test-probe` runs five boundary suites sequentially under full injection:

| Exit code | Meaning |
| :--- | :--- |
| 0 | All five boundary suites passed |
| 1 | Registry suite failure |
| 2 | Shell paths suite failure |
| 3 | Credentials suite failure |
| 4 | Process injection suite failure |
| 5 | Process identity suite failure |

Arbitration depth: the process-identity suite additionally sets an app-requested identity
through the real shell32 export and asserts it is re-parented into the same root-scoped
namespace; the shell-paths suite verifies all four redirected folders and the legacy
`SHGetFolderPathW` CSIDL selector.

Auxiliary modes: `--child` (verify virtualized environment in a spawned child),
`--echo-args` (argument passthrough echo), `--help` (passthrough help).
The integration harness (`e2e_virtualization.rs`) asserts both process success and
that the process identity suite executed.

## 6. Package Trust and Install Atomicity

### 6.1 Trust model

`ppm` treats **the latest release published by the upstream host as authoritative**. There is no
hash pinning and no trust-on-first-use comparison, because an application that resolves to
"latest" has no hash to pin ahead of time: a changed hash is the expected outcome of a new
release, so warning about one would only train the user to ignore the warning.

That leaves the transport as the trust boundary. Downloads are therefore refused unless the URL's
scheme is `https`, since TLS is the only thing authenticating that the bytes came from the host
the manifest names - and the payload is executed afterwards. A manifest pointing at `http://`
fails the download rather than silently degrading to an unauthenticated fetch.

Stated plainly: whoever controls the release endpoint controls what `ppm` installs and runs. Point
the manifest only at endpoints you would trust with code execution.

### 6.2 Install atomicity

An install extracts into a staging directory beside the destination, then swaps it in by rename:
the previous installation is moved aside, the new payload is moved into place, and the retired
copy is deleted. Three consequences follow.

* An update **removes files the new release no longer ships**. Copying the payload over the
  previous installation produced the union of both releases, which is how an application ends up
  loading a module its own release notes say was removed.
* The payload is moved rather than copied byte by byte, so install cost does not scale with the
  size of the payload.
* If the new payload cannot be moved into place, the retired installation is restored before the
  error propagates. If a file in the current installation is open - the application is running -
  the update fails and changes nothing.

## 7. Intentional Non-Goals

Kernel synchronization objects, named pipes, and host window discovery are **not**
intercepted. An exploration of that boundary lives on the `explore/sync-isolation`
branch. Resurrection policy: only if the live e2e probe demonstrates a contract gap
(i.e., a real application exhibits fixed-name single-instance or IPC collisions that
the four path/identity boundaries cannot already resolve). See
[ADR-004](docs/adr/004-reject-kernel-object-and-window-discovery-boundary.md) and
[ADR-005](docs/adr/005-e2e-probe-as-scope-arbiter.md).
