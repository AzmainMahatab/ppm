# ADR-003: Root-Scoped AppUserModelID Namespace

**Status**: Accepted

## Context

Without an explicit identity, Windows groups taskbar windows by executable path
or by whatever `AppUserModelID` the application sets. A portable deployment and a
host-installed copy of the same application therefore merged into one taskbar
group, and the portable instance's identity could be hijacked or ambiguous.
An earlier iteration hardcoded a single fixed identity, which collided across
deployment roots.

## Decision

At DLL attach the engine proactively calls
`SetCurrentProcessExplicitAppUserModelID` with:

```
PPM.Portable.<root-hash-16hex>.<identity>
```

* `root-hash` = FNV-1a-64 over the canonicalized, lowercased deployment root.
* `identity` = the runner-injected application name (`PPM_APP_NAME`), falling
  back to the executable stem.

App-initiated `SetCurrentProcessExplicitAppUserModelID` calls are intercepted and
re-parented into the same `PPM.Portable.<hash>` namespace, preserving the
application's suffix but never letting it escape the deployment scope.

## Consequences

* Two deployment roots of the same application always group separately.
* A host-installed copy and a portable copy never merge.
* Per Microsoft's documentation, an explicit `AppUserModelID` is the only
  guaranteed taskbar grouping mechanism — hence it is established before any
  window exists (proactively at attach, not on first window creation).
* A background monitor stamps visible windows with a Portable Mode overlay badge
  (`ITaskbarList3::SetOverlayIcon`) so users can distinguish portable windows at
  a glance.
