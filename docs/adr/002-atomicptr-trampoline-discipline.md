# ADR-002: AtomicPtr Trampoline Discipline

**Status**: Accepted

## Context

Hook installation originally stored trampoline function pointers in
`static mut` variables, read and written from `DllMain` and from every
detour invocation. `static mut` access is undefined behavior when shared
across threads (which Windows threads are), requires `unsafe` at every use
site, and defeats the borrow checker's aliasing guarantees.

## Decision

All hook state follows one discipline:

* Every intercepted API's original trampoline lives in an
  `AtomicPtr<c_void>` slot exposed by its boundary module.
* Installation goes through `install_detour`; invocation goes through
  `load_trampoline` — the only two primitives touching the raw pointers.
* All other state uses atomics, `OnceLock`, or thread-locals; the crate
  compiles with zero `static mut`.

## Consequences

* Concurrency is well-defined without a global mutex on the hot path.
* Adding a hook is a mechanical pattern, not an exercise in unsafety
  reasoning.
* Edition-2024 `unsafe` blocks are explicit at each trampoline call.
