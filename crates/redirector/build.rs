use std::env;
use std::path::PathBuf;

// Intention: Export Detours' helper entry point from redirector.dll.
// Why: Detours injects a process of the other bitness through `rundll32 <dll>,#1`, so ordinal 1
//      must be `DetourFinishHelperProcess` (exports.def). Detours itself is compiled and linked
//      by the `injection` crate.
fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("invariant: cargo sets CARGO_MANIFEST_DIR for build scripts");
    let exports_def = manifest_dir.join("exports.def");
    println!(
        "cargo:rustc-cdylib-link-arg=/DEF:{}",
        exports_def.to_string_lossy().replace('\\', "/")
    );
    println!("cargo:rerun-if-changed={}", exports_def.display());
}
