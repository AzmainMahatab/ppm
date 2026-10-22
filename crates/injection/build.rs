use std::env;
use std::path::PathBuf;

const DETOURS_TRANSLATION_UNITS: &[&str] = &[
    "detours.cpp",
    "modules.cpp",
    "disasm.cpp",
    "image.cpp",
    "creatwth.cpp",
    "disolx86.cpp",
    "disolx64.cpp",
    "disolia64.cpp",
    "disolarm.cpp",
    "disolarm64.cpp",
];

fn main() {
    compile_detours();
}

/// Whether this build compiles for ARM64, from the target Cargo reports to build scripts.
fn target_is_arm64() -> bool {
    env::var("CARGO_CFG_TARGET_ARCH").expect("invariant: cargo sets CARGO_CFG_TARGET_ARCH for build scripts")
        == "aarch64"
}

fn workspace_root() -> PathBuf {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("CARGO_MANIFEST_DIR is not set; this build script must be driven by cargo")
        });

    manifest_dir
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| panic!("Cannot resolve workspace root from '{}'", manifest_dir.display()))
        .to_path_buf()
}

// Intention: Compile the vendored Microsoft Detours C++ translation units into one static
// library. Cargo links it into every artifact that depends on this crate - ppm.exe (root
// launches) and redirector.dll (hooks and child injection) - so Detours is built once per target.
fn compile_detours() {
    let detours_src = workspace_root().join("vendor").join("detours").join("src");
    let mut build = cc::Build::new();
    build.cpp(true);
    build.include(&detours_src);
    for translation_unit in DETOURS_TRANSLATION_UNITS {
        build.file(detours_src.join(translation_unit));
    }
    if target_is_arm64() {
        // Why: Detours injects a 32-bit process from a 64-bit one through a `rundll32` helper,
        //      and DETOURS_OPTION_BITS is what makes it start the 32-bit one from SysWOW64.
        //      detours.h sets it for x64 but not for ARM64, so an ARM64 build started the native
        //      `system32\rundll32.exe`, which cannot load the x86 engine - and `rundll32` still
        //      exits 0, so the x86 process was resumed with no engine at all. ARM64 Windows runs
        //      exactly one 32-bit architecture, x86, from SysWOW64, as x64 Windows does.
        build.define("DETOURS_OPTION_BITS", "32");
    }
    build.compile("detours");

    println!("cargo:rerun-if-changed={}", detours_src.display());
}
