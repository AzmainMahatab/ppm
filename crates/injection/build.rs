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
    build.compile("detours");

    println!("cargo:rerun-if-changed={}", detours_src.display());
}
