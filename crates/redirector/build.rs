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
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("invariant: cargo sets CARGO_MANIFEST_DIR for build scripts");
    let workspace_root = manifest_dir.join("../..");

    let detours_src = workspace_root.join("vendor").join("detours").join("src");
    let mut build = cc::Build::new();
    build.cpp(true);
    build.include(&detours_src);
    for translation_unit in DETOURS_TRANSLATION_UNITS {
        build.file(detours_src.join(translation_unit));
    }
    build.compile("detours_redirector");

    let exports_def = manifest_dir.join("exports.def");
    println!(
        "cargo:rustc-cdylib-link-arg=/DEF:{}",
        exports_def.to_string_lossy().replace('\\', "/")
    );
    println!("cargo:rerun-if-changed={}", detours_src.display());
    println!("cargo:rerun-if-changed={}", exports_def.display());
}
