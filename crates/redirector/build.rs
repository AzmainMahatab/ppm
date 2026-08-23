use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.join("../..");

    // 1. Compile Microsoft Detours C/C++ source
    let detours_src = workspace_root.join("vendor").join("detours").join("src");
    let mut build = cc::Build::new();
    build.cpp(true);
    build.include(&detours_src);
    build.file(detours_src.join("detours.cpp"));
    build.file(detours_src.join("modules.cpp"));
    build.file(detours_src.join("disasm.cpp"));
    build.file(detours_src.join("image.cpp"));
    build.file(detours_src.join("creatwth.cpp"));
    build.file(detours_src.join("disolx86.cpp"));
    build.file(detours_src.join("disolx64.cpp"));
    build.file(detours_src.join("disolia64.cpp"));
    build.file(detours_src.join("disolarm.cpp"));
    build.file(detours_src.join("disolarm64.cpp"));
    build.compile("detours_redirector");

    println!(
        "cargo:rustc-cdylib-link-arg=/DEF:{}/exports.def",
        manifest_dir.to_string_lossy().replace('\\', "/")
    );
}
