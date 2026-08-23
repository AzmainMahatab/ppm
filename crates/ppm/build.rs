use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.join("../..");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest_dll = out_dir.join("redirector.dll");

    // 1. Compile Microsoft Detours
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
    build.compile("detours");

    // 2. Ensure redirector.dll is built and embedded into ppm.exe
    let release_redirector = workspace_root.join("target").join("release").join("redirector.dll");

    // Auto-invoke cargo to build redirector.dll if missing
    if !release_redirector.exists() {
        let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let _ = Command::new(cargo)
            .current_dir(&workspace_root)
            .args(["build", "--release", "-p", "redirector"])
            .status();
    }

    if release_redirector.exists() {
        let _ = fs::copy(&release_redirector, &dest_dll);
    } else {
        // Fallback stub for initial compiler check passes
        if !dest_dll.exists() {
            let _ = fs::write(&dest_dll, b"");
        }
    }

    println!("cargo:rerun-if-changed=../../vendor/detours/src");
    println!("cargo:rerun-if-changed=../../crates/redirector/src");
    println!("cargo:rerun-if-changed=../../target/release/redirector.dll");
}
