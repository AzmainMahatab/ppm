use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.join("../..");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest_dll = out_dir.join("redirector.dll");
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

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

    // 2. Locate built redirector.dll from target directory
    let target_redirector = workspace_root.join("target").join(&profile).join("redirector.dll");
    let release_redirector = workspace_root.join("target").join("release").join("redirector.dll");
    let debug_redirector = workspace_root.join("target").join("debug").join("redirector.dll");

    if target_redirector.is_file() {
        let _ = fs::copy(&target_redirector, &dest_dll);
    } else if release_redirector.is_file() {
        let _ = fs::copy(&release_redirector, &dest_dll);
    } else if debug_redirector.is_file() {
        let _ = fs::copy(&debug_redirector, &dest_dll);
    } else if !dest_dll.exists() {
        let _ = fs::write(&dest_dll, b"");
    }

    println!("cargo:rerun-if-changed=../../vendor/detours/src");
    println!("cargo:rerun-if-changed=../../target/debug/redirector.dll");
    println!("cargo:rerun-if-changed=../../target/release/redirector.dll");
}
