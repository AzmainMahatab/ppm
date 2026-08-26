use std::env;
use std::path::PathBuf;

const REDIRECTOR_DLL: &str = "redirector.dll";
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
    export_redirector_dll_path();
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

fn target_directory() -> PathBuf {
    env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"))
}

// Intention: Resolve WHERE the redirector cdylib artifact will live, without touching the file.
// Why: Cargo orders dependency compilation before dependent-crate compilation, but build-script
//      execution races with sibling compilation. Consuming the DLL via include_bytes! in the
//      crate (guaranteed-late phase) instead of copying it here (racy phase) removes the race.
// Ex: cross build (TARGET != HOST) -> <target>/<triple>/release/redirector.dll;
//     native build (TARGET == HOST) -> <target>/release/redirector.dll.
fn export_redirector_dll_path() {
    let target_root = target_directory();
    let profile = env::var("PROFILE").unwrap_or_else(|_| String::from("debug"));

    // Intention: Mirror exactly where Cargo places cdylib outputs for this invocation.
    // Why: Cargo sets TARGET to the host triple even without an explicit --target, where the
    //      flat <profile> layout is used; only genuine cross builds nest under the triple.
    let is_cross_compiling = matches!((env::var_os("TARGET"), env::var_os("HOST")),
        (Some(target), Some(host)) if target != host);

    let artifact_dir = if is_cross_compiling {
        let triple = env::var("TARGET").unwrap_or_default();
        target_root.join(triple).join(&profile)
    } else {
        target_root.join(&profile)
    };
    // Intention: Prefer the promoted root copy, fall back to the un-promoted deps artifact.
    // Why: Cargo links <profile>/redirector.dll only for directly-built workspace members;
    //      when redirector compiles purely as a dependency the cdylib stays under deps/.
    let candidates = [
        artifact_dir.join(REDIRECTOR_DLL),
        artifact_dir.join("deps").join(REDIRECTOR_DLL),
    ];

    let resolved = candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .cloned()
        .unwrap_or_else(|| {
            // Intention: Export the canonical path even when it does not exist yet.
            // Why: The dependent crate compiles strictly after the redirector dependency, so the
            //      artifact is guaranteed by the time include_bytes! reads this path; failing
            //      there names the exact missing file instead of racing here.
            candidates
                .first()
                .cloned()
                .expect("at least one candidate path is always constructed")
        });

    println!("cargo:rustc-env=PPM_REDIRECTOR_DLL={}", resolved.display());

    if resolved.is_file() {
        println!("cargo:rerun-if-changed={}", resolved.display());
    }
    println!("cargo:rerun-if-changed=../redirector/Cargo.toml");
}

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
    println!("cargo:rerun-if-changed=../redirector/src");
}
