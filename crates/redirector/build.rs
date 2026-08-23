fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-cdylib-link-arg=/DEF:{}/exports.def", dir.replace("\\", "/"));
}
