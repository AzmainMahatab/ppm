// Intention: Embed the redirector engine binary produced by the workspace dependency.
// Why: The cdylib artifact dependency (`artifact = "cdylib"`) makes Cargo build redirector.dll
//      as part of ppm's build graph and export its exact staging path via
//      CARGO_CDYLIB_FILE_REDIRECTOR_redirector - no layout guessing, no build-script race.
pub const EMBEDDED_REDIRECTOR_DLL: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_REDIRECTOR_redirector"));

// Intention: `manifests/apps.json` is the single source of truth for the default app
// collection - the same file developers maintain - embedded into the binary at build
// time so `ppm init` can seed new roots without a runtime file dependency.
pub const DEFAULT_APPS_JSON: &str = include_str!("../../../../manifests/apps.json");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_redirector_is_a_non_empty_pe_image() {
        assert!(!EMBEDDED_REDIRECTOR_DLL.is_empty());
        assert_eq!(
            &EMBEDDED_REDIRECTOR_DLL[..2],
            b"MZ",
            "embedded engine must be a PE image"
        );
    }
}
