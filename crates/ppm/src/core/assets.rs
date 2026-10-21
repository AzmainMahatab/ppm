use injection::{ENGINE_DLL_32, ENGINE_DLL_64, Machine};

/// One engine file `ppm init` deploys: `.ppm/lib/<folder>/<file_name>`.
pub struct EngineFile {
    /// The machine folder it belongs in - always a 64-bit machine (see `injection`'s layout).
    pub folder: Machine,
    pub file_name: &'static str,
    pub bytes: &'static [u8],
}

// Intention: Embed the engine built for ppm's own target.
// Why: The cdylib artifact dependency (`artifact = "cdylib"`) makes Cargo build redirector.dll
//      as part of ppm's build graph and export its exact staging path via
//      CARGO_CDYLIB_FILE_REDIRECTOR_redirector - no layout guessing, no build-script race.
const NATIVE_ENGINE: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_REDIRECTOR_redirector"));

/// Every engine file this build deploys.
///
/// Each 64-bit machine folder carries its own engine and the x86 engine beside it, because
/// Detours injects a 32-bit process through a helper that loads the x86 file from the folder of
/// the 64-bit one. An ARM64 build also carries the x64 engine for applications that run
/// emulated.
#[cfg(not(target_arch = "aarch64"))]
pub const ENGINE_FILES: &[EngineFile] = &[
    EngineFile {
        folder: Machine::X64,
        file_name: ENGINE_DLL_64,
        bytes: NATIVE_ENGINE,
    },
    EngineFile {
        folder: Machine::X64,
        file_name: ENGINE_DLL_32,
        bytes: engine_x86::REDIRECTOR_DLL,
    },
];

#[cfg(target_arch = "aarch64")]
pub const ENGINE_FILES: &[EngineFile] = &[
    EngineFile {
        folder: Machine::Arm64,
        file_name: ENGINE_DLL_64,
        bytes: NATIVE_ENGINE,
    },
    EngineFile {
        folder: Machine::Arm64,
        file_name: ENGINE_DLL_32,
        bytes: engine_x86::REDIRECTOR_DLL,
    },
    EngineFile {
        folder: Machine::X64,
        file_name: ENGINE_DLL_64,
        bytes: engine_x64::REDIRECTOR_DLL,
    },
    EngineFile {
        folder: Machine::X64,
        file_name: ENGINE_DLL_32,
        bytes: engine_x86::REDIRECTOR_DLL,
    },
];

// Intention: `manifests/apps.json` is the single source of truth for the default app
// collection - the same file developers maintain - embedded into the binary at build
// time so `ppm init` can seed new roots without a runtime file dependency.
pub const DEFAULT_APPS_JSON: &str = include_str!("../../../../manifests/apps.json");

#[cfg(test)]
mod tests {
    use super::*;

    /// The PE `Machine` field of an image: the `e_lfanew` offset at 0x3C locates the `PE\0\0`
    /// signature, and the machine follows it (PE/COFF specification, sections 2 and 3.3).
    fn pe_machine(image: &[u8]) -> u16 {
        assert_eq!(&image[..2], b"MZ", "not a PE image");
        let pe_offset = u32::from_le_bytes(image[0x3C..0x40].try_into().unwrap()) as usize;
        assert_eq!(&image[pe_offset..pe_offset + 4], b"PE\0\0");
        u16::from_le_bytes(image[pe_offset + 4..pe_offset + 6].try_into().unwrap())
    }

    /// Each file is the build its name and folder promise: injecting a mismatched build is
    /// exactly the failure the per-machine layout exists to prevent.
    #[test]
    fn every_embedded_engine_is_built_for_the_machine_its_location_names() {
        const I386: u16 = 0x014c;
        const AMD64: u16 = 0x8664;
        const ARM64: u16 = 0xAA64;
        for file in ENGINE_FILES {
            let expected = match (file.file_name, file.folder) {
                (ENGINE_DLL_32, _) => I386,
                (_, Machine::X64) => AMD64,
                (_, Machine::Arm64) => ARM64,
                (_, Machine::X86) => unreachable!("invariant: engine folders are 64-bit machines"),
            };
            assert_eq!(
                pe_machine(file.bytes),
                expected,
                "{}/{}",
                file.folder,
                file.file_name
            );
        }
    }
}
