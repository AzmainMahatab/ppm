//! Which engine file a process needs, and how it gets there.

use std::ffi::CString;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Globalization::{CP_ACP, WC_NO_BEST_FIT_CHARS, WideCharToMultiByte};
use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;

use crate::{InjectError, Machine};

/// The 64-bit engine in each `<lib>/<machine>/` folder.
pub const ENGINE_DLL_64: &str = "redirector64.dll";
/// The x86 engine beside it. Detours derives this name from [`ENGINE_DLL_64`] by swapping `64.`
/// for `32.`, so the two names must differ in exactly that.
pub const ENGINE_DLL_32: &str = "redirector32.dll";

/// How the engine reaches the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The injector patches the target's import table itself.
    Direct,
    /// The target's bitness differs from the injector's, which cannot patch it; Detours starts a
    /// helper of the target's bitness that loads the `32`/`64`-swapped name of [`EngineChoice::dll`]
    /// and patches the target from there.
    ViaHelper,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineChoice {
    /// The path handed to Detours.
    pub dll: PathBuf,
    pub route: Route,
}

impl EngineChoice {
    /// Every file the injection loads: the named DLL and, through a helper, its swapped sibling.
    pub fn required_files(&self) -> Vec<PathBuf> {
        match self.route {
            Route::Direct => vec![self.dll.clone()],
            Route::ViaHelper => vec![self.dll.clone(), swap_bitness(&self.dll)],
        }
    }
}

/// The sibling Detours' helper loads: the same folder, the other bitness's file name.
fn swap_bitness(dll: &Path) -> PathBuf {
    let other = match dll.file_name().and_then(|name| name.to_str()) {
        Some(ENGINE_DLL_64) => ENGINE_DLL_32,
        Some(ENGINE_DLL_32) => ENGINE_DLL_64,
        _ => unreachable!("invariant: choose_engine only names the two engine files"),
    };
    dll.with_file_name(other)
}

/// Picks the engine file and route for injecting a `child` process from an `injector` process
/// on a `host` whose native machine is given.
///
/// | child  | injector | route  | file                                     |
/// |--------|----------|--------|------------------------------------------|
/// | 64-bit | 64-bit   | direct | `<child>/redirector64.dll`               |
/// | 64-bit | x86      | helper | `<child>/redirector32.dll` (helper: 64)  |
/// | x86    | 64-bit   | helper | `<host>/redirector64.dll` (helper: 32)   |
/// | x86    | x86      | direct | `<host>/redirector32.dll`                |
///
/// A 64-bit child is served from its own machine's folder. An x86 child is served from the
/// host's folder, which every deployment on that host carries.
///
/// The helper Detours starts is the host's own `rundll32` for a 64-bit target, so an x86 injector
/// can only reach a 64-bit child of the host's native machine: an x64 child of an x86 process on
/// an ARM64 host has no route and is refused.
pub fn choose_engine(
    lib_dir: &Path,
    injector: Machine,
    host: Machine,
    child: Machine,
) -> Result<EngineChoice, InjectError> {
    let folder_machine = if child.is_64_bit() { child } else { host };
    let folder = lib_dir.join(folder_machine.as_str());

    let (file, route) = match (child.is_64_bit(), injector.is_64_bit()) {
        (true, true) => (ENGINE_DLL_64, Route::Direct),
        (true, false) if child == host => (ENGINE_DLL_32, Route::ViaHelper),
        (true, false) => {
            return Err(InjectError::UnsupportedRoute {
                injector,
                child,
                host,
            });
        }
        (false, true) => (ENGINE_DLL_64, Route::ViaHelper),
        (false, false) => (ENGINE_DLL_32, Route::Direct),
    };
    Ok(EngineChoice {
        dll: folder.join(file),
        route,
    })
}

/// Encodes UTF-16 text in `code_page`, or `None` when any character has no exact representation
/// there (a best-fit substitute would name a different file).
pub fn encode_in_code_page(wide: &[u16], code_page: u32) -> Option<Vec<u8>> {
    if wide.is_empty() {
        return Some(Vec::new());
    }
    let length = i32::try_from(wide.len()).ok()?;
    let mut used_default = 0;
    // SAFETY: a sizing call - no output buffer; `wide` is live for its declared length.
    let needed = unsafe {
        WideCharToMultiByte(
            code_page,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            &mut used_default,
        )
    };
    if needed <= 0 || used_default != 0 {
        return None;
    }
    let mut encoded = vec![0u8; needed as usize];
    // SAFETY: `encoded` holds exactly the size the sizing call reported.
    let written = unsafe {
        WideCharToMultiByte(
            code_page,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            length,
            encoded.as_mut_ptr(),
            needed,
            std::ptr::null(),
            &mut used_default,
        )
    };
    (written == needed && used_default == 0).then_some(encoded)
}

/// The engine path as the NUL-terminated ANSI string Detours writes into the import table.
///
/// # Why ANSI, and why the short-name fallback
/// An import-table entry is an 8-bit string that the loader decodes with the system ANSI code
/// page. Handing Detours UTF-8, as before, broke injection for any root containing a non-ASCII
/// character. When the path has no exact ANSI form, its 8.3 short name - ASCII where the volume
/// keeps short names - is tried before giving up with an error that names the cause.
pub(crate) fn ansi_path(path: &Path) -> Result<CString, InjectError> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let encoded = encode_in_code_page(&wide, CP_ACP).or_else(|| {
        let short = short_path(&wide)?;
        encode_in_code_page(&short, CP_ACP)
    });
    encoded
        .and_then(|bytes| CString::new(bytes).ok())
        .ok_or_else(|| InjectError::PathNotAnsi(path.to_path_buf()))
}

/// The 8.3 short form of an existing path, or `None` when the volume keeps no short names.
fn short_path(wide: &[u16]) -> Option<Vec<u16>> {
    let terminated: Vec<u16> = wide.iter().copied().chain(std::iter::once(0)).collect();
    // SAFETY: sizing call with a NUL-terminated input and no output buffer.
    let needed = unsafe { GetShortPathNameW(terminated.as_ptr(), std::ptr::null_mut(), 0) };
    if needed == 0 {
        return None;
    }
    let mut buffer = vec![0u16; needed as usize];
    // SAFETY: `buffer` holds the size the sizing call reported, terminator included.
    let written = unsafe { GetShortPathNameW(terminated.as_ptr(), buffer.as_mut_ptr(), needed) };
    if written == 0 || written >= needed {
        return None;
    }
    buffer.truncate(written as usize);
    Some(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIB: &str = r"R:\root\.ppm\lib";

    fn choice(injector: Machine, host: Machine, child: Machine) -> Result<EngineChoice, InjectError> {
        choose_engine(Path::new(LIB), injector, host, child)
    }

    fn expect(dll: &str, route: Route) -> EngineChoice {
        EngineChoice {
            dll: PathBuf::from(dll),
            route,
        }
    }

    #[test]
    fn a_64_bit_child_gets_its_own_machines_engine() {
        use Machine::*;
        assert_eq!(
            choice(X64, X64, X64).unwrap(),
            expect(r"R:\root\.ppm\lib\x64\redirector64.dll", Route::Direct)
        );
        // Regression: an ARM64 injector used to hand an emulated x64 child its own ARM64 build.
        assert_eq!(
            choice(Arm64, Arm64, X64).unwrap(),
            expect(r"R:\root\.ppm\lib\x64\redirector64.dll", Route::Direct)
        );
        assert_eq!(
            choice(X64, Arm64, Arm64).unwrap(),
            expect(r"R:\root\.ppm\lib\arm64\redirector64.dll", Route::Direct)
        );
    }

    /// Regression: a 64-bit injector cannot patch a 32-bit process, and no x86 engine existed,
    /// so every 32-bit child of a 64-bit application was refused.
    #[test]
    fn a_32_bit_child_of_a_64_bit_injector_goes_through_the_helper() {
        use Machine::*;
        let x64_host = choice(X64, X64, X86).unwrap();
        assert_eq!(
            x64_host,
            expect(r"R:\root\.ppm\lib\x64\redirector64.dll", Route::ViaHelper)
        );
        assert_eq!(
            x64_host.required_files(),
            vec![
                PathBuf::from(r"R:\root\.ppm\lib\x64\redirector64.dll"),
                PathBuf::from(r"R:\root\.ppm\lib\x64\redirector32.dll"),
            ]
        );
        assert_eq!(
            choice(Arm64, Arm64, X86).unwrap(),
            expect(r"R:\root\.ppm\lib\arm64\redirector64.dll", Route::ViaHelper)
        );
    }

    #[test]
    fn a_32_bit_injector_reaches_32_bit_children_directly_and_native_64_bit_ones_by_helper() {
        use Machine::*;
        assert_eq!(
            choice(X86, X64, X86).unwrap(),
            expect(r"R:\root\.ppm\lib\x64\redirector32.dll", Route::Direct)
        );
        assert_eq!(
            choice(X86, X64, X64).unwrap(),
            expect(r"R:\root\.ppm\lib\x64\redirector32.dll", Route::ViaHelper)
        );
        // The ARM64 host's helper is an ARM64 rundll32, which cannot load the x64 engine.
        assert!(matches!(
            choice(X86, Arm64, X64),
            Err(InjectError::UnsupportedRoute { .. })
        ));
    }

    // Windows-1252 is pinned rather than the machine's ANSI code page, so the expectations are
    // literals from the code page table and hold on any test machine.
    const WINDOWS_1252: u32 = 1252;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// Regression: the path was handed to Detours as UTF-8, which the loader decodes as ANSI, so
    /// a root such as `D:\Café` named a file that does not exist.
    #[test]
    fn a_path_is_encoded_in_the_code_page_not_as_utf_8() {
        assert_eq!(
            encode_in_code_page(&wide(r"D:\Café\lib"), WINDOWS_1252),
            Some(b"D:\\Caf\xE9\\lib".to_vec())
        );
        assert_eq!(
            encode_in_code_page(&wide(r"D:\plain"), WINDOWS_1252),
            Some(b"D:\\plain".to_vec())
        );
    }

    #[test]
    fn a_character_the_code_page_lacks_is_refused_rather_than_substituted() {
        // U+65E5 has no Windows-1252 form; U+0101 would best-fit to plain `a` - a different path.
        assert_eq!(encode_in_code_page(&wide(r"D:\日本"), WINDOWS_1252), None);
        assert_eq!(encode_in_code_page(&wide(r"D:\ā"), WINDOWS_1252), None);
    }
}
