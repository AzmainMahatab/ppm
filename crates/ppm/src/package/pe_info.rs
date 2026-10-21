use anyhow::{Context, Result, bail};
use object::pe::{IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, ImageDosHeader};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
use std::path::Path;

/// Writes a copy of the running test binary to `dest` with its PE `Subsystem` field set to
/// `subsystem` (2 = Windows GUI, 3 = Windows console).
///
/// The field's place is fixed by the PE/COFF specification: the `e_lfanew` value at 0x3C locates
/// the `PE\0\0` signature, the 20-byte COFF header follows it, and `Subsystem` sits 68 bytes into
/// the optional header in both PE32 and PE32+.
#[cfg(test)]
pub(crate) fn write_test_executable(dest: &Path, subsystem: u16) {
    let mut image =
        std::fs::read(std::env::current_exe().expect("test binary path")).expect("read test binary");
    let pe_offset = u32::from_le_bytes(image[0x3C..0x40].try_into().expect("4 bytes")) as usize;
    let field = pe_offset + 4 + 20 + 68;
    image[field..field + 2].copy_from_slice(&subsystem.to_le_bytes());
    std::fs::write(dest, image).expect("write test executable");
}

/// Whether an executable is built for the Windows console subsystem rather than the GUI one.
///
/// Only the headers are read - through a cache over the open file, not by loading an executable
/// that may run to hundreds of megabytes.
pub fn is_console_executable(exe_path: &Path) -> Result<bool> {
    let file =
        std::fs::File::open(exe_path).with_context(|| format!("Failed to open '{}'", exe_path.display()))?;
    let data = object::ReadCache::new(file);
    let not_pe = || format!("'{}' is not a PE image", exe_path.display());

    let dos = ImageDosHeader::parse(&data).with_context(not_pe)?;
    let mut offset = u64::from(dos.nt_headers_offset());
    let subsystem = match object::read::pe::optional_header_magic(&data).with_context(not_pe)? {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => object::pe::ImageNtHeaders64::parse(&data, &mut offset)
            .with_context(not_pe)?
            .0
            .optional_header()
            .subsystem(),
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => object::pe::ImageNtHeaders32::parse(&data, &mut offset)
            .with_context(not_pe)?
            .0
            .optional_header()
            .subsystem(),
        magic => bail!(
            "'{}' has an unknown optional-header magic 0x{magic:04x}",
            exe_path.display()
        ),
    };
    Ok(subsystem == object::pe::IMAGE_SUBSYSTEM_WINDOWS_CUI)
}

/// Dynamically extracts the binary product version directly from Windows PE header resources (VS_FIXEDFILEINFO).
pub fn get_pe_product_version(exe_path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        get_windows_pe_version(exe_path)
    }
    #[cfg(not(windows))]
    {
        let _ = exe_path;
        None
    }
}

/// Fallback: reads the version from an Electron payload's `package.json`.
pub fn get_electron_package_version(exe_path: &Path) -> Option<String> {
    let parent = exe_path.parent()?;
    // Ex: `resources/app/package.json` is the unpacked Electron layout; `package.json` beside
    //     the executable is the flattened one. An `app.asar` payload carries its manifest
    //     inside the archive and is not readable without an asar reader, so it is not listed.
    let candidate_paths = [
        parent.join("resources").join("app").join("package.json"),
        parent.join("package.json"),
    ];

    for path in &candidate_paths {
        if path.is_file()
            && let Ok(content) = std::fs::read_to_string(path)
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
            && let Some(ver) = json.get("version").and_then(|v| v.as_str())
        {
            return Some(ver.to_string());
        }
    }

    None
}

#[cfg(windows)]
mod windows_version_api {
    use std::ffi::c_void;
    use std::sync::LazyLock;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    pub(super) type FnGetFileVersionInfoSizeW = unsafe extern "system" fn(*const u16, *mut u32) -> u32;
    pub(super) type FnGetFileVersionInfoW =
        unsafe extern "system" fn(*const u16, u32, u32, *mut c_void) -> i32;
    pub(super) type FnVerQueryValueW =
        unsafe extern "system" fn(*const c_void, *const u16, *mut *mut c_void, *mut u32) -> i32;

    /// The `version.dll` entry points, resolved once for the process.
    ///
    /// # Why the module is never released
    /// The previous shape re-loaded `version.dll` on every call and released it again through
    /// six separate `FreeLibrary` calls - one per early return - which is resource discipline by
    /// remembered cleanup, exactly the shape a resolved-once handle makes unnecessary.
    /// `version.dll` is a system library that stays mapped for the process lifetime regardless,
    /// so holding one reference costs nothing and cannot leak per call.
    pub(super) struct VersionApi {
        pub(super) get_size: FnGetFileVersionInfoSizeW,
        pub(super) get_info: FnGetFileVersionInfoW,
        pub(super) query_value: FnVerQueryValueW,
    }

    static VERSION_API: LazyLock<Option<VersionApi>> = LazyLock::new(load);

    pub(super) fn version_api() -> Option<&'static VersionApi> {
        VERSION_API.as_ref()
    }

    fn load() -> Option<VersionApi> {
        // SAFETY: `version.dll` is a system library loaded by name; each export is transmuted to
        // the signature documented for it in winver.h, and the module is never unloaded, so the
        // pointers stay valid for the process lifetime.
        unsafe {
            let module = LoadLibraryW(windows_sys::core::w!("version.dll"));
            if module.is_null() {
                return None;
            }
            let get_size = GetProcAddress(module, c"GetFileVersionInfoSizeW".as_ptr().cast())?;
            let get_info = GetProcAddress(module, c"GetFileVersionInfoW".as_ptr().cast())?;
            let query_value = GetProcAddress(module, c"VerQueryValueW".as_ptr().cast())?;

            Some(VersionApi {
                get_size: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnGetFileVersionInfoSizeW,
                >(get_size),
                get_info: std::mem::transmute::<unsafe extern "system" fn() -> isize, FnGetFileVersionInfoW>(
                    get_info,
                ),
                query_value: std::mem::transmute::<unsafe extern "system" fn() -> isize, FnVerQueryValueW>(
                    query_value,
                ),
            })
        }
    }
}

/// The VS_FIXEDFILEINFO signature that marks a well-formed fixed-info block (winver.h).
#[cfg(windows)]
const VS_FFI_SIGNATURE: u32 = 0xFEEF_04BD;

#[cfg(windows)]
#[repr(C)]
struct VsFixedFileInfo {
    dw_signature: u32,
    dw_struc_version: u32,
    dw_file_version_ms: u32,
    dw_file_version_ls: u32,
    dw_product_version_ms: u32,
    dw_product_version_ls: u32,
    dw_file_flags_mask: u32,
    dw_file_flags: u32,
    dw_file_os: u32,
    dw_file_type: u32,
    dw_file_subtype: u32,
    dw_file_date_ms: u32,
    dw_file_date_ls: u32,
}

/// Formats a product version from its two packed DWORDs, dropping a zero build component.
#[cfg(windows)]
fn format_product_version(version_ms: u32, version_ls: u32) -> String {
    let major = (version_ms >> 16) & 0xFFFF;
    let minor = version_ms & 0xFFFF;
    let patch = (version_ls >> 16) & 0xFFFF;
    let build = version_ls & 0xFFFF;

    match build {
        0 => format!("{major}.{minor}.{patch}"),
        _ => format!("{major}.{minor}.{patch}.{build}"),
    }
}

#[cfg(windows)]
fn get_windows_pe_version(exe_path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_version_api::version_api;

    if !exe_path.is_file() {
        return None;
    }

    let api = version_api()?;
    let path_wide: Vec<u16> = exe_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `path_wide` is a NUL-terminated wide path; `buffer` is sized by the API's own
    // size query before it is filled; `lp_buffer` and `len` are out-parameters the API writes,
    // and the fixed-info block is only read after its length is checked against its own size.
    unsafe {
        let mut _handle = 0u32;
        let size = (api.get_size)(path_wide.as_ptr(), &mut _handle);
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        if (api.get_info)(
            path_wide.as_ptr(),
            0,
            size,
            buffer.as_mut_ptr().cast::<std::ffi::c_void>(),
        ) == 0
        {
            return None;
        }

        // The root sub-block ("\") selects the VS_FIXEDFILEINFO struct.
        let mut lp_buffer: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        let queried = (api.query_value)(
            buffer.as_ptr().cast::<std::ffi::c_void>(),
            windows_sys::core::w!("\\"),
            &mut lp_buffer,
            &mut len,
        );

        if queried == 0 || lp_buffer.is_null() || (len as usize) < std::mem::size_of::<VsFixedFileInfo>() {
            return None;
        }

        let info = &*lp_buffer.cast::<VsFixedFileInfo>();
        if info.dw_signature != VS_FFI_SIGNATURE {
            return None;
        }

        Some(format_product_version(
            info.dw_product_version_ms,
            info.dw_product_version_ls,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subsystem_distinguishes_console_from_gui_executables() {
        let dir = tempfile::tempdir().unwrap();
        let console = dir.path().join("console.exe");
        let gui = dir.path().join("gui.exe");
        write_test_executable(&console, 3);
        write_test_executable(&gui, 2);

        assert!(is_console_executable(&console).unwrap());
        assert!(!is_console_executable(&gui).unwrap());
    }

    #[test]
    fn a_file_that_is_not_a_pe_image_is_an_error() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"not an executable").unwrap();
        assert!(is_console_executable(file.path()).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_extract_pe_version_from_system_binary() {
        let kernel32_path = Path::new("C:\\Windows\\System32\\kernel32.dll");
        if kernel32_path.is_file() {
            let version = get_pe_product_version(kernel32_path);
            assert!(version.is_some(), "Should extract version from kernel32.dll");
            let ver_str = version.unwrap();
            assert!(
                ver_str.starts_with("10.0") || ver_str.starts_with("6."),
                "Expected Windows version format, got: {}",
                ver_str
            );
        }
    }

    /// Repeated calls must keep working: the entry points are resolved once and the module is
    /// deliberately never released, so a second call cannot find a freed export.
    #[test]
    #[cfg(windows)]
    fn repeated_queries_reuse_the_resolved_entry_points() {
        let kernel32_path = Path::new("C:\\Windows\\System32\\kernel32.dll");
        if kernel32_path.is_file() {
            let first = get_pe_product_version(kernel32_path);
            let second = get_pe_product_version(kernel32_path);
            assert_eq!(first, second);
            assert!(first.is_some());
        }
    }

    #[test]
    #[cfg(windows)]
    fn product_version_drops_only_a_zero_build_component() {
        // major.minor packed in MS, patch.build packed in LS.
        assert_eq!(format_product_version((1 << 16) | 2, (3 << 16) | 4), "1.2.3.4");
        assert_eq!(format_product_version((1 << 16) | 2, 3 << 16), "1.2.3");
    }

    #[test]
    fn a_missing_file_has_no_version() {
        assert!(get_pe_product_version(Path::new("Q:\\definitely\\missing.exe")).is_none());
        assert!(get_electron_package_version(Path::new("Q:\\definitely\\missing.exe")).is_none());
    }
}
