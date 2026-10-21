//! The system modules the engine hooks, and the guarantee that they are loaded before it runs.
//!
//! # Why static imports instead of `LoadLibraryW` at attach
//! Hooks are installed in `DllMain`, under the loader lock, so that no application code runs
//! before its boundaries exist. Loading a library there is what Microsoft's DLL best practices
//! forbid: the new library's own initialization runs nested inside ours, and can deadlock or
//! touch state that is not ready. Importing each hooked module statically moves that work to the
//! loader, which maps and initializes every dependency *before* calling our `DllMain`; at attach
//! the module is then only looked up. See ADR-008.
//!
//! The statics below exist for their relocations: each references one function of a module the
//! engine hooks, which makes the linker record that module in redirector.dll's import table.

use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::core::{BOOL, GUID, HRESULT, PCWSTR, PWSTR};

#[used]
static ADVAPI32_IMPORT: unsafe extern "system" fn(*const c_void) =
    windows_sys::Win32::Security::Credentials::CredFree;

#[used]
static SHELL32_IMPORT: unsafe extern "system" fn(*const GUID, u32, HANDLE, *mut PWSTR) -> HRESULT =
    windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

#[used]
static USERENV_IMPORT: unsafe extern "system" fn(HANDLE, PWSTR, *mut u32) -> BOOL =
    windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

/// A hooked system module, already loaded and initialized by the time the engine attaches.
///
/// Returns null only if `name` is not among the engine's imports - a programming error that the
/// caller reports, since `DllMain` cannot fail the process over a missing hook.
pub(crate) fn loaded(name: PCWSTR) -> HMODULE {
    // Why: `#[used]` alone does not survive `/OPT:REF`; taking the statics' addresses from live
    //      code keeps their import relocations in the image.
    std::hint::black_box((&ADVAPI32_IMPORT, &SHELL32_IMPORT, &USERENV_IMPORT));
    // SAFETY: `name` is a NUL-terminated module name; the lookup takes no loader action.
    unsafe { GetModuleHandleW(name) }
}
