//! Process identity boundary verification: the redirector must have proactively
//! established a root-scoped AppUserModelID at DLL attach.

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::Shell::GetCurrentProcessExplicitAppUserModelID;
use windows_sys::core::HRESULT;

use crate::support::from_wide_ptr;

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 5/5] Process Identity Boundary...");
    unsafe {
        let mut aumid_ptr: *mut u16 = ptr::null_mut();
        let hr = GetCurrentProcessExplicitAppUserModelID(&mut aumid_ptr);
        if hr != S_OK || aumid_ptr.is_null() {
            return Err(format!(
                "GetCurrentProcessExplicitAppUserModelID failed: HRESULT 0x{:08X}",
                hr
            ));
        }

        let aumid = from_wide_ptr(aumid_ptr);
        CoTaskMemFree(aumid_ptr as *mut c_void);
        println!("  -> Process AppUserModelID: '{}'", aumid);

        validate_portable_aumid(&aumid)?;
        verify_reparenting(&aumid)?;
    }

    println!("  -> Process Identity Boundary PASSED!");
    Ok(())
}

/// Validates the structural contract of the portable identity namespace:
/// `PPM.Portable.<16-hex root hash>.<non-empty identity>`.
fn validate_portable_aumid(aumid: &str) -> Result<(), String> {
    const ISOLATION_PREFIX: &str = "PPM.Portable.";

    let root_hash_and_identity = aumid
        .strip_prefix(ISOLATION_PREFIX)
        .ok_or_else(|| format!("AppUserModelID '{aumid}' lacks the '{ISOLATION_PREFIX}' isolation prefix"))?;

    let (root_hash, identity) = root_hash_and_identity.split_once('.').ok_or_else(|| {
        format!("AppUserModelID '{aumid}' is missing the '.' separator between root hash and identity")
    })?;

    let hash_is_canonical = root_hash.len() == 16 && root_hash.bytes().all(|b| b.is_ascii_hexdigit());
    if !hash_is_canonical {
        return Err(format!(
            "AppUserModelID '{aumid}' root hash '{root_hash}' must be exactly 16 hex characters"
        ));
    }

    if identity.is_empty() {
        return Err(format!("AppUserModelID '{aumid}' carries an empty app identity"));
    }

    Ok(())
}

/// Exercises the re-parenting contract: an app-initiated identity change must be mapped
/// into the same root-scoped namespace - root hash preserved, identity segment replaced.
/// The export is resolved dynamically exactly like the redirector resolves it, so the
/// detour on the real shell32 export is what gets exercised.
fn verify_reparenting(original_aumid: &str) -> Result<(), String> {
    const APP_REQUESTED_ID: &str = "Probe.Reparenting";

    unsafe {
        let shell32 = LoadLibraryW(windows_sys::core::w!("shell32.dll"));
        if shell32.is_null() {
            return Err("shell32.dll unavailable for SetCurrentProcessExplicitAppUserModelID".to_string());
        }

        let Some(set_proc) = GetProcAddress(
            shell32,
            c"SetCurrentProcessExplicitAppUserModelID".as_ptr().cast(),
        ) else {
            return Err("SetCurrentProcessExplicitAppUserModelID not found".to_string());
        };
        type FnSetAumid = unsafe extern "system" fn(*const u16) -> HRESULT;
        // SAFETY: `set_proc` comes from GetProcAddress on shell32 with the matching ABI.
        let set_aumid: FnSetAumid = std::mem::transmute(set_proc);

        let requested_wide: Vec<u16> = APP_REQUESTED_ID
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `requested_wide` is a NUL-terminated UTF-16 buffer outliving the call;
        // the API only reads it. The redirector detour on this export re-parents the ID.
        let hr = set_aumid(requested_wide.as_ptr());
        if hr != S_OK {
            return Err(format!(
                "SetCurrentProcessExplicitAppUserModelID failed: 0x{hr:08X}"
            ));
        }

        let mut aumid_ptr: *mut u16 = ptr::null_mut();
        let hr = GetCurrentProcessExplicitAppUserModelID(&mut aumid_ptr);
        if hr != S_OK || aumid_ptr.is_null() {
            return Err(format!(
                "GetCurrentProcessExplicitAppUserModelID failed after re-parenting: 0x{hr:08X}"
            ));
        }
        let reparented = from_wide_ptr(aumid_ptr);
        CoTaskMemFree(aumid_ptr as *mut c_void);
        println!("  -> Re-parented AppUserModelID: '{reparented}'");

        let expected_hash = original_aumid
            .strip_prefix("PPM.Portable.")
            .and_then(|rest| rest.split_once('.'))
            .map(|(hash, _)| hash)
            .ok_or_else(|| "original AUMID is not in the portable namespace".to_string())?;
        let expected = format!("PPM.Portable.{expected_hash}.{APP_REQUESTED_ID}");
        if reparented != expected {
            return Err(format!(
                "Re-parenting mapped '{APP_REQUESTED_ID}' to '{reparented}', expected '{expected}'"
            ));
        }
    }

    Ok(())
}
