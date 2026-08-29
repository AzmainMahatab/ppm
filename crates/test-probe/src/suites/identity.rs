//! Taskbar identity boundary verification: the redirector must have proactively
//! established a root-scoped AppUserModelID at DLL attach.

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::GetCurrentProcessExplicitAppUserModelID;

use crate::support::from_wide_ptr;

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 5/5] Taskbar Identity Boundary...");
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
    }

    println!("  -> Taskbar Identity Boundary PASSED!");
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
