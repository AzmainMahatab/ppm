//! Shell known-folder redirection boundary verification.

use std::ptr;

use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{SHGetFolderPathW, SHGetKnownFolderPath};
use windows_sys::core::GUID;

use crate::support::from_wide_ptr;

const FOLDERID_PROFILE: GUID = GUID {
    data1: 0x5e6c858f,
    data2: 0x0e22,
    data3: 0x4760,
    data4: [0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73],
};

const FOLDERID_LOCAL_APP_DATA: GUID = GUID {
    data1: 0xf1b32785,
    data2: 0x6fba,
    data3: 0x4fcf,
    data4: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
};

const FOLDERID_ROAMING_APP_DATA: GUID = GUID {
    data1: 0x3eb68528,
    data2: 0x012f,
    data3: 0x4761,
    data4: [0xb2, 0xde, 0x46, 0x54, 0x79, 0xe0, 0x70, 0x23],
};

const FOLDERID_DOCUMENTS: GUID = GUID {
    data1: 0xfdd39ad0,
    data2: 0x238f,
    data3: 0x46af,
    data4: [0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7],
};

// CSIDL_LOCAL_APPDATA - the legacy SHGetFolderPathW selector for the same folder.
const CSIDL_LOCAL_APPDATA: i32 = 0x001c;

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 2/5] Shell Paths Boundary...");

    verify_known_folder(&FOLDERID_PROFILE, "FOLDERID_Profile", "Home")?;
    verify_known_folder(
        &FOLDERID_LOCAL_APP_DATA,
        "FOLDERID_LocalAppData",
        "Home/AppData/Local",
    )?;
    verify_known_folder(
        &FOLDERID_ROAMING_APP_DATA,
        "FOLDERID_RoamingAppData",
        "Home/AppData/Roaming",
    )?;
    verify_known_folder(&FOLDERID_DOCUMENTS, "FOLDERID_Documents", "Home/Documents")?;
    verify_sh_get_folder_path_w()?;

    println!("  -> Shell Paths Boundary PASSED!");
    Ok(())
}

/// Asserts that a known folder resolves under the virtualized profile location.
fn verify_known_folder(folder: &GUID, label: &str, expected_tail: &str) -> Result<(), String> {
    unsafe {
        let mut path_out: *mut u16 = ptr::null_mut();
        let hr = SHGetKnownFolderPath(folder, 0, ptr::null_mut(), &mut path_out);
        if hr != S_OK || path_out.is_null() {
            return Err(format!(
                "SHGetKnownFolderPath({label}) failed with HRESULT 0x{hr:08X}"
            ));
        }

        let folder_path = from_wide_ptr(path_out);
        CoTaskMemFree(path_out.cast());
        println!("  -> Resolved {label}: '{folder_path}'");

        if !folder_path.replace('\\', "/").contains(expected_tail) {
            return Err(format!(
                "{label} was not redirected under '{expected_tail}': '{folder_path}'"
            ));
        }
    }

    Ok(())
}

/// Exercises the legacy SHGetFolderPathW hook path (CSIDL selectors), which the
/// SHGetKnownFolderPath checks above do not reach.
fn verify_sh_get_folder_path_w() -> Result<(), String> {
    unsafe {
        let mut buf = [0u16; 260];
        let hr = SHGetFolderPathW(
            ptr::null_mut(),
            CSIDL_LOCAL_APPDATA,
            ptr::null_mut(),
            0,
            buf.as_mut_ptr(),
        );
        if hr != S_OK {
            return Err(format!(
                "SHGetFolderPathW(CSIDL_LOCAL_APPDATA) failed: 0x{hr:08X}"
            ));
        }

        let folder_path = from_wide_ptr(buf.as_ptr());
        println!("  -> Resolved CSIDL_LOCAL_APPDATA: '{folder_path}'");

        if !folder_path.replace('\\', "/").contains("Home/AppData/Local") {
            return Err(format!(
                "CSIDL_LOCAL_APPDATA was not redirected under Home/AppData/Local: '{folder_path}'"
            ));
        }
    }

    Ok(())
}
