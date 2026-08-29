//! Shell known-folder redirection boundary verification.

use std::ptr;

use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
use windows_sys::core::GUID;

use crate::support::from_wide_ptr;

const FOLDERID_PROFILE: GUID = GUID {
    data1: 0x5e6c858f,
    data2: 0x0e22,
    data3: 0x4760,
    data4: [0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73],
};

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 2/5] Shell Paths Boundary...");
    unsafe {
        let mut path_out: *mut u16 = ptr::null_mut();
        let hr = SHGetKnownFolderPath(&FOLDERID_PROFILE, 0, ptr::null_mut(), &mut path_out);
        if hr != S_OK || path_out.is_null() {
            return Err(format!("SHGetKnownFolderPath failed with HRESULT 0x{:08X}", hr));
        }

        let folder_path = from_wide_ptr(path_out);
        println!("  -> Resolved FOLDERID_Profile: '{}'", folder_path);

        if !folder_path.replace('\\', "/").ends_with("Home") && !folder_path.contains("Home") {
            return Err(format!(
                "Profile path was not redirected to Home: '{}'",
                folder_path
            ));
        }
    }

    println!("  -> Shell Paths Boundary PASSED!");
    Ok(())
}
