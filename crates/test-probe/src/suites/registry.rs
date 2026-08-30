//! Registry Copy-on-Write boundary verification.

use std::ptr;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW,
    RegDeleteValueW, RegQueryValueExW, RegSetValueExW,
};

use crate::support::{from_wide_ptr, to_wide};

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 1/5] Registry Boundary (Copy-on-Write)...");
    unsafe {
        let subkey = to_wide("Software\\PPMTestProbe");
        let mut hkey: HKEY = ptr::null_mut();
        let mut disp: u32 = 0;

        let res = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            ptr::null_mut(),
            &mut hkey,
            &mut disp,
        );
        if res != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW failed with code {}", res));
        }

        let val_name = to_wide("VirtualKey");
        let val_data = to_wide("VirtualSuccess123");
        let data_bytes = val_data.len() * 2;

        let res = RegSetValueExW(
            hkey,
            val_name.as_ptr(),
            0,
            REG_SZ,
            val_data.as_ptr() as *const u8,
            data_bytes as u32,
        );
        if res != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegSetValueExW failed with code {}", res));
        }

        // Query value back
        let mut buf = [0u16; 128];
        let mut buf_len = (buf.len() * 2) as u32;
        let mut val_type = 0u32;

        let res = RegQueryValueExW(
            hkey,
            val_name.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_len,
        );
        if res != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegQueryValueExW failed with code {}", res));
        }

        let read_str = from_wide_ptr(buf.as_ptr());
        if read_str != "VirtualSuccess123" {
            let _ = RegCloseKey(hkey);
            return Err(format!(
                "RegQueryValueExW returned unexpected data: '{}'",
                read_str
            ));
        }

        // Delete value
        let res = RegDeleteValueW(hkey, val_name.as_ptr());
        if res != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegDeleteValueW failed with code {}", res));
        }

        let _ = RegCloseKey(hkey);

        // Delete key: the CoW tombstone path must succeed while leaving the host key
        // untouched. The disposition of a follow-up create proves which side the key
        // lives on: REG_OPENED_EXISTING_KEY means the host key survived (the delete was
        // virtualized); REG_CREATED_NEW_KEY means RegDeleteKeyW escaped the hook and
        // really deleted the host key.
        let res = RegDeleteKeyW(HKEY_CURRENT_USER, subkey.as_ptr());
        if res != ERROR_SUCCESS {
            return Err(format!("RegDeleteKeyW failed with code {}", res));
        }

        const REG_CREATED_NEW_KEY: u32 = 1;
        const REG_OPENED_EXISTING_KEY: u32 = 2;

        let mut hkey2: HKEY = ptr::null_mut();
        let mut disposition: u32 = 0;
        let res = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            ptr::null_mut(),
            &mut hkey2,
            &mut disposition,
        );
        let _ = RegCloseKey(hkey2);
        if res != ERROR_SUCCESS {
            return Err(format!("re-create after RegDeleteKeyW failed with code {}", res));
        }
        if disposition != REG_OPENED_EXISTING_KEY {
            return Err(format!(
                "RegDeleteKeyW escaped the hook: re-create reported disposition                  {disposition} (REG_CREATED_NEW_KEY = {REG_CREATED_NEW_KEY}) instead of                  opening the surviving host key (REG_OPENED_EXISTING_KEY)"
            ));
        }
    }

    println!("  -> Registry Boundary PASSED!");
    Ok(())
}
