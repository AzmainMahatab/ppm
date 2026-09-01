//! Registry Copy-on-Write boundary verification.
//!
//! # How a host escape is detected from inside the sandbox
//! The probe runs under injection, so it cannot read the real registry directly to prove a
//! delete never landed there. `RegCreateKeyExW` reports it instead: subkey *existence* still
//! falls through to the host, so the disposition of a re-create names the side the key lives
//! on. `REG_OPENED_EXISTING_KEY` means the host key survived and the delete was virtualized;
//! `REG_CREATED_NEW_KEY` means the delete escaped the hook and really destroyed it.
//!
//! # Host residue
//! Every subkey below lives under one root, `HKCU\Software\PPMTestProbe`, because deletes are
//! virtualized and the probe therefore cannot remove what its own creates leave behind.

use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegDeleteKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegDeleteValueW, RegGetValueW, RegQueryValueExW,
    RegSetValueExW,
};

use crate::support::{from_wide_ptr, to_wide};

const PROBE_ROOT: &str = "Software\\PPMTestProbe";
const REG_CREATED_NEW_KEY: u32 = 1;
const REG_OPENED_EXISTING_KEY: u32 = 2;

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 1/5] Registry Boundary (Copy-on-Write)...");

    copy_on_write_value_round_trip()?;
    reg_get_value_with_subkey_reads_the_overlay()?;
    delete_key_ex_does_not_reach_the_host()?;
    delete_tree_does_not_reach_the_host()?;
    // Runs last: it tombstones the whole probe subtree.
    delete_key_does_not_reach_the_host()?;

    println!("  -> Registry Boundary PASSED!");
    Ok(())
}

/// Creates (or opens) `subkey` under HKCU, returning the handle and the create disposition.
unsafe fn create_probe_key(subkey: &str) -> Result<(HKEY, u32), String> {
    unsafe {
        let wide = to_wide(subkey);
        let mut hkey: HKEY = ptr::null_mut();
        let mut disposition: u32 = 0;

        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            ptr::null_mut(),
            &mut hkey,
            &mut disposition,
        );
        if status != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW('{subkey}') failed with code {status}"));
        }
        Ok((hkey, disposition))
    }
}

/// Asserts that re-creating `subkey` opens a surviving host key rather than making a new one.
unsafe fn assert_host_key_survived(subkey: &str, deleting_api: &str) -> Result<(), String> {
    unsafe {
        let (hkey, disposition) = create_probe_key(subkey)?;
        let _ = RegCloseKey(hkey);

        if disposition != REG_OPENED_EXISTING_KEY {
            return Err(format!(
                "{deleting_api} escaped the hook and deleted the real host key '{subkey}': the re-create reported disposition {disposition} (REG_CREATED_NEW_KEY = {REG_CREATED_NEW_KEY}) instead of opening the surviving host key (REG_OPENED_EXISTING_KEY = {REG_OPENED_EXISTING_KEY})"
            ));
        }
        Ok(())
    }
}

unsafe fn set_string_value(hkey: HKEY, name: &str, value: &str) -> Result<(), String> {
    unsafe {
        let name_wide = to_wide(name);
        let value_wide = to_wide(value);
        let status = RegSetValueExW(
            hkey,
            name_wide.as_ptr(),
            0,
            REG_SZ,
            value_wide.as_ptr() as *const u8,
            (value_wide.len() * 2) as u32,
        );
        if status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW('{name}') failed with code {status}"));
        }
        Ok(())
    }
}

/// The original boundary contract: a value written through the hook reads back through it,
/// and deleting it masks it.
fn copy_on_write_value_round_trip() -> Result<(), String> {
    unsafe {
        let (hkey, _) = create_probe_key(PROBE_ROOT)?;
        set_string_value(hkey, "VirtualKey", "VirtualSuccess123").inspect_err(|_| {
            let _ = RegCloseKey(hkey);
        })?;

        let mut buf = [0u16; 128];
        let mut buf_len = (buf.len() * 2) as u32;
        let mut val_type = 0u32;
        let name_wide = to_wide("VirtualKey");

        let status = RegQueryValueExW(
            hkey,
            name_wide.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_len,
        );
        if status != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegQueryValueExW failed with code {status}"));
        }

        let read_str = from_wide_ptr(buf.as_ptr());
        if read_str != "VirtualSuccess123" {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegQueryValueExW returned unexpected data: '{read_str}'"));
        }

        let status = RegDeleteValueW(hkey, name_wide.as_ptr());
        let _ = RegCloseKey(hkey);
        if status != ERROR_SUCCESS {
            return Err(format!("RegDeleteValueW failed with code {status}"));
        }
        Ok(())
    }
}

/// Regression: `RegGetValueW` resolves its `lpSubKey` through an entry point the engine does
/// not intercept, so the read used to reach the host registry and miss the overlay entirely.
fn reg_get_value_with_subkey_reads_the_overlay() -> Result<(), String> {
    let subkey = format!("{PROBE_ROOT}\\GetValue");

    unsafe {
        let (hkey, _) = create_probe_key(&subkey)?;
        let result = set_string_value(hkey, "Answer", "OverlayAnswer");
        let _ = RegCloseKey(hkey);
        result?;

        let subkey_wide = to_wide(&subkey);
        let value_wide = to_wide("Answer");
        let mut buf = [0u16; 128];
        let mut buf_len = (buf.len() * 2) as u32;
        let mut val_type = 0u32;

        let status = RegGetValueW(
            HKEY_CURRENT_USER,
            subkey_wide.as_ptr(),
            value_wide.as_ptr(),
            RRF_RT_REG_SZ,
            &mut val_type,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            &mut buf_len,
        );
        if status != ERROR_SUCCESS {
            return Err(format!(
                "RegGetValueW with an lpSubKey failed with code {status}: the read did not reach the virtual overlay"
            ));
        }

        let read_str = from_wide_ptr(buf.as_ptr());
        if read_str != "OverlayAnswer" {
            return Err(format!(
                "RegGetValueW read '{read_str}' instead of the overlay value: the subkey open escaped virtualization"
            ));
        }
        if val_type != REG_SZ {
            return Err(format!("RegGetValueW reported type {val_type}, expected REG_SZ"));
        }
        Ok(())
    }
}

/// Regression: `RegDeleteKeyExW` reaches `RegDeleteKeyExInternalW` without passing through
/// `RegDeleteKeyW`, so it used to delete keys in the real host registry.
fn delete_key_ex_does_not_reach_the_host() -> Result<(), String> {
    let subkey = format!("{PROBE_ROOT}\\DeleteKeyEx");

    unsafe {
        let (hkey, _) = create_probe_key(&subkey)?;
        let _ = RegCloseKey(hkey);

        let wide = to_wide(&subkey);
        let status = RegDeleteKeyExW(HKEY_CURRENT_USER, wide.as_ptr(), KEY_ALL_ACCESS, 0);
        if status != ERROR_SUCCESS {
            return Err(format!("RegDeleteKeyExW failed with code {status}"));
        }

        assert_host_key_survived(&subkey, "RegDeleteKeyExW")
    }
}

/// Regression: `RegDeleteTreeW` walked and destroyed whole host subtrees unhooked.
fn delete_tree_does_not_reach_the_host() -> Result<(), String> {
    let tree = format!("{PROBE_ROOT}\\Tree");
    let child = format!("{tree}\\Child");

    unsafe {
        let (tree_key, _) = create_probe_key(&tree)?;
        let _ = RegCloseKey(tree_key);
        let (child_key, _) = create_probe_key(&child)?;
        let _ = RegCloseKey(child_key);

        let tree_wide = to_wide(&tree);
        let status = RegDeleteTreeW(HKEY_CURRENT_USER, tree_wide.as_ptr());
        if status != ERROR_SUCCESS {
            return Err(format!("RegDeleteTreeW failed with code {status}"));
        }

        // The RegDeleteTreeW contract: the subtree goes, the key itself stays.
        let child_wide = to_wide(&child);
        let mut probe_type = 0u32;
        let mut probe_len = 0u32;
        let masked = RegGetValueW(
            HKEY_CURRENT_USER,
            child_wide.as_ptr(),
            ptr::null(),
            RRF_RT_REG_SZ,
            &mut probe_type,
            ptr::null_mut(),
            &mut probe_len,
        );
        if masked != ERROR_FILE_NOT_FOUND {
            return Err(format!(
                "after RegDeleteTreeW the deleted child key still resolved (code {masked}); the subtree mask did not take effect"
            ));
        }

        // The host copies of both keys must have survived the virtualized delete.
        assert_host_key_survived(&child, "RegDeleteTreeW")?;
        assert_host_key_survived(&tree, "RegDeleteTreeW")
    }
}

/// The already-covered contract, kept last because it tombstones the whole probe subtree.
fn delete_key_does_not_reach_the_host() -> Result<(), String> {
    unsafe {
        let wide = to_wide(PROBE_ROOT);
        let status = RegDeleteKeyW(HKEY_CURRENT_USER, wide.as_ptr());
        if status != ERROR_SUCCESS {
            return Err(format!("RegDeleteKeyW failed with code {status}"));
        }

        assert_host_key_survived(PROBE_ROOT, "RegDeleteKeyW")
    }
}
