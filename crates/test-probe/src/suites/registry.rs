//! Registry Copy-on-Write boundary verification.
//!
//! # Where a host escape is detected
//! The probe runs under injection, so it cannot read the real registry to prove a write or a
//! delete never landed there. The harness that launches it can: before the run it seeds real
//! host keys under the root named by `PPM_TEST_REGISTRY_ROOT`, and afterwards it checks that the
//! seeded tree is exactly as it left it - nothing deleted, nothing changed, nothing added. From
//! inside, the probe asserts what the application sees: seeded host keys open as existing
//! keys, and keys it deletes disappear from its view.
//!
//! Seeded by the harness: the root (with a value), `DeleteKeyEx`, `Tree` and `Tree\Child` (each
//! with a value), and `Enumerated\Doomed` and `Enumerated\Kept` (no values).

use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegDeleteKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW,
    RegGetValueW, RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW,
};

use crate::support::{from_wide_ptr, to_wide};

mod ansi;

const REG_CREATED_NEW_KEY: u32 = 1;
const REG_OPENED_EXISTING_KEY: u32 = 2;

/// The HKCU-relative key the harness seeded for this run.
fn probe_root() -> Result<String, String> {
    std::env::var("PPM_TEST_REGISTRY_ROOT").map_err(|e| format!("PPM_TEST_REGISTRY_ROOT is not set: {e}"))
}

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 1/5] Registry Boundary (Copy-on-Write)...");
    let root = probe_root()?;

    copy_on_write_value_round_trip(&root)?;
    reg_get_value_with_subkey_reads_the_overlay(&root)?;
    delete_key_ex_is_virtualized(&root)?;
    delete_tree_is_virtualized(&root)?;
    enumeration_reflects_the_boundary(&root)?;
    ansi::run(&root)?;
    // Runs last: it tombstones the whole probe subtree.
    delete_key_is_virtualized(&root)?;

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

/// Asserts that creating the seeded `subkey` opens the host key the harness made: host keys
/// still show through the overlay.
unsafe fn assert_opens_seeded_key(subkey: &str) -> Result<(), String> {
    unsafe {
        let (hkey, disposition) = create_probe_key(subkey)?;
        let _ = RegCloseKey(hkey);

        if disposition != REG_OPENED_EXISTING_KEY {
            return Err(format!(
                "RegCreateKeyExW('{subkey}') reported disposition {disposition} for a key the host holds; expected REG_OPENED_EXISTING_KEY ({REG_OPENED_EXISTING_KEY})"
            ));
        }
        Ok(())
    }
}

/// Asserts that `subkey`, deleted through `deleting_api`, is gone from the application's view:
/// re-creating it makes a new key rather than reopening the host copy.
unsafe fn assert_deleted_in_view(subkey: &str, deleting_api: &str) -> Result<(), String> {
    unsafe {
        let (hkey, disposition) = create_probe_key(subkey)?;
        let _ = RegCloseKey(hkey);

        if disposition != REG_CREATED_NEW_KEY {
            return Err(format!(
                "after {deleting_api}, re-creating '{subkey}' reported disposition {disposition}; expected REG_CREATED_NEW_KEY ({REG_CREATED_NEW_KEY}) for a deleted key"
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
fn copy_on_write_value_round_trip(root: &str) -> Result<(), String> {
    unsafe {
        let (hkey, _) = create_probe_key(root)?;
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
fn reg_get_value_with_subkey_reads_the_overlay(root: &str) -> Result<(), String> {
    let subkey = format!("{root}\\GetValue");

    unsafe {
        let (hkey, disposition) = create_probe_key(&subkey)?;
        if disposition != REG_CREATED_NEW_KEY {
            let _ = RegCloseKey(hkey);
            return Err(format!(
                "RegCreateKeyExW('{subkey}') reported disposition {disposition} for a key that exists nowhere; expected REG_CREATED_NEW_KEY ({REG_CREATED_NEW_KEY})"
            ));
        }
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
fn delete_key_ex_is_virtualized(root: &str) -> Result<(), String> {
    let subkey = format!("{root}\\DeleteKeyEx");

    unsafe {
        assert_opens_seeded_key(&subkey)?;

        let wide = to_wide(&subkey);
        let status = RegDeleteKeyExW(HKEY_CURRENT_USER, wide.as_ptr(), KEY_ALL_ACCESS, 0);
        if status != ERROR_SUCCESS {
            return Err(format!("RegDeleteKeyExW failed with code {status}"));
        }

        assert_deleted_in_view(&subkey, "RegDeleteKeyExW")
    }
}

/// Regression: `RegDeleteTreeW` walked and destroyed whole host subtrees unhooked.
fn delete_tree_is_virtualized(root: &str) -> Result<(), String> {
    let tree = format!("{root}\\Tree");
    let child = format!("{tree}\\Child");

    unsafe {
        assert_opens_seeded_key(&tree)?;
        assert_opens_seeded_key(&child)?;

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

        // The tree key itself stays in view (with its subtree gone); the child does not.
        assert_opens_seeded_key(&tree).map_err(|e| format!("after RegDeleteTreeW: {e}"))?;
        assert_deleted_in_view(&child, "RegDeleteTreeW")
    }
}

/// Lists every value name an enumeration of `hkey` yields.
unsafe fn enumerate_value_names(hkey: HKEY) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    unsafe {
        for index in 0.. {
            let mut buffer = [0u16; 256];
            let mut length = buffer.len() as u32;
            let status = RegEnumValueW(
                hkey,
                index,
                buffer.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                return Err(format!("RegEnumValueW({index}) failed with code {status}"));
            }
            names.push(from_wide_ptr(buffer.as_ptr()));
        }
    }
    Ok(names)
}

/// Lists every subkey name an enumeration of `hkey` yields.
unsafe fn enumerate_subkey_names(hkey: HKEY) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    unsafe {
        for index in 0.. {
            let mut buffer = [0u16; 256];
            let mut length = buffer.len() as u32;
            let status = RegEnumKeyExW(
                hkey,
                index,
                buffer.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                return Err(format!("RegEnumKeyExW({index}) failed with code {status}"));
            }
            names.push(from_wide_ptr(buffer.as_ptr()));
        }
    }
    Ok(names)
}

/// Regression: value and key enumeration were never intercepted, so an application could write
/// a value through the boundary and then not see it when it enumerated its own key, and a key
/// it had deleted through the boundary kept appearing because the host copy survives by design.
fn enumeration_reflects_the_boundary(root: &str) -> Result<(), String> {
    let enum_key = format!("{root}\\Enumerated");
    let doomed = format!("{enum_key}\\Doomed");
    let kept = format!("{enum_key}\\Kept");

    unsafe {
        let (hkey, _) = create_probe_key(&enum_key)?;

        // Values written through the boundary live only in the overlay: the host key is empty,
        // so anything enumeration reports here came from the virtual store.
        let written =
            set_string_value(hkey, "ProxyServer", "on").and_then(|()| set_string_value(hkey, "Beta", "two"));
        if let Err(error) = written {
            let _ = RegCloseKey(hkey);
            return Err(error);
        }

        // Two host-backed children, one of which is then deleted through the boundary. The
        // host copy of the deleted one survives - that is the copy-on-write contract - so an
        // unfiltered host enumeration would still list it.
        for child in [&doomed, &kept] {
            let (child_key, _) = create_probe_key(child)?;
            let _ = RegCloseKey(child_key);
        }
        let doomed_wide = to_wide(&doomed);
        let status = RegDeleteKeyW(HKEY_CURRENT_USER, doomed_wide.as_ptr());
        if status != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!(
                "RegDeleteKeyW on the doomed child failed with code {status}"
            ));
        }

        let value_names = enumerate_value_names(hkey).inspect_err(|_| {
            let _ = RegCloseKey(hkey);
        })?;
        let subkey_names = enumerate_subkey_names(hkey).inspect_err(|_| {
            let _ = RegCloseKey(hkey);
        })?;

        // RegQueryInfoKeyW sizes the caller's buffers and bounds its loop, so it must agree
        // with the walk exactly - a larger count stops a caller early, a smaller one hides
        // entries it will never ask for.
        let mut reported_subkeys = 0u32;
        let mut reported_values = 0u32;
        let mut max_subkey_len = 0u32;
        let mut max_value_name_len = 0u32;
        let info_status = RegQueryInfoKeyW(
            hkey,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            &mut reported_subkeys,
            &mut max_subkey_len,
            ptr::null_mut(),
            &mut reported_values,
            &mut max_value_name_len,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let _ = RegCloseKey(hkey);
        if info_status != ERROR_SUCCESS {
            return Err(format!("RegQueryInfoKeyW failed with code {info_status}"));
        }

        // The overlay's own values must be visible to an enumeration of their key ...
        for expected in ["ProxyServer", "Beta"] {
            if !value_names.iter().any(|name| name == expected) {
                return Err(format!(
                    "value '{expected}' was written through the boundary but RegEnumValueW listed {value_names:?}: enumeration did not reach the virtual overlay"
                ));
            }
        }

        // ... spelled the way the application wrote them, not case-folded by the index.
        if !value_names.iter().any(|name| name == "ProxyServer") {
            return Err(format!(
                "RegEnumValueW returned {value_names:?}; the stored casing of 'ProxyServer' was lost"
            ));
        }

        // A key deleted through the boundary must not surface, even though its host copy lives.
        if subkey_names.iter().any(|name| name == "Doomed") {
            return Err(format!(
                "RegEnumKeyExW listed {subkey_names:?}: a key deleted through the boundary is still enumerated from the host"
            ));
        }
        if !subkey_names.iter().any(|name| name == "Kept") {
            return Err(format!(
                "RegEnumKeyExW listed {subkey_names:?}, missing the surviving child 'Kept'"
            ));
        }

        if reported_values as usize != value_names.len() {
            return Err(format!(
                "RegQueryInfoKeyW reported {reported_values} values but the walk yielded {}: an application would size its loop wrongly",
                value_names.len()
            ));
        }
        if reported_subkeys as usize != subkey_names.len() {
            return Err(format!(
                "RegQueryInfoKeyW reported {reported_subkeys} subkeys but the walk yielded {}",
                subkey_names.len()
            ));
        }

        // The reported maxima must cover every name the walk returns, or a caller sizing from
        // them truncates the very entries it is about to read.
        let longest_value = value_names
            .iter()
            .map(|name| name.chars().count())
            .max()
            .unwrap_or(0);
        let longest_subkey = subkey_names
            .iter()
            .map(|name| name.chars().count())
            .max()
            .unwrap_or(0);
        if (max_value_name_len as usize) < longest_value {
            return Err(format!(
                "RegQueryInfoKeyW reported a longest value name of {max_value_name_len} but the walk returned one of {longest_value}"
            ));
        }
        if (max_subkey_len as usize) < longest_subkey {
            return Err(format!(
                "RegQueryInfoKeyW reported a longest subkey of {max_subkey_len} but the walk returned one of {longest_subkey}"
            ));
        }
    }

    Ok(())
}

/// The already-covered contract, kept last because it tombstones the whole probe subtree.
fn delete_key_is_virtualized(root: &str) -> Result<(), String> {
    unsafe {
        let wide = to_wide(root);
        let status = RegDeleteKeyW(HKEY_CURRENT_USER, wide.as_ptr());
        if status != ERROR_SUCCESS {
            return Err(format!("RegDeleteKeyW failed with code {status}"));
        }

        assert_deleted_in_view(root, "RegDeleteKeyW")
    }
}
