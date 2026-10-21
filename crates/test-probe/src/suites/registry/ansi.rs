//! ANSI and legacy registry writes must land in the copy-on-write overlay, as their wide
//! counterparts do.
//!
//! # How a host escape is detected from inside the sandbox
//! The probe cannot read the real registry, so it reads the overlay journal
//! (`$PPM_ROOT\.ppm\system\registry.jsonl`), which records every virtualized write and mask in
//! plain text. A write with no journal record, yet visible through the hooked wide read, lives
//! in the host registry: unshadowed values fall through to it.
//!
//! # Host residue
//! Key creation still falls through to the host by design (see the registry suite), so this
//! suite leaves empty keys under `ANSI_ROOT`. No value reaches the host.

use std::fs;
use std::ptr;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegDeleteKeyValueA, RegDeleteKeyValueW, RegDeleteValueA, RegGetValueW, RegOpenKeyExA, RegSetKeyValueA,
    RegSetKeyValueW, RegSetValueA, RegSetValueExA, RegSetValueExW, RegSetValueW,
};

use crate::support::{to_ansi, to_wide};

const ANSI_ROOT: &str = "Software\\PPMTestProbe\\AnsiEntryPoints";

pub(super) fn run() -> Result<(), String> {
    let journal = journal_path()?;
    unsafe {
        ansi_writes_reach_the_overlay(&journal)?;
        ansi_deletes_mask_the_overlay(&journal)?;
    }
    Ok(())
}

fn journal_path() -> Result<String, String> {
    let root = std::env::var("PPM_ROOT").map_err(|e| format!("PPM_ROOT is not set: {e}"))?;
    Ok(format!("{root}\\.ppm\\system\\registry.jsonl"))
}

/// Whether the journal holds an `op` record (`set_value` or `delete_value`) that mentions `tag`.
fn journaled(journal: &str, op: &str, tag: &str) -> Result<bool, String> {
    let text = fs::read_to_string(journal).map_err(|e| format!("cannot read '{journal}': {e}"))?;
    Ok(text.lines().any(|line| line.contains(op) && line.contains(tag)))
}

/// Reads a string value through the hooked wide API; `None` when the value is absent.
unsafe fn visible_wide(subkey: &str, name: &str) -> Option<String> {
    unsafe {
        let subkey_w = to_wide(subkey);
        let name_w = to_wide(name);
        let mut buf = [0u16; 256];
        let mut len = (buf.len() * 2) as u32;
        let status = RegGetValueW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            name_w.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        );
        if status != ERROR_SUCCESS {
            return None;
        }
        let units = (len as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&buf[..units]))
    }
}

/// Opens (creating if needed) the probe's ANSI test key through the wide API.
unsafe fn open_root() -> Result<HKEY, String> {
    unsafe {
        let root = to_wide(ANSI_ROOT);
        let mut hkey: HKEY = ptr::null_mut();
        let mut disposition = 0;
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            root.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            ptr::null_mut(),
            &mut hkey,
            &mut disposition,
        );
        if status != ERROR_SUCCESS {
            return Err(format!(
                "RegCreateKeyExW('{ANSI_ROOT}') failed with code {status}"
            ));
        }
        Ok(hkey)
    }
}

/// Asserts that a write reported success, is journaled as an overlay `set_value` for `tag`, and
/// reads back through the wide API as `tag`. `visible` is that wide read's result.
fn assert_overlay_write(
    api: &str,
    status: u32,
    journal: &str,
    tag: &str,
    visible: Option<String>,
) -> Result<(), String> {
    if status != ERROR_SUCCESS {
        return Err(format!("{api} failed with code {status}"));
    }
    if !journaled(journal, "set_value", tag)? {
        return Err(format!(
            "{api} wrote '{tag}' to the host registry: the overlay journal has no set_value record for it"
        ));
    }
    if visible.as_deref() != Some(tag) {
        return Err(format!(
            "{api} wrote '{tag}', but the wide read returns {visible:?}"
        ));
    }
    Ok(())
}

unsafe fn ansi_writes_reach_the_overlay(journal: &str) -> Result<(), String> {
    unsafe {
        let parent = open_root()?;
        let name_virtual = to_ansi("ansi_setvalueexa_virtual").ok_or("name is not ANSI-encodable")?;
        let data_virtual = to_ansi("ansi_setvalueexa_virtual").ok_or("data is not ANSI-encodable")?;
        let status = RegSetValueExA(
            parent,
            name_virtual.as_ptr(),
            0,
            REG_SZ,
            data_virtual.as_ptr(),
            data_virtual.len() as u32,
        );
        assert_overlay_write(
            "RegSetValueExA (virtual handle)",
            status,
            journal,
            "ansi_setvalueexa_virtual",
            visible_wide(ANSI_ROOT, "ansi_setvalueexa_virtual"),
        )?;

        let root_a = to_ansi(ANSI_ROOT).ok_or("root is not ANSI-encodable")?;
        let mut opened: HKEY = ptr::null_mut();
        let open_status = RegOpenKeyExA(HKEY_CURRENT_USER, root_a.as_ptr(), 0, KEY_ALL_ACCESS, &mut opened);
        if open_status != ERROR_SUCCESS {
            return Err(format!("RegOpenKeyExA failed with code {open_status}"));
        }
        let name_open = to_ansi("ansi_setvalueexa_open").ok_or("name is not ANSI-encodable")?;
        let data_open = to_ansi("ansi_setvalueexa_open").ok_or("data is not ANSI-encodable")?;
        let status = RegSetValueExA(
            opened,
            name_open.as_ptr(),
            0,
            REG_SZ,
            data_open.as_ptr(),
            data_open.len() as u32,
        );
        let _ = RegCloseKey(opened);
        assert_overlay_write(
            "RegSetValueExA (RegOpenKeyExA handle)",
            status,
            journal,
            "ansi_setvalueexa_open",
            visible_wide(ANSI_ROOT, "ansi_setvalueexa_open"),
        )?;

        let name_key = to_ansi("ansi_setkeyvaluea").ok_or("name is not ANSI-encodable")?;
        let data_key = to_ansi("ansi_setkeyvaluea").ok_or("data is not ANSI-encodable")?;
        let status = RegSetKeyValueA(
            HKEY_CURRENT_USER,
            root_a.as_ptr(),
            name_key.as_ptr(),
            REG_SZ,
            data_key.as_ptr().cast(),
            data_key.len() as u32,
        );
        assert_overlay_write(
            "RegSetKeyValueA",
            status,
            journal,
            "ansi_setkeyvaluea",
            visible_wide(ANSI_ROOT, "ansi_setkeyvaluea"),
        )?;

        let name_wide = to_wide("wide_setkeyvaluew");
        let data_wide = to_wide("wide_setkeyvaluew");
        let root_w = to_wide(ANSI_ROOT);
        let status = RegSetKeyValueW(
            HKEY_CURRENT_USER,
            root_w.as_ptr(),
            name_wide.as_ptr(),
            REG_SZ,
            data_wide.as_ptr().cast(),
            (data_wide.len() * 2) as u32,
        );
        assert_overlay_write(
            "RegSetKeyValueW",
            status,
            journal,
            "wide_setkeyvaluew",
            visible_wide(ANSI_ROOT, "wide_setkeyvaluew"),
        )?;

        // The legacy default-value writers store under the subkey they are given, named "".
        let default_w = format!("{ANSI_ROOT}\\defval_w");
        let default_w_wide = to_wide(&default_w);
        let data_default_w = to_wide("defval_w");
        let status = RegSetValueW(
            HKEY_CURRENT_USER,
            default_w_wide.as_ptr(),
            REG_SZ,
            data_default_w.as_ptr(),
            (data_default_w.len() * 2) as u32,
        );
        assert_overlay_write(
            "RegSetValueW",
            status,
            journal,
            "defval_w",
            visible_wide(&default_w, ""),
        )?;

        let default_a = format!("{ANSI_ROOT}\\defval_a");
        let default_a_ansi = to_ansi(&default_a).ok_or("key is not ANSI-encodable")?;
        let data_default_a = to_ansi("defval_a").ok_or("data is not ANSI-encodable")?;
        let status = RegSetValueA(
            HKEY_CURRENT_USER,
            default_a_ansi.as_ptr(),
            REG_SZ,
            data_default_a.as_ptr(),
            data_default_a.len() as u32,
        );
        assert_overlay_write(
            "RegSetValueA",
            status,
            journal,
            "defval_a",
            visible_wide(&default_a, ""),
        )?;

        let _ = RegCloseKey(parent);
    }
    Ok(())
}

/// Seeds `tag` as an overlay value through the wide API, so a later ANSI delete has something
/// to mask.
unsafe fn seed_wide_value(parent: HKEY, tag: &str) -> Result<(), String> {
    unsafe {
        let name = to_wide(tag);
        let data = to_wide(tag);
        let status = RegSetValueExW(
            parent,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        );
        if status != ERROR_SUCCESS {
            return Err(format!(
                "seeding '{tag}' through RegSetValueExW failed with code {status}"
            ));
        }
    }
    Ok(())
}

/// Asserts that a delete reported success, is journaled as an overlay `delete_value` for `tag`,
/// and leaves the wide read with no value.
unsafe fn assert_overlay_delete(
    api: &str,
    status: u32,
    journal: &str,
    tag: &str,
    subkey: &str,
) -> Result<(), String> {
    if status != ERROR_SUCCESS {
        return Err(format!("{api} failed with code {status}"));
    }
    if !journaled(journal, "delete_value", tag)? {
        return Err(format!(
            "{api} deleted '{tag}' from the host registry: the overlay journal has no delete_value record"
        ));
    }
    let still = unsafe { visible_wide(subkey, tag) };
    if still.is_some() {
        return Err(format!(
            "{api} left '{tag}' visible through the wide read: the overlay did not mask it"
        ));
    }
    Ok(())
}

unsafe fn ansi_deletes_mask_the_overlay(journal: &str) -> Result<(), String> {
    unsafe {
        let parent = open_root()?;
        let root_a = to_ansi(ANSI_ROOT).ok_or("root is not ANSI-encodable")?;
        let root_w = to_wide(ANSI_ROOT);

        seed_wide_value(parent, "del_valuea")?;
        let name_a = to_ansi("del_valuea").ok_or("name is not ANSI-encodable")?;
        let status = RegDeleteValueA(parent, name_a.as_ptr());
        assert_overlay_delete("RegDeleteValueA", status, journal, "del_valuea", ANSI_ROOT)?;

        seed_wide_value(parent, "del_keyvaluea")?;
        let name_key_a = to_ansi("del_keyvaluea").ok_or("name is not ANSI-encodable")?;
        let status = RegDeleteKeyValueA(HKEY_CURRENT_USER, root_a.as_ptr(), name_key_a.as_ptr());
        assert_overlay_delete("RegDeleteKeyValueA", status, journal, "del_keyvaluea", ANSI_ROOT)?;

        seed_wide_value(parent, "del_keyvaluew")?;
        let name_key_w = to_wide("del_keyvaluew");
        let status = RegDeleteKeyValueW(HKEY_CURRENT_USER, root_w.as_ptr(), name_key_w.as_ptr());
        assert_overlay_delete("RegDeleteKeyValueW", status, journal, "del_keyvaluew", ANSI_ROOT)?;

        let _ = RegCloseKey(parent);
    }
    Ok(())
}
