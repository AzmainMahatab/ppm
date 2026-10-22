//! ANSI and legacy registry writes must land in the copy-on-write overlay, as their wide
//! counterparts do.
//!
//! # How a host escape is detected from inside the sandbox
//! The probe cannot read the real registry, so it reads the overlay journal
//! (`$PPM_ROOT\.ppm\system\registry.jsonl`), which records every virtualized write and mask in
//! plain text. A write with no journal record, yet visible through the hooked wide read, lives
//! in the host registry: unshadowed values fall through to it.
//!
//! Every key lives under `AnsiEntryPoints` below the harness-seeded probe root; the harness
//! checks afterwards that none of them reached the host.

use std::fs;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegCreateKeyW, RegDeleteKeyValueA, RegDeleteKeyValueW, RegDeleteValueA, RegEnumKeyExA, RegEnumValueA,
    RegGetValueA, RegGetValueW, RegOpenKeyExA, RegOpenKeyW, RegQueryInfoKeyA, RegQueryValueExA,
    RegSetKeyValueA, RegSetKeyValueW, RegSetValueA, RegSetValueExA, RegSetValueExW, RegSetValueW,
};

use crate::support::{to_ansi, to_wide};

pub(super) fn run(probe_root: &str) -> Result<(), String> {
    let ansi_root = &format!("{probe_root}\\AnsiEntryPoints");
    let journal = journal_path()?;
    unsafe {
        ansi_writes_reach_the_overlay(ansi_root, &journal)?;
        ansi_deletes_mask_the_overlay(ansi_root, &journal)?;
        ansi_reads_see_the_overlay(ansi_root)?;
        ansi_enumerations_list_the_overlay(ansi_root)?;
        legacy_handles_and_info_see_the_overlay(ansi_root, &journal)?;
        // Last: it adds values under the root, which the info check above counts exactly.
        non_ascii_text_crosses_the_code_page(ansi_root)?;
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
unsafe fn open_root(ansi_root: &str) -> Result<HKEY, String> {
    unsafe {
        let root = to_wide(ansi_root);
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
                "RegCreateKeyExW('{ansi_root}') failed with code {status}"
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

unsafe fn ansi_writes_reach_the_overlay(ansi_root: &str, journal: &str) -> Result<(), String> {
    unsafe {
        let parent = open_root(ansi_root)?;
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
            visible_wide(ansi_root, "ansi_setvalueexa_virtual"),
        )?;

        let root_a = to_ansi(ansi_root).ok_or("root is not ANSI-encodable")?;
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
            visible_wide(ansi_root, "ansi_setvalueexa_open"),
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
            visible_wide(ansi_root, "ansi_setkeyvaluea"),
        )?;

        let name_wide = to_wide("wide_setkeyvaluew");
        let data_wide = to_wide("wide_setkeyvaluew");
        let root_w = to_wide(ansi_root);
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
            visible_wide(ansi_root, "wide_setkeyvaluew"),
        )?;

        // The legacy default-value writers store under the subkey they are given, named "".
        let default_w = format!("{ansi_root}\\defval_w");
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

        let default_a = format!("{ansi_root}\\defval_a");
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

unsafe fn ansi_deletes_mask_the_overlay(ansi_root: &str, journal: &str) -> Result<(), String> {
    unsafe {
        let parent = open_root(ansi_root)?;
        let root_a = to_ansi(ansi_root).ok_or("root is not ANSI-encodable")?;
        let root_w = to_wide(ansi_root);

        seed_wide_value(parent, "del_valuea")?;
        let name_a = to_ansi("del_valuea").ok_or("name is not ANSI-encodable")?;
        let status = RegDeleteValueA(parent, name_a.as_ptr());
        assert_overlay_delete("RegDeleteValueA", status, journal, "del_valuea", ansi_root)?;

        seed_wide_value(parent, "del_keyvaluea")?;
        let name_key_a = to_ansi("del_keyvaluea").ok_or("name is not ANSI-encodable")?;
        let status = RegDeleteKeyValueA(HKEY_CURRENT_USER, root_a.as_ptr(), name_key_a.as_ptr());
        assert_overlay_delete("RegDeleteKeyValueA", status, journal, "del_keyvaluea", ansi_root)?;

        seed_wide_value(parent, "del_keyvaluew")?;
        let name_key_w = to_wide("del_keyvaluew");
        let status = RegDeleteKeyValueW(HKEY_CURRENT_USER, root_w.as_ptr(), name_key_w.as_ptr());
        assert_overlay_delete("RegDeleteKeyValueW", status, journal, "del_keyvaluew", ansi_root)?;

        let _ = RegCloseKey(parent);
    }
    Ok(())
}

/// The ANSI read entry points must return what the overlay holds for values the write paths
/// stored, or an application that writes and reads through the ANSI API sees host data.
unsafe fn ansi_reads_see_the_overlay(ansi_root: &str) -> Result<(), String> {
    unsafe {
        let root_a = to_ansi(ansi_root).ok_or("root is not ANSI-encodable")?;
        let mut opened: HKEY = ptr::null_mut();
        let status = RegOpenKeyExA(HKEY_CURRENT_USER, root_a.as_ptr(), 0, KEY_ALL_ACCESS, &mut opened);
        if status != ERROR_SUCCESS {
            return Err(format!("RegOpenKeyExA failed with code {status}"));
        }

        let name = to_ansi("ansi_setvalueexa_virtual").ok_or("name is not ANSI-encodable")?;
        let mut buf = [0u8; 256];
        let mut len = buf.len() as u32;
        let mut value_type = 0u32;
        let status = RegQueryValueExA(
            opened,
            name.as_ptr(),
            ptr::null_mut(),
            &mut value_type,
            buf.as_mut_ptr(),
            &mut len,
        );
        let _ = RegCloseKey(opened);
        if status != ERROR_SUCCESS {
            return Err(format!(
                "RegQueryValueExA('ansi_setvalueexa_virtual') failed with code {status}"
            ));
        }
        let read = ansi_text(&buf[..len as usize]);
        if read != "ansi_setvalueexa_virtual" {
            return Err(format!("RegQueryValueExA returned '{read}' for an overlay value"));
        }

        let key_name = to_ansi("ansi_setkeyvaluea").ok_or("name is not ANSI-encodable")?;
        let mut get_buf = [0u8; 256];
        let mut get_len = get_buf.len() as u32;
        let status = RegGetValueA(
            HKEY_CURRENT_USER,
            root_a.as_ptr(),
            key_name.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            get_buf.as_mut_ptr().cast(),
            &mut get_len,
        );
        if status != ERROR_SUCCESS {
            return Err(format!(
                "RegGetValueA('ansi_setkeyvaluea') failed with code {status}"
            ));
        }
        let read = ansi_text(&get_buf[..get_len as usize]);
        if read != "ansi_setkeyvaluea" {
            return Err(format!("RegGetValueA returned '{read}' for an overlay value"));
        }
    }
    Ok(())
}

/// Legacy entry points that open keys by wide name must hand back a handle the engine tracks, so
/// ANSI calls through it reach the overlay; `RegQueryInfoKeyA` must count what the overlay holds.
unsafe fn legacy_handles_and_info_see_the_overlay(ansi_root: &str, journal: &str) -> Result<(), String> {
    unsafe {
        let root_w = to_wide(ansi_root);
        let mut opened: HKEY = ptr::null_mut();
        let status = RegOpenKeyW(HKEY_CURRENT_USER, root_w.as_ptr(), &mut opened);
        if status != ERROR_SUCCESS {
            return Err(format!("RegOpenKeyW failed with code {status}"));
        }

        let name = to_ansi("ansi_setvalueexa_virtual").ok_or("name is not ANSI-encodable")?;
        let mut buf = [0u8; 256];
        let mut len = buf.len() as u32;
        let status = RegQueryValueExA(
            opened,
            name.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut len,
        );
        if status != ERROR_SUCCESS {
            let _ = RegCloseKey(opened);
            return Err(format!(
                "RegQueryValueExA through a RegOpenKeyW handle failed with code {status}"
            ));
        }
        let read = ansi_text(&buf[..len as usize]);
        if read != "ansi_setvalueexa_virtual" {
            let _ = RegCloseKey(opened);
            return Err(format!(
                "RegQueryValueExA through a RegOpenKeyW handle returned '{read}'"
            ));
        }

        // Live values under the root: the four written by the write tests. The deleted ones are
        // masked and not listed. The longest name is 'ansi_setvalueexa_virtual'.
        let mut values = 0u32;
        let mut max_value_name = 0u32;
        let status = RegQueryInfoKeyA(
            opened,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut values,
            &mut max_value_name,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let _ = RegCloseKey(opened);
        if status != ERROR_SUCCESS {
            return Err(format!("RegQueryInfoKeyA failed with code {status}"));
        }
        if values != 4 {
            return Err(format!("RegQueryInfoKeyA reports {values} values; expected 4"));
        }
        if max_value_name != 24 {
            return Err(format!(
                "RegQueryInfoKeyA reports a longest value name of {max_value_name} bytes; expected 24"
            ));
        }

        let created_path = format!("{ansi_root}\\legacy_created");
        let created_w = to_wide(&created_path);
        let mut created: HKEY = ptr::null_mut();
        let status = RegCreateKeyW(HKEY_CURRENT_USER, created_w.as_ptr(), &mut created);
        if status != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyW failed with code {status}"));
        }
        let name = to_ansi("ansi_legacy_create").ok_or("name is not ANSI-encodable")?;
        let data = to_ansi("ansi_legacy_create").ok_or("data is not ANSI-encodable")?;
        let status = RegSetValueExA(
            created,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr(),
            data.len() as u32,
        );
        let _ = RegCloseKey(created);
        assert_overlay_write(
            "RegSetValueExA (RegCreateKeyW handle)",
            status,
            journal,
            "ansi_legacy_create",
            visible_wide(&created_path, "ansi_legacy_create"),
        )
    }
}

/// Decodes an ANSI `REG_SZ` payload the caller read back, dropping its terminator.
fn ansi_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// The ANSI enumeration entry points must list the overlay's values and subkeys, or an
/// application that enumerates through the ANSI API misses what it wrote.
unsafe fn ansi_enumerations_list_the_overlay(ansi_root: &str) -> Result<(), String> {
    unsafe {
        let root_a = to_ansi(ansi_root).ok_or("root is not ANSI-encodable")?;
        let mut opened: HKEY = ptr::null_mut();
        let status = RegOpenKeyExA(HKEY_CURRENT_USER, root_a.as_ptr(), 0, KEY_ALL_ACCESS, &mut opened);
        if status != ERROR_SUCCESS {
            return Err(format!("RegOpenKeyExA failed with code {status}"));
        }

        let mut values = Vec::new();
        for index in 0.. {
            let mut name = [0u8; 256];
            let mut name_len = name.len() as u32;
            let status = RegEnumValueA(
                opened,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                let _ = RegCloseKey(opened);
                return Err(format!("RegEnumValueA({index}) failed with code {status}"));
            }
            values.push(ansi_text(&name[..name_len as usize]));
        }

        let mut subkeys = Vec::new();
        for index in 0.. {
            let mut name = [0u8; 256];
            let mut name_len = name.len() as u32;
            let status = RegEnumKeyExA(
                opened,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                let _ = RegCloseKey(opened);
                return Err(format!("RegEnumKeyExA({index}) failed with code {status}"));
            }
            subkeys.push(ansi_text(&name[..name_len as usize]));
        }
        let _ = RegCloseKey(opened);

        if !values.iter().any(|v| v == "ansi_setvalueexa_virtual") {
            return Err(format!(
                "RegEnumValueA omits the overlay value 'ansi_setvalueexa_virtual': listed {values:?}"
            ));
        }
        if !subkeys.iter().any(|k| k == "defval_a") {
            return Err(format!(
                "RegEnumKeyExA omits the overlay subkey 'defval_a': listed {subkeys:?}"
            ));
        }
        // A deleted value is masked: listing it would show the application data it removed.
        for deleted in ["del_valuea", "del_keyvaluea", "del_keyvaluew"] {
            if values.iter().any(|v| v == deleted) {
                return Err(format!(
                    "RegEnumValueA lists the deleted value '{deleted}': listed {values:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Non-ASCII text the system ANSI code page can represent: one sample per common code page
/// (Western and Central European, Cyrillic, Greek, Hebrew, Arabic, Thai, Vietnamese, CJK), so the
/// check runs on any locale.
fn code_page_sample() -> Result<String, String> {
    ["café", "жук", "Ωμέγα", "שלום", "عربي", "ไทย", "ăn", "日本"]
        .into_iter()
        .find(|sample| to_ansi(sample).is_some())
        .map(str::to_string)
        .ok_or_else(|| "no non-ASCII sample is representable in the system ANSI code page".to_string())
}

/// Text written through one API family must read back through the other unchanged, which only
/// holds if the engine converts between UTF-16 and the system ANSI code page - not UTF-8, and
/// not raw UTF-16 bytes. ASCII text cannot tell those apart; this sample can.
unsafe fn non_ascii_text_crosses_the_code_page(ansi_root: &str) -> Result<(), String> {
    let sample = code_page_sample()?;
    let sample_ansi = to_ansi(&sample).ok_or("sample was chosen as ANSI-representable")?;
    unsafe {
        let parent = open_root(ansi_root)?;

        // Wide write, ANSI read: the engine encodes the stored UTF-16 into the code page.
        let name_w = to_wide("nonascii_wide_written");
        let data_w = to_wide(&sample);
        let status = RegSetValueExW(
            parent,
            name_w.as_ptr(),
            0,
            REG_SZ,
            data_w.as_ptr().cast(),
            (data_w.len() * 2) as u32,
        );
        if status != ERROR_SUCCESS {
            let _ = RegCloseKey(parent);
            return Err(format!("RegSetValueExW('{sample}') failed with code {status}"));
        }
        let name_a = to_ansi("nonascii_wide_written").ok_or("name is not ANSI-encodable")?;
        let mut buf = [0u8; 256];
        let mut len = buf.len() as u32;
        let status = RegQueryValueExA(
            parent,
            name_a.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut len,
        );
        if status != ERROR_SUCCESS {
            let _ = RegCloseKey(parent);
            return Err(format!(
                "RegQueryValueExA of a non-ASCII value failed with code {status}"
            ));
        }
        if buf[..len as usize] != sample_ansi[..] {
            let _ = RegCloseKey(parent);
            return Err(format!(
                "RegQueryValueExA returned bytes {:02x?} for '{sample}'; the code page encodes it as {sample_ansi:02x?}",
                &buf[..len as usize]
            ));
        }

        // ANSI write, wide read: the engine decodes the code page into the stored UTF-16.
        let name_a = to_ansi("nonascii_ansi_written").ok_or("name is not ANSI-encodable")?;
        let status = RegSetValueExA(
            parent,
            name_a.as_ptr(),
            0,
            REG_SZ,
            sample_ansi.as_ptr(),
            sample_ansi.len() as u32,
        );
        let _ = RegCloseKey(parent);
        if status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExA('{sample}') failed with code {status}"));
        }
        let read = visible_wide(ansi_root, "nonascii_ansi_written");
        if read.as_deref() != Some(sample.as_str()) {
            return Err(format!(
                "an ANSI write of '{sample}' read back through the wide API as {read:?}"
            ));
        }
    }
    Ok(())
}
