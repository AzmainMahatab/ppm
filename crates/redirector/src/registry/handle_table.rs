use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::HANDLE;

#[derive(Debug, Clone)]
pub struct VirtualHandleEntry {
    pub path: String,
    pub is_synthetic: bool,
}

// Predefined registry-key pseudo-handle values (Win32 HKEY_* constants).
const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
const HKEY_CURRENT_USER: u32 = 0x8000_0001;
const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
const HKEY_USERS: u32 = 0x8000_0003;
const HKEY_CURRENT_CONFIG: u32 = 0x8000_0005;

pub struct VirtualHandleTable {
    next_synthetic_id: AtomicUsize,
    entries: RwLock<HashMap<usize, VirtualHandleEntry>>,
}

static HANDLE_TABLE: LazyLock<VirtualHandleTable> = LazyLock::new(VirtualHandleTable::new);

impl Default for VirtualHandleTable {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_handle_table() -> &'static VirtualHandleTable {
    &HANDLE_TABLE
}

impl VirtualHandleTable {
    pub fn new() -> Self {
        VirtualHandleTable {
            next_synthetic_id: AtomicUsize::new(0x70000000),
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Allocates a new synthetic virtual handle ID.
    pub fn register_virtual_handle(&self, path: String) -> HANDLE {
        let id = self.next_synthetic_id.fetch_add(4, Ordering::SeqCst);
        let mut map = self.entries.write();
        map.insert(
            id,
            VirtualHandleEntry {
                path,
                is_synthetic: true,
            },
        );
        id as HANDLE
    }

    /// Associates a real host OS handle with a normalized registry path.
    pub fn register_host_handle(&self, real_handle: HANDLE, path: String) {
        if real_handle.is_null() {
            return;
        }
        let id = real_handle as usize;
        let mut map = self.entries.write();
        map.insert(
            id,
            VirtualHandleEntry {
                path,
                is_synthetic: false,
            },
        );
    }

    /// Looks up the normalized key path for a given handle.
    pub fn get_path(&self, handle: HANDLE) -> Option<String> {
        if handle.is_null() {
            return None;
        }
        let h_u32 = (handle as usize) as u32;
        let predefined = match h_u32 {
            HKEY_CLASSES_ROOT => "HKCR",
            HKEY_CURRENT_USER => "HKCU",
            HKEY_LOCAL_MACHINE => "HKLM",
            HKEY_USERS => "HKU",
            HKEY_CURRENT_CONFIG => "HKCC",
            _ => {
                let map = self.entries.read();
                return map.get(&(handle as usize)).map(|e| e.path.clone());
            }
        };
        Some(predefined.to_string())
    }

    /// Checks if a handle is a synthetic virtual handle.
    pub fn is_synthetic(&self, handle: HANDLE) -> bool {
        if handle.is_null() {
            return false;
        }
        let map = self.entries.read();
        map.get(&(handle as usize))
            .map(|e| e.is_synthetic)
            .unwrap_or(false)
    }

    /// Closes and removes a handle from tracking.
    pub fn close_handle(&self, handle: HANDLE) -> Option<VirtualHandleEntry> {
        if handle.is_null() {
            return None;
        }
        let mut map = self.entries.write();
        map.remove(&(handle as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predefined_pseudo_handles_map_to_canonical_hive_names() {
        let table = VirtualHandleTable::new();

        assert_eq!(
            table.get_path(HKEY_CLASSES_ROOT as HANDLE),
            Some("HKCR".to_string())
        );
        assert_eq!(
            table.get_path(HKEY_CURRENT_USER as HANDLE),
            Some("HKCU".to_string())
        );
        assert_eq!(
            table.get_path(HKEY_LOCAL_MACHINE as HANDLE),
            Some("HKLM".to_string())
        );
        assert_eq!(table.get_path(HKEY_USERS as HANDLE), Some("HKU".to_string()));
        assert_eq!(
            table.get_path(HKEY_CURRENT_CONFIG as HANDLE),
            Some("HKCC".to_string())
        );
    }

    #[test]
    fn virtual_handles_allocate_track_and_close() {
        let table = VirtualHandleTable::new();

        let h1 = table.register_virtual_handle("HKCU\\Software\\App1".to_string());
        assert!(!h1.is_null());
        assert!(table.is_synthetic(h1));
        assert_eq!(table.get_path(h1), Some("HKCU\\Software\\App1".to_string()));

        // Synthetic IDs advance by 4, never colliding or reusing the predefined range.
        let h2 = table.register_virtual_handle("HKCU\\Software\\App2".to_string());
        assert_eq!(h2 as usize - h1 as usize, 4);

        let host_raw = 0x1234 as HANDLE;
        table.register_host_handle(host_raw, "HKLM\\Software\\App2".to_string());
        assert!(!table.is_synthetic(host_raw));
        assert_eq!(table.get_path(host_raw), Some("HKLM\\Software\\App2".to_string()));

        let closed = table.close_handle(h1);
        assert!(closed.is_some());
        assert!(table.get_path(h1).is_none());
    }
}
