use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HANDLE;

#[derive(Debug, Clone)]
pub struct VirtualHandleEntry {
    pub path: String,
    pub real_handle: Option<isize>,
    pub is_synthetic: bool,
}

pub struct VirtualHandleTable {
    next_synthetic_id: AtomicUsize,
    entries: RwLock<HashMap<usize, VirtualHandleEntry>>,
}

static HANDLE_TABLE: OnceLock<VirtualHandleTable> = OnceLock::new();

impl Default for VirtualHandleTable {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_handle_table() -> &'static VirtualHandleTable {
    HANDLE_TABLE.get_or_init(VirtualHandleTable::new)
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
                real_handle: None,
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
                real_handle: Some(real_handle as isize),
                is_synthetic: false,
            },
        );
    }

    /// Looks up the normalized key path for a given handle.
    pub fn get_path(&self, handle: HANDLE) -> Option<String> {
        if handle.is_null() {
            return None;
        }
        let h_val = handle as usize;
        if h_val == 0x80000001 || h_val == 0xFFFFFFFF80000001 {
            return Some("HKCU".to_string());
        }
        if h_val == 0x80000002 || h_val == 0xFFFFFFFF80000002 {
            return Some("HKLM".to_string());
        }
        if h_val == 0x80000000 || h_val == 0xFFFFFFFF80000000 {
            return Some("HKCR".to_string());
        }
        if h_val == 0x80000003 || h_val == 0xFFFFFFFF80000003 {
            return Some("HKU".to_string());
        }
        let map = self.entries.read();
        map.get(&h_val).map(|e| e.path.clone())
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
    fn test_virtual_handle_table_lifecycle() {
        let table = VirtualHandleTable::new();

        // 1. Test Synthetic Handle Registration
        let h1 = table.register_virtual_handle("HKCU\\Software\\App1".to_string());
        assert!(!h1.is_null());
        assert!(table.is_synthetic(h1));
        assert_eq!(table.get_path(h1), Some("HKCU\\Software\\App1".to_string()));

        // 2. Test Host Handle Registration
        let host_raw = 0x1234 as HANDLE;
        table.register_host_handle(host_raw, "HKLM\\Software\\App2".to_string());
        assert!(!table.is_synthetic(host_raw));
        assert_eq!(table.get_path(host_raw), Some("HKLM\\Software\\App2".to_string()));

        // 3. Test Handle Close
        let closed = table.close_handle(h1);
        assert!(closed.is_some());
        assert!(table.get_path(h1).is_none());
    }
}
