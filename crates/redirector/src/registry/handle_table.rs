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

pub fn get_handle_table() -> &'static VirtualHandleTable {
    HANDLE_TABLE.get_or_init(|| VirtualHandleTable {
        next_synthetic_id: AtomicUsize::new(0x70000000),
        entries: RwLock::new(HashMap::new()),
    })
}

impl VirtualHandleTable {
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
        let map = self.entries.read();
        map.get(&(handle as usize)).map(|e| e.path.clone())
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
