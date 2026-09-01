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

/// What the engine knows about an incoming `HKEY`.
///
/// # Why this replaces `Option<String>`
/// Every hook used to resolve a handle with `get_path(...).unwrap_or_default()`, so a handle
/// the engine had never seen became the empty key path. Distinct unknown handles then all
/// addressed one anonymous overlay key: reads missed, writes accumulated somewhere no read
/// could reach, and the corruption was silent. Making the unknown case a variant forces every
/// hook to state its policy for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyScope {
    /// A predefined hive pseudo-handle, or a handle the engine watched being opened.
    ///
    /// `synthetic` marks a handle the engine fabricated for a key that exists only in the
    /// overlay. Such a handle has no host counterpart and must never reach a real registry API.
    Tracked { path: String, synthetic: bool },
    /// The engine never saw this handle open: it predates DLL attach, or it came from a
    /// registry entry point this engine does not intercept. Its key identity is unknowable,
    /// so no operation on it can be virtualized.
    Untracked,
}

// Predefined registry-key pseudo-handle values (Win32 HKEY_* constants).
const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
const HKEY_CURRENT_USER: u32 = 0x8000_0001;
const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
const HKEY_USERS: u32 = 0x8000_0003;
const HKEY_CURRENT_CONFIG: u32 = 0x8000_0005;

/// Maps a predefined pseudo-handle to its canonical hive name.
///
/// `HKEY_PERFORMANCE_*` is deliberately absent: performance data is a synthetic provider
/// namespace, not a persisted hive, so it stays `Untracked` and passes through to the host.
fn predefined_hive(handle: HANDLE) -> Option<&'static str> {
    match (handle as usize) as u32 {
        HKEY_CLASSES_ROOT => Some("HKCR"),
        HKEY_CURRENT_USER => Some("HKCU"),
        HKEY_LOCAL_MACHINE => Some("HKLM"),
        HKEY_USERS => Some("HKU"),
        HKEY_CURRENT_CONFIG => Some("HKCC"),
        _ => None,
    }
}

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

    /// Resolves what the engine knows about `handle` in a single lookup.
    pub fn resolve(&self, handle: HANDLE) -> KeyScope {
        if handle.is_null() {
            return KeyScope::Untracked;
        }
        if let Some(hive) = predefined_hive(handle) {
            return KeyScope::Tracked {
                path: hive.to_string(),
                synthetic: false,
            };
        }
        let map = self.entries.read();
        match map.get(&(handle as usize)) {
            Some(entry) => KeyScope::Tracked {
                path: entry.path.clone(),
                synthetic: entry.is_synthetic,
            },
            None => KeyScope::Untracked,
        }
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

    fn tracked(scope: KeyScope) -> (String, bool) {
        match scope {
            KeyScope::Tracked { path, synthetic } => (path, synthetic),
            KeyScope::Untracked => panic!("expected a tracked handle"),
        }
    }

    #[test]
    fn predefined_pseudo_handles_map_to_canonical_hive_names() {
        let table = VirtualHandleTable::new();

        for (handle, hive) in [
            (HKEY_CLASSES_ROOT, "HKCR"),
            (HKEY_CURRENT_USER, "HKCU"),
            (HKEY_LOCAL_MACHINE, "HKLM"),
            (HKEY_USERS, "HKU"),
            (HKEY_CURRENT_CONFIG, "HKCC"),
        ] {
            let (path, synthetic) = tracked(table.resolve(handle as HANDLE));
            assert_eq!(path, hive);
            assert!(!synthetic, "a predefined hive handle is a real host handle");
        }
    }

    #[test]
    fn virtual_handles_allocate_track_and_close() {
        let table = VirtualHandleTable::new();

        let h1 = table.register_virtual_handle("HKCU\\Software\\App1".to_string());
        assert!(!h1.is_null());
        let (path, synthetic) = tracked(table.resolve(h1));
        assert_eq!(path, "HKCU\\Software\\App1");
        assert!(synthetic);

        // Synthetic IDs advance by 4, never colliding or reusing the predefined range.
        let h2 = table.register_virtual_handle("HKCU\\Software\\App2".to_string());
        assert_eq!(h2 as usize - h1 as usize, 4);

        let host_raw = 0x1234 as HANDLE;
        table.register_host_handle(host_raw, "HKLM\\Software\\App2".to_string());
        let (host_path, host_synthetic) = tracked(table.resolve(host_raw));
        assert_eq!(host_path, "HKLM\\Software\\App2");
        assert!(!host_synthetic);

        let closed = table.close_handle(h1);
        assert!(closed.is_some());
        assert_eq!(table.resolve(h1), KeyScope::Untracked);
    }

    /// A handle the engine never watched being opened must be reported as unknown, not as
    /// the empty key path that the previous `unwrap_or_default()` shape produced.
    #[test]
    fn an_unseen_handle_resolves_as_untracked() {
        let table = VirtualHandleTable::new();

        assert_eq!(table.resolve(0x4321 as HANDLE), KeyScope::Untracked);
        assert_eq!(table.resolve(std::ptr::null_mut()), KeyScope::Untracked);
    }
}
