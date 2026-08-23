use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub target_name: String,
    pub user_name: String,
    pub credential_blob: Vec<u8>,
    pub cred_type: u32,
    pub flags: u32,
    pub persist: u32,
}

pub struct CredStore {
    creds: RwLock<HashMap<String, StoredCredential>>,
    allocations: RwLock<HashSet<usize>>,
}

static STORE: OnceLock<CredStore> = OnceLock::new();

pub fn get_store() -> &'static CredStore {
    STORE.get_or_init(|| {
        let mut map = HashMap::new();
        let cfg = crate::paths::init_paths();
        if cfg.credentials_file.exists() {
            if let Ok(data) = fs::read_to_string(&cfg.credentials_file) {
                if let Ok(loaded) = serde_json::from_str::<HashMap<String, StoredCredential>>(&data) {
                    map = loaded;
                }
            }
        }
        CredStore {
            creds: RwLock::new(map),
            allocations: RwLock::new(HashSet::new()),
        }
    })
}

fn save_store_atomic(file_path: &Path, map: &HashMap<String, StoredCredential>) {
    if let Ok(json) = serde_json::to_string_pretty(map) {
        let tmp_path = file_path.with_extension("tmp");
        if fs::write(&tmp_path, json).is_ok() {
            let _ = fs::rename(&tmp_path, file_path);
        }
    }
}

pub fn cred_write(cred: StoredCredential) -> bool {
    let store = get_store();
    let cfg = crate::paths::init_paths();
    let target = cred.target_name.clone();

    {
        let mut map = store.creds.write();
        map.insert(target, cred);
        save_store_atomic(&cfg.credentials_file, &map);
    }
    true
}

pub fn cred_delete(target_name: &str) -> bool {
    let store = get_store();
    let cfg = crate::paths::init_paths();

    let mut map = store.creds.write();
    if map.remove(target_name).is_some() {
        save_store_atomic(&cfg.credentials_file, &map);
        true
    } else {
        false
    }
}

pub fn cred_read(target_name: &str) -> Option<*mut c_void> {
    let store = get_store();
    let map = store.creds.read();
    let cred = map.get(target_name)?;

    // Construct contiguous memory block containing CREDENTIALW + wide strings + blob
    let target_w: Vec<u16> = cred.target_name.encode_utf16().chain(std::iter::once(0)).collect();
    let user_w: Vec<u16> = cred.user_name.encode_utf16().chain(std::iter::once(0)).collect();

    let struct_size = std::mem::size_of::<windows_sys::Win32::Security::Credentials::CREDENTIALW>();
    let target_bytes = target_w.len() * 2;
    let user_bytes = user_w.len() * 2;
    let blob_bytes = cred.credential_blob.len();

    let total_size = struct_size + target_bytes + user_bytes + blob_bytes;

    unsafe {
        let layout = std::alloc::Layout::from_size_align_unchecked(total_size, std::mem::align_of::<usize>());
        let mem = std::alloc::alloc_zeroed(layout);
        if mem.is_null() {
            return None;
        }

        let p_cred = mem as *mut windows_sys::Win32::Security::Credentials::CREDENTIALW;
        let mut cursor = mem.add(struct_size);

        // TargetName pointer
        let p_target = cursor as *mut u16;
        std::ptr::copy_nonoverlapping(target_w.as_ptr(), p_target, target_w.len());
        cursor = cursor.add(target_bytes);

        // UserName pointer
        let p_user = cursor as *mut u16;
        std::ptr::copy_nonoverlapping(user_w.as_ptr(), p_user, user_w.len());
        cursor = cursor.add(user_bytes);

        // CredentialBlob pointer
        let p_blob = cursor;
        if blob_bytes > 0 {
            std::ptr::copy_nonoverlapping(cred.credential_blob.as_ptr(), p_blob, blob_bytes);
        }

        // Fill CREDENTIALW struct
        (*p_cred).Flags = cred.flags;
        (*p_cred).Type = cred.cred_type;
        (*p_cred).TargetName = p_target;
        (*p_cred).Comment = std::ptr::null_mut();
        (*p_cred).CredentialBlobSize = blob_bytes as u32;
        (*p_cred).CredentialBlob = p_blob;
        (*p_cred).Persist = cred.persist;
        (*p_cred).AttributeCount = 0;
        (*p_cred).Attributes = std::ptr::null_mut();
        (*p_cred).TargetAlias = std::ptr::null_mut();
        (*p_cred).UserName = p_user;

        store.allocations.write().insert(mem as usize);
        Some(mem as *mut c_void)
    }
}

pub fn is_custom_allocation(ptr: *const c_void) -> bool {
    let store = get_store();
    store.allocations.read().contains(&(ptr as usize))
}

pub fn free_custom_allocation(ptr: *mut c_void) -> bool {
    let store = get_store();
    let mut allocs = store.allocations.write();
    if allocs.remove(&(ptr as usize)) {
        unsafe {
            // Memory layout size is variable, but dealloc with non-zero layout is safe or we can free
            let p_cred = ptr as *const windows_sys::Win32::Security::Credentials::CREDENTIALW;
            let target_len = if !(*p_cred).TargetName.is_null() {
                let mut l = 0;
                while *(*p_cred).TargetName.add(l) != 0 {
                    l += 1;
                }
                (l + 1) * 2
            } else {
                0
            };
            let user_len = if !(*p_cred).UserName.is_null() {
                let mut l = 0;
                while *(*p_cred).UserName.add(l) != 0 {
                    l += 1;
                }
                (l + 1) * 2
            } else {
                0
            };
            let blob_len = (*p_cred).CredentialBlobSize as usize;
            let struct_size = std::mem::size_of::<windows_sys::Win32::Security::Credentials::CREDENTIALW>();
            let total_size = struct_size + target_len + user_len + blob_len;

            let layout = std::alloc::Layout::from_size_align_unchecked(total_size, std::mem::align_of::<usize>());
            std::alloc::dealloc(ptr as *mut u8, layout);
        }
        true
    } else {
        false
    }
}
