use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedValue {
    pub val_type: u32,
    pub data_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedKey {
    pub values: HashMap<String, SerializedValue>,
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub deleted_values: HashSet<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_tombstone: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirtualRegistryData {
    pub keys: HashMap<String, SerializedKey>,
}

pub struct VirtualRegistry {
    path: PathBuf,
    data: RwLock<VirtualRegistryData>,
}

static REGISTRY_STORE: LazyLock<VirtualRegistry> = LazyLock::new(|| {
    let cfg = crate::paths::init_paths();
    VirtualRegistry::new(cfg.registry_json.clone())
});

pub fn get_registry_store() -> &'static VirtualRegistry {
    &REGISTRY_STORE
}

impl VirtualRegistry {
    pub fn new(path: PathBuf) -> Self {
        let data = crate::persist::load_state(&path, "registry");

        VirtualRegistry {
            path,
            data: RwLock::new(data),
        }
    }

    fn normalize_key(key: &str) -> String {
        key.trim_matches('\\').to_uppercase()
    }

    fn normalize_val_name(val_name: &str) -> String {
        val_name.to_lowercase()
    }

    pub fn get_value(&self, key_path: &str, val_name: &str) -> Option<Result<(u32, Vec<u8>), ()>> {
        let norm_key = Self::normalize_key(key_path);
        let norm_val = Self::normalize_val_name(val_name);

        let data = self.data.read();
        let key_node = data.keys.get(&norm_key)?;

        if key_node.is_tombstone {
            return Some(Err(()));
        }

        if key_node.deleted_values.contains(&norm_val) {
            return Some(Err(()));
        }

        if let Some(val) = key_node.values.get(&norm_val)
            && let Ok(bytes) = hex::decode(&val.data_hex)
        {
            return Some(Ok((val.val_type, bytes)));
        }

        None
    }

    pub fn set_value(&self, key_path: &str, val_name: &str, val_type: u32, data: &[u8]) {
        let norm_key = Self::normalize_key(key_path);
        let norm_val = Self::normalize_val_name(val_name);
        let data_hex = hex::encode(data);

        {
            let mut reg_data = self.data.write();
            let key_node = reg_data.keys.entry(norm_key).or_insert_with(|| SerializedKey {
                values: HashMap::new(),
                deleted_values: HashSet::new(),
                is_tombstone: false,
            });

            key_node.is_tombstone = false;
            key_node.deleted_values.remove(&norm_val);
            key_node
                .values
                .insert(norm_val, SerializedValue { val_type, data_hex });
        }

        self.persist();
    }

    pub fn delete_value(&self, key_path: &str, val_name: &str) {
        let norm_key = Self::normalize_key(key_path);
        let norm_val = Self::normalize_val_name(val_name);

        {
            let mut reg_data = self.data.write();
            let key_node = reg_data.keys.entry(norm_key).or_insert_with(|| SerializedKey {
                values: HashMap::new(),
                deleted_values: HashSet::new(),
                is_tombstone: false,
            });

            key_node.values.remove(&norm_val);
            key_node.deleted_values.insert(norm_val);
        }

        self.persist();
    }

    pub fn key_exists(&self, key_path: &str) -> bool {
        let norm_key = Self::normalize_key(key_path);
        let data = self.data.read();
        if let Some(node) = data.keys.get(&norm_key) {
            !node.is_tombstone
        } else {
            false
        }
    }

    pub fn delete_key(&self, key_path: &str) {
        let norm_key = Self::normalize_key(key_path);

        {
            let mut reg_data = self.data.write();
            let prefix = format!("{}\\", norm_key);

            for (k, v) in reg_data.keys.iter_mut() {
                if k == &norm_key || k.starts_with(&prefix) {
                    v.is_tombstone = true;
                    v.values.clear();
                }
            }

            let key_node = reg_data.keys.entry(norm_key).or_insert_with(|| SerializedKey {
                values: HashMap::new(),
                deleted_values: HashSet::new(),
                is_tombstone: true,
            });
            key_node.is_tombstone = true;
        }

        self.persist();
    }

    pub fn create_key(&self, key_path: &str) {
        let norm_key = Self::normalize_key(key_path);

        {
            let mut reg_data = self.data.write();
            let key_node = reg_data.keys.entry(norm_key).or_insert_with(|| SerializedKey {
                values: HashMap::new(),
                deleted_values: HashSet::new(),
                is_tombstone: false,
            });
            key_node.is_tombstone = false;
        }

        self.persist();
    }

    pub fn is_key_tombstoned(&self, key_path: &str) -> bool {
        let norm_key = Self::normalize_key(key_path);
        let data = self.data.read();
        data.keys.get(&norm_key).map(|k| k.is_tombstone).unwrap_or(false)
    }

    fn persist(&self) {
        let data = self.data.read();
        crate::persist::persist_state(&self.path, &*data, "registry");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_state_survives_a_full_disk_round_trip() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let reg_file = temp_dir.path().join("registry.json");

        {
            let store = VirtualRegistry::new(reg_file.clone());
            store.set_value("HKCU\\Software\\MyApp", "Greeting", 1, b"HelloVirtualWorld\0");
            store.set_value("HKCU\\Software\\MyApp", "Deleted", 2, b"x");
            store.set_value("HKCU\\Software\\Other", "Keep", 3, b"ok");
            store.delete_value("HKCU\\Software\\MyApp", "Deleted");
            store.delete_key("HKCU\\Software\\Gone");
        }
        // `store` is dropped: the on-disk hive is the only state left.

        let reopened = VirtualRegistry::new(reg_file.clone());

        // Surviving values round-trip with type and bytes intact.
        let (val_type, bytes) = reopened
            .get_value("hkcu\\software\\myapp", "GREETING")
            .unwrap()
            .expect("value should survive the reload");
        assert_eq!(val_type, 1);
        assert_eq!(bytes, b"HelloVirtualWorld\0");

        // Normalization must be stable across the reload.
        let (val_type2, _) = reopened
            .get_value("HKCU\\SOFTWARE\\MYAPP", "greeting")
            .unwrap()
            .expect("normalization must be stable across reloads");
        assert_eq!(val_type2, 1);

        // Value-level and key-level tombstones survive the reload.
        assert_eq!(
            reopened.get_value("HKCU\\Software\\MyApp", "Deleted"),
            Some(Err(()))
        );
        assert!(reopened.is_key_tombstoned("HKCU\\Software\\Gone"));

        // Unrelated keys remain intact.
        let (keep_type, keep_bytes) = reopened
            .get_value("HKCU\\Software\\Other", "Keep")
            .unwrap()
            .expect("unrelated key should survive");
        assert_eq!(keep_type, 3);
        assert_eq!(keep_bytes, b"ok");

        // The on-disk hive carries the canonical serialized shape.
        let on_disk = std::fs::read_to_string(&reg_file).expect("registry.json must exist");
        assert!(on_disk.contains("MYAPP"));
        assert!(on_disk.contains(&hex::encode(b"HelloVirtualWorld\0")));
        assert!(on_disk.contains("is_tombstone"));
        assert!(on_disk.contains("deleted_values"));
    }
}
