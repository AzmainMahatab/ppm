use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

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

static REGISTRY_STORE: OnceLock<VirtualRegistry> = OnceLock::new();

pub fn get_registry_store() -> &'static VirtualRegistry {
    REGISTRY_STORE.get_or_init(|| {
        let cfg = crate::paths::init_paths();
        VirtualRegistry::new(cfg.registry_json.clone())
    })
}

impl VirtualRegistry {
    pub fn new(path: PathBuf) -> Self {
        let data = if path.is_file() {
            if let Ok(content) = fs::read_to_string(&path) {
                serde_json::from_str(&content).unwrap_or_default()
            } else {
                VirtualRegistryData::default()
            }
        } else {
            VirtualRegistryData::default()
        };

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

        if let Some(val) = key_node.values.get(&norm_val) {
            if let Ok(bytes) = hex::decode(&val.data_hex) {
                return Some(Ok((val.val_type, bytes)));
            }
        }

        None
    }

    pub fn set_value(&self, key_path: &str, val_name: &str, val_type: u32, data: &[u8]) {
        let norm_key = Self::normalize_key(key_path);
        let norm_val = Self::normalize_val_name(val_name);
        let data_hex = hex::encode(data);

        {
            let mut reg_data = self.data.write();
            let key_node = reg_data
                .keys
                .entry(norm_key)
                .or_insert_with(|| SerializedKey {
                    values: HashMap::new(),
                    deleted_values: HashSet::new(),
                    is_tombstone: false,
                });

            key_node.is_tombstone = false;
            key_node.deleted_values.remove(&norm_val);
            key_node.values.insert(
                norm_val,
                SerializedValue {
                    val_type,
                    data_hex,
                },
            );
        }

        self.persist();
    }

    pub fn delete_value(&self, key_path: &str, val_name: &str) {
        let norm_key = Self::normalize_key(key_path);
        let norm_val = Self::normalize_val_name(val_name);

        {
            let mut reg_data = self.data.write();
            let key_node = reg_data
                .keys
                .entry(norm_key)
                .or_insert_with(|| SerializedKey {
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

            let key_node = reg_data
                .keys
                .entry(norm_key)
                .or_insert_with(|| SerializedKey {
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
            let key_node = reg_data
                .keys
                .entry(norm_key)
                .or_insert_with(|| SerializedKey {
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
        let json_str = {
            let data = self.data.read();
            serde_json::to_string_pretty(&*data).unwrap_or_default()
        };

        if !json_str.is_empty() {
            if let Some(parent) = self.path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&self.path, json_str);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_store_set_get_value() {
        let temp_dir = std::env::temp_dir().join(format!("ppm_test_reg_{}", std::process::id()));
        let reg_file = temp_dir.join("registry.json");
        let store = VirtualRegistry::new(reg_file.clone());

        // Set value
        let val_bytes = b"HelloVirtualWorld\0";
        store.set_value("HKCU\\Software\\MyApp", "Greeting", 1, val_bytes);

        // Get value
        let res = store.get_value("HKCU\\Software\\MyApp", "Greeting");
        assert!(res.is_some());
        let (val_type, bytes) = res.unwrap().expect("Value should exist and not be tombstoned");
        assert_eq!(val_type, 1);
        assert_eq!(bytes, val_bytes);

        // Delete value
        store.delete_value("HKCU\\Software\\MyApp", "Greeting");
        let res_deleted = store.get_value("HKCU\\Software\\MyApp", "Greeting");
        assert_eq!(res_deleted, Some(Err(()))); // Tombstoned / masked

        // Tombstone entire key
        store.delete_key("HKCU\\Software\\MyApp");
        assert!(store.is_key_tombstoned("HKCU\\Software\\MyApp"));

        // Clean up
        let _ = fs::remove_file(&reg_file);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
