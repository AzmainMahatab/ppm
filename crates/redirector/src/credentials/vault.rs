use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCredential {
    pub target_name: String,
    pub cred_type: u32,
    pub user_name: String,
    pub credential_blob_hex: String,
    pub persist: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    pub credentials: HashMap<String, VaultCredential>,
}

pub struct CredentialVault {
    path: PathBuf,
    data: RwLock<VaultData>,
}

static VAULT: OnceLock<CredentialVault> = OnceLock::new();

pub fn get_vault() -> &'static CredentialVault {
    VAULT.get_or_init(|| {
        let cfg = crate::paths::init_paths();
        CredentialVault::new(cfg.credentials_json.clone())
    })
}

impl CredentialVault {
    pub fn new(path: PathBuf) -> Self {
        let data = if path.is_file() {
            if let Ok(content) = fs::read_to_string(&path) {
                serde_json::from_str(&content).unwrap_or_default()
            } else {
                VaultData::default()
            }
        } else {
            VaultData::default()
        };

        CredentialVault {
            path,
            data: RwLock::new(data),
        }
    }

    fn normalize_target(target: &str) -> String {
        target.to_lowercase()
    }

    pub fn get(&self, target_name: &str) -> Option<VaultCredential> {
        let key = Self::normalize_target(target_name);
        let data = self.data.read();
        data.credentials.get(&key).cloned()
    }

    pub fn set(
        &self,
        target_name: String,
        cred_type: u32,
        user_name: String,
        blob: &[u8],
        persist: u32,
    ) {
        let key = Self::normalize_target(&target_name);
        let blob_hex = hex::encode(blob);

        {
            let mut data = self.data.write();
            data.credentials.insert(
                key,
                VaultCredential {
                    target_name,
                    cred_type,
                    user_name,
                    credential_blob_hex: blob_hex,
                    persist,
                },
            );
        }

        self.persist();
    }

    pub fn delete(&self, target_name: &str) -> bool {
        let key = Self::normalize_target(target_name);
        let removed = {
            let mut data = self.data.write();
            data.credentials.remove(&key).is_some()
        };

        if removed {
            self.persist();
        }

        removed
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
    fn test_credential_vault_crud() {
        let temp_dir = std::env::temp_dir().join(format!("ppm_test_vault_{}", std::process::id()));
        let vault_file = temp_dir.join("credentials.json");
        let vault = CredentialVault::new(vault_file.clone());

        // 1. Insert credential
        let secret = b"super_secret_token";
        vault.set(
            "git:https://github.com".to_string(),
            1,
            "john_doe".to_string(),
            secret,
            1,
        );

        // 2. Query credential
        let cred = vault.get("git:https://github.com");
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.user_name, "john_doe");
        let decoded = hex::decode(&cred.credential_blob_hex).unwrap();
        assert_eq!(decoded, secret);

        // 3. Delete credential
        assert!(vault.delete("git:https://github.com"));
        assert!(vault.get("git:https://github.com").is_none());

        // Clean up
        let _ = fs::remove_file(&vault_file);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
