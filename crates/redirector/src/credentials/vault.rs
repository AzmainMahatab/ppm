use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;

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

static VAULT: LazyLock<CredentialVault> = LazyLock::new(|| {
    let cfg = crate::paths::init_paths();
    CredentialVault::new(cfg.credentials_json.clone())
});

pub fn get_vault() -> &'static CredentialVault {
    &VAULT
}

impl CredentialVault {
    pub fn new(path: PathBuf) -> Self {
        let data = crate::persist::load_state(&path, "credentials");

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

    pub fn set(&self, target_name: String, cred_type: u32, user_name: String, blob: &[u8], persist: u32) {
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
        let data = self.data.read();
        crate::persist::persist_state(&self.path, &*data, "credentials");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_survive_a_full_disk_round_trip() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let vault_file = temp_dir.path().join("credentials.json");

        {
            let vault = CredentialVault::new(vault_file.clone());
            vault.set(
                "git:https://github.com".to_string(),
                1,
                "john_doe".to_string(),
                b"super_secret_token",
                1,
            );
            vault.set("second:target".to_string(), 1, "other".to_string(), b"abc", 1);
            assert!(vault.delete("git:https://github.com"));
        }
        // `vault` is dropped: the on-disk vault is the only state left.

        let reopened = CredentialVault::new(vault_file.clone());

        // Deleted credentials stay deleted across the reload.
        assert!(reopened.get("git:https://github.com").is_none());

        // Surviving credentials round-trip fully, lookup case-insensitively.
        let cred = reopened
            .get("SECOND:TARGET")
            .expect("credential should survive the reload");
        assert_eq!(cred.user_name, "other");
        assert_eq!(hex::decode(&cred.credential_blob_hex).unwrap(), b"abc");
    }

    #[test]
    fn corrupt_state_file_starts_empty_and_recovers_on_next_write() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let vault_file = temp_dir.path().join("credentials.json");
        std::fs::write(&vault_file, b"{ not valid json").unwrap();

        let vault = CredentialVault::new(vault_file.clone());

        // Documented loud-failure behavior: corrupt state starts from empty instead of
        // pretending the lost entries still exist.
        assert!(vault.get("anything").is_none());

        // The recovered empty state persists on the next write.
        vault.set("fresh".to_string(), 1, "user".to_string(), b"blob", 1);
        let reopened = CredentialVault::new(vault_file.clone());
        assert!(reopened.get("fresh").is_some());
    }
}
