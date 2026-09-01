//! The portable credential store behind the `Cred*` isolation boundary.
//!
//! # At-rest representation: plaintext
//! Blobs are stored hex-encoded, which is an encoding, **not** encryption - anyone who can read
//! `.ppm/system/credentials.json` can recover every secret in it. This is a property of the
//! goal, not an omission: a store that must decrypt itself on any machine it is plugged into
//! has nowhere to keep a key that an attacker holding the volume does not also get. DPAPI would
//! bind the file to one user on one machine and destroy portability, and a key kept beside the
//! ciphertext protects nothing while claiming to.
//!
//! The boundary this store *does* provide is isolation, not confidentiality: application
//! secrets never reach the host credential manager, and the real user's secrets never reach the
//! application. Treat the deployment volume itself as the secret.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultCredential {
    pub target_name: String,
    pub cred_type: u32,
    pub user_name: String,
    pub credential_blob_hex: String,
    pub persist: u32,
}

/// Credentials indexed the way Windows indexes them: by target name *and* credential type.
///
/// # Why the type is part of the identity
/// `CredReadW` and `CredDeleteW` both take a type alongside the target, and the store may hold
/// two credentials that share a target and differ only in type. Keying by target alone let a
/// generic credential answer a domain-password read - the wrong secret, returned silently.
///
/// The inner key is the decimal credential type: JSON object keys are strings, and keeping the
/// mapping in one place (`type_key`) keeps every caller working in `u32`.
type CredentialsByTargetAndType = HashMap<String, HashMap<String, VaultCredential>>;

fn type_key(cred_type: u32) -> String {
    cred_type.to_string()
}

fn normalize_target(target: &str) -> String {
    target.to_lowercase()
}

/// The shapes `credentials.json` may carry on disk.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StoredCredentials {
    /// Current shape: target -> credential type -> credential.
    ByTargetAndType(CredentialsByTargetAndType),
    /// The original shape, keyed by target alone. Migrated on load rather than discarded: a
    /// format change must not silently erase a user's stored secrets.
    ByTargetOnly(HashMap<String, VaultCredential>),
}

impl Default for StoredCredentials {
    fn default() -> Self {
        StoredCredentials::ByTargetAndType(HashMap::new())
    }
}

impl StoredCredentials {
    fn into_current(self) -> CredentialsByTargetAndType {
        match self {
            StoredCredentials::ByTargetAndType(current) => current,
            StoredCredentials::ByTargetOnly(legacy) => {
                let migrated = legacy.len();
                let mut current: CredentialsByTargetAndType = HashMap::new();
                for (target, credential) in legacy {
                    current
                        .entry(target)
                        .or_default()
                        .insert(type_key(credential.cred_type), credential);
                }
                tracing::info!(
                    "Credential vault: migrated {migrated} target-keyed entries to the target-and-type index"
                );
                current
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VaultData {
    pub credentials: CredentialsByTargetAndType,
}

#[derive(Deserialize)]
struct VaultDataOnDisk {
    #[serde(default)]
    credentials: StoredCredentials,
}

impl<'de> Deserialize<'de> for VaultData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let on_disk = VaultDataOnDisk::deserialize(deserializer)?;
        Ok(VaultData {
            credentials: on_disk.credentials.into_current(),
        })
    }
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

/// Decides whether a `CredEnumerateW` filter admits `target_name`.
///
/// The filter is a target name that may end in a single `*` wildcard; comparison is
/// case-insensitive, matching the credential store's own key semantics. `None` is the
/// documented "enumerate everything" filter.
fn filter_admits(filter: Option<&str>, target_name: &str) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let filter = normalize_target(filter);
    let target = normalize_target(target_name);
    match filter.strip_suffix('*') {
        Some(prefix) => target.starts_with(prefix),
        None => target == filter,
    }
}

impl CredentialVault {
    pub fn new(path: PathBuf) -> Self {
        let data = crate::persist::load_state(&path, "credentials");

        CredentialVault {
            path,
            data: RwLock::new(data),
        }
    }

    pub fn get(&self, target_name: &str, cred_type: u32) -> Option<VaultCredential> {
        let data = self.data.read();
        data.credentials
            .get(&normalize_target(target_name))?
            .get(&type_key(cred_type))
            .cloned()
    }

    pub fn set(&self, target_name: String, cred_type: u32, user_name: String, blob: &[u8], persist: u32) {
        let key = normalize_target(&target_name);
        let blob_hex = hex::encode(blob);

        {
            let mut data = self.data.write();
            data.credentials.entry(key).or_default().insert(
                type_key(cred_type),
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

    /// Removes one credential, reporting whether it was present.
    pub fn delete(&self, target_name: &str, cred_type: u32) -> bool {
        let key = normalize_target(target_name);
        let removed = {
            let mut data = self.data.write();
            let Some(by_type) = data.credentials.get_mut(&key) else {
                return false;
            };
            let removed = by_type.remove(&type_key(cred_type)).is_some();
            if by_type.is_empty() {
                data.credentials.remove(&key);
            }
            removed
        };

        if removed {
            self.persist();
        }

        removed
    }

    /// Selects every stored credential the `CredEnumerateW` filter admits.
    ///
    /// The order is stabilized by target and type so repeated enumerations of an unchanged
    /// vault return the same sequence - `HashMap` iteration order would not.
    pub fn matching(&self, filter: Option<&str>) -> Vec<VaultCredential> {
        let data = self.data.read();
        let mut selected: Vec<VaultCredential> = data
            .credentials
            .iter()
            .filter(|(_, by_type)| {
                by_type
                    .values()
                    .next()
                    .is_some_and(|credential| filter_admits(filter, &credential.target_name))
            })
            .flat_map(|(_, by_type)| by_type.values().cloned())
            .collect();

        selected.sort_by(|a, b| {
            normalize_target(&a.target_name)
                .cmp(&normalize_target(&b.target_name))
                .then(a.cred_type.cmp(&b.cred_type))
        });
        selected
    }

    fn persist(&self) {
        let data = self.data.read();
        crate::persist::persist_state(&self.path, &*data, "credentials");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERIC: u32 = 1;
    const DOMAIN_PASSWORD: u32 = 2;

    fn vault() -> (tempfile::TempDir, CredentialVault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = CredentialVault::new(dir.path().join("credentials.json"));
        (dir, vault)
    }

    #[test]
    fn credentials_survive_a_full_disk_round_trip() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let vault_file = temp_dir.path().join("credentials.json");

        {
            let vault = CredentialVault::new(vault_file.clone());
            vault.set(
                "git:https://github.com".to_string(),
                GENERIC,
                "john_doe".to_string(),
                b"super_secret_token",
                1,
            );
            vault.set(
                "second:target".to_string(),
                GENERIC,
                "other".to_string(),
                b"abc",
                1,
            );
            assert!(vault.delete("git:https://github.com", GENERIC));
        }
        // `vault` is dropped: the on-disk vault is the only state left.

        let reopened = CredentialVault::new(vault_file.clone());

        // Deleted credentials stay deleted across the reload.
        assert!(reopened.get("git:https://github.com", GENERIC).is_none());

        // Surviving credentials round-trip fully, lookup case-insensitively.
        let cred = reopened
            .get("SECOND:TARGET", GENERIC)
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
        assert!(vault.get("anything", GENERIC).is_none());

        // The recovered empty state persists on the next write.
        vault.set("fresh".to_string(), GENERIC, "user".to_string(), b"blob", 1);
        let reopened = CredentialVault::new(vault_file.clone());
        assert!(reopened.get("fresh", GENERIC).is_some());
    }

    /// Regression: the vault was keyed by target name alone, so a generic credential answered
    /// a domain-password read - the wrong secret, returned as if it were the right one.
    #[test]
    fn a_credential_answers_only_its_own_type() {
        let (_dir, vault) = vault();
        vault.set(
            "shared:target".to_string(),
            GENERIC,
            "generic-user".to_string(),
            b"generic",
            1,
        );

        assert!(vault.get("shared:target", GENERIC).is_some());
        assert!(
            vault.get("shared:target", DOMAIN_PASSWORD).is_none(),
            "a generic credential must not answer a domain-password read"
        );
    }

    #[test]
    fn two_types_share_a_target_without_clobbering_each_other() {
        let (_dir, vault) = vault();
        vault.set(
            "shared:target".to_string(),
            GENERIC,
            "generic-user".to_string(),
            b"generic",
            1,
        );
        vault.set(
            "shared:target".to_string(),
            DOMAIN_PASSWORD,
            "domain-user".to_string(),
            b"domain",
            1,
        );

        assert_eq!(
            vault.get("shared:target", GENERIC).unwrap().user_name,
            "generic-user"
        );
        assert_eq!(
            vault.get("shared:target", DOMAIN_PASSWORD).unwrap().user_name,
            "domain-user"
        );

        // Deleting one type leaves the other in place.
        assert!(vault.delete("shared:target", GENERIC));
        assert!(vault.get("shared:target", GENERIC).is_none());
        assert!(vault.get("shared:target", DOMAIN_PASSWORD).is_some());
    }

    /// A vault written by the previous release is keyed by target alone; loading it must carry
    /// the secrets forward rather than reading as corrupt and starting empty.
    #[test]
    fn a_target_keyed_vault_migrates_instead_of_being_discarded() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let vault_file = temp_dir.path().join("credentials.json");
        let legacy = serde_json::json!({
            "credentials": {
                "git:https://github.com": {
                    "target_name": "git:https://github.com",
                    "cred_type": 1,
                    "user_name": "john_doe",
                    "credential_blob_hex": hex::encode(b"legacy_token"),
                    "persist": 1
                }
            }
        });
        std::fs::write(&vault_file, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let vault = CredentialVault::new(vault_file);

        let cred = vault
            .get("git:https://github.com", GENERIC)
            .expect("a legacy target-keyed entry must migrate, not vanish");
        assert_eq!(cred.user_name, "john_doe");
        assert_eq!(hex::decode(&cred.credential_blob_hex).unwrap(), b"legacy_token");
    }

    #[test]
    fn enumeration_filters_by_target_and_supports_the_trailing_wildcard() {
        let (_dir, vault) = vault();
        for target in ["git:https://github.com", "git:https://gitlab.com", "other:thing"] {
            vault.set(target.to_string(), GENERIC, "u".to_string(), b"b", 1);
        }

        let all = vault.matching(None);
        assert_eq!(all.len(), 3, "a null filter enumerates everything");

        let git = vault.matching(Some("git:*"));
        assert_eq!(git.len(), 2);
        assert!(git.iter().all(|c| c.target_name.starts_with("git:")));

        let exact = vault.matching(Some("OTHER:THING"));
        assert_eq!(exact.len(), 1, "an exact filter matches case-insensitively");

        assert!(vault.matching(Some("absent:*")).is_empty());
    }

    #[test]
    fn enumeration_order_is_stable_across_calls() {
        let (_dir, vault) = vault();
        for target in ["c:one", "a:two", "b:three"] {
            vault.set(target.to_string(), GENERIC, "u".to_string(), b"b", 1);
        }

        let first: Vec<String> = vault.matching(None).into_iter().map(|c| c.target_name).collect();
        let second: Vec<String> = vault.matching(None).into_iter().map(|c| c.target_name).collect();

        assert_eq!(first, second);
        assert_eq!(first, vec!["a:two", "b:three", "c:one"]);
    }
}
