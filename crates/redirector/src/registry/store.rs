use crate::registry::journal::{Journal, RegistryOp};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedValue {
    pub val_type: u32,
    pub data_hex: String,
}

fn is_not_set(flag: &bool) -> bool {
    !*flag
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedKey {
    #[serde(default)]
    pub values: HashMap<String, SerializedValue>,
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub deleted_values: HashSet<String>,
    #[serde(default, skip_serializing_if = "is_not_set")]
    pub is_tombstone: bool,
    // Intention: Mask every value the host holds for this key without enumerating them.
    // Why: RegDeleteTreeW deletes all values of a key, and a key re-created inside a deleted
    //      subtree must show nothing of the host copy. Both are wildcard masks - recording
    //      them as one flag keeps the operation O(1) instead of requiring a host enumeration
    //      to write one tombstone per value.
    #[serde(default, skip_serializing_if = "is_not_set")]
    pub host_values_masked: bool,
    // Intention: Mask every subkey the host holds under this key.
    // Why: Same two causes as `host_values_masked`, for the subkey axis. Ancestor resolution
    //      consults it so a host-only child that was never in the overlay still reads as gone.
    #[serde(default, skip_serializing_if = "is_not_set")]
    pub host_subkeys_masked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirtualRegistryData {
    pub keys: HashMap<String, SerializedKey>,
}

/// How the overlay answers a key-level question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyResolution {
    /// The overlay owns this key: it exists regardless of what the host holds.
    Virtual,
    /// A tombstone on the key itself, or a subtree mask on one of its ancestors, hides it.
    Masked,
    /// The overlay knows nothing about this key; the host answer stands.
    PassThrough,
}

/// How the overlay answers a value-level question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueResolution {
    /// The overlay owns this value and it shadows any host copy.
    Virtual { val_type: u32, data: Vec<u8> },
    /// A tombstone masks the value, its key, or an ancestor key.
    Masked,
    /// The overlay claims this value but its stored bytes are unreadable.
    ///
    /// # Why this is not `PassThrough`
    /// Falling through to the host on a corrupt overlay entry would answer a virtualized
    /// read with the real user's data - a silent boundary breach. The value reads as absent
    /// instead, and the corruption is logged where it was detected.
    Corrupt,
    /// The overlay knows nothing about this value; the host answer stands.
    PassThrough,
}

pub struct VirtualRegistry {
    data: RwLock<VirtualRegistryData>,
    // Intention: Serialize journal access independently of the hive lock.
    // Why: A mutation must append to the journal in the same critical section in which it
    //      mutates memory, or two processes could interleave their appends in an order that
    //      does not match the order their in-memory states applied them. The lock order is
    //      always journal-then-data.
    journal: Mutex<Journal>,
}

static REGISTRY_STORE: LazyLock<VirtualRegistry> = LazyLock::new(|| {
    let cfg = crate::paths::init_paths();
    VirtualRegistry::new(cfg.registry_json.clone())
});

pub fn get_registry_store() -> &'static VirtualRegistry {
    &REGISTRY_STORE
}

/// Canonicalizes a registry path into the overlay's key space: uppercased, single-separator,
/// no leading or trailing separator.
///
/// # Why structural instead of `trim_matches`
/// Ancestor resolution walks the key one separator at a time, so every spelling of a path
/// must reduce to exactly one key. Two spellings addressing two entries would let a
/// tombstone on a parent miss its own children.
fn normalize_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    for segment in key.split('\\').filter(|segment| !segment.is_empty()) {
        if !normalized.is_empty() {
            normalized.push('\\');
        }
        normalized.extend(segment.chars().flat_map(char::to_uppercase));
    }
    normalized
}

fn normalize_val_name(val_name: &str) -> String {
    val_name.to_lowercase()
}

/// Yields `norm_key` then each ancestor, nearest first, ending at the hive name.
fn key_and_ancestors(norm_key: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(norm_key), |candidate| {
        candidate.rsplit_once('\\').map(|(parent, _)| parent)
    })
}

/// Ancestor-aware key resolution: the nearest entry on the `key -> ... -> hive` chain decides.
///
/// # Why the nearest entry wins
/// A tombstone must mask host-only children that were never in the overlay, so resolution
/// cannot stop at an exact-match lookup. It must equally not mask a key the application
/// re-created after the delete, so a nearer live entry supersedes a farther tombstone -
/// which is exactly what `materialize_chain` maintains on every create and write.
fn resolve_key_in(data: &VirtualRegistryData, norm_key: &str) -> KeyResolution {
    for (depth, candidate) in key_and_ancestors(norm_key).enumerate() {
        let Some(node) = data.keys.get(candidate) else {
            continue;
        };
        let is_self = depth == 0;
        return match (is_self, node.is_tombstone) {
            (true, true) => KeyResolution::Masked,
            (true, false) => KeyResolution::Virtual,
            (false, true) => KeyResolution::Masked,
            (false, false) if node.host_subkeys_masked => KeyResolution::Masked,
            (false, false) => KeyResolution::PassThrough,
        };
    }
    KeyResolution::PassThrough
}

/// Materializes `norm_key` and as many ancestors as the chain needs as live overlay entries.
///
/// # Why a key can be born masked
/// Creating a key inside a subtree the application already deleted must not resurrect the
/// host copy's values or children: the app asked for a fresh key. When the chain resolves as
/// `Masked`, the new entries are therefore born with both host masks set.
///
/// # Invariant
/// On return, `data.keys[norm_key]` exists and is not a tombstone.
fn materialize_chain(data: &mut VirtualRegistryData, norm_key: &str) {
    let born_masked = matches!(resolve_key_in(data, norm_key), KeyResolution::Masked);
    let chain: Vec<String> = key_and_ancestors(norm_key).map(str::to_string).collect();

    for (depth, candidate) in chain.into_iter().enumerate() {
        let is_self = depth == 0;
        let existed = data.keys.contains_key(&candidate);
        let node = data.keys.entry(candidate).or_default();

        node.is_tombstone = false;
        if born_masked {
            node.host_values_masked = true;
            node.host_subkeys_masked = true;
        }

        // An ancestor that already had an entry settles the whole chain above it: either it
        // was live (so its own ancestors were never in question) or it was the tombstone that
        // masked this key, and clearing it is exactly the revival the caller asked for.
        if !is_self && existed {
            break;
        }
    }
}

/// Tombstones every overlay entry strictly under `norm_key`.
///
/// # Why the overlay descendants must be tombstoned too
/// Resolution lets the nearest entry win, so a live descendant entry left behind would
/// un-mask the deleted subtree. The trailing separator makes this a structural containment
/// test on the normalized key space, not a textual prefix guess.
fn tombstone_descendants(data: &mut VirtualRegistryData, norm_key: &str) {
    let prefix = format!("{norm_key}\\");
    for (path, node) in data.keys.iter_mut() {
        if path.starts_with(&prefix) {
            node.is_tombstone = true;
            node.values.clear();
            node.deleted_values.clear();
        }
    }
}

impl VirtualRegistry {
    /// Opens the hive at `path`, replaying its journal (and migrating a legacy snapshot).
    pub fn new(path: PathBuf) -> Self {
        let mut journal = Journal::open(&path);
        let mut data = VirtualRegistryData::default();

        for op in journal.read_new_ops().ops {
            op.apply(&mut data);
        }

        // Attach is the one moment this process knows it is not mid-mutation, so it is
        // where accumulated history is collapsed.
        journal.compact_if_worthwhile(&data.keys);

        VirtualRegistry {
            data: RwLock::new(data),
            journal: Mutex::new(journal),
        }
    }

    /// Applies one mutation to the in-memory hive and appends it to the journal.
    ///
    /// # Why other processes' ops are adopted first
    /// Another injected process may have appended since this one last wrote. Replaying
    /// those records before applying our own keeps this process converging on the shared
    /// hive instead of drifting away from it.
    fn record(&self, op: RegistryOp) {
        let mut journal = self.journal.lock();
        let mut data = self.data.write();

        let read = journal.read_new_ops();
        if read.reset_first {
            *data = VirtualRegistryData::default();
        }
        for external in read.ops {
            external.apply(&mut data);
        }

        op.apply(&mut data);
        journal.append(&op);
    }

    pub fn resolve_key(&self, key_path: &str) -> KeyResolution {
        let norm_key = normalize_key(key_path);
        let data = self.data.read();
        resolve_key_in(&data, &norm_key)
    }

    pub fn resolve_value(&self, key_path: &str, val_name: &str) -> ValueResolution {
        let norm_key = normalize_key(key_path);
        let norm_val = normalize_val_name(val_name);

        let data = self.data.read();

        if let Some(node) = data.keys.get(&norm_key) {
            if node.is_tombstone {
                return ValueResolution::Masked;
            }
            if let Some(val) = node.values.get(&norm_val) {
                return match hex::decode(&val.data_hex) {
                    Ok(data) => ValueResolution::Virtual {
                        val_type: val.val_type,
                        data,
                    },
                    Err(e) => {
                        tracing::error!(
                            "Registry overlay value '{norm_key}' / '{norm_val}' has unreadable stored bytes ({e}); reading as absent rather than falling through to the host"
                        );
                        ValueResolution::Corrupt
                    }
                };
            }
            if node.deleted_values.contains(&norm_val) || node.host_values_masked {
                return ValueResolution::Masked;
            }
        }

        // No overlay entry for the value itself: an ancestor tombstone can still hide it.
        match resolve_key_in(&data, &norm_key) {
            KeyResolution::Masked => ValueResolution::Masked,
            KeyResolution::Virtual | KeyResolution::PassThrough => ValueResolution::PassThrough,
        }
    }

    pub fn set_value(&self, key_path: &str, val_name: &str, val_type: u32, data: &[u8]) {
        self.record(RegistryOp::SetValue {
            key: normalize_key(key_path),
            name: normalize_val_name(val_name),
            val_type,
            data_hex: hex::encode(data),
        });
    }

    pub fn delete_value(&self, key_path: &str, val_name: &str) {
        self.record(RegistryOp::DeleteValue {
            key: normalize_key(key_path),
            name: normalize_val_name(val_name),
        });
    }

    pub fn create_key(&self, key_path: &str) {
        self.record(RegistryOp::CreateKey {
            key: normalize_key(key_path),
        });
    }

    /// Masks the key and its whole subtree - the `RegDeleteKeyW` / `RegDeleteKeyExW` contract.
    pub fn delete_key(&self, key_path: &str) {
        self.record(RegistryOp::DeleteKey {
            key: normalize_key(key_path),
        });
    }

    /// Masks every subkey and every value of the key while leaving the key itself openable -
    /// the `RegDeleteTreeW` contract.
    pub fn delete_tree(&self, key_path: &str) {
        self.record(RegistryOp::DeleteTree {
            key: normalize_key(key_path),
        });
    }
}

impl RegistryOp {
    /// Applies this op to an in-memory hive.
    ///
    /// # Why replay and live mutation share this path
    /// A hive reloaded from the journal must be indistinguishable from the one the writes
    /// produced. Giving replay its own copy of the tombstone and mask rules is exactly how
    /// the two drift apart, so both go through here. Keys arrive already normalized.
    pub(crate) fn apply(&self, data: &mut VirtualRegistryData) {
        match self {
            RegistryOp::Snapshot { keys } => {
                data.keys = keys.clone();
            }
            RegistryOp::CreateKey { key } => {
                materialize_chain(data, key);
            }
            RegistryOp::SetValue {
                key,
                name,
                val_type,
                data_hex,
            } => {
                materialize_chain(data, key);
                let node = data
                    .keys
                    .get_mut(key)
                    .expect("invariant: materialize_chain leaves the key present and live");
                node.deleted_values.remove(name);
                node.values.insert(
                    name.clone(),
                    SerializedValue {
                        val_type: *val_type,
                        data_hex: data_hex.clone(),
                    },
                );
            }
            RegistryOp::DeleteValue { key, name } => {
                materialize_chain(data, key);
                let node = data
                    .keys
                    .get_mut(key)
                    .expect("invariant: materialize_chain leaves the key present and live");
                node.values.remove(name);
                node.deleted_values.insert(name.clone());
            }
            RegistryOp::DeleteKey { key } => {
                tombstone_descendants(data, key);
                let node = data.keys.entry(key.clone()).or_default();
                node.is_tombstone = true;
                node.values.clear();
                node.deleted_values.clear();
            }
            RegistryOp::DeleteTree { key } => {
                tombstone_descendants(data, key);
                materialize_chain(data, key);
                let node = data
                    .keys
                    .get_mut(key)
                    .expect("invariant: materialize_chain leaves the key present and live");
                node.values.clear();
                node.deleted_values.clear();
                node.host_values_masked = true;
                node.host_subkeys_masked = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, VirtualRegistry) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = VirtualRegistry::new(dir.path().join("registry.json"));
        (dir, store)
    }

    fn virtual_bytes(resolution: ValueResolution) -> (u32, Vec<u8>) {
        match resolution {
            ValueResolution::Virtual { val_type, data } => (val_type, data),
            other => panic!("expected a virtual value, got {other:?}"),
        }
    }

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
        let (val_type, bytes) = virtual_bytes(reopened.resolve_value("hkcu\\software\\myapp", "GREETING"));
        assert_eq!(val_type, 1);
        assert_eq!(bytes, b"HelloVirtualWorld\0");

        // Normalization must be stable across the reload.
        let (val_type2, _) = virtual_bytes(reopened.resolve_value("HKCU\\SOFTWARE\\MYAPP", "greeting"));
        assert_eq!(val_type2, 1);

        // Value-level and key-level tombstones survive the reload.
        assert_eq!(
            reopened.resolve_value("HKCU\\Software\\MyApp", "Deleted"),
            ValueResolution::Masked
        );
        assert_eq!(
            reopened.resolve_key("HKCU\\Software\\Gone"),
            KeyResolution::Masked
        );

        // Unrelated keys remain intact.
        let (keep_type, keep_bytes) = virtual_bytes(reopened.resolve_value("HKCU\\Software\\Other", "Keep"));
        assert_eq!(keep_type, 3);
        assert_eq!(keep_bytes, b"ok");

        // The on-disk journal carries one record per mutation, in the order they happened.
        let journal =
            std::fs::read_to_string(reg_file.with_extension("jsonl")).expect("registry.jsonl must exist");
        assert!(journal.contains("MYAPP"));
        assert!(journal.contains(&hex::encode(b"HelloVirtualWorld\0")));
        assert!(journal.contains("set_value"));
        assert!(journal.contains("delete_value"));
        assert!(journal.contains("delete_key"));

        // Every record is a whole line of JSON; replay depends on that.
        for line in journal.lines().filter(|line| !line.trim().is_empty()) {
            serde_json::from_str::<serde_json::Value>(line).expect("each record is valid JSON");
        }
    }

    #[test]
    fn every_spelling_of_a_path_reaches_one_key() {
        let (_dir, store) = store();
        store.set_value("HKCU\\Software\\MyApp", "V", 1, b"a");

        for spelling in [
            "HKCU\\Software\\MyApp",
            "\\HKCU\\Software\\MyApp\\",
            "HKCU\\\\Software\\\\MyApp",
            "hkcu\\SOFTWARE\\myapp",
        ] {
            let (_, bytes) = virtual_bytes(store.resolve_value(spelling, "v"));
            assert_eq!(bytes, b"a", "spelling '{spelling}' must reach the same key");
        }
    }

    /// Regression: a deleted key used to mask only overlay entries, so a child that lived
    /// solely in the host registry stayed openable underneath a tombstoned parent.
    #[test]
    fn a_tombstoned_key_masks_host_only_children() {
        let (_dir, store) = store();

        store.delete_key("HKCU\\Software\\App");

        assert_eq!(store.resolve_key("HKCU\\Software\\App"), KeyResolution::Masked);
        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\Sub"),
            KeyResolution::Masked,
            "a child that exists only on the host must be masked by its deleted parent"
        );
        assert_eq!(
            store.resolve_value("HKCU\\Software\\App\\Sub", "AnyValue"),
            ValueResolution::Masked
        );

        // A sibling outside the deleted subtree is untouched.
        assert_eq!(
            store.resolve_key("HKCU\\Software\\Other"),
            KeyResolution::PassThrough
        );
    }

    #[test]
    fn re_creating_a_key_supersedes_the_ancestor_tombstone_but_stays_clean() {
        let (_dir, store) = store();

        store.delete_key("HKCU\\Software\\App");
        store.create_key("HKCU\\Software\\App\\Fresh");

        // The re-created key and its revived parent exist again ...
        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\Fresh"),
            KeyResolution::Virtual
        );
        assert_eq!(store.resolve_key("HKCU\\Software\\App"), KeyResolution::Virtual);

        // ... but nothing of the host copy shows through a key born inside a deleted subtree.
        assert_eq!(
            store.resolve_value("HKCU\\Software\\App\\Fresh", "HostValue"),
            ValueResolution::Masked
        );
        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\Fresh\\HostChild"),
            KeyResolution::Masked
        );

        // A sibling never re-created stays masked by the original tombstone.
        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\Untouched"),
            KeyResolution::Masked
        );
    }

    /// Regression: `RegDeleteTreeW` reached the host registry entirely unhooked.
    #[test]
    fn delete_tree_keeps_the_key_and_masks_its_contents() {
        let (_dir, store) = store();
        store.set_value("HKCU\\Software\\App", "Own", 1, b"x");
        store.set_value("HKCU\\Software\\App\\Child", "Deep", 1, b"y");

        store.delete_tree("HKCU\\Software\\App");

        // The key itself survives - that is the RegDeleteTreeW contract ...
        assert_eq!(store.resolve_key("HKCU\\Software\\App"), KeyResolution::Virtual);
        // ... while its values and subkeys, overlay and host alike, are gone.
        assert_eq!(
            store.resolve_value("HKCU\\Software\\App", "Own"),
            ValueResolution::Masked
        );
        assert_eq!(
            store.resolve_value("HKCU\\Software\\App", "HostOnlyValue"),
            ValueResolution::Masked
        );
        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\Child"),
            KeyResolution::Masked
        );
        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\HostOnlyChild"),
            KeyResolution::Masked
        );
    }

    #[test]
    fn writing_after_delete_tree_revives_only_what_was_written() {
        let (_dir, store) = store();
        store.delete_tree("HKCU\\Software\\App");

        store.set_value("HKCU\\Software\\App", "Rewritten", 4, b"z");

        let (val_type, bytes) = virtual_bytes(store.resolve_value("HKCU\\Software\\App", "Rewritten"));
        assert_eq!((val_type, bytes.as_slice()), (4, b"z".as_slice()));
        assert_eq!(
            store.resolve_value("HKCU\\Software\\App", "HostOnlyValue"),
            ValueResolution::Masked,
            "the wildcard host mask must survive an unrelated write to the same key"
        );
    }

    /// Regression: unreadable stored bytes used to fall through to the host registry,
    /// answering a virtualized read with the real user's data.
    #[test]
    fn unreadable_stored_bytes_read_as_absent_instead_of_falling_through() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let reg_file = temp_dir.path().join("registry.json");
        let seeded_hive = concat!(
            r#"{"keys":{"HKCU\\SOFTWARE\\APP":"#,
            r#"{"values":{"v":{"val_type":1,"data_hex":"zz"}}}}}"#
        );
        std::fs::write(&reg_file, seeded_hive).expect("seed hive");

        let store = VirtualRegistry::new(reg_file);

        assert_eq!(
            store.resolve_value("HKCU\\Software\\App", "V"),
            ValueResolution::Corrupt
        );
    }
}
