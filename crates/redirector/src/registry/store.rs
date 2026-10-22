use crate::registry::journal::{Journal, RegistryOp};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedValue {
    pub val_type: u32,
    pub data_hex: String,
    // Intention: Remember the value name as the application spelled it.
    // Why: The index key is case-folded so lookups are case-insensitive, but an enumeration
    //      must hand back the caller's own casing - an application that writes "ProxyServer"
    //      and enumerates would otherwise be told its value is named "proxyserver", and code
    //      that compares the returned name case-sensitively breaks. Absent for entries written
    //      before this field existed, where the folded name is the only name on record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

fn is_not_set(flag: &bool) -> bool {
    !*flag
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedKey {
    #[serde(default)]
    pub values: HashMap<String, SerializedValue>,
    // Intention: Remember this key's own last segment as the application spelled it.
    // Why: Same reason as `SerializedValue::display_name`, for the subkey axis of an
    //      enumeration. Only the leaf segment is stored: a key's ancestors carry their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
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

/// The overlay's contribution to one key's enumeration.
///
/// Names are returned as the application spelled them; the masking sets are normalized,
/// because they are matched against host names that carry the host's own casing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayKeyView {
    /// Immediate child keys the overlay holds live.
    pub child_keys: Vec<String>,
    /// Values the overlay holds live.
    pub value_names: Vec<String>,
    /// Normalized names of immediate child keys the overlay tombstones individually.
    pub masked_child_keys: HashSet<String>,
    /// Normalized names of values the overlay tombstones individually.
    pub masked_values: HashSet<String>,
    /// Every value the host holds for this key is masked.
    pub host_values_masked: bool,
    /// Every subkey the host holds under this key is masked.
    pub host_subkeys_masked: bool,
}

pub struct VirtualRegistry {
    data: RwLock<VirtualRegistryData>,
    // Intention: Serialize journal access independently of the hive lock.
    // Why: A mutation must append to the journal in the same critical section in which it
    //      mutates memory, or two processes could interleave their appends in an order that
    //      does not match the order their in-memory states applied them. The lock order is
    //      always journal-then-data.
    journal: Mutex<Journal>,
    // Intention: Let an enumeration snapshot know when the overlay has moved under it.
    // Why: RegQueryInfoKeyW reports the counts an application sizes its buffers from, and the
    //      enumerators must then walk exactly that many entries. Recomputing the merged view
    //      per call would let a write between two calls change the answer mid-walk; caching it
    //      against this counter keeps one enumeration internally consistent and invalidates it
    //      the moment the overlay actually changes.
    generation: AtomicU64,
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
    for segment in key_segments(key) {
        if !normalized.is_empty() {
            normalized.push('\\');
        }
        normalized.push_str(&normalized_segment(segment));
    }
    normalized
}

/// The non-empty segments of a registry path, in order.
///
/// One definition so `normalize_key` and `key_chain` cannot disagree about what a segment is;
/// they must agree, or a key's normalized form and its recorded display names would misalign.
fn key_segments(key: &str) -> impl Iterator<Item = &str> {
    key.split('\\').filter(|segment| !segment.is_empty())
}

/// Case-folds one path segment into the overlay's key space.
pub(crate) fn normalized_segment(segment: &str) -> String {
    segment.chars().flat_map(char::to_uppercase).collect()
}

pub(crate) fn normalize_val_name(val_name: &str) -> String {
    val_name.to_lowercase()
}

/// The key and each of its ancestors, nearest first, paired with the segment name as the
/// application spelled it.
///
/// # Ex
/// `HKCU\Software\MyApp` -> `[(HKCU\SOFTWARE\MYAPP, MyApp), (HKCU\SOFTWARE, Software), (HKCU, HKCU)]`
fn key_chain(key_path: &str) -> Vec<(String, String)> {
    let mut chain = Vec::new();
    let mut normalized = String::new();
    for segment in key_segments(key_path) {
        if !normalized.is_empty() {
            normalized.push('\\');
        }
        normalized.push_str(&normalized_segment(segment));
        chain.push((normalized.clone(), segment.to_string()));
    }
    chain.reverse();
    chain
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
/// `Masked`, the entries this call brings to life - new ones and revived tombstones - are
/// therefore born with both host masks set. A live ancestor the walk stops at is left as it
/// was: masking it would hide every host sibling of the re-created key.
///
/// # Invariant
/// On return, `data.keys[..]` holds the returned normalized key and it is not a tombstone.
fn materialize_chain(data: &mut VirtualRegistryData, key_path: &str) -> String {
    let chain = key_chain(key_path);
    let norm_key = chain
        .first()
        .map(|(normalized, _)| normalized.clone())
        .unwrap_or_default();
    let born_masked = matches!(resolve_key_in(data, &norm_key), KeyResolution::Masked);

    for (depth, (candidate, display)) in chain.into_iter().enumerate() {
        let is_self = depth == 0;
        let existed = data.keys.contains_key(&candidate);
        let node = data.keys.entry(candidate).or_default();
        let comes_to_life = is_self || !existed || node.is_tombstone;

        node.is_tombstone = false;
        // First writer names the key: a later differently-cased reference must not rewrite the
        // spelling an enumeration has already been handing back.
        if node.display_name.is_none() {
            node.display_name = Some(display);
        }
        if born_masked && comes_to_life {
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

    norm_key
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
            generation: AtomicU64::new(0),
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

        // Published last, under both locks, so no reader can observe a bumped generation
        // against a hive that has not yet taken the mutation.
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Counts every mutation this process has applied. An enumeration snapshot taken at one
    /// generation stays valid until the number changes.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The overlay's side of an enumeration of `key_path`, or `None` when the key is masked.
    ///
    /// # Why the child scan is a full pass
    /// The hive is a flat map keyed by full path, so immediate children are found by scanning.
    /// The result is cached per handle against [`generation`](Self::generation), so a complete
    /// enumeration pays for this once rather than once per index.
    pub fn overlay_key_view(&self, key_path: &str) -> Option<OverlayKeyView> {
        let norm_key = normalize_key(key_path);
        if norm_key.is_empty() {
            return None;
        }

        let data = self.data.read();
        if resolve_key_in(&data, &norm_key) == KeyResolution::Masked {
            return None;
        }

        let mut view = OverlayKeyView::default();

        let child_prefix = format!("{norm_key}\\");
        for (path, child) in &data.keys {
            let Some(relative) = path.strip_prefix(&child_prefix) else {
                continue;
            };
            // Only immediate children: anything with a further separator is a grandchild.
            if relative.contains('\\') {
                continue;
            }
            match child.is_tombstone {
                true => {
                    view.masked_child_keys.insert(relative.to_string());
                }
                false => view
                    .child_keys
                    .push(child.display_name.clone().unwrap_or_else(|| relative.to_string())),
            }
        }

        if let Some(node) = data.keys.get(&norm_key) {
            view.value_names = node
                .values
                .iter()
                .map(|(normalized, value)| value.display_name.clone().unwrap_or_else(|| normalized.clone()))
                .collect();
            view.masked_values = node.deleted_values.clone();
            view.host_values_masked = node.host_values_masked;
            view.host_subkeys_masked = node.host_subkeys_masked;
        }

        // `HashMap` iteration order is arbitrary; an enumeration must not reorder between two
        // walks of an unchanged hive.
        view.child_keys.sort();
        view.value_names.sort();

        Some(view)
    }

    /// The stored byte length of one overlay value, for `RegQueryInfoKeyW`'s longest-value
    /// figure. `None` when the overlay does not hold the value or cannot decode it.
    pub fn overlay_value_len(&self, key_path: &str, val_name: &str) -> Option<usize> {
        match self.resolve_value(key_path, val_name) {
            ValueResolution::Virtual { data, .. } => Some(data.len()),
            _ => None,
        }
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
            key: key_path.to_string(),
            name: val_name.to_string(),
            val_type,
            data_hex: hex::encode(data),
        });
    }

    pub fn delete_value(&self, key_path: &str, val_name: &str) {
        self.record(RegistryOp::DeleteValue {
            key: key_path.to_string(),
            name: val_name.to_string(),
        });
    }

    pub fn create_key(&self, key_path: &str) {
        self.record(RegistryOp::CreateKey {
            key: key_path.to_string(),
        });
    }

    /// Masks the key and its whole subtree - the `RegDeleteKeyW` / `RegDeleteKeyExW` contract.
    pub fn delete_key(&self, key_path: &str) {
        self.record(RegistryOp::DeleteKey {
            key: key_path.to_string(),
        });
    }

    /// Masks every subkey and every value of the key while leaving the key itself openable -
    /// the `RegDeleteTreeW` contract.
    pub fn delete_tree(&self, key_path: &str) {
        self.record(RegistryOp::DeleteTree {
            key: key_path.to_string(),
        });
    }
}

impl RegistryOp {
    /// Applies this op to an in-memory hive.
    ///
    /// # Why replay and live mutation share this path
    /// A hive reloaded from the journal must be indistinguishable from the one the writes
    /// produced. Giving replay its own copy of the tombstone and mask rules is exactly how
    /// the two drift apart, so both go through here.
    ///
    /// # Why the op carries un-normalized text
    /// Records hold the key and value names as the application spelled them, and normalization
    /// happens here. That keeps the journal readable, keeps one normalization implementation,
    /// and is what lets an enumeration return the caller's own casing. Normalization is
    /// idempotent, so records written before this change - which already held folded names -
    /// replay to exactly the same hive.
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
                let norm_key = materialize_chain(data, key);
                let norm_val = normalize_val_name(name);
                let node = data
                    .keys
                    .get_mut(&norm_key)
                    .expect("invariant: materialize_chain leaves the key present and live");
                node.deleted_values.remove(&norm_val);
                node.values.insert(
                    norm_val,
                    SerializedValue {
                        val_type: *val_type,
                        data_hex: data_hex.clone(),
                        display_name: Some(name.clone()),
                    },
                );
            }
            RegistryOp::DeleteValue { key, name } => {
                let norm_key = materialize_chain(data, key);
                let norm_val = normalize_val_name(name);
                let node = data
                    .keys
                    .get_mut(&norm_key)
                    .expect("invariant: materialize_chain leaves the key present and live");
                node.values.remove(&norm_val);
                node.deleted_values.insert(norm_val);
            }
            RegistryOp::DeleteKey { key } => {
                let norm_key = normalize_key(key);
                tombstone_descendants(data, &norm_key);
                let node = data.keys.entry(norm_key).or_default();
                node.is_tombstone = true;
                node.values.clear();
                node.deleted_values.clear();
            }
            RegistryOp::DeleteTree { key } => {
                tombstone_descendants(data, &normalize_key(key));
                let norm_key = materialize_chain(data, key);
                let node = data
                    .keys
                    .get_mut(&norm_key)
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

        // The on-disk journal carries one record per mutation, in the order they happened,
        // spelled the way the application wrote it - normalization is applied on replay, so a
        // record stays readable and still carries the casing an enumeration must hand back.
        let journal =
            std::fs::read_to_string(reg_file.with_extension("jsonl")).expect("registry.jsonl must exist");
        assert!(journal.contains("MyApp"));
        assert!(journal.contains("Greeting"));
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

    /// Regression: re-creating a deleted key also set the host masks on its live parent, so every
    /// host sibling of that key - and the parent's own host values - vanished from view.
    #[test]
    fn re_creating_a_deleted_key_leaves_its_live_parent_untouched() {
        let (_dir, store) = store();

        store.create_key("HKCU\\Software\\App");
        store.delete_key("HKCU\\Software\\App\\Doomed");
        store.create_key("HKCU\\Software\\App\\Doomed");

        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\HostSibling"),
            KeyResolution::PassThrough
        );
        assert_eq!(
            store.resolve_value("HKCU\\Software\\App", "HostValue"),
            ValueResolution::PassThrough
        );
        // The re-created key itself is fresh: nothing of its deleted host copy shows through.
        assert_eq!(
            store.resolve_key("HKCU\\Software\\App\\Doomed\\HostChild"),
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

    #[test]
    fn the_overlay_view_lists_immediate_children_with_the_spelling_the_app_used() {
        let (_dir, store) = store();
        store.create_key("HKCU\\Software\\MyApp");
        store.create_key("HKCU\\Software\\MyApp\\Nested\\Deeper");
        store.create_key("HKCU\\Software\\Sibling");
        store.set_value("HKCU\\Software\\MyApp", "ProxyServer", 1, b"x");

        let view = store
            .overlay_key_view("hkcu\\software\\myapp")
            .expect("a live key has a view");

        // Immediate children only - the grandchild must not surface here.
        assert_eq!(view.child_keys, vec!["Nested"]);
        // Casing is the application's, not the index's.
        assert_eq!(view.value_names, vec!["ProxyServer"]);
        assert!(!view.host_values_masked);
        assert!(!view.host_subkeys_masked);
    }

    #[test]
    fn the_overlay_view_reports_masks_rather_than_hiding_them() {
        let (_dir, store) = store();
        store.create_key("HKCU\\Software\\App\\Doomed");
        store.set_value("HKCU\\Software\\App", "Gone", 1, b"x");
        store.delete_key("HKCU\\Software\\App\\Doomed");
        store.delete_value("HKCU\\Software\\App", "Gone");

        let view = store
            .overlay_key_view("HKCU\\Software\\App")
            .expect("a live key has a view");

        assert!(view.child_keys.is_empty());
        assert!(view.value_names.is_empty());
        // The merge needs the masks by name to filter the host's own listing.
        assert!(view.masked_child_keys.contains("DOOMED"));
        assert!(view.masked_values.contains("gone"));
    }

    #[test]
    fn delete_tree_reports_wildcard_masks_to_the_view() {
        let (_dir, store) = store();
        store.create_key("HKCU\\Software\\App");
        store.delete_tree("HKCU\\Software\\App");

        let view = store
            .overlay_key_view("HKCU\\Software\\App")
            .expect("delete_tree keeps the key itself");

        assert!(view.host_values_masked);
        assert!(view.host_subkeys_masked);
    }

    #[test]
    fn a_masked_key_has_no_view_at_all() {
        let (_dir, store) = store();
        store.delete_key("HKCU\\Software\\Gone");

        assert!(store.overlay_key_view("HKCU\\Software\\Gone").is_none());
        assert!(
            store.overlay_key_view("HKCU\\Software\\Gone\\Child").is_none(),
            "a child masked by its deleted parent has no view either"
        );
    }

    /// The spelling an enumeration hands back must survive the journal, or a reloaded hive
    /// would start reporting case-folded names for keys the application already knows.
    #[test]
    fn display_names_survive_a_reload() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let reg_file = temp_dir.path().join("registry.json");

        {
            let store = VirtualRegistry::new(reg_file.clone());
            store.create_key("HKCU\\Software\\MyApp\\SubKey");
            store.set_value("HKCU\\Software\\MyApp", "ProxyServer", 1, b"x");
        }

        let reopened = VirtualRegistry::new(reg_file);
        let view = reopened
            .overlay_key_view("HKCU\\Software\\MyApp")
            .expect("the reloaded key is live");

        assert_eq!(view.child_keys, vec!["SubKey"]);
        assert_eq!(view.value_names, vec!["ProxyServer"]);
    }

    #[test]
    fn the_generation_advances_on_every_mutation_and_not_on_reads() {
        let (_dir, store) = store();
        let start = store.generation();

        store.create_key("HKCU\\Software\\App");
        let after_create = store.generation();
        assert!(after_create > start);

        let _ = store.overlay_key_view("HKCU\\Software\\App");
        let _ = store.resolve_key("HKCU\\Software\\App");
        assert_eq!(
            store.generation(),
            after_create,
            "queries must not invalidate an enumeration snapshot"
        );

        store.set_value("HKCU\\Software\\App", "V", 1, b"x");
        assert!(store.generation() > after_create);
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
