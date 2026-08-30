//! Shared loud-failure JSON persistence for the virtual state stores.
//!
//! # Why not `unwrap_or_default`
//! These files are the durable state of two isolation boundaries: a serialization or
//! write failure that silently skipped persistence would leave the in-memory view and
//! the on-disk hive diverging without a trace, and a corrupt file silently wiping all
//! virtual state on load is indistinguishable from a fresh sandbox. Neither failure
//! can propagate out of `DllMain`, so both surface as loud structured errors instead.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) fn load_state<T: Default + DeserializeOwned>(path: &Path, label: &str) -> T {
    if !path.is_file() {
        return T::default();
    }

    match fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(state) => state,
            Err(e) => {
                tracing::error!(
                    "{label} state file '{}' is corrupt ({e}); starting from empty state",
                    path.display()
                );
                T::default()
            }
        },
        Err(e) => {
            tracing::error!("Failed to read {label} state file '{}': {e}", path.display());
            T::default()
        }
    }
}

static PERSIST_SEQ: AtomicU64 = AtomicU64::new(0);

pub(crate) fn persist_state<T: Serialize>(path: &Path, state: &T, label: &str) {
    let json_str = match serde_json::to_string_pretty(state) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!("Failed to serialize {label} state for '{}': {e}", path.display());
            return;
        }
    };

    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        tracing::error!(
            "Failed to create directory for {label} state '{}': {e}",
            path.display()
        );
        return;
    }

    // Why a unique temp + rename: several hook threads and several processes of the app
    // persist concurrently. A shared temp name would let one writer tear another's temp
    // between write and rename; unique temps make every rename source a complete file,
    // and the final rename (MoveFileEx REPLACE_EXISTING) is atomic, so a concurrent
    // reader never observes a truncated state file.
    let seq = PERSIST_SEQ.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_file_name(format!(
        "{}.{}.{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| label.to_string()),
        std::process::id(),
        seq
    ));

    let write_result = fs::write(&temp, &json_str).and_then(|()| fs::rename(&temp, path));
    if let Err(e) = write_result {
        tracing::error!("Failed to persist {label} state to '{}': {e}", path.display());
        // Best-effort cleanup of the orphaned temp; a leftover is harmless but noisy.
        if let Err(cleanup_err) = fs::remove_file(&temp)
            && cleanup_err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                "Failed to remove orphaned temp file '{}': {cleanup_err}",
                temp.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_state_is_atomic_and_leaves_no_temp_residue() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let state_path = temp_dir.path().join("state.json");

        persist_state(&state_path, &serde_json::json!({ "v": 1 }), "test");
        persist_state(&state_path, &serde_json::json!({ "v": 2 }), "test");

        let content = std::fs::read_to_string(&state_path).expect("state file must exist");
        let parsed = serde_json::from_str::<serde_json::Value>(&content).expect("state must be valid JSON");
        assert_eq!(parsed["v"], 2);

        // The rename consumes every temp: only the final state file remains.
        let leftovers: Vec<String> = std::fs::read_dir(temp_dir.path())
            .expect("tempdir readable")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers, vec!["state.json".to_string()]);
    }
}
