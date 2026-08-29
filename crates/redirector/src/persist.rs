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

    if let Err(e) = fs::write(path, &json_str) {
        tracing::error!("Failed to write {label} state to '{}': {e}", path.display());
    }
}
