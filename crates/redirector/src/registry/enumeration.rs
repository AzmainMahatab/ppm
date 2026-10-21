//! The merged host-plus-overlay listing that a registry enumeration walks.
//!
//! # Why enumeration needs its own merge
//! Copy-on-write answers point lookups by asking the overlay first and the host second. An
//! enumeration has no single key to ask about: it must present one list that contains the
//! host's entries, minus everything the overlay masks, plus everything the overlay added -
//! and it must present the *same* list to `RegQueryInfoKeyW`, whose counts the application
//! sizes its buffers from before walking. A count that disagrees with the walk makes callers
//! either stop early and miss entries or read past what enumeration will return.
//!
//! The merge is kept pure and free of Win32 so the masking rules - the part that is actually
//! subtle - can be tested directly.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;

use crate::registry::store::{OverlayKeyView, normalize_val_name, normalized_segment};

/// Which side of the boundary an enumerated value's data must come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueOrigin {
    /// The overlay holds the data; serve it from the store.
    Overlay,
    /// Only the host holds the data; fetch it through the real registry API by name.
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnumeratedValue {
    pub(crate) name: String,
    pub(crate) origin: ValueOrigin,
}

/// One key's merged listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeyView {
    pub(crate) subkeys: Vec<String>,
    pub(crate) values: Vec<EnumeratedValue>,
}

/// What the host registry itself lists for a key. Empty for a key that exists only in the
/// overlay, which has no host counterpart to enumerate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HostListing {
    pub(crate) subkeys: Vec<String>,
    pub(crate) values: Vec<String>,
}

/// Merges the host's listing with the overlay's, applying every masking rule.
///
/// Host entries keep their host order - applications observe a stable order from the OS and
/// some depend on it - and overlay-only entries follow, already sorted by the store. An entry
/// present on both sides appears once, spelled the way the application wrote it, because that
/// spelling is the one the application will compare against.
pub(crate) fn merge(overlay: &OverlayKeyView, host: &HostListing) -> KeyView {
    let overlay_subkeys: HashMap<String, &String> = overlay
        .child_keys
        .iter()
        .map(|name| (normalized_segment(name), name))
        .collect();
    let overlay_values: HashMap<String, &String> = overlay
        .value_names
        .iter()
        .map(|name| (normalize_val_name(name), name))
        .collect();

    let mut subkeys = Vec::new();
    let mut seen_subkeys: HashSet<String> = HashSet::new();

    if !overlay.host_subkeys_masked {
        for host_name in &host.subkeys {
            let normalized = normalized_segment(host_name);
            if overlay.masked_child_keys.contains(&normalized) {
                continue;
            }
            let name = match overlay_subkeys.get(&normalized) {
                Some(overlay_name) => (*overlay_name).clone(),
                None => host_name.clone(),
            };
            if seen_subkeys.insert(normalized) {
                subkeys.push(name);
            }
        }
    }
    for overlay_name in &overlay.child_keys {
        if seen_subkeys.insert(normalized_segment(overlay_name)) {
            subkeys.push(overlay_name.clone());
        }
    }

    let mut values = Vec::new();
    let mut seen_values: HashSet<String> = HashSet::new();

    if !overlay.host_values_masked {
        for host_name in &host.values {
            let normalized = normalize_val_name(host_name);
            if overlay.masked_values.contains(&normalized) {
                continue;
            }
            // An overlay value shadows the host copy: same slot, overlay spelling, and the
            // data must come from the overlay rather than the host.
            let (name, origin) = match overlay_values.get(&normalized) {
                Some(overlay_name) => ((*overlay_name).clone(), ValueOrigin::Overlay),
                None => (host_name.clone(), ValueOrigin::Host),
            };
            if seen_values.insert(normalized) {
                values.push(EnumeratedValue { name, origin });
            }
        }
    }
    for overlay_name in &overlay.value_names {
        if seen_values.insert(normalize_val_name(overlay_name)) {
            values.push(EnumeratedValue {
                name: overlay_name.clone(),
                origin: ValueOrigin::Overlay,
            });
        }
    }

    KeyView { subkeys, values }
}

/// Per-handle merged listings, valid while the overlay generation is unchanged.
///
/// # Why the cache is keyed by handle
/// An application enumerates by walking indices 0..n on one open handle. Rebuilding the merge
/// per index would be quadratic and, worse, would let a concurrent write change the listing
/// between two indices of the same walk. The entry is dropped when the handle is closed.
/// A cached listing and the overlay generation it was built against.
type CachedListing = (u64, Arc<KeyView>);

static VIEW_CACHE: LazyLock<Mutex<HashMap<usize, CachedListing>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Returns the cached listing for `handle`, building it with `build` when absent or stale.
pub(crate) fn cached_view(handle: usize, generation: u64, build: impl FnOnce() -> KeyView) -> Arc<KeyView> {
    let mut cache = VIEW_CACHE.lock();
    if let Some((cached_generation, view)) = cache.get(&handle)
        && *cached_generation == generation
    {
        return Arc::clone(view);
    }

    let view = Arc::new(build());
    cache.insert(handle, (generation, Arc::clone(&view)));
    view
}

/// Drops any cached listing for a handle that is being closed.
pub(crate) fn forget(handle: usize) {
    VIEW_CACHE.lock().remove(&handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay(child_keys: &[&str], value_names: &[&str]) -> OverlayKeyView {
        OverlayKeyView {
            child_keys: child_keys.iter().map(|name| name.to_string()).collect(),
            value_names: value_names.iter().map(|name| name.to_string()).collect(),
            ..OverlayKeyView::default()
        }
    }

    fn host(subkeys: &[&str], values: &[&str]) -> HostListing {
        HostListing {
            subkeys: subkeys.iter().map(|name| name.to_string()).collect(),
            values: values.iter().map(|name| name.to_string()).collect(),
        }
    }

    fn value_names(view: &KeyView) -> Vec<&str> {
        view.values.iter().map(|value| value.name.as_str()).collect()
    }

    /// The gap this whole module exists to close: a value written through the boundary was
    /// invisible to an enumeration of its own key.
    #[test]
    fn an_overlay_only_value_appears_in_the_listing() {
        let view = merge(&overlay(&[], &["Written"]), &host(&[], &["HostValue"]));

        assert_eq!(value_names(&view), vec!["HostValue", "Written"]);
        assert_eq!(view.values[0].origin, ValueOrigin::Host);
        assert_eq!(view.values[1].origin, ValueOrigin::Overlay);
    }

    #[test]
    fn an_overlay_value_shadows_the_host_copy_in_place() {
        let view = merge(&overlay(&[], &["Shared"]), &host(&[], &["SHARED", "Other"]));

        // One slot, in the host's position, carrying the application's own spelling, and the
        // data must come from the overlay.
        assert_eq!(value_names(&view), vec!["Shared", "Other"]);
        assert_eq!(view.values[0].origin, ValueOrigin::Overlay);
        assert_eq!(view.values[1].origin, ValueOrigin::Host);
    }

    #[test]
    fn individually_masked_entries_are_dropped_from_both_axes() {
        let mut view_input = overlay(&[], &[]);
        view_input.masked_values.insert("gone".to_string());
        view_input.masked_child_keys.insert("OLDCHILD".to_string());

        let view = merge(&view_input, &host(&["OldChild", "Kept"], &["Gone", "Retained"]));

        assert_eq!(view.subkeys, vec!["Kept"]);
        assert_eq!(value_names(&view), vec!["Retained"]);
    }

    /// `RegDeleteTreeW`, and a key re-created inside a deleted subtree, mask the host wholesale
    /// without listing what they mask.
    #[test]
    fn wildcard_masks_hide_every_host_entry_but_keep_overlay_ones() {
        let mut view_input = overlay(&["Fresh"], &["Rewritten"]);
        view_input.host_values_masked = true;
        view_input.host_subkeys_masked = true;

        let view = merge(&view_input, &host(&["HostChild"], &["HostValue"]));

        assert_eq!(view.subkeys, vec!["Fresh"]);
        assert_eq!(value_names(&view), vec!["Rewritten"]);
    }

    #[test]
    fn host_order_is_preserved_and_overlay_only_entries_follow() {
        let view = merge(
            &overlay(&["Zebra"], &["Zulu"]),
            &host(&["Middle", "Alpha"], &["Mike", "Alfa"]),
        );

        assert_eq!(view.subkeys, vec!["Middle", "Alpha", "Zebra"]);
        assert_eq!(value_names(&view), vec!["Mike", "Alfa", "Zulu"]);
    }

    #[test]
    fn a_synthetic_key_lists_only_what_the_overlay_holds() {
        let view = merge(&overlay(&["Child"], &["Value"]), &HostListing::default());

        assert_eq!(view.subkeys, vec!["Child"]);
        assert_eq!(value_names(&view), vec!["Value"]);
    }

    #[test]
    fn a_cached_listing_is_reused_until_the_generation_moves() {
        let handle = 0x9001;
        forget(handle);

        let first = cached_view(handle, 7, || {
            merge(&overlay(&["A"], &[]), &HostListing::default())
        });
        let second = cached_view(handle, 7, || panic!("an unchanged generation must not rebuild"));
        assert!(Arc::ptr_eq(&first, &second));

        let rebuilt = cached_view(handle, 8, || {
            merge(&overlay(&["B"], &[]), &HostListing::default())
        });
        assert_eq!(rebuilt.subkeys, vec!["B"]);

        forget(handle);
        let after_close = cached_view(handle, 8, || {
            merge(&overlay(&["C"], &[]), &HostListing::default())
        });
        assert_eq!(
            after_close.subkeys,
            vec!["C"],
            "closing a handle must drop its cached listing"
        );
        forget(handle);
    }
}
