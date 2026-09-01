//! Append-only durability for the virtual registry hive.
//!
//! # Why a journal replaced the snapshot file
//! Every `RegSetValueExW` used to serialize the *entire* hive to pretty-printed JSON and rename
//! it over `registry.json`. Two defects followed from that shape:
//!
//! * **Cost.** Writing n values cost O(n) full serializations - quadratic in the hive size, paid
//!   inside a detour hook, on whatever medium the deployment sits on.
//! * **Lost updates across processes.** Each injected process holds its own copy of the hive and
//!   rewrote the whole file from it. An Electron application runs a dozen injected processes, so
//!   process B's rewrite silently dropped every key process A had written. The atomic
//!   temp-and-rename made each rewrite indivisible; it could not make one process's snapshot
//!   include another's data.
//!
//! Appending one line per mutation fixes both: a write is O(1) and touches only its own bytes,
//! and no writer can erase another's ops because no writer rewrites the file. Rust opens append
//! handles with `FILE_APPEND_DATA` and without `FILE_WRITE_DATA`, which is exactly the Windows
//! mode whose writes are atomic with respect to the end of file, so concurrent appenders
//! interleave whole lines rather than corrupting each other.
//!
//! # Coherence contract
//! A process adopts other processes' ops whenever it records one of its own, so writers
//! converge. Reads are served from the in-process hive, which is a snapshot as of that
//! process's last write - the same visibility the snapshot file provided, minus the data loss.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::registry::store::{SerializedKey, VirtualRegistryData};

// Intention: Compact once the journal is several times larger than the snapshot it collapses to.
// Why: At 4x, at least three quarters of the file is ops that a later op already superseded, so
//      replay cost is dominated by history the snapshot already captures. Below that ratio the
//      rewrite costs more than the replay it saves. The trigger is derived from the data, not
//      from a chosen file size, so it scales with the hive instead of with a guess.
const COMPACTION_SIZE_RATIO: u64 = 4;

// Intention: Never rewrite a journal this small.
// Why: One NTFS cluster. Below a single cluster the file occupies the same disk either way, so
//      compaction buys nothing.
const COMPACTION_FLOOR_BYTES: u64 = 4096;

/// One durable mutation of the virtual registry.
///
/// Keys and value names are stored already normalized: the journal is the store's own log, not
/// an external interface, so replay must reproduce exactly what the live mutation produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum RegistryOp {
    /// A whole-hive image that *replaces* the reader's state.
    ///
    /// Written by compaction and by migration from the legacy `registry.json`. Replacing rather
    /// than merging is what makes compaction exact: the snapshot already encodes every
    /// tombstone and mask the collapsed ops produced.
    Snapshot {
        keys: HashMap<String, SerializedKey>,
    },
    CreateKey {
        key: String,
    },
    SetValue {
        key: String,
        name: String,
        val_type: u32,
        data_hex: String,
    },
    DeleteValue {
        key: String,
        name: String,
    },
    DeleteKey {
        key: String,
    },
    DeleteTree {
        key: String,
    },
}

/// The ops a journal read yielded.
pub(crate) struct JournalRead {
    /// Set when the journal shrank - it was compacted or replaced while this process held an
    /// offset into it - so the caller must discard its hive before applying `ops`.
    pub(crate) reset_first: bool,
    pub(crate) ops: Vec<RegistryOp>,
}

pub(crate) struct Journal {
    path: PathBuf,
    /// How far into the journal this process has already replayed.
    replayed_to: u64,
}

impl Journal {
    /// Opens the journal for `snapshot_path`'s hive, migrating a legacy snapshot file if that is
    /// all that exists.
    pub(crate) fn open(snapshot_path: &Path) -> Self {
        let path = journal_path_for(snapshot_path);
        let mut journal = Journal { path, replayed_to: 0 };
        journal.migrate_legacy_snapshot(snapshot_path);
        journal
    }

    /// Converts a pre-journal `registry.json` into the journal's first snapshot line.
    ///
    /// # Why migrate instead of starting empty
    /// The snapshot file is a user's accumulated virtual registry. Silently starting from an
    /// empty hive because the on-disk format changed is exactly the "corrupt file wipes all
    /// state" failure the persistence layer was written to avoid.
    fn migrate_legacy_snapshot(&mut self, snapshot_path: &Path) {
        if self.path.exists() || !snapshot_path.is_file() {
            return;
        }

        let legacy: VirtualRegistryData = crate::persist::load_state(snapshot_path, "registry");
        if legacy.keys.is_empty() {
            return;
        }

        let key_count = legacy.keys.len();
        self.append(&RegistryOp::Snapshot { keys: legacy.keys });
        // `append` credits this process with having already replayed what it wrote, which is
        // right for its own mutations but wrong here: the migrating process has not applied the
        // snapshot to its hive yet. Rewinding lets the caller's replay pick it up, so the
        // process that migrates ends up with the same state as every process after it.
        self.replayed_to = 0;
        tracing::info!(
            "Registry journal: migrated {key_count} keys from the legacy snapshot '{}'",
            snapshot_path.display()
        );
    }

    /// Reads every op appended since the last call.
    pub(crate) fn read_new_ops(&mut self) -> JournalRead {
        let Ok(file) = File::open(&self.path) else {
            // No journal yet: nothing has ever been written, which is not a failure.
            return JournalRead {
                reset_first: false,
                ops: Vec::new(),
            };
        };

        let length = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(e) => {
                tracing::error!(
                    "Registry journal '{}' could not be measured ({e}); keeping the in-memory hive",
                    self.path.display()
                );
                return JournalRead {
                    reset_first: false,
                    ops: Vec::new(),
                };
            }
        };

        // A journal that shrank was compacted or replaced under us; our offset means nothing
        // against the new content, so replay it from the start.
        let reset_first = length < self.replayed_to;
        let start = if reset_first { 0 } else { self.replayed_to };
        if length == start {
            return JournalRead {
                reset_first: false,
                ops: Vec::new(),
            };
        }

        let mut reader = BufReader::new(file);
        if let Err(e) = reader.seek(SeekFrom::Start(start)) {
            tracing::error!(
                "Registry journal '{}' could not be positioned at {start} ({e}); keeping the in-memory hive",
                self.path.display()
            );
            return JournalRead {
                reset_first: false,
                ops: Vec::new(),
            };
        }

        let mut ops = Vec::new();
        let mut consumed = start;
        for line in reader.by_ref().lines() {
            let line = match line {
                Ok(line) => line,
                Err(e) => {
                    tracing::error!(
                        "Registry journal '{}' is unreadable past byte {consumed} ({e}); the rest is skipped",
                        self.path.display()
                    );
                    break;
                }
            };
            // Advance past the line and its terminator so a torn final line is re-read whole
            // next time instead of being consumed half-parsed.
            let line_bytes = line.len() as u64 + 1;
            if line.trim().is_empty() {
                consumed += line_bytes;
                continue;
            }
            match serde_json::from_str::<RegistryOp>(&line) {
                Ok(op) => {
                    ops.push(op);
                    consumed += line_bytes;
                }
                Err(e) => {
                    tracing::error!(
                        "Registry journal '{}' holds an unparseable record at byte {consumed} ({e}); it is skipped",
                        self.path.display()
                    );
                    consumed += line_bytes;
                }
            }
        }

        self.replayed_to = consumed;
        JournalRead { reset_first, ops }
    }

    /// Appends one op as a single line.
    pub(crate) fn append(&mut self, op: &RegistryOp) {
        let mut line = match serde_json::to_string(op) {
            Ok(line) => line,
            Err(e) => {
                tracing::error!("Failed to serialize a registry op ({e}); the mutation is not durable");
                return;
            }
        };
        line.push('\n');

        if let Some(parent) = self.path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::error!(
                "Failed to create the directory for registry journal '{}': {e}",
                self.path.display()
            );
            return;
        }

        // One `write_all` of one line: append handles make that atomic with respect to the end
        // of file, so concurrent writers interleave whole records.
        match OpenOptions::new().append(true).create(true).open(&self.path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(line.as_bytes()) {
                    tracing::error!(
                        "Failed to append to registry journal '{}': {e}",
                        self.path.display()
                    );
                    return;
                }
                self.replayed_to += line.len() as u64;
            }
            Err(e) => tracing::error!(
                "Failed to open registry journal '{}' for append: {e}",
                self.path.display()
            ),
        }
    }

    /// Collapses the journal to a single snapshot line when it has accumulated enough superseded
    /// history to be worth rewriting.
    ///
    /// # Why exclusivity comes from the share mode
    /// Compaction is the one operation that rewrites the file, so it must not run beside an
    /// appender. Opening with no sharing makes Windows itself refuse when anyone else holds the
    /// file, which needs no lock file and cannot leave a stale lock behind. Losing the race is
    /// harmless: the journal is simply compacted on a later attach.
    pub(crate) fn compact_if_worthwhile(&mut self, keys: &HashMap<String, SerializedKey>) {
        let Ok(metadata) = std::fs::metadata(&self.path) else {
            return;
        };
        let journal_len = metadata.len();
        if journal_len < COMPACTION_FLOOR_BYTES {
            return;
        }

        let snapshot = RegistryOp::Snapshot { keys: keys.clone() };
        let Ok(mut line) = serde_json::to_string(&snapshot) else {
            return;
        };
        line.push('\n');

        if journal_len < line.len() as u64 * COMPACTION_SIZE_RATIO {
            return;
        }

        use std::os::windows::fs::OpenOptionsExt;
        let exclusive = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&self.path);
        let Ok(mut file) = exclusive else {
            // Another process holds the journal; compaction is never urgent.
            return;
        };

        let rewritten = file
            .set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(line.as_bytes()))
            .and_then(|()| file.flush());
        match rewritten {
            Ok(()) => {
                self.replayed_to = line.len() as u64;
                tracing::info!(
                    "Registry journal compacted from {journal_len} to {} bytes",
                    line.len()
                );
            }
            Err(e) => tracing::error!(
                "Failed to compact registry journal '{}': {e}",
                self.path.display()
            ),
        }
    }
}

/// The journal that accompanies a hive snapshot path: `registry.json` -> `registry.jsonl`.
fn journal_path_for(snapshot_path: &Path) -> PathBuf {
    snapshot_path.with_extension("jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with(key: &str) -> HashMap<String, SerializedKey> {
        HashMap::from([(key.to_string(), SerializedKey::default())])
    }

    #[test]
    fn the_journal_sits_beside_the_hive_it_records() {
        assert_eq!(
            journal_path_for(Path::new(r"C:\root\.ppm\system\registry.json")),
            PathBuf::from(r"C:\root\.ppm\system\registry.jsonl")
        );
    }

    #[test]
    fn appended_ops_are_read_back_once_each() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut journal = Journal::open(&dir.path().join("registry.json"));

        journal.append(&RegistryOp::CreateKey {
            key: "HKCU\\A".to_string(),
        });
        journal.append(&RegistryOp::DeleteKey {
            key: "HKCU\\B".to_string(),
        });

        // The writer already accounted for its own appends, so it re-reads nothing.
        assert!(journal.read_new_ops().ops.is_empty());

        // A second reader - the stand-in for another injected process - sees both.
        let mut reader = Journal::open(&dir.path().join("registry.json"));
        let read = reader.read_new_ops();
        assert!(!read.reset_first);
        assert_eq!(read.ops.len(), 2);
        assert!(reader.read_new_ops().ops.is_empty(), "ops are yielded once");
    }

    /// The defect that motivated the journal: with a whole-file snapshot, the second writer's
    /// rewrite erased the first writer's keys. Appending cannot.
    #[test]
    fn two_writers_on_one_journal_never_lose_each_others_ops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hive = dir.path().join("registry.json");

        let mut first = Journal::open(&hive);
        let mut second = Journal::open(&hive);

        first.append(&RegistryOp::SetValue {
            key: "HKCU\\FIRST".to_string(),
            name: "v".to_string(),
            val_type: 1,
            data_hex: "00".to_string(),
        });
        second.append(&RegistryOp::SetValue {
            key: "HKCU\\SECOND".to_string(),
            name: "v".to_string(),
            val_type: 1,
            data_hex: "01".to_string(),
        });

        let mut auditor = Journal::open(&hive);
        let ops = auditor.read_new_ops().ops;
        assert_eq!(ops.len(), 2, "both writers' ops must survive");

        let keys: Vec<String> = ops
            .iter()
            .filter_map(|op| match op {
                RegistryOp::SetValue { key, .. } => Some(key.clone()),
                _ => None,
            })
            .collect();
        assert!(keys.contains(&"HKCU\\FIRST".to_string()));
        assert!(keys.contains(&"HKCU\\SECOND".to_string()));
    }

    #[test]
    fn a_legacy_snapshot_file_migrates_into_the_journal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hive = dir.path().join("registry.json");
        std::fs::write(
            &hive,
            serde_json::to_vec(&VirtualRegistryData {
                keys: snapshot_with("HKCU\\LEGACY"),
            })
            .unwrap(),
        )
        .unwrap();

        let mut journal = Journal::open(&hive);
        assert!(dir.path().join("registry.jsonl").is_file());

        // Regression: the migrating instance credited itself with having replayed the snapshot
        // it wrote, so the one process that performed the migration was the only one that never
        // applied it - it started from an empty hive while every later process saw the data.
        let migrated = journal.read_new_ops().ops;
        assert!(
            matches!(migrated.as_slice(), [RegistryOp::Snapshot { .. }]),
            "the migrating process must replay the snapshot it just wrote"
        );

        // A fresh reader recovers the same hive from the journal alone.
        let mut reader = Journal::open(&hive);
        let ops = reader.read_new_ops().ops;
        assert!(matches!(ops.as_slice(), [RegistryOp::Snapshot { .. }]));

        // Migration is not repeated once the journal exists.
        let mut again = Journal::open(&hive);
        assert_eq!(again.read_new_ops().ops.len(), 1);
    }

    #[test]
    fn an_unparseable_record_is_skipped_without_losing_the_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hive = dir.path().join("registry.json");
        let journal_file = dir.path().join("registry.jsonl");
        std::fs::write(
            &journal_file,
            b"{\"op\":\"create_key\",\"key\":\"HKCU\\\\A\"}\nnot json at all\n{\"op\":\"delete_key\",\"key\":\"HKCU\\\\B\"}\n",
        )
        .unwrap();

        let mut journal = Journal::open(&hive);
        let ops = journal.read_new_ops().ops;

        assert_eq!(ops.len(), 2, "the two valid records must survive the bad one");
    }

    #[test]
    fn compaction_collapses_history_and_readers_recover_from_the_shrink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hive = dir.path().join("registry.json");
        let mut writer = Journal::open(&hive);

        // Enough redundant history to clear the floor and the ratio.
        for index in 0..400 {
            writer.append(&RegistryOp::SetValue {
                key: "HKCU\\HOT".to_string(),
                name: format!("value_{index}"),
                val_type: 1,
                data_hex: "deadbeef".to_string(),
            });
        }
        let before = std::fs::metadata(dir.path().join("registry.jsonl"))
            .unwrap()
            .len();
        assert!(before > COMPACTION_FLOOR_BYTES);

        // A reader that is up to date before the compaction.
        let mut reader = Journal::open(&hive);
        let _ = reader.read_new_ops();

        writer.compact_if_worthwhile(&snapshot_with("HKCU\\HOT"));

        let after = std::fs::metadata(dir.path().join("registry.jsonl"))
            .unwrap()
            .len();
        assert!(after < before, "compaction must shrink the journal");

        // The reader's offset is now past the end; it must be told to start over.
        let read = reader.read_new_ops();
        assert!(read.reset_first, "a shrunken journal must force a full replay");
        assert!(matches!(read.ops.as_slice(), [RegistryOp::Snapshot { .. }]));
    }

    #[test]
    fn a_journal_below_the_floor_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hive = dir.path().join("registry.json");
        let mut journal = Journal::open(&hive);
        journal.append(&RegistryOp::CreateKey {
            key: "HKCU\\A".to_string(),
        });

        let before = std::fs::metadata(dir.path().join("registry.jsonl"))
            .unwrap()
            .len();
        journal.compact_if_worthwhile(&snapshot_with("HKCU\\A"));
        let after = std::fs::metadata(dir.path().join("registry.jsonl"))
            .unwrap()
            .len();

        assert_eq!(before, after, "compacting a tiny journal buys nothing");
    }
}
