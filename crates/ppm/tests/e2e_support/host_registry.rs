//! Real host registry keys a probe run is checked against.
//!
//! # Why the harness owns this check
//! The probe runs under injection, so every registry call it makes goes through the engine and
//! it cannot see the real registry. This harness runs uninjected: it seeds host keys before the
//! run and reads the real tree afterwards, which is the only place a write or delete that
//! escaped the overlay shows up.

use std::collections::BTreeMap;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, KEY_READ, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW,
    RegDeleteTreeW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegSetValueExW,
};

/// Where every probe root lives, relative to HKCU.
const PROBE_PARENT: &str = r"Software\PPMTestProbe";

/// The tree seeded under each probe root - the layout the probe's registry suite documents -
/// as (key relative to the root, the one string value it holds).
const SEEDED: &[(&str, Option<(&str, &str)>)] = &[
    ("", Some(("Seeded", "host-root"))),
    ("DeleteKeyEx", Some(("Seeded", "host-delete-key-ex"))),
    ("Enumerated", None),
    (r"Enumerated\Doomed", None),
    (r"Enumerated\Kept", None),
    ("Tree", Some(("Seeded", "host-tree"))),
    (r"Tree\Child", Some(("Seeded", "host-tree-child"))),
];

static NEXT_ROOT: AtomicU32 = AtomicU32::new(0);

/// A key's values as name -> (type, raw data).
type Values = BTreeMap<String, (u32, Vec<u8>)>;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn utf16_bytes_with_nul(text: &str) -> Vec<u8> {
    wide(text).iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn join(root: &str, relative: &str) -> String {
    match relative {
        "" => root.to_string(),
        _ => format!(r"{root}\{relative}"),
    }
}

/// An open registry key, closed when dropped.
struct OpenKey(HKEY);

impl Drop for OpenKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful open or create and is closed exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn create(path: &str) -> OpenKey {
    let path_w = wide(path);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated and outlives the call; `hkey` receives the handle.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path_w.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, ERROR_SUCCESS, "creating host key HKCU\\{path}");
    OpenKey(hkey)
}

fn open(path: &str) -> Option<OpenKey> {
    let path_w = wide(path);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated and outlives the call; `hkey` receives the handle.
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path_w.as_ptr(), 0, KEY_READ, &mut hkey) };
    match status {
        ERROR_SUCCESS => Some(OpenKey(hkey)),
        ERROR_FILE_NOT_FOUND => None,
        other => panic!("opening host key HKCU\\{path} failed with code {other}"),
    }
}

/// Removes `path` and everything under it; absent is already removed.
fn remove_tree(path: &str) -> Result<(), String> {
    let path_w = wide(path);
    // SAFETY: `path_w` is NUL-terminated and outlives both calls.
    let (tree, key) = unsafe {
        (
            RegDeleteTreeW(HKEY_CURRENT_USER, path_w.as_ptr()),
            RegDeleteKeyW(HKEY_CURRENT_USER, path_w.as_ptr()),
        )
    };
    match [tree, key]
        .into_iter()
        .find(|&status| status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
    {
        Some(status) => Err(format!(
            "removing host key HKCU\\{path} failed with code {status}"
        )),
        None => Ok(()),
    }
}

/// The longest subkey name, value name and value data `key` holds, in the units the
/// enumeration buffers need (UTF-16 units for names, bytes for data).
fn info(key: &OpenKey, path: &str) -> (usize, usize, usize) {
    let (mut subkey_len, mut name_len, mut data_len) = (0u32, 0u32, 0u32);
    // SAFETY: `key` is open; every requested count points at a live local, the rest are null.
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut subkey_len,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut name_len,
            &mut data_len,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(status, ERROR_SUCCESS, "querying host key HKCU\\{path}");
    // The reported name lengths exclude the terminator.
    (subkey_len as usize + 1, name_len as usize + 1, data_len as usize)
}

fn subkeys(key: &OpenKey, path: &str, max_name: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut buffer = vec![0u16; max_name];
    for index in 0.. {
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` holds `len` units; the optional class and time outputs are null.
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                buffer.as_mut_ptr(),
                &mut len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        match status {
            ERROR_SUCCESS => names.push(String::from_utf16_lossy(&buffer[..len as usize])),
            ERROR_NO_MORE_ITEMS => break,
            other => panic!("enumerating subkeys of HKCU\\{path} failed with code {other}"),
        }
    }
    names
}

fn values(key: &OpenKey, path: &str, max_name: usize, max_data: usize) -> Values {
    let mut found = Values::new();
    let mut name = vec![0u16; max_name];
    let mut data = vec![0u8; max_data];
    for index in 0.. {
        let mut name_len = name.len() as u32;
        let mut data_len = data.len() as u32;
        let mut value_type = 0u32;
        // SAFETY: `name` holds `name_len` units and `data` holds `data_len` bytes.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                &mut value_type,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        match status {
            ERROR_SUCCESS => {
                found.insert(
                    String::from_utf16_lossy(&name[..name_len as usize]),
                    (value_type, data[..data_len as usize].to_vec()),
                );
            }
            ERROR_NO_MORE_ITEMS => break,
            other => panic!("enumerating values of HKCU\\{path} failed with code {other}"),
        }
    }
    found
}

/// Every key under `root` (relative to it, `""` for the root) with its values.
fn snapshot(root: &str) -> BTreeMap<String, Values> {
    let mut tree = BTreeMap::new();
    let mut pending = vec![String::new()];
    while let Some(relative) = pending.pop() {
        let path = join(root, &relative);
        let Some(key) = open(&path) else { continue };
        let (max_subkey, max_name, max_data) = info(&key, &path);
        for child in subkeys(&key, &path, max_subkey) {
            pending.push(match relative.as_str() {
                "" => child,
                parent => format!(r"{parent}\{child}"),
            });
        }
        tree.insert(relative, values(&key, &path, max_name, max_data));
    }
    tree
}

fn seeded_tree() -> BTreeMap<String, Values> {
    SEEDED
        .iter()
        .map(|(relative, value)| {
            let values = value
                .iter()
                .map(|(name, data)| (name.to_string(), (REG_SZ, utf16_bytes_with_nul(data))))
                .collect();
            (relative.to_string(), values)
        })
        .collect()
}

/// A real HKCU tree seeded for one probe run, removed when dropped.
pub struct SeededProbeRoot {
    path: String,
}

impl SeededProbeRoot {
    /// Seeds a fresh root, unique to this test, under [`PROBE_PARENT`].
    ///
    /// # Why one root per test
    /// The end-to-end tests run concurrently; a shared root would let one test's cleanup remove
    /// the keys another test's probe is about to open.
    pub fn seed(label: &str) -> Self {
        let path = format!(
            r"{PROBE_PARENT}\{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        );
        // Debris from an interrupted run under a reused process id.
        remove_tree(&path).expect("clearing the probe root");
        for (relative, value) in SEEDED {
            let key = create(&join(&path, relative));
            if let Some((name, data)) = value {
                let name_w = wide(name);
                let bytes = utf16_bytes_with_nul(data);
                // SAFETY: `key` is open with write access; both buffers outlive the call.
                let status = unsafe {
                    RegSetValueExW(
                        key.0,
                        name_w.as_ptr(),
                        0,
                        REG_SZ,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                    )
                };
                assert_eq!(status, ERROR_SUCCESS, "seeding value '{name}' under HKCU\\{path}");
            }
        }
        Self { path }
    }

    /// The root, relative to HKCU, as the probe's `PPM_TEST_REGISTRY_ROOT`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Asserts the real tree under the root is exactly what was seeded: no key or value deleted
    /// or changed, and nothing the virtualized probe created or wrote.
    pub fn assert_untouched(&self) {
        assert_eq!(
            snapshot(&self.path),
            seeded_tree(),
            "the real registry under HKCU\\{} changed during a virtualized run",
            self.path
        );
    }
}

impl Drop for SeededProbeRoot {
    fn drop(&mut self) {
        // Why not while unwinding: a second panic aborts the whole test run and hides the
        //      failure that started the unwind.
        if let Err(error) = remove_tree(&self.path)
            && !std::thread::panicking()
        {
            panic!("{error}");
        }
    }
}
