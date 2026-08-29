use crate::detour::{install_detour, load_trampoline};
use crate::paths::init_paths;
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::AtomicPtr;
use windows_sys::core::HRESULT;

thread_local! {
    static IN_APP_ID_HOOK: Cell<bool> = const { Cell::new(false) };
}

type FnSetCurrentProcessExplicitAppUserModelID = unsafe extern "system" fn(*const u16) -> HRESULT;
static REAL_SET_APP_USER_MODEL_ID: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ROOT_HASH: OnceLock<String> = OnceLock::new();

// Intention: Namespace every virtualized identity as
//             PPM.Portable.<root-hash-16hex>.<Identity>.
// Why: Microsoft requires the same AppUserModelID across all windows and processes of one
//      application, and the portable root is the isolation boundary - the same app unpacked at
//      two different roots is two different machines (separate Home profiles, registry hives,
//      credential vaults) and must never share a taskbar group, pin, or notification channel
//      with the host-installed original or another root. The hash is FNV-1a-64 over the
//      canonicalized, case-normalized root path, so identities are stable across launches
//      (pinning survives) and deterministic per deployment location.
fn root_hash16() -> &'static str {
    ROOT_HASH.get_or_init(|| {
        let root = init_paths().root.clone();
        let canonical = std::fs::canonicalize(&root).unwrap_or(root);
        let normalized = canonical.to_string_lossy();
        // Strip the `\\?\` verbatim prefix canonicalize adds on Windows so the hash does not
        // depend on whether canonicalization succeeded.
        let normalized = normalized.strip_prefix(r"\\?\").unwrap_or(&normalized);
        let normalized = normalized.to_lowercase();

        // FNV-1a 64-bit: dependency-free, deterministic, and collision-free for any realistic
        // number of deployment roots (disambiguation duty only - not a security primitive).
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in normalized.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{hash:016x}")
    })
}

fn sanitize_identity(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Builds the isolated AUMID for this (portable root, identity) pair.
///
/// The identity segment is truncated so the full AUMID stays within the strictest documented
/// character budget; the root hash never is, and it alone carries the isolation boundary.
fn synthetic_aumid(identity: &str) -> String {
    let mut identity = sanitize_identity(identity);
    identity.truncate(34);
    format!("PPM.Portable.{}.{}", root_hash16(), identity)
}

fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

struct AppIdHookGuard;

impl AppIdHookGuard {
    fn enter() -> Option<Self> {
        if IN_APP_ID_HOOK.try_with(|h| h.get()).unwrap_or(false) {
            return None;
        }
        let _ = IN_APP_ID_HOOK.try_with(|h| h.set(true));
        Some(AppIdHookGuard)
    }
}

impl Drop for AppIdHookGuard {
    fn drop(&mut self) {
        let _ = IN_APP_ID_HOOK.try_with(|h| h.set(false));
    }
}

/// Proactively establishes the isolated identity during DLL attach, before any window can
/// exist. Reactive-only interception would leave the majority of applications - which never
/// call SetCurrentProcessExplicitAppUserModelID - grouped under their host-derived implicit
/// identity, out of sync with the virtualized profile (the documented first-commit behavior,
/// evolved to dynamic per-root derivation).
pub fn init_app_user_model_id() {
    // Identity precedence: runner-injected app name -> executable stem -> generic fallback.
    let raw_name = std::env::var("PPM_APP_NAME").unwrap_or_else(|_| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "App".to_string())
    });
    let synthetic_id = synthetic_aumid(&raw_name);
    let app_id_wide: Vec<u16> = synthetic_id.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let shell32 = LoadLibraryW(windows_sys::core::w!("shell32.dll"));
        if !shell32.is_null()
            && let Some(target) = GetProcAddress(
                shell32,
                c"SetCurrentProcessExplicitAppUserModelID".as_ptr().cast(),
            )
        {
            let set_aumid: FnSetCurrentProcessExplicitAppUserModelID = std::mem::transmute(target);
            // SAFETY: `app_id_wide` is a NUL-terminated UTF-16 buffer outliving the call;
            // SetCurrentProcessExplicitAppUserModelID only reads it and records the identity
            // for this process.
            let res = set_aumid(app_id_wide.as_ptr());
            tracing::info!(
                "SetCurrentProcessExplicitAppUserModelID dynamically set to '{synthetic_id}', status: 0x{res:08X}"
            );
        }
    }
}

unsafe extern "system" fn hook_set_app_user_model_id(app_id: *const u16) -> HRESULT {
    let real_fn: FnSetCurrentProcessExplicitAppUserModelID =
        unsafe { std::mem::transmute(load_trampoline(&REAL_SET_APP_USER_MODEL_ID)) };

    let _guard = match AppIdHookGuard::enter() {
        Some(g) => g,
        // SAFETY: forwarding to the original API is the documented fallback for re-entrant
        // calls; `load_trampoline` guarantees the trampoline is published and call-valid.
        None => unsafe { return real_fn(app_id) },
    };

    // Keep app-initiated identity requests inside the same root-scoped namespace as the
    // proactive AUMID set during attach: Microsoft requires one AppUserModelID across all
    // windows and processes of an application, so an app-provided ID is re-parented under the
    // portable root instead of colliding with the host-installed original.
    let app_id_str = wide_to_string(app_id);
    let synthetic_id = synthetic_aumid(&app_id_str);
    let synthetic_wide: Vec<u16> = synthetic_id.encode_utf16().chain(std::iter::once(0)).collect();

    tracing::debug!("SetCurrentProcessExplicitAppUserModelID: mapped '{app_id_str}' -> '{synthetic_id}'");

    // SAFETY: forwarding the rewritten AppID to the original API.
    unsafe { real_fn(synthetic_wide.as_ptr()) }
}

/// Wires the identity layer: proactive AUMID establishment first (before any window
/// can exist), then the interception guard so app-initiated identity changes stay in sync
/// with the isolated namespace instead of clobbering it.
pub fn init_hooks() {
    init_app_user_model_id();
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    unsafe {
        let shell32 = LoadLibraryW(windows_sys::core::w!("shell32.dll"));
        if !shell32.is_null()
            && let Some(proc) = GetProcAddress(
                shell32,
                c"SetCurrentProcessExplicitAppUserModelID".as_ptr().cast(),
            )
        {
            install_detour(
                &REAL_SET_APP_USER_MODEL_ID,
                proc as *mut c_void,
                hook_set_app_user_model_id as *mut c_void,
            );
        }
    }
}
