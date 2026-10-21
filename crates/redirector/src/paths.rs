use crate::winstr::{path_to_wide, to_wide};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone)]
pub struct PathConfig {
    pub root: PathBuf,
    pub ppm_dir: PathBuf,
    pub system_dir: PathBuf,
    pub registry_json: PathBuf,
    pub credentials_json: PathBuf,
    pub logs_dir: PathBuf,

    // Canonical Portable Profile Paths
    pub user_profile: PathBuf,
    pub local_appdata: PathBuf,
    pub roaming_appdata: PathBuf,
    pub documents: PathBuf,

    // Pre-encoded Wide Strings for Win32 Fast Matching & Return
    pub user_profile_w: Vec<u16>,
    pub local_appdata_w: Vec<u16>,
    pub roaming_appdata_w: Vec<u16>,
    pub documents_w: Vec<u16>,
}

/// Environment variable holding a `tracing` filter directive for `redirector.<date>.log`.
pub const LOG_FILTER_VAR: &str = "PPM_LOG";

static PATHS: LazyLock<PathConfig> = LazyLock::new(build_paths);
static LOGGER_GUARD: LazyLock<WorkerGuard> = LazyLock::new(init_worker_guard);

pub fn init_paths() -> &'static PathConfig {
    &PATHS
}

fn build_paths() -> PathConfig {
    let root = resolve_root();
    let ppm_dir = root.join(".ppm");
    let system_dir = ppm_dir.join("system");
    let logs_dir = ppm_dir.join("logs");

    ensure_dir(&system_dir);
    ensure_dir(&logs_dir);

    let registry_json = system_dir.join("registry.json");
    let credentials_json = system_dir.join("credentials.json");

    let user_profile = root.join("Home");
    let local_appdata = user_profile.join("AppData").join("Local");
    let roaming_appdata = user_profile.join("AppData").join("Roaming");
    let documents = user_profile.join("Documents");

    ensure_dir(&local_appdata);
    ensure_dir(&roaming_appdata);
    ensure_dir(&documents);

    // wide strings are encoded from the canonical PathBufs below

    PathConfig {
        user_profile_w: path_to_wide(&user_profile),
        local_appdata_w: path_to_wide(&local_appdata),
        roaming_appdata_w: path_to_wide(&roaming_appdata),
        documents_w: path_to_wide(&documents),
        root,
        ppm_dir,
        system_dir,
        registry_json,
        credentials_json,
        logs_dir,
        user_profile,
        local_appdata,
        roaming_appdata,
        documents,
    }
}

/// Initializes the high-performance non-blocking concurrent logger.
/// Emitted logs are dispatched to an in-memory lock-free queue with sub-microsecond latency,
/// while a dedicated background worker thread flushes batches to `.ppm/logs/redirector.<date>.log`.
pub fn init_logger() {
    // Touching the LazyLock initializes the subscriber and pins the worker guard.
    std::hint::black_box(&*LOGGER_GUARD);
}

// Why: one file per day and a week of history, so a portable volume's log directory stays
//      bounded however many injected processes write to it. Matches the CLI's ppm.log
//      retention; raise both if diagnosing issues routinely needs older runs.
const RETAINED_LOG_FILES: usize = 7;

// Why `info`: debug lines are emitted per intercepted call, which a busy application turns into
//      megabytes an hour. `PPM_LOG=debug` brings them back for a diagnosis.
const DEFAULT_LOG_FILTER: &str = "info";

/// Builds the non-blocking worker guard; runs once via `LazyLock`.
fn init_worker_guard() -> WorkerGuard {
    let cfg = init_paths();
    let appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("redirector")
        .filename_suffix("log")
        .max_log_files(RETAINED_LOG_FILES)
        .build(&cfg.logs_dir);
    let (non_blocking, guard) = match appender {
        Ok(appender) => tracing_appender::non_blocking(appender),
        Err(error) => {
            // Why: DllMain cannot fail the host process over a log file, and with no file there
            //      is no log to report to; the debugger channel is the one sink left.
            report_to_debugger(&format!(
                "redirector: logging disabled, cannot open '{}': {error}",
                cfg.logs_dir.display()
            ));
            tracing_appender::non_blocking(std::io::sink())
        }
    };

    // Why: The engine runs inside third-party processes, many of which set RUST_LOG for their
    //      own purposes; reading that would let an application silently reconfigure engine
    //      logging. PPM_LOG is ours alone, and the launcher's environment block passes it through.
    let filter =
        EnvFilter::try_from_env(LOG_FILTER_VAR).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));

    let _ = tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .try_init();

    guard
}

/// Creates a directory tree, loudly reporting failure. `DllMain` cannot propagate a
/// directory error to the host process, so the boundary keeps running - but a path the
/// engine could not materialize is exactly the kind of silent environmental failure
/// that must not pass unnoticed.
///
/// Paths are built before the logger exists (the logger needs the log directory), so the failure
/// also goes to the debugger channel, which is always available.
fn ensure_dir(path: &Path) {
    if let Err(e) = std::fs::create_dir_all(path) {
        let message = format!("redirector: failed to create directory '{}': {e}", path.display());
        report_to_debugger(&message);
        tracing::warn!("{message}");
    }
}

/// Writes a line to the attached debugger (DebugView, WinDbg), the one sink that exists before
/// and without the log file.
fn report_to_debugger(message: &str) {
    let wide = to_wide(message);
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the call.
    unsafe { windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW(wide.as_ptr()) };
}

fn resolve_root() -> PathBuf {
    // 1. Check PPM_ROOT environment variable
    if let Ok(root_env) = std::env::var("PPM_ROOT") {
        let p = PathBuf::from(root_env);
        if p.exists() {
            return p;
        }
    }

    // 2. Resolve from DLL module directory
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;

        unsafe {
            let mut buf = [0u16; 1024];
            let hmodule = crate::HMODULE_SELF.load(std::sync::atomic::Ordering::SeqCst)
                as windows_sys::Win32::Foundation::HMODULE;
            let len = GetModuleFileNameW(hmodule, buf.as_mut_ptr(), 1024);
            if len > 0 {
                let dll_path = String::from_utf16_lossy(&buf[..len as usize]);
                let p = PathBuf::from(dll_path);
                if let Some(parent) = p.parent() {
                    // If DLL is in .ppm/lib/, walk up 2 levels
                    let parent_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if (parent_name == "lib" || parent_name == ".ppm")
                        && let Some(ppm_parent) = parent.parent()
                    {
                        let ppm_name = ppm_parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if ppm_name == ".ppm"
                            && let Some(root) = ppm_parent.parent()
                        {
                            return root.to_path_buf();
                        }
                        return ppm_parent.to_path_buf();
                    }
                    return parent.to_path_buf();
                }
            }
        }
    }

    // Fallback: current working directory. DllMain cannot propagate a failure to the
    // host process, so the degenerate root is retained - but the cause stays loud:
    // every boundary keys off this root and must not silently mis-anchor.
    std::env::current_dir().unwrap_or_else(|e| {
        tracing::error!("current_dir() failed ({e}); redirector falling back to a relative root - isolation boundaries will key off an invalid location");
        PathBuf::from(".")
    })
}
