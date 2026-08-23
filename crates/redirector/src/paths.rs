use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct PathConfig {
    pub root: PathBuf,
    pub ppm_dir: PathBuf,
    pub system_dir: PathBuf,
    pub registry_json: PathBuf,
    pub credentials_json: PathBuf,
    pub log_file: PathBuf,

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

static PATHS: OnceLock<PathConfig> = OnceLock::new();

pub fn init_paths() -> &'static PathConfig {
    PATHS.get_or_init(|| {
        let root = resolve_root();
        let ppm_dir = root.join(".ppm");
        let system_dir = ppm_dir.join("system");
        let logs_dir = ppm_dir.join("logs");

        let _ = std::fs::create_dir_all(&system_dir);
        let _ = std::fs::create_dir_all(&logs_dir);

        let registry_json = system_dir.join("registry.json");
        let credentials_json = system_dir.join("credentials.json");
        let log_file = logs_dir.join("redirector.log");

        let user_profile = root.join("Home");
        let local_appdata = user_profile.join("AppData").join("Local");
        let roaming_appdata = user_profile.join("AppData").join("Roaming");
        let documents = user_profile.join("Documents");

        let _ = std::fs::create_dir_all(&local_appdata);
        let _ = std::fs::create_dir_all(&roaming_appdata);
        let _ = std::fs::create_dir_all(&documents);

        let to_wide = |p: &Path| -> Vec<u16> {
            use std::os::windows::ffi::OsStrExt;
            p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
        };

        PathConfig {
            user_profile_w: to_wide(&user_profile),
            local_appdata_w: to_wide(&local_appdata),
            roaming_appdata_w: to_wide(&roaming_appdata),
            documents_w: to_wide(&documents),

            root,
            ppm_dir,
            system_dir,
            registry_json,
            credentials_json,
            log_file,
            user_profile,
            local_appdata,
            roaming_appdata,
            documents,
        }
    })
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
            let hmodule = crate::HMODULE_SELF.load(std::sync::atomic::Ordering::SeqCst) as windows_sys::Win32::Foundation::HMODULE;
            let len = GetModuleFileNameW(hmodule, buf.as_mut_ptr(), 1024);
            if len > 0 {
                let dll_path = String::from_utf16_lossy(&buf[..len as usize]);
                let p = PathBuf::from(dll_path);
                if let Some(parent) = p.parent() {
                    // If DLL is in .ppm/lib/, walk up 2 levels
                    if parent.ends_with("lib") || parent.ends_with(".ppm") {
                        if let Some(ppm_parent) = parent.parent() {
                            if ppm_parent.ends_with(".ppm") {
                                if let Some(root) = ppm_parent.parent() {
                                    return root.to_path_buf();
                                }
                            }
                            return ppm_parent.to_path_buf();
                        }
                    }
                    return parent.to_path_buf();
                }
            }
        }
    }

    // Fallback: Current working directory
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn log_msg(msg: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;

    let cfg = init_paths();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&cfg.log_file) {
        let _ = writeln!(file, "[redirector] {}", msg);
    }
}
