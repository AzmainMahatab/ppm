use std::path::PathBuf;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HINSTANCE;

#[derive(Debug, Clone)]
pub struct PathConfig {
    pub root: PathBuf,
    pub user_profile: PathBuf,
    pub user_profile_w: Vec<u16>,
    pub local_appdata: PathBuf,
    pub local_appdata_w: Vec<u16>,
    pub roaming_appdata: PathBuf,
    pub roaming_appdata_w: Vec<u16>,
    pub documents: PathBuf,
    pub documents_w: Vec<u16>,
    pub credentials_file: PathBuf,
    pub log_file: PathBuf,
}

static CONFIG: OnceLock<PathConfig> = OnceLock::new();
static DLL_HANDLE: OnceLock<usize> = OnceLock::new();

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn set_win32_env(name: &str, value: &str) {
    let name_w = to_wide_null(name);
    let val_w = to_wide_null(value);
    windows_sys::Win32::System::Environment::SetEnvironmentVariableW(name_w.as_ptr(), val_w.as_ptr());
}

pub fn set_dll_handle(hinst: HINSTANCE) {
    let _ = DLL_HANDLE.set(hinst as usize);
}

pub fn get_dll_directory() -> PathBuf {
    let mut buffer = [0u16; 1024];
    unsafe {
        let handle = DLL_HANDLE.get().copied().unwrap_or(0) as HINSTANCE;
        let len = windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(
            handle,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        );
        if len > 0 {
            let path_str = String::from_utf16_lossy(&buffer[..len as usize]);
            let path = PathBuf::from(path_str);
            if let Some(parent) = path.parent() {
                return parent.to_path_buf();
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn init_paths() -> &'static PathConfig {
    CONFIG.get_or_init(|| {
        let dll_dir = get_dll_directory();
        
        // Calculate root: if DLL is in <root>\.ppm, <root>\Engine, <root>\lib, or <root>\scratch, parent is <root>
        let root = if dll_dir.ends_with(".ppm")
            || dll_dir.ends_with("Engine")
            || dll_dir.ends_with("lib")
            || dll_dir.ends_with("scratch")
        {
            dll_dir.parent().unwrap_or(&dll_dir).to_path_buf()
        } else {
            dll_dir.clone()
        };

        // Canonical Windows NT User Profile layout under <root>\Home
        let user_profile = root.join("Home");
        let local_appdata = user_profile.join("AppData").join("Local");
        let roaming_appdata = user_profile.join("AppData").join("Roaming");
        let documents = user_profile.join("Documents");
        let credentials_file = roaming_appdata.join("credentials.json");
        let log_file = root.join(".ppm").join("logs").join("redirector.log");

        // Ensure directories exist
        let _ = std::fs::create_dir_all(&user_profile);
        let _ = std::fs::create_dir_all(&local_appdata);
        let _ = std::fs::create_dir_all(&roaming_appdata);
        let _ = std::fs::create_dir_all(&documents);
        if let Some(p) = log_file.parent() {
            let _ = std::fs::create_dir_all(p);
        }

        let root_str = root.to_string_lossy().to_string();
        let up_str = user_profile.to_string_lossy().to_string();
        let la_str = local_appdata.to_string_lossy().to_string();
        let ra_str = roaming_appdata.to_string_lossy().to_string();
        let doc_str = documents.to_string_lossy().to_string();

        // Enforce generic portable protocol & Win32 OS environment block variables
        unsafe {
            set_win32_env("ELECTRON_NO_UPDATER", "1");
            set_win32_env("PORTABLE_EXECUTABLE_DIR", &root_str);
            set_win32_env("PORTABLE_APP", "1");
            set_win32_env("PORTABLE_ROOT", &root_str);
            set_win32_env("PORTABLE_DEBUG", "1");

            set_win32_env("USERPROFILE", &up_str);
            set_win32_env("HOME", &up_str);
            set_win32_env("LOCALAPPDATA", &la_str);
            set_win32_env("APPDATA", &ra_str);
        }

        PathConfig {
            root,
            user_profile_w: to_wide_null(&up_str),
            user_profile,
            local_appdata_w: to_wide_null(&la_str),
            local_appdata,
            roaming_appdata_w: to_wide_null(&ra_str),
            roaming_appdata,
            documents_w: to_wide_null(&doc_str),
            documents,
            credentials_file,
            log_file,
        }
    })
}

pub fn log_always(msg: &str) {
    let cfg = init_paths();
    let line = format!("[REDIRECTOR {:?}] {}\n", std::time::SystemTime::now(), msg);
    
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&cfg.log_file) {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    }

    unsafe {
        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW(wide.as_ptr());
    }
}
