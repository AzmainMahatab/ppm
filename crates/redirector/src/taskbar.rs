use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{BOOL, FALSE, HWND, S_OK, TRUE, LPARAM};
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateIconFromResourceEx, GetClassNameW, GetWindowLongW, GetWindowTextLengthW,
    GetWindowThreadProcessId, IsWindowVisible, GWL_EXSTYLE, HICON, WS_EX_TOOLWINDOW,
};

// CLSID_TaskbarList = 56FDF344-FD6D-11d0-958A-006097C9A090
const CLSID_TASKBAR_LIST: GUID = GUID {
    data1: 0x56fdf344,
    data2: 0xfd6d,
    data3: 0x11d0,
    data4: [0x95, 0x8a, 0x00, 0x60, 0x97, 0xc9, 0xa0, 0x90],
};

// IID_ITaskbarList3 = ea1afb91-9e28-4b86-90e9-9e9f8a5eefaf
const IID_ITASKBAR_LIST3: GUID = GUID {
    data1: 0xea1afb91,
    data2: 0x9e28,
    data3: 0x4b86,
    data4: [0x90, 0xe9, 0x9e, 0x9f, 0x8a, 0x5e, 0xef, 0xaf],
};

#[repr(C)]
#[allow(non_snake_case)]
pub struct ITaskbarList3Vtbl {
    // IUnknown
    pub QueryInterface: unsafe extern "system" fn(*mut std::ffi::c_void, *const GUID, *mut *mut std::ffi::c_void) -> i32,
    pub AddRef: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    pub Release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,

    // ITaskbarList
    pub HrInit: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32,
    pub AddTab: unsafe extern "system" fn(*mut std::ffi::c_void, HWND) -> i32,
    pub DeleteTab: unsafe extern "system" fn(*mut std::ffi::c_void, HWND) -> i32,
    pub ActivateTab: unsafe extern "system" fn(*mut std::ffi::c_void, HWND) -> i32,
    pub SetActiveAlt: unsafe extern "system" fn(*mut std::ffi::c_void, HWND) -> i32,

    // ITaskbarList2
    pub MarkFullscreenWindow: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, BOOL) -> i32,

    // ITaskbarList3
    pub SetProgressValue: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, u64, u64) -> i32,
    pub SetProgressState: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, i32) -> i32,
    pub RegisterTab: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, HWND) -> i32,
    pub UnregisterTab: unsafe extern "system" fn(*mut std::ffi::c_void, HWND) -> i32,
    pub SetTabOrder: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, HWND) -> i32,
    pub SetTabActive: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, HWND, u32) -> i32,
    pub ThumbBarAddButtons: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, u32, *const std::ffi::c_void) -> i32,
    pub ThumbBarUpdateButtons: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, u32, *const std::ffi::c_void) -> i32,
    pub ThumbBarSetImageList: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, *mut std::ffi::c_void) -> i32,
    pub SetOverlayIcon: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, HICON, *const u16) -> i32,
    pub SetThumbnailTooltip: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, *const u16) -> i32,
    pub SetThumbnailClip: unsafe extern "system" fn(*mut std::ffi::c_void, HWND, *const std::ffi::c_void) -> i32,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct ITaskbarList3 {
    pub lpVtbl: *const ITaskbarList3Vtbl,
}

static MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);
static BADGE_HICON: OnceLock<usize> = OnceLock::new();

type FnSetCurrentProcessExplicitAppUserModelID = unsafe extern "system" fn(*const u16) -> i32;

pub fn init_app_user_model_id() {
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
        let shell32 = LoadLibraryA(b"shell32.dll\0".as_ptr());
        if !shell32.is_null() {
            let func_ptr = GetProcAddress(shell32, b"SetCurrentProcessExplicitAppUserModelID\0".as_ptr());
            if let Some(target) = func_ptr {
                let set_aumid: FnSetCurrentProcessExplicitAppUserModelID = std::mem::transmute(target);
                let app_id: Vec<u16> = "Google.Antigravity.Portable\0"
                    .encode_utf16()
                    .collect();
                let res = set_aumid(app_id.as_ptr());
                crate::paths::log_always(&format!("SetCurrentProcessExplicitAppUserModelID set to 'Google.Antigravity.Portable', status: 0x{:08x}", res));
            }
        }
    }
}

pub fn get_or_create_badge_icon() -> HICON {
    let handle = *BADGE_HICON.get_or_init(|| {
        unsafe {
            let width = 16usize;
            let height = 16usize;
            
            // Standard RT_ICON resource buffer:
            // 40 bytes BITMAPINFOHEADER + 1024 bytes BGRA + 64 bytes 1bpp mask
            let mut res_bytes = Vec::with_capacity(40 + 1024 + 64);

            // 1. BITMAPINFOHEADER
            res_bytes.extend_from_slice(&40u32.to_le_bytes());
            res_bytes.extend_from_slice(&16i32.to_le_bytes());
            res_bytes.extend_from_slice(&32i32.to_le_bytes()); // height * 2 for icon
            res_bytes.extend_from_slice(&1u16.to_le_bytes());
            res_bytes.extend_from_slice(&32u16.to_le_bytes());
            res_bytes.extend_from_slice(&0u32.to_le_bytes());
            res_bytes.extend_from_slice(&1024u32.to_le_bytes());
            res_bytes.extend_from_slice(&0i32.to_le_bytes());
            res_bytes.extend_from_slice(&0i32.to_le_bytes());
            res_bytes.extend_from_slice(&0u32.to_le_bytes());
            res_bytes.extend_from_slice(&0u32.to_le_bytes());

            // 2. 32-bit BGRA Color Pixels (Bottom-to-Top in DIB)
            let mut pixel_grid = vec![[0u8, 0u8, 0u8, 0u8]; width * height];

            let bg_b = 0x88u8;
            let bg_g = 0x94u8;
            let bg_r = 0x0Du8; // Vibrant Teal #0D9488
            let white = 0xFFu8;

            for y in 0..height {
                for x in 0..width {
                    let dx = x as f32 - 7.5;
                    let dy = y as f32 - 7.5;
                    let dist = (dx * dx + dy * dy).sqrt();

                    if dist <= 7.2 {
                        if dist > 6.0 {
                            // White border
                            pixel_grid[y * width + x] = [white, white, white, white];
                        } else {
                            // Teal background
                            pixel_grid[y * width + x] = [bg_b, bg_g, bg_r, white];
                        }
                    }
                }
            }

            // Draw letter 'P'
            for y in 4..=11 {
                pixel_grid[y * width + 5] = [white, white, white, white];
                pixel_grid[y * width + 6] = [white, white, white, white];
            }
            for x in 7..=9 {
                pixel_grid[4 * width + x] = [white, white, white, white];
                pixel_grid[5 * width + x] = [white, white, white, white];
                pixel_grid[7 * width + x] = [white, white, white, white];
                pixel_grid[8 * width + x] = [white, white, white, white];
            }
            for y in 5..=7 {
                pixel_grid[y * width + 10] = [white, white, white, white];
                pixel_grid[y * width + 11] = [white, white, white, white];
            }

            // DIB rows are stored bottom-to-top
            for row in (0..height).rev() {
                for col in 0..width {
                    let bgra = pixel_grid[row * width + col];
                    res_bytes.extend_from_slice(&bgra);
                }
            }

            // 3. 1-bit AND mask (64 bytes of 0x00)
            res_bytes.extend(std::iter::repeat(0u8).take(64));

            let h_icon = CreateIconFromResourceEx(
                res_bytes.as_ptr(),
                res_bytes.len() as u32,
                TRUE,
                0x00030000,
                16,
                16,
                0,
            );

            if h_icon.is_null() {
                crate::paths::log_always("Failed to create badge HICON via CreateIconFromResourceEx");
            } else {
                crate::paths::log_always("Created 16x16 badge HICON successfully");
            }

            h_icon as usize
        }
    });

    handle as HICON
}

unsafe fn apply_overlay_to_window(hwnd: HWND, hicon: HICON) -> bool {
    let hr_init = CoInitializeEx(std::ptr::null_mut(), COINIT_APARTMENTTHREADED as u32);
    let mut p_taskbar_raw: *mut std::ffi::c_void = std::ptr::null_mut();

    let res = CoCreateInstance(
        &CLSID_TASKBAR_LIST,
        std::ptr::null_mut(),
        CLSCTX_INPROC_SERVER,
        &IID_ITASKBAR_LIST3,
        &mut p_taskbar_raw,
    );

    if res == S_OK && !p_taskbar_raw.is_null() {
        let taskbar = &*(p_taskbar_raw as *const ITaskbarList3);
        let vtbl = &*taskbar.lpVtbl;

        let _ = (vtbl.HrInit)(p_taskbar_raw);

        let desc: Vec<u16> = "Portable Mode\0".encode_utf16().collect();
        let overlay_res = (vtbl.SetOverlayIcon)(p_taskbar_raw, hwnd, hicon, desc.as_ptr());

        let _ = (vtbl.Release)(p_taskbar_raw);
        if hr_init == S_OK {
            CoUninitialize();
        }

        if overlay_res == S_OK {
            crate::paths::log_always(&format!("Successfully applied Taskbar Overlay Badge to HWND: 0x{:08x}", hwnd as usize));
            return true;
        }
    }

    if hr_init == S_OK {
        CoUninitialize();
    }
    false
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let target_pid = std::process::id();
    let mut window_pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &mut window_pid);

    if window_pid == target_pid {
        let is_visible = IsWindowVisible(hwnd) != FALSE;
        let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
        let is_tool_window = (ex_style & WS_EX_TOOLWINDOW) != 0;

        if is_visible && !is_tool_window {
            let mut class_name_buf = [0u16; 256];
            let class_len = GetClassNameW(hwnd, class_name_buf.as_mut_ptr(), 256);
            let class_name = String::from_utf16_lossy(&class_name_buf[..class_len as usize]);

            if class_name.contains("Chrome_WidgetWin_1") 
                || class_name.contains("Tauri") 
                || class_name.contains("CabinetWClass") 
                || GetWindowTextLengthW(hwnd) > 0 {
                let list = &mut *(lparam as *mut Vec<HWND>);
                list.push(hwnd);
            }
        }
    }
    TRUE
}

pub fn start_taskbar_monitor() {
    if MONITOR_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }

    std::thread::Builder::new()
        .name("taskbar_monitor".to_string())
        .spawn(|| {
            let hicon = get_or_create_badge_icon();
            if hicon.is_null() {
                return;
            }

            let mut badged_windows: HashSet<usize> = HashSet::new();

            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));

                let mut current_windows: Vec<HWND> = Vec::new();
                unsafe {
                    use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;
                    EnumWindows(Some(enum_windows_callback), &mut current_windows as *mut _ as LPARAM);
                }

                for hwnd in current_windows {
                    let id = hwnd as usize;
                    if !badged_windows.contains(&id) {
                        unsafe {
                            if apply_overlay_to_window(hwnd, hicon) {
                                badged_windows.insert(id);
                            }
                        }
                    }
                }
            }
        })
        .ok();
}

pub fn init_taskbar_integration() {
    init_app_user_model_id();
    start_taskbar_monitor();
}
