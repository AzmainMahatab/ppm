use crate::{BOOL, FALSE, TRUE};
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, S_OK};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GWL_EXSTYLE, GetClassNameW, GetWindowLongW, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, HICON, IsWindowVisible, WS_EX_TOOLWINDOW,
};
use windows_sys::core::{GUID, HRESULT};

static MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);
static BADGE_HICON: LazyLock<AtomicPtr<c_void>> = LazyLock::new(|| AtomicPtr::new(create_badge_icon()));

// CLSID_TaskbarList = 56FDF344-FD6D-11d0-958A-006097C9A090
const CLSID_TASKBAR_LIST: GUID = GUID {
    data1: 0x56fdf344,
    data2: 0xfd6d,
    data3: 0x11d0,
    data4: [0x95, 0x8a, 0x00, 0x60, 0x97, 0xc9, 0xa0, 0x90],
};

// IID_ITASKBAR_LIST3 = ea1afb91-9e28-4b86-90e9-9e9f8a5eefaf
const IID_ITASKBAR_LIST3: GUID = GUID {
    data1: 0xea1afb91,
    data2: 0x9e28,
    data3: 0x4b86,
    data4: [0x90, 0xe9, 0x9e, 0x9f, 0x8a, 0x5e, 0xef, 0xaf],
};

#[repr(C)]
#[allow(non_snake_case)]
struct ITaskbarList3Vtbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    HrInit: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    AddTab: unsafe extern "system" fn(*mut c_void, HWND) -> HRESULT,
    DeleteTab: unsafe extern "system" fn(*mut c_void, HWND) -> HRESULT,
    ActivateTab: unsafe extern "system" fn(*mut c_void, HWND) -> HRESULT,
    SetActiveAlt: unsafe extern "system" fn(*mut c_void, HWND) -> HRESULT,
    MarkFullscreenWindow: unsafe extern "system" fn(*mut c_void, HWND, BOOL) -> HRESULT,
    SetProgressValue: unsafe extern "system" fn(*mut c_void, HWND, u64, u64) -> HRESULT,
    SetProgressState: unsafe extern "system" fn(*mut c_void, HWND, i32) -> HRESULT,
    RegisterTab: unsafe extern "system" fn(*mut c_void, HWND, HWND) -> HRESULT,
    UnregisterTab: unsafe extern "system" fn(*mut c_void, HWND) -> HRESULT,
    SetTabOrder: unsafe extern "system" fn(*mut c_void, HWND, HWND) -> HRESULT,
    SetTabActive: unsafe extern "system" fn(*mut c_void, HWND, HWND, u32) -> HRESULT,
    ThumbBarAddButtons: unsafe extern "system" fn(*mut c_void, HWND, u32, *const c_void) -> HRESULT,
    ThumbBarUpdateButtons: unsafe extern "system" fn(*mut c_void, HWND, u32, *const c_void) -> HRESULT,
    ThumbBarSetImageList: unsafe extern "system" fn(*mut c_void, HWND, *mut c_void) -> HRESULT,
    SetOverlayIcon: unsafe extern "system" fn(*mut c_void, HWND, HICON, *const u16) -> HRESULT,
    SetThumbnailTooltip: unsafe extern "system" fn(*mut c_void, HWND, *const u16) -> HRESULT,
    SetThumbnailClip: unsafe extern "system" fn(*mut c_void, HWND, *const c_void) -> HRESULT,
}

#[repr(C)]
#[allow(non_snake_case)]
struct ITaskbarList3 {
    lpVtbl: *const ITaskbarList3Vtbl,
}

/// Paints the 16x16 badge into a top-down 32bpp DIB and its 1bpp AND mask: a teal disc
/// (Vibrant Teal #0D9488) with a white border ring and a white "P" glyph; everything
/// outside the disc stays transparent.
fn paint_badge_pixels(pixel_ptr: *mut u8, mask_bytes: &mut [u8; 32]) {
    const BG_R: u8 = 0x0D;
    const BG_G: u8 = 0x94;
    const BG_B: u8 = 0x88;
    const WHITE: u8 = 0xFF;

    let set_pixel = |x: usize, y: usize| {
        let offset = (y * 16 + x) * 4;
        // SAFETY: `pixel_ptr` addresses the 16x16x4-byte DIB from CreateDIBSection; every
        // offset below stays inside it for x, y < 16.
        let px = unsafe { pixel_ptr.add(offset) };
        unsafe {
            *px = WHITE;
            *px.add(1) = WHITE;
            *px.add(2) = WHITE;
            *px.add(3) = WHITE;
        }
    };

    for y in 0..16usize {
        for x in 0..16usize {
            let dx = x as f32 - 7.5;
            let dy = y as f32 - 7.5;
            let dist = (dx * dx + dy * dy).sqrt();

            let offset = (y * 16 + x) * 4;
            if dist <= 7.2 {
                // Inside circular badge: clear mask bit (0 = opaque)
                let mask_byte_idx = y * 2 + (x / 8);
                let mask_bit_idx = 7 - (x % 8);
                mask_bytes[mask_byte_idx] &= !(1 << mask_bit_idx);

                if dist > 6.0 {
                    // White border ring
                    set_pixel(x, y);
                } else {
                    // Teal background
                    // SAFETY: same DIB bounds as above.
                    let px = unsafe { pixel_ptr.add(offset) };
                    unsafe {
                        *px = BG_B;
                        *px.add(1) = BG_G;
                        *px.add(2) = BG_R;
                        *px.add(3) = WHITE;
                    }
                }
            } else {
                // Transparent outside
                // SAFETY: same DIB bounds as above.
                let px = unsafe { pixel_ptr.add(offset) };
                unsafe {
                    *px = 0;
                    *px.add(1) = 0;
                    *px.add(2) = 0;
                    *px.add(3) = 0;
                }
            }
        }
    }

    // Draw letter 'P'
    for y in 4..=11 {
        set_pixel(5, y);
        set_pixel(6, y);
    }
    for x in 7..=9 {
        set_pixel(x, 4);
        set_pixel(x, 5);
        set_pixel(x, 7);
        set_pixel(x, 8);
    }
    for y in 5..=7 {
        set_pixel(10, y);
        set_pixel(11, y);
    }
}

/// Lazily materializes the 16x16 "Portable Mode" overlay badge: a teal disc with a white
/// border and a white "P" glyph, drawn into a top-down DIB and converted to a real HICON.
/// Cached process-wide; the GDI intermediates are freed, the HICON lives for the process.
pub fn get_or_create_badge_icon() -> HICON {
    BADGE_HICON.load(Ordering::Acquire)
}

/// Builds the badge HICON once: DIB creation, pixel painting, and ICONINFO assembly.
fn create_badge_icon() -> HICON {
    unsafe {
        use windows_sys::Win32::Graphics::Gdi::{
            BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
            DeleteObject, GetDC, RGBQUAD, ReleaseDC,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, ICONINFO};

        let width = 16i32;
        let height = 16i32;

        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height, // Top-down DIB
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: (width * height * 4) as u32,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD {
                rgbBlue: 0,
                rgbGreen: 0,
                rgbRed: 0,
                rgbReserved: 0,
            }],
        };

        let mut p_bits: *mut c_void = std::ptr::null_mut();
        let hdc = GetDC(std::ptr::null_mut());
        let hbm_color = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &mut p_bits, std::ptr::null_mut(), 0);
        ReleaseDC(std::ptr::null_mut(), hdc);

        if hbm_color.is_null() || p_bits.is_null() {
            tracing::warn!("Failed to create DIB section for badge icon");
            return std::ptr::null_mut();
        }

        let pixel_ptr = p_bits.cast::<u8>();
        let mut mask_bytes = [0xFFu8; 32]; // 16x16 1bpp mask (2 bytes per row * 16 rows)
        paint_badge_pixels(pixel_ptr, &mut mask_bytes);

        let hbm_mask = CreateBitmap(16, 16, 1, 1, mask_bytes.as_ptr().cast::<c_void>());

        let icon_info = ICONINFO {
            fIcon: TRUE,
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: hbm_mask,
            hbmColor: hbm_color,
        };

        let h_icon = CreateIconIndirect(&icon_info);

        DeleteObject(hbm_color);
        DeleteObject(hbm_mask);

        if h_icon.is_null() {
            tracing::warn!("Failed to create Taskbar Badge HICON via CreateIconIndirect");
        } else {
            tracing::info!("Taskbar Badge HICON created successfully via CreateIconIndirect (16x16)");
        }

        h_icon
    }
}

unsafe fn apply_overlay_to_window(hwnd: HWND, hicon: HICON) -> bool {
    unsafe {
        let hr_init = CoInitializeEx(std::ptr::null_mut(), COINIT_APARTMENTTHREADED as u32);
        let mut p_taskbar_raw: *mut c_void = std::ptr::null_mut();

        let mut class_name_buf = [0u16; 256];
        let class_len = GetClassNameW(hwnd, class_name_buf.as_mut_ptr(), 256);
        let class_name = String::from_utf16_lossy(&class_name_buf[..class_len as usize]);

        let mut title_buf = [0u16; 256];
        let title_len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), 256);
        let title = String::from_utf16_lossy(&title_buf[..title_len as usize]);

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

            let hr_init_res = (vtbl.HrInit)(p_taskbar_raw);

            let desc: Vec<u16> = "Portable Mode\0".encode_utf16().collect();
            let overlay_res = (vtbl.SetOverlayIcon)(p_taskbar_raw, hwnd, hicon, desc.as_ptr());

            let _ = (vtbl.Release)(p_taskbar_raw);
            if hr_init == S_OK {
                CoUninitialize();
            }

            if overlay_res == S_OK {
                tracing::info!(
                    "Applied Taskbar Overlay Badge to HWND: 0x{:08x} ('{}' / '{}')",
                    hwnd as usize,
                    class_name,
                    title
                );
                return true;
            } else {
                tracing::debug!(
                    "SetOverlayIcon returned 0x{:08X} (HrInit: 0x{:08X}) for HWND: 0x{:08x} ('{}' / '{}')",
                    overlay_res,
                    hr_init_res,
                    hwnd as usize,
                    class_name,
                    title
                );
            }
        } else {
            tracing::warn!("CoCreateInstance for CLSID_TASKBAR_LIST returned 0x{:08X}", res);
        }

        if hr_init == S_OK {
            CoUninitialize();
        }
        false
    }
}

unsafe fn is_window_owned_by_current_session(hwnd: HWND) -> bool {
    unsafe {
        let mut window_pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut window_pid);
        if window_pid == std::process::id() {
            return true;
        }
        if window_pid == 0 {
            return false;
        }
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        };
        let h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, window_pid);
        if !h_proc.is_null() {
            let mut buf = [0u16; 1024];
            let mut size = 1024u32;
            if QueryFullProcessImageNameW(h_proc, 0, buf.as_mut_ptr(), &mut size) != 0 {
                CloseHandle(h_proc);
                let exe_str = String::from_utf16_lossy(&buf[..size as usize]);
                let exe_path = std::path::PathBuf::from(exe_str);
                let cfg = crate::paths::init_paths();
                return exe_path.starts_with(&cfg.root);
            }
            CloseHandle(h_proc);
        }
        false
    }
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    unsafe {
        if is_window_owned_by_current_session(hwnd) {
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
                    || class_name.contains("Window")
                    || GetWindowTextLengthW(hwnd) > 0
                {
                    let list = &mut *(lparam as *mut Vec<HWND>);
                    list.push(hwnd);
                }
            }
        }
        TRUE
    }
}

/// Background reconciliation loop: every 500 ms it re-enumerates this session's candidate
/// windows and (re-)applies the overlay badge to any not yet badged. Windows that close or
/// hide to tray are evicted from the badged set via `retain`, so restoring them re-badges.
/// Best-effort by design: a spawn failure only forfeits the badge, never the virtualization.
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
                    EnumWindows(
                        Some(enum_windows_callback),
                        &mut current_windows as *mut _ as LPARAM,
                    );

                    // Evict windows that were hidden to tray or closed so badges re-apply on restore
                    badged_windows.retain(|&id| current_windows.iter().any(|&h| (h as usize) == id));

                    for hwnd in current_windows {
                        let id = hwnd as usize;
                        if !badged_windows.contains(&id) && apply_overlay_to_window(hwnd, hicon) {
                            badged_windows.insert(id);
                        }
                    }
                }
            }
        })
        .ok();
}

/// Runs the Portable Mode overlay badge monitor so the identity established by
/// `identity::init_hooks` is visible to the user, not just to the shell.
pub fn init_hooks() {
    start_taskbar_monitor();
}
