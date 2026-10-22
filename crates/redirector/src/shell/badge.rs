use crate::{BOOL, FALSE, TRUE};
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, S_OK, WPARAM};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
use windows_sys::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CHILDID_SELF, CWPSTRUCT, CallNextHookEx, DispatchMessageW, EVENT_OBJECT_SHOW, EnumWindows, GA_ROOT,
    GWL_EXSTYLE, GetAncestor, GetClassNameW, GetMessageW, GetWindowLongW, GetWindowTextW,
    GetWindowThreadProcessId, HC_ACTION, HICON, IsWindowVisible, MSG, OBJID_WINDOW, PM_NOREMOVE,
    PeekMessageW, PostThreadMessageW, RegisterWindowMessageW, SetWindowsHookExW, WH_CALLWNDPROC,
    WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNTHREAD, WM_APP, WM_USER, WS_EX_TOOLWINDOW,
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

        let mut class_name_buf = [0u16; 256];
        let class_len = GetClassNameW(hwnd, class_name_buf.as_mut_ptr(), 256);
        let class_name = String::from_utf16_lossy(&class_name_buf[..class_len as usize]);

        let mut title_buf = [0u16; 256];
        let title_len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), 256);
        let title = String::from_utf16_lossy(&title_buf[..title_len as usize]);

        let mut p_taskbar_raw: *mut c_void = std::ptr::null_mut();
        let res = CoCreateInstance(
            &CLSID_TASKBAR_LIST,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ITASKBAR_LIST3,
            &mut p_taskbar_raw,
        );

        let mut applied = false;
        if res == S_OK && !p_taskbar_raw.is_null() {
            let taskbar = &*(p_taskbar_raw as *const ITaskbarList3);
            let vtbl = &*taskbar.lpVtbl;

            let hr_init_res = (vtbl.HrInit)(p_taskbar_raw);

            let desc: Vec<u16> = "Portable Mode\0".encode_utf16().collect();
            let overlay_res = (vtbl.SetOverlayIcon)(p_taskbar_raw, hwnd, hicon, desc.as_ptr());

            let _ = (vtbl.Release)(p_taskbar_raw);

            if overlay_res == S_OK {
                tracing::info!(
                    "Applied Taskbar Overlay Badge to HWND: 0x{:08x} ('{}' / '{}')",
                    hwnd as usize,
                    class_name,
                    title
                );
                applied = true;
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

        // Balance CoInitializeEx exactly once on every exit path: S_OK *and* S_FALSE
        // (hr >= 0) both took a COM reference that CoUninitialize must return; a
        // failure result left COM untouched and must not be balanced. The previous
        // shape called CoUninitialize twice whenever the overlay failed.
        if hr_init >= 0 {
            CoUninitialize();
        }

        applied
    }
}

/// The registered message Explorer sends a window each time it creates that window's taskbar
/// button - when it first appears, when it returns from the tray, and after Explorer restarts.
static TASKBAR_BUTTON_CREATED: AtomicU32 = AtomicU32::new(0);

/// The monitor thread, to which the per-thread message hooks post newly buttoned windows.
static MONITOR_THREAD_ID: AtomicU32 = AtomicU32::new(0);

// Intention: Name the thread message that hands the monitor a window to badge (`wParam`).
// Why: The `WM_APP` range is reserved for the application's own messages, and this one is only
//      ever posted to the monitor thread's queue, never to a window.
const WM_BADGE_WINDOW: u32 = WM_APP + 1;

thread_local! {
    /// GUI threads of this process that already carry the message hook. Touched only on the
    /// monitor thread, where every hook callback runs.
    static WATCHED_THREADS: RefCell<HashSet<u32>> = RefCell::new(HashSet::new());
}

/// Badges `hwnd` when it is a window that gets a taskbar button: top-level, visible, and not a
/// tool window.
unsafe fn badge_if_eligible(hwnd: HWND, hicon: HICON) {
    unsafe {
        let is_top_level = GetAncestor(hwnd, GA_ROOT) == hwnd;
        let is_visible = IsWindowVisible(hwnd) != FALSE;
        let is_tool_window = (GetWindowLongW(hwnd, GWL_EXSTYLE) as u32 & WS_EX_TOOLWINDOW) != 0;
        if is_top_level && is_visible && !is_tool_window {
            apply_overlay_to_window(hwnd, hicon);
        }
    }
}

/// Runs on an application GUI thread for every message sent to its windows, and forwards
/// `TaskbarButtonCreated` to the monitor.
///
/// # Why the badge is not applied here
/// Applying it initializes COM and calls into the shell; doing that on the application's own
/// thread would change that thread's COM state under the application. The monitor thread owns
/// all of it instead.
unsafe extern "system" fn on_window_message(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 {
        // SAFETY: for `HC_ACTION`, a `WH_CALLWNDPROC` hook's `lParam` points to the message's
        // `CWPSTRUCT`, valid for the duration of the call.
        let message = unsafe { &*(lparam as *const CWPSTRUCT) };
        let button_created = TASKBAR_BUTTON_CREATED.load(Ordering::Acquire);
        if button_created != 0 && message.message == button_created {
            // SAFETY: posting a thread message has no memory preconditions; a failure only
            // forfeits this badge.
            unsafe {
                PostThreadMessageW(
                    MONITOR_THREAD_ID.load(Ordering::Acquire),
                    WM_BADGE_WINDOW,
                    message.hwnd as WPARAM,
                    0,
                )
            };
        }
    }
    // SAFETY: passes the hook chain's own arguments on unchanged.
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

/// Hooks `thread_id`'s window messages once, so its windows' `TaskbarButtonCreated` reaches the
/// monitor.
///
/// # Why the hook goes in before the first badge attempt
/// A window's button is created some time after it is shown. With the hook in place first,
/// either the button already exists when the attempt runs, or its creation message arrives
/// through the hook - there is no moment in between where it can be missed.
///
/// # Known gap
/// A hook belongs to the thread object, but this set remembers thread ids. If a GUI thread
/// exits and Windows reuses its id for a new GUI thread, that thread is never hooked: its
/// windows are still badged when shown, but not when their button only appears later.
fn watch_thread(thread_id: u32) {
    WATCHED_THREADS.with_borrow_mut(|watched| {
        if !watched.insert(thread_id) {
            return;
        }
        // SAFETY: a thread-local hook on a thread of this process needs no module handle;
        // `on_window_message` lives in this DLL for the life of the process.
        let hook = unsafe {
            SetWindowsHookExW(
                WH_CALLWNDPROC,
                Some(on_window_message),
                std::ptr::null_mut(),
                thread_id,
            )
        };
        if hook.is_null() {
            watched.remove(&thread_id);
            tracing::warn!(
                "Taskbar badge cannot watch GUI thread {thread_id}: {}",
                std::io::Error::last_os_error()
            );
        }
    });
}

/// Hooks the window's thread, then attempts the badge.
unsafe fn on_shown(hwnd: HWND, thread_id: u32, hicon: HICON) {
    watch_thread(thread_id);
    // SAFETY: `hwnd` came from the system for a window of this process.
    unsafe { badge_if_eligible(hwnd, hicon) };
}

/// Receives `EVENT_OBJECT_SHOW` for this process's windows, on the monitor thread.
unsafe extern "system" fn on_window_shown(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    thread_id: u32,
    _time: u32,
) {
    if id_object != OBJID_WINDOW || id_child != CHILDID_SELF as i32 {
        return;
    }
    // SAFETY: the event names a window of this process.
    unsafe { on_shown(hwnd, thread_id, get_or_create_badge_icon()) };
}

unsafe extern "system" fn collect_own_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let mut pid = 0u32;
    // SAFETY: `hwnd` comes from EnumWindows and `lparam` is the `Vec` `badge_existing_windows`
    // passed, alive for the whole enumeration.
    unsafe {
        let thread_id = GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == GetCurrentProcessId() {
            (*(lparam as *mut Vec<(HWND, u32)>)).push((hwnd, thread_id));
        }
    }
    TRUE
}

/// Treats every window this process already has as just shown: any shown before the event hook
/// was registered would otherwise never be seen.
unsafe fn badge_existing_windows(hicon: HICON) {
    let mut windows: Vec<(HWND, u32)> = Vec::new();
    // SAFETY: the callback only appends to `windows`, which outlives the call.
    unsafe {
        EnumWindows(Some(collect_own_window), &mut windows as *mut _ as LPARAM);
        for (hwnd, thread_id) in windows {
            on_shown(hwnd, thread_id, hicon);
        }
    }
}

/// The monitor thread: hooks this process's window events, then pumps the messages those
/// hooks deliver until the process ends.
fn run_monitor() {
    let hicon = get_or_create_badge_icon();
    if hicon.is_null() {
        return;
    }
    // SAFETY: plain Win32 calls on this thread; `msg` and the name buffer outlive their calls.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        // Why: a thread has no message queue until it first calls a message function, and a
        //      thread message posted before that is lost - so the queue exists before any hook
        //      can post to it.
        PeekMessageW(&mut msg, std::ptr::null_mut(), WM_USER, WM_USER, PM_NOREMOVE);
        MONITOR_THREAD_ID.store(GetCurrentThreadId(), Ordering::Release);
        let name: Vec<u16> = "TaskbarButtonCreated\0".encode_utf16().collect();
        TASKBAR_BUTTON_CREATED.store(RegisterWindowMessageW(name.as_ptr()), Ordering::Release);

        let hook = SetWinEventHook(
            EVENT_OBJECT_SHOW,
            EVENT_OBJECT_SHOW,
            std::ptr::null_mut(),
            Some(on_window_shown),
            GetCurrentProcessId(),
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNTHREAD,
        );
        if hook.is_null() {
            tracing::warn!(
                "Taskbar badge monitor cannot hook window events; portable-mode overlay badges inactive"
            );
            return;
        }
        badge_existing_windows(hicon);

        loop {
            match GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) {
                0 => return,
                -1 => {
                    tracing::warn!(
                        "Taskbar badge monitor stopped: {}",
                        std::io::Error::last_os_error()
                    );
                    return;
                }
                _ if msg.hwnd.is_null() && msg.message == WM_BADGE_WINDOW => {
                    apply_overlay_to_window(msg.wParam as HWND, hicon);
                }
                _ => {
                    DispatchMessageW(&msg);
                }
            }
        }
    }
}

/// Starts the badge monitor once per process. It badges this process's own windows: each
/// virtualized process runs its own monitor, so every window of the session is covered, and a
/// window of a process that runs outside virtualization is not badged as if it were inside.
/// Best-effort by design: a spawn failure only forfeits the badge, never the virtualization.
pub fn start_taskbar_monitor() {
    if MONITOR_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }

    if let Err(e) = std::thread::Builder::new()
        .name("taskbar_monitor".to_string())
        .spawn(run_monitor)
    {
        // Release the single-flight flag so a later attach can retry the monitor.
        MONITOR_RUNNING.store(false, Ordering::SeqCst);
        tracing::warn!("Taskbar badge monitor failed to spawn ({e}); portable-mode overlay badges inactive");
    }
}

/// Runs the Portable Mode overlay badge monitor so the identity established by
/// `identity::init_hooks` is visible to the user, not just to the shell.
pub fn init_hooks() {
    start_taskbar_monitor();
}
