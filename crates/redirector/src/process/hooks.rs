use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::{BOOL, TRUE};
use std::cell::Cell;
use std::ffi::{CString, c_void};
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, GetProcessMitigationPolicy, PROCESS_INFORMATION, ProcessDynamicCodePolicy,
    ProcessSignaturePolicy, ResumeThread, STARTUPINFOW, TerminateProcess,
};

#[allow(clippy::upper_case_acronyms)]
type LPSTARTUPINFOW = *mut STARTUPINFOW;
#[allow(clippy::upper_case_acronyms)]
type LpprocessInformation = *mut PROCESS_INFORMATION;

thread_local! {
    static IN_PROC_HOOK: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "C" {
    fn DetourCreateProcessWithDllExW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: u32,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
        lpDllName: *const std::ffi::c_char,
        pfCreateProcessW: *mut c_void,
    ) -> BOOL;
}

type FnCreateProcessW = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    *const u16,
    LPSTARTUPINFOW,
    LpprocessInformation,
) -> BOOL;

static REAL_CREATE_PROCESS_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Queries the frozen child's actual mitigation policies to decide whether an injected
/// redirector.dll can load there at all.
///
/// # Why kernel truth instead of command-line heuristics
/// The previous string-match bypass (`--type=`, `msedgewebview2.exe`, `crashpad_handler.exe`)
/// guessed which children the kernel would kill on injection. The kernel itself publishes
/// that answer: a child with Code Integrity Guard (MicrosoftSignedOnly, bit 0 of the binary
/// signature policy - winnt.h) will refuse our unsigned DLL at load time, and a child with
/// Arbitrary Code Guard (ProhibitDynamicCode, bit 0 of the dynamic-code policy - winnt.h)
/// will refuse the detour trampolines. Querying the policies directly makes the decision
/// generic for every hardened app - Chromium, Electron, hardened launchers, anything -
/// with zero app knowledge in the engine.
///
/// A failed query is a fail-safe NO: injecting on an unknown policy state risks the
/// kernel-kill failure mode this check exists to prevent. The caller then recreates the
/// child plainly, so it still runs - unvirtualized - instead of being killed at boot.
///
/// # Safety
/// `h_child` must be a live process handle granting PROCESS_QUERY_LIMITED_INFORMATION;
/// the handle this hook holds from the suspended create satisfies that by construction.
unsafe fn child_permits_injection(h_child: HANDLE) -> bool {
    // SAFETY: `h_child` is a live handle owned by the caller's PROCESS_INFORMATION for the
    // duration of this call; each out-buffer is a fully sized, stack-allocated policy struct.
    unsafe {
        let mut signature = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
        let sig_ok = GetProcessMitigationPolicy(
            h_child,
            ProcessSignaturePolicy,
            &mut signature as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY>(),
        );
        if sig_ok != 0 && (signature.Anonymous.Flags & 0x1) != 0 {
            tracing::info!(
                "CreateProcess [Hardened Child]: Code Integrity Guard active (MicrosoftSignedOnly); injection forbidden"
            );
            return false;
        }

        let mut dynamic = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
        let dyn_ok = GetProcessMitigationPolicy(
            h_child,
            ProcessDynamicCodePolicy,
            &mut dynamic as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>(),
        );
        if dyn_ok != 0 && (dynamic.Anonymous.Flags & 0x1) != 0 {
            tracing::info!(
                "CreateProcess [Hardened Child]: Arbitrary Code Guard active (ProhibitDynamicCode); injection forbidden"
            );
            return false;
        }

        if sig_ok == 0 || dyn_ok == 0 {
            tracing::warn!(
                "CreateProcess [Policy Query Failed]: GetProcessMitigationPolicy failed (sig {sig_ok}, dyn {dyn_ok}); child not injected"
            );
            return false;
        }
    }

    true
}

unsafe extern "system" fn hook_create_process_w(
    app_name: *const u16,
    cmd_line: *mut u16,
    proc_attr: *const c_void,
    thread_attr: *const c_void,
    inherit: BOOL,
    flags: u32,
    env: *const c_void,
    curr_dir: *const u16,
    startup_info: LPSTARTUPINFOW,
    proc_info: LpprocessInformation,
) -> BOOL {
    let real_fn: FnCreateProcessW = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_PROCESS_W)) };
    guard_detour!(
        &IN_PROC_HOOK,
        unsafe {
            real_fn(
                app_name,
                cmd_line,
                proc_attr,
                thread_attr,
                inherit,
                flags,
                env,
                curr_dir,
                startup_info,
                proc_info,
            )
        },
        {
            let cfg = crate::paths::init_paths();
            let dll_path = cfg.ppm_dir.join("lib").join("redirector.dll");

            if dll_path.is_file()
                && let Ok(dll_cstr) = CString::new(dll_path.to_string_lossy().as_bytes())
            {
                // SAFETY: every pointer argument is forwarded verbatim from the hooked
                // CreateProcessW frame; `dll_cstr` outlives the call; `proc_attr`,
                // `thread_attr`, `env`, `startup_info`, and `proc_info` only need their
                // const-to-mut qualifiers relaxed to match the Detours ABI.
                //
                // CREATE_SUSPENDED is added deliberately: Detours (creatwth.cpp) resumes
                // the child itself only when the caller did not ask for suspended, so the
                // child stays frozen here at pre-boot - its mitigation policies are already
                // applied (the kernel sets them at create time from the parent's attribute
                // list) but no code of ours has run in it yet.
                let res = unsafe {
                    DetourCreateProcessWithDllExW(
                        app_name,
                        cmd_line,
                        proc_attr.cast_mut(),
                        thread_attr.cast_mut(),
                        inherit,
                        flags | CREATE_SUSPENDED,
                        env.cast_mut(),
                        curr_dir,
                        startup_info.cast(),
                        proc_info.cast(),
                        dll_cstr.as_ptr(),
                        std::ptr::null_mut(),
                    )
                };
                if res != 0 {
                    // SAFETY: `proc_info` was filled by the successful create and the child
                    // is frozen (this hook added CREATE_SUSPENDED); the handles live in the
                    // caller's PROCESS_INFORMATION for the duration of this call.
                    if unsafe { child_permits_injection((*proc_info).hProcess) } {
                        // Resume only when the caller wanted a running child: a caller that
                        // passed CREATE_SUSPENDED itself must still receive a frozen child.
                        if flags & CREATE_SUSPENDED == 0 {
                            // SAFETY: resuming the frozen child this hook created suspended;
                            // the injection is verified safe for it.
                            unsafe { ResumeThread((*proc_info).hThread) };
                        }
                        tracing::info!(
                            "CreateProcess [Child Injected]: Injected redirector.dll into new child process"
                        );
                        return TRUE;
                    }

                    // Hardened or unverifiable child: the kernel would kill it at boot if the
                    // injection proceeded. Terminate the frozen pre-boot child and fall
                    // through to the plain create, which yields an unvirtualized child the
                    // kernel will happily run.
                    // SAFETY: handles from the successful suspended create; the child has
                    // not executed a single instruction, so nothing inside it is mid-state.
                    unsafe {
                        TerminateProcess((*proc_info).hProcess, 1);
                        CloseHandle((*proc_info).hProcess);
                        CloseHandle((*proc_info).hThread);
                    }
                }
            }

            unsafe {
                real_fn(
                    app_name,
                    cmd_line,
                    proc_attr,
                    thread_attr,
                    inherit,
                    flags,
                    env,
                    curr_dir,
                    startup_info,
                    proc_info,
                )
            }
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    unsafe {
        let kernelbase = GetModuleHandleW(windows_sys::core::w!("kernelbase.dll"));
        let kernel32 = GetModuleHandleW(windows_sys::core::w!("kernel32.dll"));

        // KernelBase exports CreateProcessW on modern Windows; kernel32 is the fallback.
        let attached = [kernelbase, kernel32].into_iter().any(|module| {
            !module.is_null()
                && hook_export(
                    module,
                    "CreateProcessW",
                    &REAL_CREATE_PROCESS_W,
                    hook_create_process_w as *mut c_void,
                )
        });
        if !attached {
            tracing::warn!("CreateProcessW: hook not attached; child injection inactive");
        }
    }
}
