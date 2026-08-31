use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::{BOOL, FALSE, TRUE};
use std::cell::Cell;
use std::ffi::{CString, c_void};
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, HANDLE, SetLastError,
};
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

/// The three outcomes of the pre-boot injection check, each with a distinct action.
enum InjectionDecision {
    /// Policy verified clean: the child accepts an injected redirector.dll.
    Permitted,
    /// Code Integrity Guard or Arbitrary Code Guard active: the kernel forbids our DLL
    /// or thunks. The child runs unvirtualized by documented design - its own sandbox
    /// is its isolation.
    ForbiddenByPolicy,
    /// The policy query itself failed: the child's injectability is unknowable, so the
    /// spawn is refused with the real OS error code (fail-fast - see ADR-006).
    Unknown(i32),
}

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
/// A failed query means the child's injectability is unknowable: the spawn is refused
/// with the real OS error rather than silently running a child outside the sandbox
/// (fail-fast, per the injection contract - see ADR-006).
///
/// # Safety
/// `h_child` must be a live process handle granting PROCESS_QUERY_LIMITED_INFORMATION;
/// the handle this hook holds from the suspended create satisfies that by construction.
unsafe fn child_injection_decision(h_child: HANDLE) -> InjectionDecision {
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
            return InjectionDecision::ForbiddenByPolicy;
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
            return InjectionDecision::ForbiddenByPolicy;
        }

        if sig_ok == 0 || dyn_ok == 0 {
            // Fail-fast: the real OS error propagates to the refused spawn, carrying the
            // true cause of the unenforceable boundary.
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return InjectionDecision::Unknown(code);
        }
    }

    InjectionDecision::Permitted
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

            // Fail-fast contract (ADR-006): the engine must be deployed and every child
            // verifiably injectable. A spawn the engine cannot guarantee fails loudly with
            // the real OS error - a child never runs outside the sandbox.

            if !dll_path.is_file() {
                // The isolation engine is not deployed at this root; spawning would let the
                // app write to the real host silently. Refuse instead of degrading.
                tracing::error!(
                    "CreateProcess [Engine Missing]: redirector.dll not found at '{}'; refusing unvirtualized spawn",
                    dll_path.display()
                );
                unsafe { SetLastError(ERROR_FILE_NOT_FOUND) };
                return FALSE;
            }

            // Defense-in-depth: an interior NUL cannot occur in an NT path, but if one
            // ever did, failing loudly beats an unterminated CString read.
            let dll_cstr = match CString::new(dll_path.to_string_lossy().as_bytes()) {
                Ok(cstr) => cstr,
                Err(_) => {
                    tracing::error!(
                        "CreateProcess [Bad Path]: redirector.dll path contains an interior NUL; refusing unvirtualized spawn"
                    );
                    unsafe { SetLastError(ERROR_INVALID_PARAMETER) };
                    return FALSE;
                }
            };

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
            if res == 0 {
                // Fail-fast: the injected create failed; a silent unvirtualized retry would
                // breach the boundary. The real OS error propagates to the caller.
                let code = std::io::Error::last_os_error();
                tracing::error!(
                    "CreateProcess [Injection Failed]: DetourCreateProcessWithDllExW failed for a child of this root ({code}); spawn refused"
                );
                unsafe { SetLastError(code.raw_os_error().unwrap_or(0) as u32) };
                return FALSE;
            }

            // SAFETY: `proc_info` was filled by the successful create and the child is
            // frozen (this hook added CREATE_SUSPENDED); the handles live in the caller's
            // PROCESS_INFORMATION for the duration of this call.
            match unsafe { child_injection_decision((*proc_info).hProcess) } {
                InjectionDecision::Permitted => {
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
                    TRUE
                }
                InjectionDecision::ForbiddenByPolicy => {
                    // Documented contract: a child the kernel forbids us to inject runs
                    // unvirtualized in its own sandbox (which is its isolation). Terminate
                    // the frozen pre-boot child and recreate plainly.
                    tracing::info!(
                        "CreateProcess [Hardened Child]: mitigation policy forbids injection; recreating without redirector.dll"
                    );
                    // SAFETY: handles from the successful suspended create; the child has
                    // not executed a single instruction, so nothing inside it is mid-state.
                    unsafe {
                        TerminateProcess((*proc_info).hProcess, 1);
                        CloseHandle((*proc_info).hProcess);
                        CloseHandle((*proc_info).hThread);
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
                InjectionDecision::Unknown(err) => {
                    // Fail-fast: an unverifiable policy state is a boundary hole in the
                    // making - the spawn is refused with the real OS error rather than
                    // silently running a child outside the sandbox.
                    // SAFETY: handles from the successful suspended create; discarding the
                    // pre-boot child together with this failure is clean.
                    unsafe {
                        TerminateProcess((*proc_info).hProcess, 1);
                        CloseHandle((*proc_info).hProcess);
                        CloseHandle((*proc_info).hThread);
                    }
                    tracing::error!(
                        "CreateProcess [Policy Query Failed]: GetProcessMitigationPolicy failed ({err}); spawn refused rather than running a child outside the sandbox"
                    );
                    unsafe { SetLastError(err as u32) };
                    FALSE
                }
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
