use crate::detour::{guard_detour, hook_export, load_trampoline};
use crate::{BOOL, FALSE, TRUE};
use std::cell::Cell;
use std::ffi::{CString, c_char, c_void};
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, HANDLE, SetLastError,
};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, GetProcessMitigationPolicy, PROCESS_INFORMATION, ProcessDynamicCodePolicy,
    ProcessSignaturePolicy, ResumeThread, STARTUPINFOA, STARTUPINFOW, TerminateProcess,
};

#[allow(clippy::upper_case_acronyms)]
type LPSTARTUPINFOW = *mut STARTUPINFOW;
#[allow(clippy::upper_case_acronyms)]
type LPSTARTUPINFOA = *mut STARTUPINFOA;
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
        lpDllName: *const c_char,
        pfCreateProcessW: *mut c_void,
    ) -> BOOL;

    fn DetourCreateProcessWithDllExA(
        lpApplicationName: *const c_char,
        lpCommandLine: *mut c_char,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: u32,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const c_char,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
        lpDllName: *const c_char,
        pfCreateProcessA: *mut c_void,
    ) -> BOOL;

    fn DetourUpdateProcessWithDll(hProcess: HANDLE, rlpDlls: *const *const c_char, nDlls: u32) -> BOOL;
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

type FnCreateProcessA = unsafe extern "system" fn(
    *const c_char,
    *mut c_char,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    *const c_char,
    LPSTARTUPINFOA,
    LpprocessInformation,
) -> BOOL;

type FnCreateProcessAsUserW = unsafe extern "system" fn(
    HANDLE,
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
static REAL_CREATE_PROCESS_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_CREATE_PROCESS_AS_USER_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

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

/// What the caller must do with a child that Detours already created frozen and injected.
enum ChildDisposition {
    /// The child is injected and ready to start.
    Injected,
    /// The kernel forbids injection. The frozen pre-boot child has been discarded; the caller
    /// recreates it plainly through its own trampoline.
    RecreatePlain,
    /// The spawn is refused. The frozen child has been discarded and the OS error is set.
    Refused,
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

/// Resolves the engine DLL every child must be injected with, or the Win32 error that must
/// fail the spawn.
///
/// # Why a missing engine refuses the spawn
/// ADR-006: the engine must be deployed and every child verifiably injectable. Degrading to a
/// plain spawn would let the application write to the real host silently.
fn engine_dll_for_injection(api: &str) -> Result<CString, u32> {
    let cfg = crate::paths::init_paths();
    let dll_path = cfg.ppm_dir.join("lib").join("redirector.dll");

    if !dll_path.is_file() {
        tracing::error!(
            "{api} [Engine Missing]: redirector.dll not found at '{}'; refusing unvirtualized spawn",
            dll_path.display()
        );
        return Err(ERROR_FILE_NOT_FOUND);
    }

    // Defense-in-depth: an interior NUL cannot occur in an NT path, but if one ever did,
    // failing loudly beats an unterminated CString read.
    CString::new(dll_path.to_string_lossy().as_bytes()).map_err(|_| {
        tracing::error!(
            "{api} [Bad Path]: redirector.dll path contains an interior NUL; refusing unvirtualized spawn"
        );
        ERROR_INVALID_PARAMETER
    })
}

/// Terminates and closes a child that has not executed a single instruction.
///
/// # Safety
/// `proc_info` must be a filled `PROCESS_INFORMATION` from a successful suspended create whose
/// handles the caller still owns.
unsafe fn discard_frozen_child(proc_info: LpprocessInformation) {
    // SAFETY: handles from a successful suspended create; the child has not run, so nothing
    // inside it is mid-state.
    unsafe {
        TerminateProcess((*proc_info).hProcess, 1);
        CloseHandle((*proc_info).hProcess);
        CloseHandle((*proc_info).hThread);
    }
}

/// Starts a frozen child, unless the caller asked for a frozen child in the first place.
///
/// # Why a failed resume is fail-fast
/// Every hook here adds `CREATE_SUSPENDED` so the policy gate can run at pre-boot. If the
/// resume then fails and the hook still reported success, the caller would wait forever on a
/// child that can never run. Discarding it and reporting the real OS error keeps the failure
/// where it happened.
///
/// # Safety
/// `proc_info` must be a filled `PROCESS_INFORMATION` from a successful suspended create.
unsafe fn start_frozen_child(api: &str, proc_info: LpprocessInformation, caller_flags: u32) -> BOOL {
    if caller_flags & CREATE_SUSPENDED != 0 {
        // The caller asked for a suspended child and must still receive one.
        return TRUE;
    }

    // ResumeThread reports failure as (DWORD)-1, not zero: zero is the valid "was not
    // suspended" previous count.
    const RESUME_FAILED: u32 = u32::MAX;

    // SAFETY: resuming the frozen child this hook created suspended.
    if unsafe { ResumeThread((*proc_info).hThread) } == RESUME_FAILED {
        let code = std::io::Error::last_os_error();
        tracing::error!(
            "{api} [Resume Failed]: the child could not be started ({code}); discarding it rather than leaving a frozen child the caller will wait on forever"
        );
        unsafe {
            discard_frozen_child(proc_info);
            SetLastError(code.raw_os_error().unwrap_or(0) as u32);
        }
        return FALSE;
    }
    TRUE
}

/// Applies the injection contract to a child Detours created frozen and already injected.
///
/// # Safety
/// `proc_info` must be a filled `PROCESS_INFORMATION` from a successful suspended create.
unsafe fn gate_detoured_child(api: &str, proc_info: LpprocessInformation) -> ChildDisposition {
    // SAFETY: `proc_info` was filled by the successful create and the child is frozen, so its
    // handles are live for this call.
    match unsafe { child_injection_decision((*proc_info).hProcess) } {
        InjectionDecision::Permitted => {
            tracing::info!("{api} [Child Injected]: Injected redirector.dll into new child process");
            ChildDisposition::Injected
        }
        InjectionDecision::ForbiddenByPolicy => {
            // Documented contract: a child the kernel forbids us to inject runs
            // unvirtualized in its own sandbox (which is its isolation). Terminate the frozen
            // pre-boot child and let the caller recreate it plainly.
            tracing::info!(
                "{api} [Hardened Child]: mitigation policy forbids injection; recreating without redirector.dll"
            );
            unsafe { discard_frozen_child(proc_info) };
            ChildDisposition::RecreatePlain
        }
        InjectionDecision::Unknown(err) => {
            // Fail-fast: an unverifiable policy state is a boundary hole in the making - the
            // spawn is refused with the real OS error rather than silently running a child
            // outside the sandbox.
            unsafe { discard_frozen_child(proc_info) };
            tracing::error!(
                "{api} [Policy Query Failed]: GetProcessMitigationPolicy failed ({err}); spawn refused rather than running a child outside the sandbox"
            );
            unsafe { SetLastError(err as u32) };
            ChildDisposition::Refused
        }
    }
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
            const API: &str = "CreateProcessW";
            let dll_cstr = match engine_dll_for_injection(API) {
                Ok(cstr) => cstr,
                Err(code) => {
                    unsafe { SetLastError(code) };
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
                    "{API} [Injection Failed]: DetourCreateProcessWithDllExW failed for a child of this root ({code}); spawn refused"
                );
                unsafe { SetLastError(code.raw_os_error().unwrap_or(0) as u32) };
                return FALSE;
            }

            match unsafe { gate_detoured_child(API, proc_info) } {
                ChildDisposition::Injected => unsafe { start_frozen_child(API, proc_info, flags) },
                ChildDisposition::RecreatePlain => unsafe {
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
                ChildDisposition::Refused => FALSE,
            }
        }
    )
}

/// `CreateProcessA` is a separate implementation that reaches `CreateProcessInternalA` without
/// passing through `CreateProcessW`, so leaving it unhooked let an application spawn children
/// with no redirector at all - silently, in direct contradiction of the injection contract.
unsafe extern "system" fn hook_create_process_a(
    app_name: *const c_char,
    cmd_line: *mut c_char,
    proc_attr: *const c_void,
    thread_attr: *const c_void,
    inherit: BOOL,
    flags: u32,
    env: *const c_void,
    curr_dir: *const c_char,
    startup_info: LPSTARTUPINFOA,
    proc_info: LpprocessInformation,
) -> BOOL {
    let real_fn: FnCreateProcessA = unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_PROCESS_A)) };
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
            const API: &str = "CreateProcessA";
            let dll_cstr = match engine_dll_for_injection(API) {
                Ok(cstr) => cstr,
                Err(code) => {
                    unsafe { SetLastError(code) };
                    return FALSE;
                }
            };

            // SAFETY: as in the wide hook - every pointer is forwarded verbatim from the
            // intercepted frame and `dll_cstr` outlives the call. The ANSI Detours entry point
            // keeps the caller's own string encoding, so nothing is transcoded here.
            let res = unsafe {
                DetourCreateProcessWithDllExA(
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
                let code = std::io::Error::last_os_error();
                tracing::error!(
                    "{API} [Injection Failed]: DetourCreateProcessWithDllExA failed for a child of this root ({code}); spawn refused"
                );
                unsafe { SetLastError(code.raw_os_error().unwrap_or(0) as u32) };
                return FALSE;
            }

            match unsafe { gate_detoured_child(API, proc_info) } {
                ChildDisposition::Injected => unsafe { start_frozen_child(API, proc_info, flags) },
                ChildDisposition::RecreatePlain => unsafe {
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
                ChildDisposition::Refused => FALSE,
            }
        }
    )
}

/// `CreateProcessAsUserW` reaches `CreateProcessInternalW` directly, so it too spawned
/// unvirtualized children while unhooked.
///
/// # Why this path injects after the create instead of through a Detours wrapper
/// Detours ships no `AsUser` create wrapper, so the hook does what the wrapper does: create the
/// child frozen through the real API, then inject with `DetourUpdateProcessWithDll`. Querying
/// the mitigation policy *before* injecting is strictly better than the wrapper's order - a
/// hardened child is simply started uninjected, with no terminate-and-recreate round trip and
/// no second PID consumed.
unsafe extern "system" fn hook_create_process_as_user_w(
    token: HANDLE,
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
    let real_fn: FnCreateProcessAsUserW =
        unsafe { std::mem::transmute(load_trampoline(&REAL_CREATE_PROCESS_AS_USER_W)) };
    guard_detour!(
        &IN_PROC_HOOK,
        unsafe {
            real_fn(
                token,
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
            const API: &str = "CreateProcessAsUserW";
            let dll_cstr = match engine_dll_for_injection(API) {
                Ok(cstr) => cstr,
                Err(code) => {
                    unsafe { SetLastError(code) };
                    return FALSE;
                }
            };

            // SAFETY: arguments are forwarded verbatim from the intercepted frame; only the
            // creation flags gain CREATE_SUSPENDED so the policy gate runs at pre-boot.
            let created = unsafe {
                real_fn(
                    token,
                    app_name,
                    cmd_line,
                    proc_attr,
                    thread_attr,
                    inherit,
                    flags | CREATE_SUSPENDED,
                    env,
                    curr_dir,
                    startup_info,
                    proc_info,
                )
            };
            if created == 0 {
                // The OS already set the real error for its own refusal.
                return FALSE;
            }

            // SAFETY: `proc_info` was filled by the successful suspended create.
            match unsafe { child_injection_decision((*proc_info).hProcess) } {
                InjectionDecision::Permitted => {
                    let dlls = [dll_cstr.as_ptr()];
                    // SAFETY: the child is frozen and its handle carries the access
                    // DetourUpdateProcessWithDll needs to rewrite the import table; `dlls`
                    // outlives the call.
                    let injected =
                        unsafe { DetourUpdateProcessWithDll((*proc_info).hProcess, dlls.as_ptr(), 1) };
                    if injected == 0 {
                        let code = std::io::Error::last_os_error();
                        tracing::error!(
                            "{API} [Injection Failed]: DetourUpdateProcessWithDll failed for a child of this root ({code}); spawn refused"
                        );
                        unsafe {
                            discard_frozen_child(proc_info);
                            SetLastError(code.raw_os_error().unwrap_or(0) as u32);
                        }
                        return FALSE;
                    }
                    tracing::info!("{API} [Child Injected]: Injected redirector.dll into new child process");
                }
                InjectionDecision::ForbiddenByPolicy => {
                    tracing::info!(
                        "{API} [Hardened Child]: mitigation policy forbids injection; the child runs in its own sandbox"
                    );
                }
                InjectionDecision::Unknown(err) => {
                    unsafe {
                        discard_frozen_child(proc_info);
                        SetLastError(err as u32);
                    }
                    tracing::error!(
                        "{API} [Policy Query Failed]: GetProcessMitigationPolicy failed ({err}); spawn refused rather than running a child outside the sandbox"
                    );
                    return FALSE;
                }
            }

            unsafe { start_frozen_child(API, proc_info, flags) }
        }
    )
}

pub fn init_hooks() {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    unsafe {
        let kernelbase = GetModuleHandleW(windows_sys::core::w!("kernelbase.dll"));
        let kernel32 = GetModuleHandleW(windows_sys::core::w!("kernel32.dll"));
        let modules = [kernelbase, kernel32];

        // Intention: One row per process-creation entry point the engine intercepts.
        // Why: `CreateProcessA` and `CreateProcessAsUserW` do not route through
        //      `CreateProcessW` - each reaches CreateProcessInternal* on its own - so hooking
        //      only the wide form left two silent paths to an unvirtualized child. A table
        //      makes the covered surface reviewable instead of implied.
        //
        //      Still outside this surface, by documented limitation rather than oversight:
        //      `CreateProcessWithTokenW` / `CreateProcessWithLogonW` (the child is spawned by
        //      the secondary-logon service, not by this process) and `ShellExecuteEx` verbs
        //      that Explorer executes out of process - in both cases the child is not a child
        //      of this process tree at all.
        let hooks: [(&str, &AtomicPtr<c_void>, *mut c_void); 3] = [
            (
                "CreateProcessW",
                &REAL_CREATE_PROCESS_W,
                hook_create_process_w as *mut c_void,
            ),
            (
                "CreateProcessA",
                &REAL_CREATE_PROCESS_A,
                hook_create_process_a as *mut c_void,
            ),
            (
                "CreateProcessAsUserW",
                &REAL_CREATE_PROCESS_AS_USER_W,
                hook_create_process_as_user_w as *mut c_void,
            ),
        ];

        // KernelBase exports these on modern Windows; kernel32 is the fallback.
        for (api, slot, hook) in hooks {
            let attached = modules
                .into_iter()
                .any(|module| !module.is_null() && hook_export(module, api, slot, hook));
            if !attached {
                tracing::warn!("{api}: hook not attached; child injection inactive for this entry point");
            }
        }
    }
}
