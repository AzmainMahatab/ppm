use crate::detour::{guard_detour, hook_export, load_trampoline, try_load_trampoline};
use crate::{BOOL, FALSE, TRUE};
use std::cell::Cell;
use std::ffi::{c_char, c_void};
use std::sync::atomic::AtomicPtr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, SetLastError};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, GetProcessMitigationPolicy, PROCESS_INFORMATION,
    ProcessDynamicCodePolicy, ProcessSignaturePolicy, ResumeThread, STARTUPINFOA, STARTUPINFOW,
    TerminateProcess,
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
    /// Policy verified clean: the child accepts an injected engine.
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
/// engine can load there at all.
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

/// The `CreateProcessW` a Detours helper is started through: the un-hooked trampoline, so the
/// helper is not itself intercepted, or the export itself when it was never hooked.
fn helper_create_process() -> *const c_void {
    try_load_trampoline(&REAL_CREATE_PROCESS_W).map_or(CreateProcessW as *const c_void, |trampoline| {
        trampoline.cast_const()
    })
}

/// Applies the injection contract to a child the hook just created suspended, then starts it.
///
/// # Why every entry point creates the child itself and injects afterwards
/// The engine needed for a child depends on the machine the child runs as - an x86 helper of a
/// 64-bit application, an emulated x64 tool on an ARM64 host - and only the created process can
/// say which that is. Creating it frozen, gating on its mitigation policy, and only then
/// injecting also means a hardened child is simply started uninjected, where the previous
/// Detours create-and-inject wrapper had to terminate it and create it a second time.
///
/// # Safety
/// `proc_info` must be a filled `PROCESS_INFORMATION` from a successful create that added
/// `CREATE_SUSPENDED`, whose handles the caller has not yet closed.
unsafe fn admit_frozen_child(api: &str, proc_info: LpprocessInformation, caller_flags: u32) -> BOOL {
    // SAFETY: per the contract, the child is frozen and its handles are live.
    let (process, pid) = unsafe { ((*proc_info).hProcess, (*proc_info).dwProcessId) };
    match unsafe { child_injection_decision(process) } {
        InjectionDecision::Permitted => {
            let lib_dir = crate::paths::init_paths().ppm_dir.join("lib");
            // SAFETY: the suspended create returned a full-access handle to process `pid`;
            // `helper_create_process` has CreateProcessW's signature and ABI.
            match unsafe { injection::inject_suspended(process, pid, &lib_dir, helper_create_process()) } {
                Ok(machine) => {
                    tracing::info!("{api} [Child Injected]: {machine} engine injected into child {pid}");
                }
                Err(error) => {
                    // Fail-fast (ADR-006): a child the engine cannot inject is refused with the
                    // cause, never started outside the sandbox.
                    tracing::error!("{api} [Injection Failed]: {error}; spawn refused");
                    unsafe {
                        discard_frozen_child(proc_info);
                        SetLastError(error.win32_code());
                    }
                    return FALSE;
                }
            }
        }
        InjectionDecision::ForbiddenByPolicy => {
            // Documented contract: a child the kernel forbids us to inject runs unvirtualized
            // in its own sandbox, which is its isolation.
            tracing::info!(
                "{api} [Hardened Child]: mitigation policy forbids injection; the child runs in its own sandbox"
            );
        }
        InjectionDecision::Unknown(err) => {
            tracing::error!(
                "{api} [Policy Query Failed]: GetProcessMitigationPolicy failed ({err}); spawn refused rather than running a child outside the sandbox"
            );
            unsafe {
                discard_frozen_child(proc_info);
                SetLastError(err as u32);
            }
            return FALSE;
        }
    }
    unsafe { start_frozen_child(api, proc_info, caller_flags) }
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
    // SAFETY (both arms): every argument is forwarded verbatim from the intercepted frame; the
    // hooked arm only adds CREATE_SUSPENDED so the child can be admitted at pre-boot.
    let create = |flags| unsafe {
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
    };
    guard_detour!(&IN_PROC_HOOK, create(flags), {
        if create(flags | CREATE_SUSPENDED) == 0 {
            // The OS already set the real error for its own refusal.
            return FALSE;
        }
        unsafe { admit_frozen_child("CreateProcessW", proc_info, flags) }
    })
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
    // SAFETY: as in the wide hook. The caller's own ANSI strings are forwarded untranscoded.
    let create = |flags| unsafe {
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
    };
    guard_detour!(&IN_PROC_HOOK, create(flags), {
        if create(flags | CREATE_SUSPENDED) == 0 {
            return FALSE;
        }
        unsafe { admit_frozen_child("CreateProcessA", proc_info, flags) }
    })
}

/// `CreateProcessAsUserW` reaches `CreateProcessInternalW` directly, so it too spawned
/// unvirtualized children while unhooked.
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
    // SAFETY: as in the wide hook.
    let create = |flags| unsafe {
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
    };
    guard_detour!(&IN_PROC_HOOK, create(flags), {
        if create(flags | CREATE_SUSPENDED) == 0 {
            return FALSE;
        }
        unsafe { admit_frozen_child("CreateProcessAsUserW", proc_info, flags) }
    })
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
