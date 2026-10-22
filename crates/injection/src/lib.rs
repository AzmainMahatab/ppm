//! Injecting the virtualization engine into a process that has just been created suspended.
//!
//! Both `ppm run` (the root launch) and the engine's own `CreateProcess*` hooks (every child)
//! inject the same way: create the process frozen, ask the kernel which machine it runs as,
//! pick the engine build for that machine, write it into the process's import table, resume.
//!
//! # Why the machine decides the DLL
//! A process can only load a DLL built for its own machine. An x64 application on an ARM64
//! host runs emulated and needs the x64 engine; a 32-bit helper spawned by a 64-bit application
//! needs the x86 engine. Injecting the injector's own build into either fails the spawn.
//!
//! # On-disk layout
//! `<lib>/<machine>/redirector64.dll` is the 64-bit engine for `<machine>` (`x64` or `arm64`), and
//! `<lib>/<machine>/redirector32.dll` beside it is the x86 engine. The names are Detours' contract:
//! a 64-bit injector cannot patch a 32-bit process itself, so Detours starts a 32-bit helper that
//! loads the DLL named with `64.` replaced by `32.` - from the same folder.

pub mod detours;
mod engine;
pub mod helper;
mod machine;

pub use engine::{ENGINE_DLL_32, ENGINE_DLL_64, EngineChoice, Route, choose_engine, encode_in_code_page};
pub use machine::Machine;

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MOD_NOT_FOUND, ERROR_NOT_SUPPORTED, HANDLE,
};

/// Why an injection did not happen. Each variant maps to the Win32 error a refused spawn reports.
#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("cannot determine which machine the process runs as")]
    MachineQuery(#[source] std::io::Error),
    #[error("the process runs as an unsupported machine type 0x{0:04x}")]
    UnsupportedMachine(u16),
    #[error("a {injector} engine cannot inject a {child} process on a {host} host")]
    UnsupportedRoute {
        injector: Machine,
        child: Machine,
        host: Machine,
    },
    #[error("the {machine} engine is missing at '{}' - run 'ppm init' to deploy it", path.display())]
    EngineMissing { machine: Machine, path: PathBuf },
    #[error(
        "the engine path '{}' cannot be expressed in the system ANSI code page, which process injection requires; move the portable root to a path without such characters",
        .0.display()
    )]
    PathNotAnsi(PathBuf),
    #[error("Detours could not inject '{}'", dll.display())]
    Detours {
        dll: PathBuf,
        #[source]
        cause: std::io::Error,
    },
    #[error("Detours reported success, but '{}' is not in the process's import table", dll.display())]
    NotApplied { dll: PathBuf },
    #[error("cannot set up the helper's confirmation for the child process")]
    HelperHandshake(#[source] std::io::Error),
}

impl InjectError {
    /// The Win32 error a hook reports through `SetLastError` when it refuses a spawn.
    pub fn win32_code(&self) -> u32 {
        let from_io = |error: &std::io::Error| {
            error
                .raw_os_error()
                .map_or(ERROR_NOT_SUPPORTED, |code| code as u32)
        };
        match self {
            InjectError::MachineQuery(cause)
            | InjectError::Detours { cause, .. }
            | InjectError::HelperHandshake(cause) => from_io(cause),
            InjectError::EngineMissing { .. } => ERROR_FILE_NOT_FOUND,
            InjectError::NotApplied { .. } => ERROR_MOD_NOT_FOUND,
            InjectError::UnsupportedMachine(_)
            | InjectError::UnsupportedRoute { .. }
            | InjectError::PathNotAnsi(_) => ERROR_NOT_SUPPORTED,
        }
    }
}

/// Injects the engine into a process created with `CREATE_SUSPENDED`, returning the machine it
/// runs as. The caller resumes it (or discards it on error).
///
/// `create_process_w` is the `CreateProcessW` the Detours helper is started through; inside the
/// engine it must be the un-hooked trampoline, so the helper is not itself intercepted.
///
/// # Safety
/// `process` must be a live handle with `PROCESS_ALL_ACCESS`-level rights to a suspended process
/// whose id is `pid`, and `create_process_w` must point to a function with `CreateProcessW`'s
/// signature and ABI.
pub unsafe fn inject_suspended(
    process: HANDLE,
    pid: u32,
    lib_dir: &Path,
    create_process_w: *const c_void,
) -> Result<Machine, InjectError> {
    // SAFETY: forwarded caller contract - `process` is a live process handle.
    let child = unsafe { machine::of_process(process) }?;
    let host = machine::host();
    let choice = choose_engine(lib_dir, Machine::current(), host, child)?;
    for required in choice.required_files() {
        if !required.is_file() {
            return Err(InjectError::EngineMissing {
                machine: child,
                path: required,
            });
        }
    }

    let dll = engine::ansi_path(&choice.dll)?;
    let dlls = [dll.as_ptr()];
    // Why each route verifies differently: the direct route patches a child of the injector's own
    // bitness, which the injector can inspect; through the helper the child may be beyond what the
    // injector can read, so the helper inspects it and confirms through the handshake.
    // SAFETY: `dlls` holds one NUL-terminated string that outlives both calls; the process is
    // suspended and the handle carries the rights the caller guarantees.
    let verified = unsafe {
        match choice.route {
            Route::Direct => {
                if detours::DetourUpdateProcessWithDll(process, dlls.as_ptr(), 1) == 0 {
                    return Err(detours_failure(choice.dll));
                }
                import_table_was_patched(process)
            }
            Route::ViaHelper => {
                let handshake = helper::Handshake::create(pid).map_err(InjectError::HelperHandshake)?;
                if detours::DetourProcessViaHelperDllsW(pid, 1, dlls.as_ptr(), create_process_w) == 0 {
                    return Err(detours_failure(choice.dll));
                }
                handshake.confirmed()
            }
        }
    };
    if !verified {
        return Err(InjectError::NotApplied { dll: choice.dll });
    }
    Ok(child)
}

/// Detours' own failure for `dll`, with the error it left.
fn detours_failure(dll: PathBuf) -> InjectError {
    InjectError::Detours {
        dll,
        cause: std::io::Error::last_os_error(),
    }
}

/// Whether Detours finished adding a DLL to the suspended process's import table.
///
/// # Why Detours' own success is not enough
/// For a process of the other bitness, Detours reports the exit code of its `rundll32` helper,
/// and `rundll32` exits 0 even when it cannot load the DLL at all - so a failed helper resumed
/// the child with no engine, outside virtualization. The restore payload is the last thing
/// Detours writes into the target once the import table is patched, and it is in place before
/// the process runs. The caller must have the child's bitness: a 32-bit process cannot read a
/// 64-bit child's memory above 4 GiB, where the payload normally lies.
///
/// # Safety
/// `process` must be a live process handle with `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION`.
pub(crate) unsafe fn import_table_was_patched(process: HANDLE) -> bool {
    // SAFETY: the caller guarantees the handle; the GUID is a static Detours defines, and the
    // optional size output is null.
    let payload = unsafe {
        detours::DetourFindRemotePayload(
            process,
            &raw const detours::DETOUR_EXE_RESTORE_GUID,
            std::ptr::null_mut(),
        )
    };
    !payload.is_null()
}
