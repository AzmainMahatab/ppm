//! Child-process injection boundary verification: a spawned child must be re-injected
//! by the redirector and observe the same virtualized environment.
//!
//! # Why every entry point is exercised, not just the wide one
//! `CreateProcessA` and `CreateProcessAsUserW` are separate implementations that reach
//! `CreateProcessInternal*` without passing through `CreateProcessW`, so hooking the wide form
//! alone left two silent routes to a completely unvirtualized child. Each route therefore gets
//! its own live spawn here: the child runs `--child`, which verifies the redirected profile and
//! exits non-zero if it is not virtualized, so a missed hook fails this suite.

use std::env;
use std::ffi::CString;
use std::ptr;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    CreateProcessA, CreateProcessAsUserW, CreateProcessW, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
    STARTUPINFOA, STARTUPINFOW, WaitForSingleObject,
};

use crate::support::to_wide;

pub(crate) fn run() -> Result<(), String> {
    // The e2e manifest declares this variable via `global_env` with a {root} template;
    // it must arrive expanded in this process - the whole runner env pipeline is under
    // test here (collect -> expand -> dedup -> env block -> CreateProcessW).
    let expected_suffix = "/injected-by-global-env";
    let global_env = env::var("PPM_TEST_GLOBAL_ENV")
        .map_err(|e| format!("PPM_TEST_GLOBAL_ENV missing from launch environment: {e}"))?;
    if !global_env.ends_with(expected_suffix) {
        return Err(format!(
            "PPM_TEST_GLOBAL_ENV not template-expanded: got {global_env:?}, expected suffix {expected_suffix:?}"
        ));
    }

    println!("[SUITE 4/5] Process Injection Boundary...");

    let child_command = child_command_line()?;
    spawn_via_create_process_w(&child_command)?;
    spawn_via_create_process_a(&child_command)?;
    spawn_via_create_process_as_user_w(&child_command)?;

    println!("  -> Process Injection Boundary PASSED!");
    Ok(())
}

/// Builds the command line that re-runs this probe in its child-verification mode.
fn child_command_line() -> Result<String, String> {
    let current_exe = env::current_exe().map_err(|e| format!("Failed to get current_exe: {e}"))?;
    Ok(format!("\"{}\" --child", current_exe.display()))
}

/// Waits for a spawned child and asserts it verified the virtualized environment.
///
/// A non-zero exit means the child ran without the redirector: `--child` re-runs the
/// shell-paths suite, which can only pass under injection.
///
/// # Safety
/// `pi` must be a filled `PROCESS_INFORMATION` from a successful create whose handles are
/// still owned here.
unsafe fn assert_child_was_virtualized(api: &str, pi: &PROCESS_INFORMATION) -> Result<(), String> {
    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);

        let mut exit_code = 0u32;
        let queried = GetExitCodeProcess(pi.hProcess, &mut exit_code);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if queried == 0 {
            return Err(format!("GetExitCodeProcess failed for the {api} child"));
        }
        if exit_code != 0 {
            return Err(format!(
                "the child spawned through {api} exited with code {exit_code}: it did not observe the virtualized environment, so {api} spawned it without the redirector"
            ));
        }
        Ok(())
    }
}

fn spawn_via_create_process_w(command: &str) -> Result<(), String> {
    let mut cmd_w = to_wide(command);

    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let res = CreateProcessW(
            ptr::null(),
            cmd_w.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            ptr::null_mut(),
            ptr::null(),
            &si,
            &mut pi,
        );
        if res == 0 {
            return Err("CreateProcessW failed to spawn child test probe".to_string());
        }

        assert_child_was_virtualized("CreateProcessW", &pi)
    }
}

/// Regression: `CreateProcessA` reaches `CreateProcessInternalA` directly, so it used to spawn
/// children with no redirector injected.
fn spawn_via_create_process_a(command: &str) -> Result<(), String> {
    let cmd_a =
        CString::new(command).map_err(|e| format!("child command line is not ANSI-representable: {e}"))?;
    let mut cmd_bytes = cmd_a.into_bytes_with_nul();

    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let res = CreateProcessA(
            ptr::null(),
            cmd_bytes.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            ptr::null_mut(),
            ptr::null(),
            &si,
            &mut pi,
        );
        if res == 0 {
            return Err("CreateProcessA failed to spawn child test probe".to_string());
        }

        assert_child_was_virtualized("CreateProcessA", &pi)
    }
}

/// Regression: `CreateProcessAsUserW` reaches `CreateProcessInternalW` directly, so it used to
/// spawn children with no redirector injected.
///
/// # Why a null token
/// `hToken` is documented as optional; passing null runs the child as the calling user, which
/// exercises the hook without needing SE_ASSIGNPRIMARYTOKEN_NAME. The point under test is the
/// interception, not impersonation.
fn spawn_via_create_process_as_user_w(command: &str) -> Result<(), String> {
    let mut cmd_w = to_wide(command);

    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let res = CreateProcessAsUserW(
            ptr::null_mut(),
            ptr::null(),
            cmd_w.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            ptr::null_mut(),
            ptr::null(),
            &si,
            &mut pi,
        );
        if res == 0 {
            let code = std::io::Error::last_os_error();
            return Err(format!(
                "CreateProcessAsUserW failed to spawn child test probe ({code})"
            ));
        }

        assert_child_was_virtualized("CreateProcessAsUserW", &pi)
    }
}
