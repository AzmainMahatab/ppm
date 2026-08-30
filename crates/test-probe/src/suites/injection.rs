//! Child-process injection boundary verification: a spawned child must be re-injected
//! by the redirector and observe the same virtualized environment.

use std::env;
use std::ptr;

use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION, STARTUPINFOW, WaitForSingleObject,
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
    let current_exe = env::current_exe().map_err(|e| format!("Failed to get current_exe: {}", e))?;
    let cmd = format!("\"{}\" --child", current_exe.display());
    let mut cmd_w = to_wide(&cmd);

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

        WaitForSingleObject(pi.hProcess, INFINITE);

        let mut exit_code = 0u32;
        GetExitCodeProcess(pi.hProcess, &mut exit_code);

        windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
        windows_sys::Win32::Foundation::CloseHandle(pi.hThread);

        if exit_code != 0 {
            return Err(format!("Child probe process failed with exit code {}", exit_code));
        }
    }

    println!("  -> Process Injection Boundary PASSED!");
    Ok(())
}
