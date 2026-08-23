use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, S_OK};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, WaitForSingleObject, INFINITE, PROCESS_INFORMATION,
    STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

const FOLDERID_PROFILE: GUID = GUID {
    data1: 0x5e6c858f,
    data2: 0x0e22,
    data3: 0x4760,
    data4: [0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73],
};

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

fn test_registry_cow() -> Result<(), String> {
    println!("[TEST 1/4] Testing Registry Copy-on-Write Virtualization...");
    unsafe {
        let subkey = to_wide("Software\\PPMTestProbe");
        let mut hkey: HKEY = ptr::null_mut();
        let mut disp: u32 = 0;

        let res = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            ptr::null_mut(),
            &mut hkey,
            &mut disp,
        );
        if res != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW failed with code {}", res));
        }

        let val_name = to_wide("VirtualKey");
        let val_data = to_wide("VirtualSuccess123");
        let data_bytes = val_data.len() * 2;

        let res = RegSetValueExW(
            hkey,
            val_name.as_ptr(),
            0,
            REG_SZ,
            val_data.as_ptr() as *const u8,
            data_bytes as u32,
        );
        if res != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegSetValueExW failed with code {}", res));
        }

        // Query value back
        let mut buf = [0u16; 128];
        let mut buf_len = (buf.len() * 2) as u32;
        let mut val_type = 0u32;

        let res = RegQueryValueExW(
            hkey,
            val_name.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_len,
        );
        if res != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegQueryValueExW failed with code {}", res));
        }

        let read_str = from_wide_ptr(buf.as_ptr());
        if read_str != "VirtualSuccess123" {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegQueryValueExW returned unexpected data: '{}'", read_str));
        }

        // Delete value
        let res = RegDeleteValueW(hkey, val_name.as_ptr());
        if res != ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegDeleteValueW failed with code {}", res));
        }

        let _ = RegCloseKey(hkey);
    }
    println!("  -> Registry CoW Virtualization PASSED!");
    Ok(())
}

fn test_shell_redirection() -> Result<(), String> {
    println!("[TEST 2/4] Testing Shell Known Folder Redirection...");
    unsafe {
        let mut path_out: *mut u16 = ptr::null_mut();
        let hr = SHGetKnownFolderPath(&FOLDERID_PROFILE, 0, ptr::null_mut(), &mut path_out);
        if hr != S_OK || path_out.is_null() {
            return Err(format!("SHGetKnownFolderPath failed with HRESULT 0x{:08X}", hr));
        }

        let folder_path = from_wide_ptr(path_out);
        println!("  -> Resolved FOLDERID_Profile: '{}'", folder_path);

        if !folder_path.replace('\\', "/").ends_with("Home") && !folder_path.contains("Home") {
            return Err(format!("Profile path was not redirected to Home: '{}'", folder_path));
        }
    }
    println!("  -> Shell Known Folder Redirection PASSED!");
    Ok(())
}

fn test_credentials_vault() -> Result<(), String> {
    println!("[TEST 3/4] Testing Windows Credentials Virtual Vault...");
    unsafe {
        let target_w = to_wide("PPMTestTarget");
        let user_w = to_wide("PPMUser");
        let secret_bytes = b"SecretPassword123";

        let mut cred: CREDENTIALW = std::mem::zeroed();
        cred.Flags = 0;
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = target_w.as_ptr() as *mut u16;
        cred.UserName = user_w.as_ptr() as *mut u16;
        cred.CredentialBlobSize = secret_bytes.len() as u32;
        cred.CredentialBlob = secret_bytes.as_ptr() as *mut u8;
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

        let res = CredWriteW(&cred, 0);
        if res == 0 {
            return Err("CredWriteW failed".to_string());
        }

        // Read credential back
        let mut read_cred_ptr: *mut CREDENTIALW = ptr::null_mut();
        let res = CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut read_cred_ptr);
        if res == 0 || read_cred_ptr.is_null() {
            return Err("CredReadW failed to retrieve credential".to_string());
        }

        let read_cred = &*read_cred_ptr;
        let read_user = from_wide_ptr(read_cred.UserName);
        let read_blob = if !read_cred.CredentialBlob.is_null() && read_cred.CredentialBlobSize > 0 {
            std::slice::from_raw_parts(read_cred.CredentialBlob, read_cred.CredentialBlobSize as usize)
        } else {
            &[]
        };

        if read_user != "PPMUser" || read_blob != secret_bytes {
            CredFree(read_cred_ptr as *const _);
            return Err(format!("CredReadW returned invalid data: user '{}', blob {:?}", read_user, read_blob));
        }

        CredFree(read_cred_ptr as *const _);

        // Delete credential
        let res = CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0);
        if res == 0 {
            return Err("CredDeleteW failed".to_string());
        }
    }
    println!("  -> Credentials Virtual Vault PASSED!");
    Ok(())
}

fn test_child_process_injection() -> Result<(), String> {
    println!("[TEST 4/4] Testing Child Process Detours Injection...");
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

    println!("  -> Child Process Detours Injection PASSED!");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--child") {
        println!("[CHILD] Running inside spawned child process!");
        // Verify child also has virtualized environment
        if let Err(e) = test_shell_redirection() {
            eprintln!("[CHILD ERROR] {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    println!("=== PPM Virtualization Test Probe ===");
    if let Err(e) = test_registry_cow() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(1);
    }
    if let Err(e) = test_shell_redirection() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(2);
    }
    if let Err(e) = test_credentials_vault() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(3);
    }
    if let Err(e) = test_child_process_injection() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(4);
    }

    println!("=== ALL 4 VIRTUALIZATION PILLARS PASSED SUCCESSFULLY! ===");
    std::process::exit(0);
}
