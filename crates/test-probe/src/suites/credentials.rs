//! Isolated credential vault boundary verification.

use std::ptr;

use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
};

use crate::support::{from_wide_ptr, to_wide};

pub(crate) fn run() -> Result<(), String> {
    println!("[SUITE 3/5] Credentials Boundary...");
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
            return Err(format!(
                "CredReadW returned invalid data: user '{}', blob {:?}",
                read_user, read_blob
            ));
        }

        CredFree(read_cred_ptr as *const _);

        // Clean-room contract: a generic credential absent from the vault must fail with
        // ERROR_NOT_FOUND instead of falling through to the host credential store.
        let missing_w = to_wide("PPMTestAbsentTarget");
        SetLastError(0);
        let mut absent_ptr: *mut CREDENTIALW = ptr::null_mut();
        let res = CredReadW(missing_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut absent_ptr);
        if res != 0 {
            CredFree(absent_ptr as *const _);
            return Err("CredReadW unexpectedly resolved an absent generic credential".to_string());
        }
        let err = GetLastError();
        if err != ERROR_NOT_FOUND {
            return Err(format!(
                "absent generic credential returned error {err}, expected ERROR_NOT_FOUND"
            ));
        }

        // Delete credential
        let res = CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0);
        if res == 0 {
            return Err("CredDeleteW failed".to_string());
        }
    }

    println!("  -> Credentials Boundary PASSED!");
    Ok(())
}
