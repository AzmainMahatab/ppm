//! Isolated credential vault boundary verification.

use std::ptr;

use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALA, CREDENTIALW, CredDeleteA, CredDeleteW,
    CredEnumerateA, CredFree, CredReadA, CredReadW, CredWriteA, CredWriteW,
};

use crate::support::{from_wide_ptr, to_ansi, to_wide};

/// RAII owner of a CREDENTIALW returned by CredReadW: the credential is freed through
/// CredFree on every exit path, replacing duplicated manual cleanup calls.
struct OwnedCredential(*mut CREDENTIALW);

impl Drop for OwnedCredential {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is either null or a CredReadW-returned credential owned
            // by this wrapper for its entire lifetime.
            unsafe { CredFree(self.0.cast()) };
        }
    }
}

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

        // The wrapper frees the credential on every exit path below.
        let read_cred_owned = OwnedCredential(read_cred_ptr);
        let read_cred = &*read_cred_owned.0;
        let read_user = from_wide_ptr(read_cred.UserName);
        let read_blob = if !read_cred.CredentialBlob.is_null() && read_cred.CredentialBlobSize > 0 {
            std::slice::from_raw_parts(read_cred.CredentialBlob, read_cred.CredentialBlobSize as usize)
        } else {
            &[]
        };

        if read_user != "PPMUser" || read_blob != secret_bytes {
            return Err(format!(
                "CredReadW returned invalid data: user '{}', blob {:?}",
                read_user, read_blob
            ));
        }

        // Clean-room contract: a generic credential absent from the vault must fail with
        // ERROR_NOT_FOUND instead of falling through to the host credential store.
        let missing_w = to_wide("PPMTestAbsentTarget");
        SetLastError(0);
        let mut absent_ptr: *mut CREDENTIALW = ptr::null_mut();
        let res = CredReadW(missing_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut absent_ptr);
        let _absent = OwnedCredential(absent_ptr);
        if res != 0 {
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

    ansi_entry_points_share_the_vault()?;

    println!("  -> Credentials Boundary PASSED!");
    Ok(())
}

/// The ANSI credential API must reach the same vault as the wide one.
///
/// # Why the families are crossed
/// A round trip through the ANSI functions alone would pass even if they bypassed the engine
/// entirely - write and read would both hit the real credential store. Writing through one
/// family and reading through the other can only succeed if both land in the vault, because
/// the wide read is clean-roomed and never sees the host store.
fn ansi_entry_points_share_the_vault() -> Result<(), String> {
    const TARGET: &str = "PPMTestTargetAnsi";
    let target_a = to_ansi(TARGET).ok_or("ANSI target name")?;
    let target_w = to_wide(TARGET);
    let user_a = to_ansi("PPMUserAnsi").ok_or("ANSI user name")?;
    let secret = b"AnsiSecret456";

    unsafe {
        let mut cred: CREDENTIALA = std::mem::zeroed();
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = target_a.as_ptr().cast_mut();
        cred.UserName = user_a.as_ptr().cast_mut();
        cred.CredentialBlobSize = secret.len() as u32;
        cred.CredentialBlob = secret.as_ptr().cast_mut();
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
        if CredWriteA(&cred, 0) == 0 {
            return Err(format!("CredWriteA failed ({})", GetLastError()));
        }

        // A -> W: the clean-roomed wide read finds it only if CredWriteA wrote to the vault.
        let mut wide_read: *mut CREDENTIALW = ptr::null_mut();
        let found_wide = CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut wide_read) != 0;
        let _wide_read = OwnedCredential(wide_read);
        if !found_wide {
            // The secret reached the real credential store; remove it before failing.
            CredDeleteA(target_a.as_ptr(), CRED_TYPE_GENERIC, 0);
            return Err("CredWriteA bypassed the vault: the credential went to the host store".to_string());
        }

        // W -> A: the ANSI read must be served from the vault, with the strings re-encoded.
        let mut ansi_read: *mut CREDENTIALA = ptr::null_mut();
        if CredReadA(target_a.as_ptr(), CRED_TYPE_GENERIC, 0, &mut ansi_read) == 0 || ansi_read.is_null() {
            return Err(format!(
                "CredReadA did not find a vault credential ({})",
                GetLastError()
            ));
        }
        let ansi_read = OwnedCredentialA(ansi_read);
        let read = &*ansi_read.0;
        let read_user = std::ffi::CStr::from_ptr(read.UserName.cast()).to_bytes();
        let read_blob = std::slice::from_raw_parts(read.CredentialBlob, read.CredentialBlobSize as usize);
        if read_user != &user_a[..user_a.len() - 1] || read_blob != secret {
            return Err(format!(
                "CredReadA returned user {:?}, blob {read_blob:?}",
                String::from_utf8_lossy(read_user)
            ));
        }

        // CredEnumerateA lists the vault, not the host store.
        let mut count = 0u32;
        let mut listed: *mut *mut CREDENTIALA = ptr::null_mut();
        if CredEnumerateA(target_a.as_ptr(), 0, &mut count, &mut listed) == 0 {
            return Err(format!(
                "CredEnumerateA did not list the vault credential ({})",
                GetLastError()
            ));
        }
        let listed_owned = OwnedCredentialA(listed.cast());
        let first = &**listed_owned.0.cast::<*mut CREDENTIALA>();
        let listed_target = std::ffi::CStr::from_ptr(first.TargetName.cast()).to_bytes();
        if count != 1 || listed_target != TARGET.as_bytes() {
            return Err(format!(
                "CredEnumerateA returned {count} credential(s), first {:?}",
                String::from_utf8_lossy(listed_target)
            ));
        }

        // A delete: the wide read must no longer find it.
        if CredDeleteA(target_a.as_ptr(), CRED_TYPE_GENERIC, 0) == 0 {
            return Err(format!("CredDeleteA failed ({})", GetLastError()));
        }
        let mut after_delete: *mut CREDENTIALW = ptr::null_mut();
        let still_there = CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut after_delete) != 0;
        let _after_delete = OwnedCredential(after_delete);
        if still_there {
            return Err("CredDeleteA left the vault credential in place".to_string());
        }
    }
    Ok(())
}

/// RAII owner of a block returned by an ANSI credential API.
struct OwnedCredentialA(*mut CREDENTIALA);

impl Drop for OwnedCredentialA {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a CredReadA/CredEnumerateA result owned by this wrapper.
            unsafe { CredFree(self.0.cast()) };
        }
    }
}
