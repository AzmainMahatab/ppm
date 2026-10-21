//! The engine built for 32-bit x86, for injecting 32-bit processes.

/// `redirector.dll` compiled for `i686-pc-windows-msvc`.
pub const REDIRECTOR_DLL: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_REDIRECTOR_redirector"));
