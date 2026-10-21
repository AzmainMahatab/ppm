//! The engine built for x64, for injecting x64 processes emulated on an ARM64 host.

/// `redirector.dll` compiled for `x86_64-pc-windows-msvc`.
pub const REDIRECTOR_DLL: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_REDIRECTOR_redirector"));
