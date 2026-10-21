//! The verification probe built for 32-bit x86.

/// Absolute path of `test-probe.exe` compiled for `i686-pc-windows-msvc`.
pub const PROBE_EXE: &str = env!("CARGO_BIN_FILE_TEST_PROBE_test-probe");
