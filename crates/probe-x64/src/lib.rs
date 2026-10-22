//! The verification probe built for x64.

/// Absolute path of `test-probe.exe` compiled for `x86_64-pc-windows-msvc`.
pub const PROBE_EXE: &str = env!("CARGO_BIN_FILE_TEST_PROBE_test-probe");
