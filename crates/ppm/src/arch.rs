use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum CpuArch {
    #[serde(rename = "x64", alias = "x86_64", alias = "amd64")]
    X64,
    #[serde(rename = "arm64", alias = "aarch64")]
    Arm64,
}

impl CpuArch {
    /// Detects the physical host CPU architecture, even when running under emulation.
    pub fn current() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            CpuArch::Arm64
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            detect_native_windows_arch()
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CpuArch::X64 => "x64",
            CpuArch::Arm64 => "arm64",
        }
    }

    pub fn all() -> &'static [CpuArch] {
        &[CpuArch::X64, CpuArch::Arm64]
    }
}

impl fmt::Display for CpuArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(windows)]
fn detect_native_windows_arch() -> CpuArch {
    use windows_sys::Win32::System::SystemInformation::{
        GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_ARM64, SYSTEM_INFO,
    };

    let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetNativeSystemInfo(&mut sys_info);
    }

    let arch_code = unsafe { sys_info.Anonymous.Anonymous.wProcessorArchitecture };
    if arch_code == PROCESSOR_ARCHITECTURE_ARM64 {
        CpuArch::Arm64
    } else {
        CpuArch::X64
    }
}

#[cfg(not(windows))]
fn detect_native_windows_arch() -> CpuArch {
    CpuArch::X64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ArchTarget {
    X64,
    Arm64,
    All,
}

impl ArchTarget {
    pub fn resolve(&self) -> Vec<CpuArch> {
        match self {
            ArchTarget::X64 => vec![CpuArch::X64],
            ArchTarget::Arm64 => vec![CpuArch::Arm64],
            ArchTarget::All => vec![CpuArch::X64, CpuArch::Arm64],
        }
    }
}
