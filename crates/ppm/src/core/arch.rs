use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum CpuArch {
    #[value(name = "x64")]
    X64,
    #[value(name = "arm64")]
    Arm64,
}

impl CpuArch {
    pub fn as_str(&self) -> &'static str {
        match self {
            CpuArch::X64 => "x64",
            CpuArch::Arm64 => "arm64",
        }
    }

    /// Detects the physical host CPU architecture using Win32 `GetNativeSystemInfo`.
    pub fn current() -> Self {
        #[cfg(windows)]
        {
            detect_windows_arch()
        }
        #[cfg(not(windows))]
        {
            #[cfg(target_arch = "aarch64")]
            {
                CpuArch::Arm64
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                CpuArch::X64
            }
        }
    }

    pub fn all() -> &'static [CpuArch] {
        &[CpuArch::X64, CpuArch::Arm64]
    }
}

impl std::fmt::Display for CpuArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ArchTarget {
    #[value(name = "x64")]
    X64,
    #[value(name = "arm64")]
    Arm64,
    #[value(name = "all")]
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

#[cfg(windows)]
fn detect_windows_arch() -> CpuArch {
    use std::mem::zeroed;
    use windows_sys::Win32::System::SystemInformation::{
        GetNativeSystemInfo, SYSTEM_INFO,
    };

    const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
    const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;

    unsafe {
        let mut sys_info: SYSTEM_INFO = zeroed();
        GetNativeSystemInfo(&mut sys_info);

        let arch_id = sys_info.Anonymous.Anonymous.wProcessorArchitecture;
        match arch_id {
            PROCESSOR_ARCHITECTURE_ARM64 => CpuArch::Arm64,
            PROCESSOR_ARCHITECTURE_AMD64 => CpuArch::X64,
            _ => CpuArch::X64,
        }
    }
}
