//! The machine a process runs as, and the host's native machine.

use std::fmt;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessInformation, IsWow64Process2, PROCESS_MACHINE_INFORMATION,
    ProcessMachineTypeInfo,
};

use crate::InjectError;

/// An instruction set a Windows process can run as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Machine {
    X86,
    X64,
    Arm64,
}

impl Machine {
    /// The machine this code was compiled for.
    pub const fn current() -> Machine {
        if cfg!(target_arch = "x86") {
            Machine::X86
        } else if cfg!(target_arch = "aarch64") {
            Machine::Arm64
        } else {
            Machine::X64
        }
    }

    /// Maps a PE `IMAGE_FILE_MACHINE_*` value, or `None` for a machine ppm has no engine for.
    pub fn from_image_machine(value: IMAGE_FILE_MACHINE) -> Option<Machine> {
        match value {
            IMAGE_FILE_MACHINE_I386 => Some(Machine::X86),
            IMAGE_FILE_MACHINE_AMD64 => Some(Machine::X64),
            IMAGE_FILE_MACHINE_ARM64 => Some(Machine::Arm64),
            _ => None,
        }
    }

    pub fn is_64_bit(self) -> bool {
        !matches!(self, Machine::X86)
    }

    /// The name ppm uses for this machine in paths (`Apps/<arch>`, `.ppm/lib/<arch>`).
    pub fn as_str(self) -> &'static str {
        match self {
            Machine::X86 => "x86",
            Machine::X64 => "x64",
            Machine::Arm64 => "arm64",
        }
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The host's native machine. An x64 process emulated on ARM64 gets `Arm64` here.
pub(crate) fn host() -> Machine {
    let (mut process, mut native) = (IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_UNKNOWN);
    // SAFETY: the pseudo-handle is always valid; both out-parameters are live locals.
    let queried = unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } != 0;
    // Why the fallback is sound: IsWow64Process2 exists on every Windows ppm supports (1709+); a
    // failure leaves `native` unset, and the code's own machine is then the only fact available,
    // which is exact everywhere except under emulation.
    queried
        .then(|| Machine::from_image_machine(native))
        .flatten()
        .unwrap_or(Machine::current())
}

/// The machine a (typically suspended) process runs as.
///
/// # Why `GetProcessInformation` first
/// `IsWow64Process2` only recognises WOW64 - a 32-bit process on a 64-bit OS. An x64 process
/// emulated on ARM64 is not WOW64, so that API reports nothing for it, and the engine would
/// inject the ARM64 build into an x64 process. `ProcessMachineTypeInfo` (Windows 11) reports the
/// actual machine; Windows 10, which has no x64 emulation, is fully served by the fallback.
///
/// # Safety
/// `process` must be a live handle with `PROCESS_QUERY_LIMITED_INFORMATION` access.
pub(crate) unsafe fn of_process(process: HANDLE) -> Result<Machine, InjectError> {
    let mut info = PROCESS_MACHINE_INFORMATION {
        ProcessMachine: IMAGE_FILE_MACHINE_UNKNOWN,
        Res0: 0,
        MachineAttributes: 0,
    };
    // SAFETY: `info` is a correctly sized, live out-buffer; `process` per the caller contract.
    let has_machine_info = unsafe {
        GetProcessInformation(
            process,
            ProcessMachineTypeInfo,
            std::ptr::from_mut(&mut info).cast(),
            size_of::<PROCESS_MACHINE_INFORMATION>() as u32,
        )
    } != 0;
    if has_machine_info {
        return Machine::from_image_machine(info.ProcessMachine)
            .ok_or(InjectError::UnsupportedMachine(info.ProcessMachine));
    }

    let (mut wow64_machine, mut native) = (IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_UNKNOWN);
    // SAFETY: as above.
    if unsafe { IsWow64Process2(process, &mut wow64_machine, &mut native) } == 0 {
        return Err(InjectError::MachineQuery(std::io::Error::last_os_error()));
    }
    // A non-WOW64 process reports UNKNOWN here and runs as the native machine.
    let effective = if wow64_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native
    } else {
        wow64_machine
    };
    Machine::from_image_machine(effective).ok_or(InjectError::UnsupportedMachine(effective))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_machine_values_map_to_their_machines() {
        // winnt.h: IMAGE_FILE_MACHINE_I386 0x014c, AMD64 0x8664, ARM64 0xAA64.
        assert_eq!(Machine::from_image_machine(0x014c), Some(Machine::X86));
        assert_eq!(Machine::from_image_machine(0x8664), Some(Machine::X64));
        assert_eq!(Machine::from_image_machine(0xAA64), Some(Machine::Arm64));
        // ARM (32-bit Thumb-2, 0x01c4) has no engine build.
        assert_eq!(Machine::from_image_machine(0x01c4), None);
    }

    #[test]
    fn this_process_is_reported_as_the_machine_it_was_built_for() {
        // SAFETY: the current-process pseudo-handle is always valid.
        let machine = unsafe { of_process(GetCurrentProcess()) }.expect("query own machine");
        assert_eq!(machine, Machine::current());
    }
}
