#![allow(non_snake_case, non_upper_case_globals)]

use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;

pub type NTSTATUS = i32;

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC0000034_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023_u32 as i32;
pub const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x80000005_u32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022_u32 as i32;
pub const STATUS_NO_MORE_ENTRIES: NTSTATUS = 0x8000001A_u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000D_u32 as i32;

// Standard Win32 Registry Types
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

impl UNICODE_STRING {
    pub unsafe fn to_string_lossy(&self) -> String {
        if self.Buffer.is_null() || self.Length == 0 {
            return String::new();
        }
        let slice = std::slice::from_raw_parts(self.Buffer, (self.Length / 2) as usize);
        String::from_utf16_lossy(slice)
    }
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

// Key Value Information Classes
pub const KeyValueBasicInformation: u32 = 0;
pub const KeyValueFullInformation: u32 = 1;
pub const KeyValuePartialInformation: u32 = 2;

#[repr(C)]
pub struct KEY_VALUE_PARTIAL_INFORMATION {
    pub TitleIndex: u32,
    pub Type: u32,
    pub DataLength: u32,
    pub Data: [u8; 1],
}

#[repr(C)]
pub struct KEY_VALUE_FULL_INFORMATION {
    pub TitleIndex: u32,
    pub Type: u32,
    pub DataOffset: u32,
    pub DataLength: u32,
    pub NameLength: u32,
    pub Name: [u16; 1],
}

#[repr(C)]
pub struct KEY_VALUE_BASIC_INFORMATION {
    pub TitleIndex: u32,
    pub Type: u32,
    pub NameLength: u32,
    pub Name: [u16; 1],
}

// Key Information Classes
pub const KeyBasicInformation: u32 = 0;
pub const KeyNodeInformation: u32 = 1;

#[repr(C)]
pub struct KEY_BASIC_INFORMATION {
    pub LastWriteTime: i64,
    pub TitleIndex: u32,
    pub NameLength: u32,
    pub Name: [u16; 1],
}
