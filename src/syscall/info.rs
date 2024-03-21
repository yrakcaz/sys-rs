use serde_derive::Deserialize;
use std::collections::HashMap;

use crate::error::SysResult;

#[derive(Clone, Deserialize)]
pub enum SyscallType {
    Int,
    Ptr,
    Str,
    Uint,
}

#[derive(Clone, Deserialize)]
pub struct SyscallArg {
    pub arg_name: String,
    pub arg_type: SyscallType,
}

#[derive(Clone, Deserialize)]
pub struct SyscallInfo {
    pub syscall_name: String,
    pub syscall_type: SyscallType,
    pub syscall_args: Option<Vec<SyscallArg>>,
}

pub struct SyscallInfos {
    map: HashMap<u64, SyscallInfo>,
}

impl SyscallInfos {
    pub fn new() -> SysResult<Self> {
        let json = include_str!("info.json");
        let map = serde_json::from_str(json)?;
        Ok(Self { map })
    }

    pub fn get(&self, id: u64) -> SyscallInfo {
        self.map.get(&id).cloned().unwrap_or_else(|| SyscallInfo {
            syscall_name: "unknown".to_string(),
            syscall_type: SyscallType::Int,
            syscall_args: None,
        })
    }
}
