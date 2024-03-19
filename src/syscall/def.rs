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
pub struct SyscallDef {
    pub syscall_name: String,
    pub syscall_type: SyscallType,
    pub syscall_args: Option<Vec<SyscallArg>>,
}

pub struct SyscallDefs {
    map: HashMap<u64, SyscallDef>,
}

impl SyscallDefs {
    pub fn new() -> SysResult<Self> {
        let json = include_str!("def.json");
        let map = serde_json::from_str(json)?;
        Ok(Self { map })
    }

    pub fn get(&self, id: u64) -> SyscallDef {
        self.map.get(&id).cloned().unwrap_or_else(|| SyscallDef {
            syscall_name: String::from("unknown"),
            syscall_type: SyscallType::Int,
            syscall_args: None,
        })
    }
}
