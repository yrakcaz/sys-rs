use core::ffi::c_void;
use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};
use serde_derive::Deserialize;
use std::collections::HashMap;

use crate::error::{operation_not_permitted, SysResult};

#[derive(Clone, Deserialize)]
enum SyscallType {
    Int,
    Ptr,
    Str,
    Uint,
}

fn read_str(addr: u64, pid: Pid) -> SysResult<String> {
    let mut ret = String::new();
    let mut offset = 0;
    loop {
        let c = ptrace::read(pid, (addr + offset) as *mut c_void)? as u8 as char;
        if c == '\0' {
            break;
        }
        ret.push(c);
        offset += 1;
    }

    Ok(ret)
}

impl SyscallType {
    fn parse_value(&self, val: u64, pid: Pid) -> SysResult<String> {
        match &self {
            SyscallType::Int => Ok(format!("{}", val as i64)),
            SyscallType::Ptr => Ok(format!("0x{:x}", val)),
            SyscallType::Str => Ok(format!("\"{}\"", read_str(val, pid)?)),
            SyscallType::Uint => Ok(format!("{}", val)),
        }
    }
}

#[derive(Clone, Deserialize)]
struct SyscallArg {
    arg_name: String,
    arg_type: SyscallType,
}

#[derive(Clone, Deserialize)]
struct SyscallDef {
    syscall_name: String,
    syscall_type: SyscallType,
    syscall_args: Option<Vec<SyscallArg>>,
}

struct SyscallDefs {
    map: HashMap<u64, SyscallDef>,
}

impl SyscallDefs {
    fn new() -> Self {
        let json = include_str!("def.json");
        Self {
            map: serde_json::from_str(&json).expect("Failed to parse JSON file"),
        }
    }

    fn get(&self, id: &u64) -> SyscallDef {
        self.map.get(id).cloned().unwrap_or_else(|| SyscallDef {
            syscall_name: String::from("unknown"),
            syscall_type: SyscallType::Int,
            syscall_args: None,
        })
    }
}

lazy_static! {
    static ref SYSCALL: SyscallDefs = SyscallDefs::new();
}

pub struct SyscallData {
    def: Option<SyscallDef>,
    regs: Option<user_regs_struct>,
    pid: Pid,
}

impl SyscallData {
    pub fn new(pid: Pid) -> Self {
        Self {
            def: None,
            regs: None,
            pid,
        }
    }

    pub fn push(&mut self, regs: user_regs_struct) -> SysResult<()> {
        match self {
            Self {
                def: None,
                regs: None,
                pid: _,
            } => {
                self.def = Some(SYSCALL.get(&regs.orig_rax));
                Ok(())
            }
            Self {
                def: _,
                regs: None,
                pid: _,
            } => {
                self.regs = Some(regs);
                Ok(())
            }
            _ => Err(operation_not_permitted()),
        }
    }

    pub fn complete(&self) -> bool {
        self.def.is_some() && self.regs.is_some()
    }

    fn validate(&self) -> SysResult<()> {
        if !self.complete() {
            return Err(operation_not_permitted());
        }

        Ok(())
    }

    fn get_name(&self) -> SysResult<String> {
        self.validate()?;
        Ok(self
            .def
            .as_ref()
            .ok_or_else(|| operation_not_permitted())?
            .syscall_name
            .clone())
    }

    fn get_return(&self) -> SysResult<String> {
        self.validate()?;
        let syscall_type = self
            .def
            .as_ref()
            .ok_or_else(|| operation_not_permitted())?
            .syscall_type
            .clone();
        syscall_type.parse_value(self.regs.unwrap().rax, self.pid)
    }

    fn get_args(&self) -> SysResult<String> {
        self.validate()?;
        let regs = self.regs.as_ref().expect("Regs not initialized");
        let reg_vals = vec![regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];

        Ok(self
            .def
            .as_ref()
            .expect("Definition not initialized")
            .syscall_args
            .as_ref()
            .map_or(Ok(String::new()), |args| {
                args.iter()
                    .enumerate()
                    .map(|(i, arg)| {
                        let mut ret = arg.arg_name.clone();
                        ret.push('=');
                        ret.push_str(&arg.arg_type.parse_value(reg_vals[i], self.pid)?);
                        Ok(ret)
                    })
                    .collect::<SysResult<Vec<String>>>()
                    .map(|v| v.join(", "))
            })?)
    }

    pub fn to_string(&self) -> SysResult<String> {
        let syscall_name = self.get_name()?;
        let return_val = self.get_return()?;
        let syscall_args = self.get_args()?;
        Ok(format!(
            "{}({}) = {}",
            syscall_name, syscall_args, return_val
        ))
    }
}
