use core::ffi::c_void;
use nix::{errno::Errno, sys::ptrace, unistd::Pid};
use std::fmt;

use super::info::{SyscallInfos, SyscallType};
use crate::error::SysResult;

pub struct SyscallRepr {
    syscall_name: String,
    syscall_return: String,
    syscall_args: String,
}

fn trace_str(addr: u64, pid: Pid) -> SysResult<String> {
    if addr == 0 {
        return Ok(String::from("?"));
    }

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

    Ok(format!("\"{ret}\""))
}

fn parse_value(syscall_type: &SyscallType, val: u64, pid: Pid) -> SysResult<String> {
    match syscall_type {
        SyscallType::Int => Ok(format!("{}", val as i64)),
        SyscallType::Ptr => {
            let ptr_str = if val == 0 {
                String::from("NULL")
            } else {
                format!("0x{val:x}")
            };
            Ok(ptr_str)
        }
        SyscallType::Str => Ok(trace_str(val, pid)?),
        SyscallType::Uint => Ok(format!("{val}")),
    }
}

impl SyscallRepr {
    pub fn build(pid: Pid, infos: &SyscallInfos) -> SysResult<Self> {
        let regs = ptrace::getregs(pid)?;
        let info = infos.get(regs.orig_rax);
        let syscall_name = info.syscall_name;
        let syscall_type = info.syscall_type;
        let syscall_return = if regs.rax as i64 == -(Errno::ENOSYS as i64) {
            String::from("?")
        } else {
            parse_value(&syscall_type, regs.rax, pid)?
        };

        let reg_vals = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        let syscall_args = info.syscall_args.map_or(Ok(String::new()), |args| {
            args.iter()
                .enumerate()
                .map(|(i, arg)| {
                    let mut ret = arg.arg_name.clone();
                    ret.push('=');
                    ret.push_str(&parse_value(&arg.arg_type, reg_vals[i], pid)?);
                    Ok(ret)
                })
                .collect::<SysResult<Vec<String>>>()
                .map(|v| v.join(", "))
        })?;

        Ok(Self {
            syscall_name,
            syscall_return,
            syscall_args,
        })
    }

    pub fn is_exit(&self) -> bool {
        self.syscall_name.contains("exit")
    }
}

impl fmt::Display for SyscallRepr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}) = {}",
            self.syscall_name, self.syscall_args, self.syscall_return
        )
    }
}
