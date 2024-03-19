use core::ffi::c_void;
use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};

use super::info::{SyscallInfos, SyscallType};
use crate::error::SysResult;

enum SyscallState {
    Enter,
    Exit,
}

pub struct SyscallPrinter {
    pid: Pid,
    infos: SyscallInfos,
    current_state: SyscallState,
}

fn trace_str(addr: u64, pid: Pid) -> SysResult<String> {
    let mut ret = String::new();
    let mut offset = 0;
    loop {
        let c = u8::try_from(ptrace::read(pid, (addr + offset) as *mut c_void)?)?
            as char;
        if c == '\0' {
            break;
        }
        ret.push(c);
        offset += 1;
    }

    Ok(ret)
}

fn parse_value(syscall_type: &SyscallType, val: u64, pid: Pid) -> SysResult<String> {
    match syscall_type {
        SyscallType::Int => Ok(format!("{}", i64::try_from(val)?)),
        SyscallType::Ptr => Ok(format!("0x{val:x}")),
        SyscallType::Str => Ok(format!("\"{}\"", trace_str(val, pid)?)),
        SyscallType::Uint => Ok(format!("{val}")),
    }
}

impl SyscallPrinter {
    pub fn new(pid: Pid) -> SysResult<Self> {
        let infos = SyscallInfos::new()?;

        Ok(Self {
            pid,
            infos,
            current_state: SyscallState::Enter,
        })
    }

    fn to_string(&self, regs: &user_regs_struct) -> SysResult<String> {
        let info = self.infos.get(regs.orig_rax);
        let syscall_name = info.syscall_name;
        let syscall_type = info.syscall_type;
        let syscall_return = parse_value(&syscall_type, regs.rax, self.pid)?;

        let reg_vals = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        let syscall_args = info.syscall_args.map_or(Ok(String::new()), |args| {
            args.iter()
                .enumerate()
                .map(|(i, arg)| {
                    let mut ret = arg.arg_name.clone();
                    ret.push('=');
                    ret.push_str(&parse_value(
                        &arg.arg_type,
                        reg_vals[i],
                        self.pid,
                    )?);
                    Ok(ret)
                })
                .collect::<SysResult<Vec<String>>>()
                .map(|v| v.join(", "))
        })?;

        Ok(format!("{syscall_name}({syscall_args}) = {syscall_return}"))
    }

    fn do_print(&self, regs: &user_regs_struct) -> SysResult<()> {
        let syscall_str = self.to_string(regs)?;
        println!("{syscall_str}");

        Ok(())
    }

    pub fn maybe_print(&mut self, regs: &user_regs_struct) -> SysResult<()> {
        match self.current_state {
            SyscallState::Enter => {
                self.current_state = SyscallState::Exit;
                Ok(())
            }
            SyscallState::Exit => {
                self.current_state = SyscallState::Enter;
                self.do_print(regs)
            }
        }
    }
}
