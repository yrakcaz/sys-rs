use core::ffi::c_void;
use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};

use crate::error::{operation_not_permitted, SysResult};
use super::def::{SyscallDefs, SyscallType};

enum SyscallState {
    Enter,
    Exit,
}

pub struct SyscallPrinter {
    pid: Pid,
    defs: SyscallDefs,
    current_state: SyscallState,
    current_syscall: Option<u64>,
}

fn trace_str(addr: &u64, pid: &Pid) -> SysResult<String> {
    let mut ret = String::new();
    let mut offset = 0;
    loop {
        let c = ptrace::read(*pid, (addr + offset) as *mut c_void)? as u8 as char;
        if c == '\0' {
            break;
        }
        ret.push(c);
        offset += 1;
    }

    Ok(ret)
}

fn parse_value(syscall_type: &SyscallType, val: &u64, pid: &Pid) -> SysResult<String> {
    match syscall_type {
        SyscallType::Int => Ok(format!("{}", *val as i64)),
        SyscallType::Ptr => Ok(format!("0x{:x}", val)),
        SyscallType::Str => Ok(format!("\"{}\"", trace_str(val, pid)?)),
        SyscallType::Uint => Ok(format!("{}", val)),
    }
}

impl SyscallPrinter {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            defs: SyscallDefs::new(),
            current_state: SyscallState::Enter,
            current_syscall: None,
        }
    }

    fn do_print(&self, regs: &user_regs_struct) -> SysResult<()> {
        let def = self.defs.get(&self.current_syscall.unwrap());
        let syscall_name = def.syscall_name;
        let syscall_type = def.syscall_type;
        let syscall_return = parse_value(&syscall_type, &regs.rax, &self.pid)?;

        let reg_vals = vec![regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        let syscall_args = def.syscall_args.map_or(Ok(String::new()), |args| {
            args.iter()
                .enumerate()
                .map(|(i, arg)| {
                    let mut ret = arg.arg_name.clone();
                    ret.push('=');
                    ret.push_str(&parse_value(&arg.arg_type, &reg_vals[i], &self.pid)?);
                    Ok(ret)
                })
                .collect::<SysResult<Vec<String>>>()
                .map(|v| v.join(", "))
        })?;

        println!("{}({}) = {}", syscall_name, syscall_args, syscall_return);
        Ok(())
    }

    pub fn maybe_print(&mut self, regs: &user_regs_struct) -> SysResult<()> {
        match self.current_state {
            SyscallState::Enter => {
                self.current_state = SyscallState::Exit;
                self.current_syscall = Some(regs.orig_rax);
                Ok(())
            }
            SyscallState::Exit => {
                self.current_state = SyscallState::Enter;
                match self.current_syscall {
                    None => operation_not_permitted(),
                    Some(v) if v != regs.orig_rax => operation_not_permitted(),
                    _ => self.do_print(regs),
                }
            }
        }
    }
}
