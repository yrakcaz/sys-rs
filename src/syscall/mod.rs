use core::ffi::c_void;
use nix::{errno::Errno, sys::ptrace, unistd::Pid};
use std::fmt;

use crate::diag::Result;

pub mod info;
use info::{Entries, Type};

pub struct Repr {
    name: String,
    args: String,
    ret_val: String,
}

fn trace_str(addr: u64, pid: Pid) -> Result<String> {
    let mut ret = String::new();
    let mut offset = 0;
    loop {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let c = ptrace::read(pid, (addr + offset) as *mut c_void)? as u8 as char;
        if c == '\0' {
            break;
        }
        ret.push(c);
        offset += 1;
    }

    Ok(format!("\"{ret}\""))
}

fn parse_value(type_repr: &Type, val: u64, pid: Pid) -> Result<String> {
    match type_repr {
        #[allow(clippy::cast_possible_wrap)]
        Type::Int => Ok(format!("{}", val as i64)),
        Type::Ptr => {
            let ptr_str = if val == 0x0 {
                "NULL".to_string()
            } else {
                format!("0x{val:x}")
            };
            Ok(ptr_str)
        }
        Type::Str => Ok(if val == 0x0 {
            "?".to_string()
        } else {
            trace_str(val, pid)?
        }),
        Type::Uint => Ok(format!("{val}")),
    }
}

impl Repr {
    /// # Errors
    ///
    /// Will return `Err` upon `ptrace::getregs()` or `ptrace::read()` failure.
    pub fn build(pid: Pid, infos: &Entries) -> Result<Self> {
        let regs = ptrace::getregs(pid)?;
        let info = infos.get(regs.orig_rax);
        let name = info.name();

        let reg_vals = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        let args = info.args().clone().map_or(Ok(String::new()), |args| {
            args.iter()
                .enumerate()
                .map(|(i, arg)| {
                    let mut ret = arg.name().clone();
                    ret.push('=');
                    ret.push_str(&parse_value(arg.arg_type(), reg_vals[i], pid)?);
                    Ok(ret)
                })
                .collect::<Result<Vec<String>>>()
                .map(|v| v.join(", "))
        })?;

        #[allow(clippy::cast_possible_wrap)]
        let ret_val = if regs.rax as i64 == -(Errno::ENOSYS as i64) {
            "?".to_string()
        } else {
            parse_value(info.ret_type(), regs.rax, pid)?
        };

        Ok(Self {
            name: name.to_string(),
            args,
            ret_val,
        })
    }

    #[must_use]
    pub fn is_exit(&self) -> bool {
        self.name.contains("exit")
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({}) = {}", self.name, self.args, self.ret_val)
    }
}
