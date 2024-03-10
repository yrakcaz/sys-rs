use core::ffi::c_void;
use libc::user_regs_struct;

use nix::{sys::ptrace, unistd::Pid};

use crate::error::{operation_not_permitted, SysResult};

mod def;
use def::SYSCALL;

pub enum SyscallType {
    INT,
    PTR,
    STR,
    UINT,
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
            SyscallType::INT => Ok(format!("{}", val as i64)),
            SyscallType::PTR => Ok(format!("0x{:x}", val)),
            SyscallType::STR => Ok(format!("\"{}\"", read_str(val, pid)?)),
            SyscallType::UINT => Ok(format!("{}", val)),
        }
    }
}

pub struct SyscallArg {
    arg_name: String,
    arg_type: SyscallType,
}

impl SyscallArg {
    pub fn new(arg_name: &str, arg_type: SyscallType) -> Self {
        Self {
            arg_name: String::from(arg_name),
            arg_type,
        }
    }
}

pub struct SyscallDef {
    syscall_name: String,
    return_type: SyscallType,
    syscall_args: Vec<SyscallArg>,
}

impl SyscallDef {
    pub fn new(name: &str, return_type: SyscallType, syscall_args: Vec<SyscallArg>) -> Self {
        Self {
            syscall_name: String::from(name),
            return_type,
            syscall_args,
        }
    }
}

pub struct SyscallData<'a> {
    def: Option<&'a SyscallDef>,
    regs: Option<user_regs_struct>,
    pid: Pid,
}

impl SyscallData<'_> {
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
                self.def = Some(&SYSCALL[&regs.orig_rax]);
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
            _ => operation_not_permitted(),
        }
    }

    pub fn complete(&self) -> bool {
        self.def.is_some() && self.regs.is_some()
    }

    fn validate(&self) -> SysResult<()> {
        if !self.complete() {
            operation_not_permitted()?;
        }

        Ok(())
    }

    fn get_name(&self) -> SysResult<&String> {
        self.validate()?;
        Ok(&self.def.unwrap().syscall_name)
    }

    fn get_return(&self) -> SysResult<String> {
        self.validate()?;
        let return_type = &self.def.unwrap().return_type;
        return_type.parse_value(self.regs.unwrap().rax, self.pid)
    }

    fn get_args(&self) -> SysResult<String> {
        self.validate()?;
        let regs = self.regs.as_ref().expect("Regs not initialized");
        let reg_vals = vec![regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];

        let args = &self
            .def
            .as_ref()
            .expect("Definition not initialized")
            .syscall_args;
        let arg_strings = args
            .iter()
            .enumerate()
            .map(|(i, arg)| {
                let mut ret = arg.arg_name.clone();
                ret.push_str(" = ");
                ret.push_str(&arg.arg_type.parse_value(reg_vals[i], self.pid)?);
                Ok(ret)
            })
            .collect::<Vec<SysResult<String>>>();

        let mut iter = arg_strings.into_iter();
        let mut ret = String::new();
        while let Some(arg) = iter.next() {
            match arg {
                Ok(s) => {
                    if !ret.is_empty() {
                        ret.push_str(", ");
                    }
                    ret.push_str(&s);
                }
                Err(errno) => return Err(errno),
            }
        }

        Ok(ret)
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
