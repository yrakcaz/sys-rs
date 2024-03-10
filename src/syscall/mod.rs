use core::ffi::c_void;
use libc::user_regs_struct;
use std::fmt;

use nix::{
    sys::ptrace,
    unistd::Pid,
};

use crate::error::{
    SysResult,
    invalid_io,
};

mod def;
use def::SYSCALL;

pub enum SyscallType {
    INT,
    PTR,
    STR,
    UINT,
}

// FIXME havin to pass the pid all the way here seems antipattern
fn read_str(pid: Pid, addr: u64) -> SysResult<String> {
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
    fn parse_value(&self, val: u64, pid: Pid) -> String {
        match &self {
            SyscallType::INT => {
                format!("{}", val as i64)
            }
            SyscallType::PTR => {
                format!("0x{:x}", val)
            }
            SyscallType::STR => {
                format!("\"{}\"", read_str(pid, val).unwrap()) // FIXME incorrect, we should use `?`
            }
            SyscallType::UINT => {
                format!("{}", val)
            }
        }
    }
}

// FIXME should we store more refs in the structs??

pub struct SyscallArg {
    arg_name: String,
    arg_type: SyscallType,
}

impl SyscallArg {
    pub fn new(arg_name: &str, arg_type: SyscallType) -> Self {
        Self { arg_name: String::from( arg_name ), arg_type }
    }
}

pub struct SyscallDef {
    syscall_name: String,
    return_type: SyscallType,
    syscall_args: Vec<SyscallArg>,
}

impl SyscallDef {
    pub fn new(name: &str, return_type: SyscallType, syscall_args: Vec<SyscallArg>) -> Self {
        Self { syscall_name: String::from( name ), return_type, syscall_args }
    }
}

pub struct SyscallData<'a> {
    def: Option<&'a SyscallDef>,
    regs: Option<user_regs_struct>,
    pid : Pid,
}

impl SyscallData<'_> {
    pub fn new( pid: Pid ) -> Self {
        Self { def: None, regs: None, pid }
    }

    pub fn push(&mut self, regs: user_regs_struct) -> SysResult<()> {
        match self {
            Self { def: None, regs: None, pid: _ } => {
                self.def = Some(&SYSCALL[&regs.orig_rax]);
                Ok(())
            }
            Self { def: _, regs: None, pid: _ } => {
                self.regs = Some(regs);
                Ok(())
            }
            _ => invalid_io()
        }
    }

    pub fn complete(&self) -> bool {
        self.def.is_some() && self.regs.is_some()
    }

    fn validate(&self) { // FIXME is this the correct way?? better error handling? use SysResult<> everywhere?
        if !self.complete() {
            panic!("Syscall didn't complete");
        }
    }

    fn get_name(&self) -> &String {
        self.validate();
        &self.def.unwrap().syscall_name
    }

    fn get_return(&self) -> String {
        self.validate();
        let return_type = &self.def.unwrap().return_type;
        return_type.parse_value(self.regs.unwrap().rax, self.pid)
    }

    fn get_args(&self) -> String { // FIXME this function is correct wrt refs!! use as an example
        self.validate();
        let regs = self.regs.as_ref().expect("Regs not initialized");
        let reg_vals = vec![
            regs.rdi,
            regs.rsi,
            regs.rdx,
            regs.r10,
            regs.r8,
            regs.r9,
        ];

        let args = &self.def.as_ref().expect("Definition not initialized").syscall_args;
        args.iter()
            .enumerate()
            .map(|(i, arg)| {
                let mut ret = arg.arg_name.clone();
                ret.push_str(" = ");
                ret.push_str(&arg.arg_type.parse_value(reg_vals[i], self.pid));
                ret
            })
            .collect::<Vec<String>>()
            .join(", ")
    }
}

impl fmt::Display for SyscallData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let syscall_name = self.get_name();
        let return_val = self.get_return();
        let syscall_args = self.get_args();
        write!(f, "{}({}) = {}", syscall_name, syscall_args, return_val)
    }
}
