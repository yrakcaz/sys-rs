use std::fmt;
use libc::user_regs_struct;

use crate::error::{
    SysResult,
    invalid_io,
};

use crate::syscall_defs::SYSCALL;

pub enum SyscallType {
    INT,
    PTR,
    STR,
    UINT,
}

impl SyscallType {
    fn parse_value(&self, val: u64) -> String {
        match &self {
            SyscallType::INT => {
                format!{"{}", val as i64}
            }
            SyscallType::PTR => {
                format!{"{:x}", val}
            }
            SyscallType::STR => {
                format!{"0x{:x}", val} // FIXME
            }
            SyscallType::UINT => {
                format!{"{}", val}
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
}

impl SyscallData<'_> {
    pub fn new() -> Self {
        Self { def: None, regs: None }
    }

    pub fn push(&mut self, regs: user_regs_struct) -> SysResult<()> {
        match self {
            Self { def: None, regs: None } => {
                self.def = Some(&SYSCALL[&regs.orig_rax]);
                Ok(())
            }
            Self { def: _, regs: None } => {
                self.regs = Some(regs);
                Ok(())
            }
            _ => invalid_io()
        }
    }

    pub fn complete(&self) -> bool {
        self.def.is_some() && self.regs.is_some()
    }

    fn validate(&self) { // FIXME is this the correct way??
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
        return_type.parse_value(self.regs.unwrap().rax)
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
                ret.push('=');
                ret.push_str(&arg.arg_type.parse_value(reg_vals[i]));
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
        write!(f, "{}({})={}", syscall_name, syscall_args, return_val)
    }
}
